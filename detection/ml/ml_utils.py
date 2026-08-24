import base64
import os
import time
import json
import joblib
import logging
import functools
import threading
from requests.utils import quote as _quote

from collections import OrderedDict
from typing import List, Dict, Any, Optional

import numpy as np
import traceback
import pandas as pd
import requests
import warnings
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from dotenv import load_dotenv
load_dotenv()
from detection.ml.features_extraction import extract_features
_HAS_BERT=False

IPQS_API_KEY = os.getenv("IPQS_API_KEY")
warnings.filterwarnings("ignore", message="X does not have valid feature names")

# RF_MODEL_PATH = "url_checker/ml_models/phiusiil_url_model.joblib"
# FEATURE_JSON_PATH = "url_checker/ml_models/phiusiil_features.json"

# Load feature list if available
FEATURE_LIST = []
features_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ml_models/phiusiil_features.json"))
if os.path.exists(features_path):
    with open(features_path, "r") as f:
        FEATURE_LIST = json.load(f)

try:
    import shap
except Exception:
    shap=None
# T Django settings if running inside Django
try:
    from django.conf import settings
    BASE_DIR=getattr(settings, 'BASE_DIR', None)
    API_KEY=getattr(settings, 'API_KEY', None)

except Exception:
    BASE_DIR=None
    API_KEY=os.environ.get('API_KEY')

# detection/ml -> Django project root. Do not create application directories
# during import; production code is often mounted read-only.
if BASE_DIR is None:
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
else:
    BASE_DIR = str(BASE_DIR)
# Keep model artifacts alongside this module. The previous location pointed to
# a non-existent project-root folder and left the classifier permanently off.
MODELS_DIR=os.path.join(os.path.dirname(__file__), 'ml_models')
RF_MODEL_NAME = "phiusiil_url_model.joblib"
HYBRID_MODEL_NAME = "phiusiil_hybrid_model.joblib"
LOG_DIR=os.path.join(BASE_DIR,'logs')

# logging
logger=logging.getLogger('ml_utils')
if not logger.handlers:
    handler=logging.StreamHandler()
    formatter=logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Local imports

try:
    from detection.ml.features_extraction import extract_features

except Exception:
     # user must provide extract_features
     def extract_features(_:str)->Dict[str,Any]:
         raise RuntimeError("features_extraction.extract_features not found. Create it before using ml_utils.")
     
_HAS_BERT=False
get_bert_score=None
try:
    from detection.ml.bert_scorer import get_bert_score
    _HAS_BERT = True
    logger.info("BERT scoring enabled.")
except Exception:
    _HAS_BERT = False
    get_bert_score = None
    logger.info("BERT scorer not available (continuing without BERT).")



#  Configuration / constants
RF_MODEL_NAME="phiusiil_url_model.joblib"      # primary feature model
HYBRID_MODEL_NAME="phiusiil_hybrid_model.joblib"  # RF + BERT hybrid model
FEATURES_JSON="features_list.json"
SHAP_SAMPLE_SIZE=200
FEATURES_JSON_CANDIDATES = ["phiusiil_features.json", "phiusiil_features_list.json", "features_list.json", "features.json"]


# # Fusion weights (tuneable)
# RF_WEIGHT=0.65
# BERT_WEIGHT=0.35
_models = {
    "rf": None,
    "hybrid": None,
    "feature_order": None,
    "shap_explainer": None
}

#  Simple LRU cache for predictions (in-memory)
_CACHE_SIZE=10000
_prediction_cache_lock=threading.Lock()
_prediction_cache=OrderedDict()



def _cache_get(key):
    with _prediction_cache_lock:
        val=_prediction_cache.get(key)
        if val is not None:
            _prediction_cache.move_to_end(key)
        return val
    
def _cache_set(key,value):
    with _prediction_cache_lock:
        _prediction_cache[key]=value
        if len(_prediction_cache) > _CACHE_SIZE:
            _prediction_cache.popitem(last=False)



def _load_joblib_model(filepath:str):
    if not os.path.exists(filepath):
        logger.warning(f"Model file missing: {filepath}")
        return None
    try:
        model=joblib.load(filepath)
        logger.info(f"Loaded model: {os.path.basename(filepath)}")
        return model
    except Exception as e:
        logger.exception(f"Failed to load model {filepath}: {e}")
        return None

def _find_features_file() -> Optional[str]:
    for name in FEATURES_JSON_CANDIDATES:
        p=os.path.join(MODELS_DIR,name)
        if os.path.exists(p):
            return p
    return None

def load_models(force_reload:bool=False):
    """Lazy load models and feature order"""
    # RF Model
    rf_path=os.path.join(MODELS_DIR,RF_MODEL_NAME)
    if _models['rf'] is None or force_reload:
        _models['rf']=_load_joblib_model(rf_path)
        logger.info("Random Forest model loaded successfully.")
    # Hybrid Model
    hybrid_path=os.path.join(MODELS_DIR,HYBRID_MODEL_NAME)
    if _models['hybrid'] is None or force_reload:
        _models['hybrid']=_load_joblib_model(hybrid_path)
        logger.info("Hybrid model loaded successfully.")

    # load features order if present
    features_path=_find_features_file()
    if features_path and  (_models['feature_order'] is None or force_reload):
        if os.path.exists(features_path):
            try:
                with open(features_path,'r') as fh:
                    data=json.load(fh)
                    if isinstance(data,dict):
                        data=list(data.keys())
                    elif not isinstance(data,list):
                        data=list(data)
                    _models["feature_order"]=data
                    logger.info(f"Loaded feature order from {os.path.basename(features_path)}")            
            except Exception as e:
                logger.exception("Failed loading feature order JSON: %s", e)
                _models["feature_order"] = None
        else:
            logger.info("No features_list.json found; feature order unset.")
            _models["feature_order"] = None

    # A fitted pipeline's feature names are authoritative. The JSON file may
    # describe a newer extractor and otherwise causes sklearn to reject input.
    rf = _models.get("rf")
    if rf is not None and hasattr(rf, "feature_names_in_"):
        _models["feature_order"] = list(rf.feature_names_in_)
    # prepare SHAP explainer lazily if possible
    if shap is not None  and _models['shap_explainer'] is None and _models['rf'] is not None:
        _models['shap_explainer'] = None 
load_models()


def _row_from_features_dict(feat_dict:Dict[str,Any]) -> np.ndarray:
    """
    Convert a dict of features (name->value) into model-order numpy array.
    If feature order not available, build order from keys (stable sort).
    Missing features are filled with -1.
    """   
    order=_models.get('feature_order')

    try:
        if order:
            ordered=[feat_dict.get(name,-1) for name in order]
        else:
             # fallback: deterministic order by sorted keys

            keys = sorted(feat_dict.keys())
            ordered = [feat_dict.get(k, -1) for k in keys]
        return np.array(ordered, dtype=float).reshape(1, -1)
    except Exception as e:
        logger.exception("Error building row from feature dict: %s", e)
        raise
       
def _ensure_models_loaded():
    if _models['rf'] is None:
        load_models()
    return _models['rf'] is not None
def tool_url_id(url:str)-> str :
    try:
        b=base64.urlsafe_b64encode(url.encode())
        s=b.decode().rstrip("=")
        return s
    except Exception:
        return _quote(url, safe="")


def lookup(url:str,api_key:Optional[str]=None)->Dict[str,Any]:
    api_key=api_key or API_KEY
    if not api_key:
        return {"error": " API key not provided"}
    if requests is None:
        return {"error": "requests library not installed"}
    try:
        url_id=tool_url_id(url)
        headers={'x-apikey':api_key}
      
        report_url=f"https://www.virustotal.com/api/v3/urls/{url_id}"
        resp=requests.get(report_url,headers=headers,timeout=10)
        if resp.status_code==200:
            data=resp.json()
            # extract useful fields safely
            stats={}
            try:
                attrs=data.get("data",{}).get("attributes",{}) if isinstance(data, dict) else {}
                analysis=attrs.get("last_analysis_stats",{})
                stats={
                    "malicious":analysis.get("malicious",0),
                    "suspicious":analysis.get("suspicious",0),
                    "harmless":analysis.get("harmless",0),
                    "undetected":analysis.get("undetected",0),

                }
            except Exception :
                stats={"raw":data}
            return{"status":"ok","stats":stats}
        else:
            return {"error": f"VT responded {resp.status_code}", "body": resp.text}
    except Exception as e:
        logger.exception(f"Lookup Failed: {e}\n{traceback.format_exc()}")
        return {"error": str(e)}
    
# Main prediction functions

def predict_from_features_dict(feat_dict:Dict[str,Any],return_raw:bool=False) -> Dict[str,Any]:
    """
    Predict using a pre-extracted feature dictionary (keys must match training features).
    Returns dict: {pred,label,proba,raw_rf,raw_hybrid,shap_top}
    """
    try:
        cache_key=f"feat::{json.dumps(feat_dict, sort_keys=True,default=str)}"
    except Exception:
        cache_key = f"feat::raw::{str(time.time())}"
    cached=_cache_get(cache_key)
    if cached:
        return cached
    
    if not _ensure_models_loaded():
        raise RuntimeError("Models not available. Train and put models in ml_models/")
    

    try:
        row=_row_from_features_dict(feat_dict)
        rf=_models.get('rf')
        hybrid=_models.get("hybrid")
        rf_proba=None
        rf_pred=None
        if rf is not None:
            try:
                    # RF prediction + probability
                if hasattr(rf,"predict_proba"):
                    rf_proba = float(rf.predict_proba(pd.DataFrame(row, columns=_models.get("feature_order") or FEATURE_LIST))[0, 1])
                else:
                    # decision_function fallback (may be raw score)
                    rf_proba = float(rf.decision_function(row)[0])
                rf_pred=int(rf.predict(row)[0])
            except Exception as e:
                    logger.exception("RF prediction error: %s", e)
                    rf_proba = None
                    rf_pred = None


        # hybrid predictions if present
        hybrid_proba=None
        hybrid_pred=None

        if hybrid:
            try:
                expected = getattr(hybrid, "n_features_in_", row.shape[1])
                if expected != row.shape[1]:
                    raise ValueError(
                        f"Hybrid model expects {expected} features, got {row.shape[1]}"
                    )
                if hasattr(hybrid,"predict_proba"):
                    hybrid_proba = float(hybrid.predict_proba(row)[0,1])
                else:
                    hybrid_proba = float(hybrid.decision_function(row)[0])
            except Exception as e:
                logger.warning("Hybrid prediction skipped: %s", e)
                hybrid_proba=None
                hybrid_pred=None       


        # BERT-based semantic score (if available)

        bert_score=None

        if _HAS_BERT and get_bert_score :
            try:
                # if user wants to call get_bert_score separately they can; we do not assume heavy GPU
                # attempt to find a representative textual input in feat_dict ('url' or 'raw_url')
                text_input=feat_dict.get("url") or feat_dict.get("URL") or feat_dict.get("raw_url") or "" 
                if text_input:
                    score = get_bert_score(text_input)
                    bert_score=float(score) if score is not None else 0.0
            except Exception as e:
                logger.exception(f"BERT scoring failed:{e}")
                bert_score=None
        

        # Fusion logic
        # If bert is present, combine; otherwise use rf_proba (or hybrid if present)
        final_score=0.0
        if  bert_score is not None and rf_proba is not None:

            # combine RF prob (0..1) and BERT score (assumed 0..1)
            RF_WEIGHT=0.65
            BERT_WEIGHT = 0.35
            final_score=RF_WEIGHT * rf_proba + BERT_WEIGHT * bert_score
        elif  hybrid_proba is not None and rf_proba is not None:
            final_score=(rf_proba+hybrid_proba)/2.0
        elif rf_proba is not None:
            final_score=rf_proba
        else:
            final_score=0.0

        label="Phishing" if final_score >= 0.5 else "Legitimate"

        out={
            "feature_input":feat_dict,
            "rf_proba":round(rf_proba,4)  if rf_proba is not None else None,
            "rf_pred":int(rf_pred)  if rf_pred is not None else None,
            "hybrid_proba":round(hybrid_proba,4) if hybrid_proba is not None else None,
            "hybrid_pred":int(hybrid_pred) if hybrid_pred is not None else None,
            "bert_score":round(bert_score,4) if bert_score is not None else None,
            "final_score":round(final_score,4) if final_score is not None else None,
            "result":label,
            "timestamp":time.time(),
        }


        # SHAP top features 
        shap_top=None
        if shap and _models["shap_explainer"] is not None:
            try:
                explainer=_models["shap_explainer"]
                # user must compute explainer offline and set _models['shap_explainer']

                # this block will attempt only if explainer exists

                shap_vals=explainer.shap_values(row)

                # provide top positive and negative contributors
                feature_names=_models.get("feature_order") or list(feat_dict.keys())
                vals=shap_vals[0] if isinstance(shap_vals,(list,tuple)) else shap_vals
                abs_idx=np.argsort(np.abs(vals))[::-1][:8]
                shap_top=[{"feature":feature_names[i],"shap_value":float(vals[i])} for i in abs_idx]
                out["shap_top"]=shap_top
            
            except Exception as e:
                    logger.debug(f"SHAP explain error: {e}")
        _cache_set(cache_key,out)
        return out
    except Exception as e:
        logger.exception(f"predict_from_features_dict failed: {e}" )
        return {"error": str(e)}

def safe_extract_features(url:str)->Dict[str,Any]:
    try:
        return extract_features(url)
    except Exception as e:
        logger.exception("Feature extraction error for %s: %s", url, e)
        raise

    
    
def predict_url(url:str,use_tool:bool=False,api_key:Optional[str]=None, fast_mode:bool=False)->Dict[str,Any]:
    """
     High-level URL prediction:
      - extracts features (via features_extraction.extract_features)
      - runs predict_from_features_dict
      - optionally queries VirusTotal and appends vt summary
    """
    # if not url or not isinstance(url,str):
    #      return {'error': "Invalid URL"}
    out = {"url": url, "features": {}, "model": {}, "tool_summary": None}
    if not url or not isinstance(url, str):
        out["error"] = "Invalid URL"
        return out
    
    cache_key=f"url::{url}::fast={fast_mode}"
    cached=_cache_get(cache_key)
    if cached:
        return cached
    
    try:
        feat_dict=extract_features(url, fetch_page=not fast_mode)
        blacklist_info=feat_dict.get("blacklist",{})
        if isinstance(blacklist_info,dict):
            if  "blacklisted" in  blacklist_info:
                feat_dict["blacklisted_flag"]=int(blacklist_info.get("blacklisted",0))
            elif "risk_score" in blacklist_info:
                feat_dict["blacklisted_flag"]=1 if int(blacklist_info["risk_score"]) > 60 else 0
            else:
                feat_dict["blacklist_flag"] = 0
        else:
            feat_dict["blacklist_flag"] = 0    
        out["features"] = feat_dict           # email adddon                      
        if not feat_dict:
            return {"error": "Feature extraction failed"}
        
        # GET MODEL PREDICTION
        result={}
        result=predict_from_features_dict(feat_dict)
        model_part = {
            "rf_proba": result.get("rf_proba"),
            "hybrid_proba": result.get("hybrid_proba"),
            "bert_score": result.get("bert_score"),
            "final_score": result.get("final_score"),
            "result": result.get("result"),
            "rf_pred": result.get("rf_pred"),
            "rf_raw": result.get("feature_input"),  # original input kept here
            "shap_top": result.get("shap_top"),
        }
        out["model"] = model_part
   
        if use_tool and api_key:
            
            tool_summary= lookup(url,api_key)
            result['tool_summary']=tool_summary
        _cache_set(cache_key,result)
        return result
    except Exception as e:
        logger.exception("Prediction failed for URL %s: %s", url, e)
        return {"error": str(e)}
    
def predict_batch(urls:list[str],use_tool:bool=False,api_key:Optional[str]=None, fast_mode:bool=False)-> List[Dict[str,Any]]:

    """
    Batch predict a list of URLs. Returns list of result dicts in same order.
    """
    results=[]
    for u in urls:
         try:
             results.append(predict_url(u,use_tool=use_tool,api_key=api_key,fast_mode=fast_mode))
         except  Exception as e:
             logger.exception(f"Batch predict error for {u}: {e}")
             results.append({"url": u, "error": str(e)})
    return results

def predict_email_urls(url_list:list[str],use_tool:bool=False,api_key: Optional[str] = None, fast_mode:bool=True)->Dict[str,Any]:
    """
    Given list of URLs extracted from an email, predict each and return aggregated summary.
    """
    results=predict_batch(url_list,use_tool=use_tool,api_key=api_key,fast_mode=fast_mode)
    summary=hybrid_final_decision(results)
    return {"results":results,"summary":summary}

def predict_attachment_urls(url_list:list[str],use_tool:bool=False,api_key: Optional[str] = None)->Dict[str,Any]:
    """Same as email URLs but named for attachments"""
    results = predict_batch(url_list, use_tool=use_tool,api_key=api_key)
    summary = hybrid_final_decision(results)
    return {"results": results, "summary": summary}


def hybrid_final_decision(results:List[Dict[str,Any]])->Dict[str,Any]:
    """
    Summarize a list of per-URL predictions into an overall document/email threat level.
    """

    if not results:
        return {"total_urls": 0, "phishing_detected": 0, "threat_ratio": 0.0, "threat_level": "No URLs"}
    
    total=0
    phishing_count=0
    highest_score=0.0

    scores=[]
    
    for r in results:
        if isinstance(r,dict) and "final_score" in r:
            total+=1
            s= float(r.get("final_score",0.0))
            scores.append(s)
            if s>= 0.5:
                phishing_count+=1
        
            highest_score=max(highest_score,s)
            
    threat_ratio=phishing_count/total if total else  0.0
    if threat_ratio>= 0.7 or highest_score >= 0.9:
        level="High Risk"
    elif threat_ratio >= 0.3 or highest_score >= 0.7:
        level="Moderate Risk"
    else:
        level="Low Risk"
    

    return{
        "total_urls":total,
        "phishing_detected":phishing_count,
        "threat_ratio":round(threat_ratio,3),
        "highest_score":round(highest_score,3),
        "threat_level":level
    }

def predict_url_legacy(url:str,use_tool:bool=False,api_key:Optional[str]=None) -> (str):
    out=predict_url(url,use_tool=use_tool,api_key=api_key)
    if not isinstance(out,dict) or "error" in out:
        logger.warning("predict_url_legacy: prediction failed for %s: %s", url, out.get("error") if isinstance(out, dict) else out)
        return "Unknown", 0.0
    label=out.get("result") or out.get("label") or  "Unknown"
    score=float(out.get("final_score",0.0))*100.0
    return label,score



def compute_shap_for_url(url:str,top_n:int=8)->Dict[str,Any]:
    """
    If SHAP explainer is available and model supports it, return top_n feature contributions for this URL.
    """
    if  shap is None:
        return{"error":"shap not installed"}
    if not  _models["shap_explainer"]:
         return {"error": "shap explainer not initialized"}
    
    try:
        feat=extract_features(url)
        row=_row_from_features_dict(feat)
        explainer=_models["shap_explainer"]
        shap_vals=explainer.shap_values(row)
        vals=shap_vals[0] if isinstance(shap_vals,(list,tuple)) else shap_vals
        names=_models.get("feature_order") or list(feat.keys())
        idx = np.argsort(np.abs(vals))[-top_n:][::-1]
        idx = idx[:min(top_n, len(names))]        
        return {"shap": [{"feature": names[i], "value": float(vals[i])} for i in idx]}
    except Exception as e:
        logger.exception("compute_shap_for_url failed: %s", e)
        return {"error": str(e)}
    
# Utility: reload models (admin use)

def reload_models():
    """Force reload models and clear cache"""
    load_models(force_reload=True)
    with _prediction_cache_lock:
        _prediction_cache.clear()
    logger.info("Models reloaded and cache cleared.")
    return True

# Module test (when run directly)

if __name__=="__main__":
    # basic self-test (requires models and feature extractor)
    test_url= "http://example.com/login"
    try:
        print("Predicting",test_url)
        out=predict_url(test_url)
        print(json.dumps(out,indent=2))
    except Exception as e:
        print(f"Self test  failed,{e}")



