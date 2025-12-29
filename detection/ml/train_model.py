
import os
import json
import joblib
import re
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
from imblearn.over_sampling import SMOTE

import shap

warnings.filterwarnings("ignore")
sns.set_style("whitegrid")

# CONFIG 
DATA_PATH = "datasets/PhiUSIIL_Phishing_URL_Dataset.csv"  # your dataset file
OUT_DIR = "models"
os.makedirs(OUT_DIR, exist_ok=True)

MODEL_OUT = os.path.join(OUT_DIR, "phiusiil_url_model.joblib")
FEATURES_OUT = os.path.join(OUT_DIR, "phiusiil_features.json")
IMPORTANCE_OUT = os.path.join(OUT_DIR, "phiusiil_feature_importance.csv")
SHAP_PLOT_OUT = os.path.join(OUT_DIR, "phiusiil_shap_summary.png")

USE_SMOTE = True   # enable if classes imbalanced
RANDOM_STATE = 42

#  Load dataset 
print("Loading dataset:", DATA_PATH)
df = pd.read_csv(DATA_PATH)

# The dataset you showed has many columns and last column named 'label'
# standardize column names
df.columns = [c.strip() for c in df.columns]

# Find label column (exact name 'label' expected)
if 'label' not in df.columns:
    raise ValueError("Expected 'label' column in dataset")

# Quick look: (optional)
print("Dataset shape:", df.shape)
print("Label distribution:\n", df['label'].value_counts())

#  Feature selection 
# Use numeric / boolean features; drop heavy text columns like 'Title' or 'Description' if present
# Candidate keepers: all columns except 'URL' and textual columns and 'label'
text_cols = []
possible_text_cols = ['URL','Title','Domain','Robots','Description','Title']  # add if present
for c in df.columns:
    if df[c].dtype == object:
        # if column contains long text or non-numeric, consider removing or encoding
        if c.lower() in ['url','title','domain','robots','description','label','favicon','title']:
            text_cols.append(c)
        else:
            # check if column is actually numeric-looking strings (try to coerce)
            try:
                pd.to_numeric(df[c].dropna().iloc[:50])
                # convertible -> keep (we will coerce)
            except Exception:
                text_cols.append(c)

print("Detected text columns to drop:", text_cols)

# Build feature dataframe
features = [c for c in df.columns if c not in text_cols and c != 'label']
print("Using features count:", len(features))

X = df[features].copy()
y = df['label'].copy()

# Coerce numeric columns (some numeric columns may be strings)
for col in X.columns:
    if X[col].dtype == object:
        X[col] = pd.to_numeric(X[col], errors='coerce')

# Fill NaNs
X = X.fillna(-1)

# Optional: quick feature pruning: remove columns with zero variance
nunique = X.nunique()
zero_var = list(nunique[nunique <= 1].index)
if zero_var:
    print("Dropping zero-variance columns:", zero_var)
    X.drop(columns=zero_var, inplace=True)
    features = [c for c in features if c not in zero_var]

#  Train/test split 
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
)

print("Train shape:", X_train.shape, "Test shape:", X_test.shape)

#  Optional: handle imbalance (SMOTE) 
if USE_SMOTE:
    print("Applying SMOTE to training set...")
    sm = SMOTE(random_state=RANDOM_STATE)
    X_train_res, y_train_res = sm.fit_resample(X_train, y_train)
else:
    X_train_res, y_train_res = X_train, y_train

print("After resample, label counts:", pd.Series(y_train_res).value_counts())

#  Models to compare 
models = {
    "RandomForest": RandomForestClassifier(n_estimators=300, max_depth=20, random_state=RANDOM_STATE, n_jobs=-1),
    "XGBoost": XGBClassifier(n_estimators=300, max_depth=10, learning_rate=0.1, random_state=RANDOM_STATE, use_label_encoder=False, eval_metric='logloss', n_jobs=-1),
    "LogisticRegression": LogisticRegression(max_iter=1000)
}

results = {}
pipes = {}

for name, clf in models.items():
    print(f"\nTraining {name} ...")
    pipe = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', clf)
    ])
    pipe.fit(X_train_res, y_train_res)
    preds = pipe.predict(X_test)
    proba = pipe.predict_proba(X_test)[:,1] if hasattr(pipe, "predict_proba") else pipe.decision_function(X_test)
    auc = roc_auc_score(y_test, proba)
    results[name] = auc
    pipes[name] = pipe
    print(name, "AUC:", round(auc,4))
    print(classification_report(y_test, preds, digits=4))
    cm = confusion_matrix(y_test, preds)
    print("Confusion matrix:\n", cm)

# choose best
best_name = max(results, key=results.get)
best_pipe = pipes[best_name]
print("\nBest model:", best_name, "AUC:", results[best_name])

# retrain best on full data (optionally with resampling on full X)
if USE_SMOTE:
    X_full_res, y_full_res = SMOTE(random_state=RANDOM_STATE).fit_resample(X, y)
    best_pipe.fit(X_full_res, y_full_res)
else:
    best_pipe.fit(X, y)

#  Save model & features 
joblib.dump(best_pipe, MODEL_OUT)
with open(FEATURES_OUT, 'w') as f:
    json.dump(features, f)

print("Saved model to:", MODEL_OUT)
print("Saved features list to:", FEATURES_OUT)

#  Feature importance (if tree-based) 
try:
    clf = best_pipe.named_steps['clf']
    if hasattr(clf, "feature_importances_"):
        importances = clf.feature_importances_
        fi = pd.DataFrame({"feature": features, "importance": importances})
        fi = fi.sort_values("importance", ascending=False)
        fi.to_csv(IMPORTANCE_OUT, index=False)
        print("Saved feature importance to:", IMPORTANCE_OUT)
        print(fi.head(20))
    else:
        print("Selected model does not expose feature_importances_")
except Exception as e:
    print("Could not compute/import feature importances:", e)

#  SHAP explainability (optional, relatively slow) 
try:
    print("Computing SHAP values (sample)...")
    explainer = shap.Explainer(best_pipe.named_steps['clf'], best_pipe.named_steps['scaler'].transform(X.iloc[:500]))
    shap_vals = explainer(best_pipe.named_steps['scaler'].transform(X.iloc[:500]))
    plt.figure(figsize=(10,6))
    shap.summary_plot(shap_vals, features=X.iloc[:500], show=False, plot_type="bar")
    plt.tight_layout()
    plt.savefig(SHAP_PLOT_OUT, dpi=150)
    plt.close()
    print("Saved SHAP summary to:", SHAP_PLOT_OUT)
except Exception as e:
    print("SHAP failed/skipped:", e)



MODEL_PATH = 'models/phiusiil_url_model.joblib'
FEATURES_PATH = 'models/phiusiil_features.json'

_model = None
_features = None

def load_model():
    global _model, _features
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    if _features is None:
        with open(FEATURES_PATH, 'r') as f:
            _features = json.load(f)
    return _model, _features

def predict_url_from_row(row_dict):
    """
    row_dict: dictionary of features (keys = feature names)
    """
    model, features = load_model()
    X = [row_dict.get(f, -1) for f in features]
    arr = np.array(X).reshape(1, -1)
    pred = model.predict(arr)[0]
    proba = model.predict_proba(arr)[0][1] if hasattr(model, "predict_proba") else model.decision_function(arr)[0]
    return int(pred), float(proba)

print("No errorr")