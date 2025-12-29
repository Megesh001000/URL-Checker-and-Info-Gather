import os
import joblib
import pandas as pd
import torch
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
from transformers import (
    BertTokenizerFast,
    BertForSequenceClassification,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding
)
from torch.utils.data import Dataset
import gc
# PATH CONFIGURATION
os.environ["USE_TF"]="0"
os.environ["HF_HOME"]="./hf_cache"


BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_DIR = os.path.join(BASE_DIR, "detection", "ml", "ml_models")

PRIMARY_MODEL_PATH = os.path.join(MODEL_DIR, "phiusiil_url_model.joblib")
HYBRID_MODEL_PATH = os.path.join(MODEL_DIR, "phiusiil_hybrid_model.joblib")
BERT_MODEL_PATH = os.path.join(MODEL_DIR, "phiusiil_bert_model")
os.makedirs(BERT_MODEL_PATH, exist_ok=True)

dataset_path=os.path.join(BASE_DIR,'datasets','PhiUSIIL_Phishing_URL_Dataset.csv')

# LOADING DATA AND BASE MODEL

print("Loading data and base model...")
df=pd.read_csv(dataset_path)

if "url"  in df.columns:
    df.rename(columns={"url":'URL'},inplace=True)

y=df["label"]
X=df.drop(columns=["label"])

base_model=joblib.load(PRIMARY_MODEL_PATH)
expected_features=base_model.feature_names_in_

X=X.reindex(columns=expected_features,fill_value=0)
base_probs=base_model.predict_proba(X)[:,1]
X["base_model_prob"]=base_probs
meta_features=pd.DataFrame({"rf_proba":base_probs})

# TRAINING THE  HYBRID META MODEL

print("\nTraining Hybrid Meta-Model...")
X_train,X_test,y_train,y_test=train_test_split(
    meta_features,y,test_size=0.2,random_state=42,stratify=y
)
meta_model=LogisticRegression(max_iter=500)
meta_model.fit(X_train,y_train)
preds=meta_model.predict(X_test)
probs=meta_model.predict_proba(X_test)[:,1]
acc=accuracy_score(y_test,preds)
f1=f1_score(y_test,preds)
auc = roc_auc_score(y_test, probs)

print(f"Hybrid Meta Model → Acc: {acc:.4f}, F1: {f1:.4f}, AUC: {auc:.4f}")

joblib.dump(meta_model,HYBRID_MODEL_PATH)
print(f"Saved hybrid model to {HYBRID_MODEL_PATH}")

# training the BERT model

print("\nPreparing BERT model training...")

texts=df["URL"].astype(str).tolist()
if df["label"].dtype == object:
    # If your dataset has textual labels like 'good' / 'bad' or 'phishing' / 'legit'
    df["label"] = df["label"].map({"phishing": 1, "legitimate": 0, "benign": 0, "malicious": 1}).fillna(df["label"]).astype(int)
else:
    df["label"] = df["label"].astype(int)

labels = df["label"].tolist()

class URLDATASET(Dataset):
    def __init__(self,texts,labels,tokenizer,max_length=128):
        self.texts=texts
        self.labels=labels
        self.tokenizer=tokenizer
        self.max_length=max_length
    
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text=self.texts[idx]
        encoding=self.tokenizer(
            text,
            add_special_tokens=True,
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt"

        )
        return{
            "input_ids":encoding["input_ids"].flatten(),
            "attention_mask":encoding["attention_mask"].flatten(),
            "labels":torch.tensor(self.labels[idx],dtype=torch.long)

        }
    
# initializing tokenizer and datasets

tokenizer=BertTokenizerFast.from_pretrained("bert-base-uncased")

train_texts,test_texts,train_labels,test_labels=train_test_split(
    texts,labels,test_size=0.2,random_state=42,stratify=labels
)

train_dataset=URLDATASET(train_texts,train_labels,tokenizer)
test_dataset=URLDATASET(test_texts,test_labels,tokenizer)

model=BertForSequenceClassification.from_pretrained(
    "bert-base-uncased",num_labels=2
)

# TRAINING CONFIGURATION
# from inspect import signature

# # Detect available argument names automatically
# params = signature(TrainingArguments.__init__).parameters

# if "evaluation_strategy" in params:
#     eval_arg = {"evaluation_strategy": "steps"}
# elif "eval_strategy" in params:
#     eval_arg = {"eval_strategy": "steps"}
# else:
#     eval_arg = {}  

training_args=TrainingArguments(
    output_dir='./bert_result',
    overwrite_output_dir=True,
    evaluation_strategy="steps",  #eval periodically
    # **eval_arg,
    eval_steps=500,
    save_steps=500,

    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    gradient_accumulation_steps=2,
    learning_rate=3e-5,
    num_train_epochs=3,
    weight_decay=0.1,
    logging_dir='./hybrid_logs',
    logging_steps=100,
    save_total_limit=2,
    fp16=False,
    report_to=None,
    load_best_model_at_end=True

)

trainer=Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset
)

# starting the training process

print("\nStarting BERT fine-tuning... (")
trainer.train()

gc.collect()
if  torch.cuda.is_available():
    torch.cuda.empty_cache()

model.save_pretrained(BERT_MODEL_PATH)
tokenizer.save_pretrained(BERT_MODEL_PATH)
print(f"Saved BERT model and tokenizer to {BERT_MODEL_PATH}")