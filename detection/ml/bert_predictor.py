from transformers import BertTokenizer, BertForSequenceClassification
import torch

MODEL_PATH = "bert_model/checkpoint-15000"

_tokenizer = None
_model = None

def load_bert():
    global _tokenizer, _model
    if _tokenizer is None:
        _tokenizer = BertTokenizer.from_pretrained(MODEL_PATH)
    if _model is None:
        _model = BertForSequenceClassification.from_pretrained(MODEL_PATH)
        _model.eval()
    return _tokenizer, _model


def predict_text(text):
    tokenizer, model = load_bert()

    inputs = tokenizer(
        text,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=512
    )

    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        proba = torch.softmax(logits, dim=1)[0][1].item()
        pred = 1 if proba >= 0.5 else 0

    return pred, float(proba)
