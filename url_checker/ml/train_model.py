import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

from features_extraction import get_features



data=pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")
print(data)


feature_list=[]
labels=[]

for i,row in data.iterrows():

    url=row['url']
    label=row['label']
    try:
        features=get_features(url)
        feature_list.append(features)
        labels.append(label)
    except:
        continue



X=pd.DataFrame(features)
y=pd.Series(labels)


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

scaler=StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train_scaled, y_train)


y_pred = model.predict(X_test_scaled)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))


with open("ml/model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("ml/scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

print(" Model & Scaler saved successfully!")




