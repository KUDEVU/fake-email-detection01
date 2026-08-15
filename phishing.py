import pandas as pd

df = pd.read_csv("CEAS_08.csv")
print(df.head())
print(df.columns)
print(df.shape)
print(df['label'].value_counts())
print(df['label'].unique())
# check for missing values
print(df.isnull().sum())

# keep only the necessary columns
df = df[['body', 'label']]

# drop rows where body or label is empty
df = df.dropna()

print(df.shape)
import re

# function to clean email text
def clean_text(text):        
    text = text.lower()      #convert to lowercase
    text = re.sub(r'<.*?>', '', text) #remove html tags
    text = re.sub(r'http\S+|www\S+|www.\S+', '', text) #remove urls
    text = re.sub(r'[^a-zA-Z\s]', '', text) #remove special characters
    text = re.sub(r'\s+', ' ', text).strip() #remove extra spaces 
    return text

#apply the cleaning to the body column
df['cleaned_body'] = df['body'].apply(clean_text)

print(df[['body', 'cleaned_body']].head())

from sklearn.model_selection import train_test_split
x = df['cleaned_body']
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)
print("Training sample:", X_train.shape[0])
print("Testing sample:", X_test.shape[0])
from sklearn.feature_extraction.text import TfidfVectorizer

# convert text into numerical features
vectorizer = TfidfVectorizer(max_features=5000)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

print("Shape of training data:", X_train_tfidf.shape)
print("Shape of testing data:", X_test_tfidf.shape)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

# create and train the model
model = LogisticRegression(max_iter=1000)
model.fit(X_train_tfidf, y_train)

# make predictions on test data
y_pred = model.predict(X_test_tfidf)

# check accuracy
accuracy = accuracy_score(y_test, y_pred)
print("Accuracy:", accuracy)

print(classification_report(y_test, y_pred))

import joblib

joblib.dump(model, 'phishing_model.pkl')
joblib.dump(vectorizer, 'tfidf_vectorizer.pkl')

print("Model saved!")