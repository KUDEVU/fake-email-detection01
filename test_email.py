import joblib
import re

#load the saved model and vectorizer
model = joblib.load('phishing_model.pkl')
vectorizer = joblib.load('tfidf_vectorizer.pkl')

#same cleaning function using before
def clean_text(text):
    text = text.lower()
    text = re.sub(r'<.*?>', '', text) 
    text = re.sub(r'http\S+|www\S+', '', text)
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()      
    return text

# put any email text you want to test here
email_text = "Hi team, please find the attached the meeting notes from yesterday's call. Let me know if you have any questions."
cleaned_email = clean_text(email_text)
vector = vectorizer.transform([cleaned_email])
prediction = model.predict(vector)

print("Prediction:", "Phishing" if prediction == 1 else "legit")