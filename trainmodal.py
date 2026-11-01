import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# STEP 1: Load dataset
data = pd.read_csv("dataset/Phishing_Email.csv")

# STEP 2: Remove unnecessary column
data = data.drop(columns=["Unnamed: 0"], errors="ignore")

# STEP 3: Remove missing values
data = data.dropna(subset=["Email Text", "Email Type"])

# STEP 4: Prepare data
X = data["Email Text"].astype(str)
y = data["Email Type"].str.strip()

print("Total Emails:", len(data))

# STEP 5: Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Training Emails:", len(X_train))
print("Testing Emails:", len(X_test))

# STEP 6: Create ML model
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        stop_words="english",
        max_features=10000
    )),
    ("classifier", LogisticRegression(
        max_iter=1000
    ))
])

# STEP 7: Train model
print("\nTraining Started...")

model.fit(X_train, y_train)

print("Training Completed!")

# STEP 8: Make predictions
predictions = model.predict(X_test)

# STEP 9: Evaluate model
accuracy = accuracy_score(y_test, predictions)

print("\nModel Accuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    zero_division=0
))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

# STEP 10: Save model
joblib.dump(model, "phishing_model.pkl")

print("\nModel Saved Successfully!")