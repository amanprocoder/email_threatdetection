import joblib
import numpy as np
import re
from urllib.parse import urlparse

# Load trained model
model = joblib.load("phishing_model.pkl")

vectorizer = model.named_steps["tfidf"]
classifier = model.named_steps["classifier"]

print("=" * 60)
print("       AI-POWERED EMAIL THREAT DETECTION SYSTEM")
print("=" * 60)

# Take email input
email = input("\nPaste your email text here:\n\n")

# Predict email
prediction = model.predict([email])[0]
probabilities = model.predict_proba([email])[0]

classes = classifier.classes_
predicted_index = list(classes).index(prediction)

confidence = probabilities[predicted_index] * 100

# Explain model prediction using word contributions
email_vector = vectorizer.transform([email])
feature_names = vectorizer.get_feature_names_out()
coefficients = classifier.coef_[0]

if prediction == classes[1]:
    contributions = email_vector.toarray()[0] * coefficients
else:
    contributions = email_vector.toarray()[0] * (-coefficients)

positive_indices = np.where(contributions > 0)[0]

top_indices = sorted(
    positive_indices,
    key=lambda i: contributions[i],
    reverse=True
)[:5]

# Detect URLs
urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email)

# Simple warning indicators
lower_email = email.lower()

indicators = []

if any(word in lower_email for word in
       ["urgent", "immediately", "right now", "act now"]):
    indicators.append(
        "The message creates urgency and pressures you to act quickly."
    )

if any(word in lower_email for word in
       ["password", "otp", "pin", "bank details"]):
    indicators.append(
        "The message mentions sensitive information such as passwords or OTPs."
    )

if any(word in lower_email for word in
       ["blocked", "suspended", "locked", "account closed"]):
    indicators.append(
        "The message uses fear of account suspension or blocking."
    )

if any(word in lower_email for word in
       ["won", "winner", "prize", "reward", "lottery"]):
    indicators.append(
        "The message offers a prize or reward that may be used to trick users."
    )

if urls:
    indicators.append(
        f"The email contains {len(urls)} link(s). Check them before clicking."
    )

# Display report
print("\n" + "=" * 60)
print("                 EMAIL SECURITY REPORT")
print("=" * 60)

print("\nCLASSIFICATION:", prediction.upper())
print("MODEL CONFIDENCE:", round(confidence, 2), "%")

# Explain prediction
print("\n1. WHY DID THE AI GIVE THIS RESULT?")

if top_indices:
    print("Words influencing the model prediction:")

    for index in top_indices:
        print("-", feature_names[index])

else:
    print("No strong individual word contribution was found.")

# Display detected indicators
print("\n2. POSSIBLE WARNING SIGNS")

if indicators:
    for item in indicators:
        print("-", item)
else:
    print("No warning signs from our basic checks were detected.")

# Possible consequences
print("\n3. WHAT COULD HAPPEN?")

if prediction == "Phishing Email":
    print("- Your personal information could be stolen.")
    print("- Your account could be misused.")
    print("- You could suffer financial loss.")

elif prediction == "Suspicious Email":
    print("- The sender may be trying to mislead you.")
    print("- A link may lead to an unsafe website.")
    print("- Your personal information may be at risk.")

else:
    print("- No strong phishing pattern was detected.")
    print("- This does not guarantee that the email is completely safe.")

# Safety advice
print("\n4. HOW CAN YOU PROTECT YOURSELF?")

print("- Never share your password, PIN or OTP.")
print("- Do not click links from unknown senders.")
print("- Verify important messages through official websites.")
print("- Never send money to claim an unexpected prize.")

# Show URLs
print("\n5. LINKS FOUND IN EMAIL")

if urls:
    for url in urls:
        print("-", url)
else:
    print("No links found.")

print("\n" + "=" * 60)
print("              ANALYSIS COMPLETED")
print("=" * 60)