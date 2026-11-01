from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import re

# ==========================================
# 1. INITIALIZE FLASK APPLICATION
# ==========================================

app = Flask(__name__)

CORS(app)

# ==========================================
# 2. LOAD TRAINED MACHINE LEARNING MODEL
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "phishing_model.pkl"
)

try:
    model = joblib.load(MODEL_PATH)
    print("ML Model loaded successfully!")

except Exception as error:
    raise RuntimeError(
        f"Could not load ML model: {error}"
    )


# ==========================================
# 3. EXTRACT URLS FROM EMAIL
# ==========================================

def extract_urls(email):

    pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'

    urls = re.findall(pattern, email)

    # Remove common punctuation at URL endings
    urls = [
        url.rstrip(".,!?;:)")
        for url in urls
    ]

    return urls


# ==========================================
# 4. DETECT POSSIBLE WARNING INDICATORS
# ==========================================

def detect_warnings(email, urls):

    lower_email = email.lower()

    warnings = []

    warning_groups = {

        "Urgent language": [
            "urgent",
            "immediately",
            "act now",
            "right now",
            "within 24 hours",
            "as soon as possible",
            "limited time"
        ],

        "Sensitive information": [
            "password",
            "otp",
            "pin",
            "bank details",
            "credit card",
            "login credentials",
            "social security"
        ],

        "Account threats": [
            "blocked",
            "suspended",
            "locked",
            "account closed",
            "account disabled",
            "unusual activity",
            "unauthorized access"
        ],

        "Prize or reward claims": [
            "winner",
            "won a prize",
            "reward",
            "lottery",
            "claim your prize",
            "congratulations"
        ],

        "Payment requests": [
            "send money",
            "payment required",
            "transfer money",
            "pay immediately"
        ]
    }

    for category, keywords in warning_groups.items():

        matched = [
            word for word in keywords
            if word in lower_email
        ]

        if matched:

            warnings.append({
                "category": category,
                "details": (
                    "Detected terms: "
                    + ", ".join(matched)
                )
            })

    # URL warning
    if urls:

        warnings.append({
            "category": "Links found",
            "details": (
                f"Email contains {len(urls)} link(s). "
                "Verify the destination before clicking."
            )
        })

    return warnings


# ==========================================
# 5. HOME API
# ==========================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({

        "status": "success",

        "project": (
            "AI-Powered Email Threat Detection, "
            "Geolocation and Forensic Intelligence Platform"
        ),

        "message": "Flask Backend is Running!"

    })


# ==========================================
# 6. EMAIL PREDICTION API
# ==========================================

@app.route("/predict", methods=["POST"])
def predict_email():

    try:

        # Receive email from React
        data = request.get_json(silent=True) or {}

        email = data.get("email", "")

        # Validate input
        if not isinstance(email, str) or not email.strip():

            return jsonify({

                "status": "error",

                "error": "Please enter valid email text."

            }), 400

        email = email.strip()

        # ==================================
        # ML MODEL PREDICTION
        # ==================================

        prediction = model.predict([email])[0]

        probabilities = model.predict_proba([email])[0]

        classes = model.classes_

        predicted_index = list(classes).index(prediction)

        confidence = (
            probabilities[predicted_index] * 100
        )

        # ==================================
        # URL EXTRACTION
        # ==================================

        urls = extract_urls(email)

        # ==================================
        # WARNING DETECTION
        # ==================================

        warnings = detect_warnings(email, urls)

        # ==================================
        # RETURN SECURITY REPORT
        # ==================================

        return jsonify({

            "status": "success",

            "prediction": str(prediction),

            "confidence": round(
                float(confidence), 2
            ),

            "urls_found": urls,

            "warning_signs": warnings,

            "message": "Email analysis completed successfully."

        })

    except Exception as error:

        print("Prediction Error:", error)

        return jsonify({

            "status": "error",

            "message": "Email analysis failed."

        }), 500


# ==========================================
# 7. RUN FLASK SERVER
# ==========================================

if __name__ == "__main__":

    print("=" * 55)

    print("AI EMAIL THREAT DETECTION SYSTEM")

    print("Backend Starting...")

    print("=" * 55)

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )