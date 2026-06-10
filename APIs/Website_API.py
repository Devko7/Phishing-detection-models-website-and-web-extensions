from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import importlib.util
from pathlib import Path

# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: Shaked Gayer
app = Flask(__name__)
CORS(app)
ai_email_model_human = joblib.load('Email Prediction Models/AI Models/human_email_phishing_classifier.joblib')
ai_email_model_llm = joblib.load('Email Prediction Models/AI Models/llm_email_phishing_classifier.joblib')
ai_url_model = joblib.load('URL Prediction Models/url_classifier.joblib')
llm_detector_model = joblib.load('Email Prediction Models/AI Models/llm_detector_classifier.joblib')

# Imported Deterministic models
ROOT = Path(__file__).resolve().parent.parent

def _load_deterministic_models(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

deterministic_email_model = _load_deterministic_models('deterministic_email_phishing_classifier', 'Email Prediction Models/Deterministic Models/deterministic_email_phishing_classifier.py')
deterministic_url_model = _load_deterministic_models('deterministic_url_phishing_classifier', 'URL Prediction Models/deterministic_url_phishing_classifier.py')

# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: Olivier van Leeuwen
# Helper function to get the email subject and body from the request
def _email_subject_body():
    if request.method == "POST" and request.is_json:
        data = request.get_json(silent=True) or {}
        return data.get("subject", "") or "", data.get("body", "") or ""
    return request.args.get("subject", default=""), request.args.get("body", default="")

# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: Olivier van Leeuwen
# Helper function to get the URL from the request
def _url_param():
    if request.method == "POST" and request.is_json:
        data = request.get_json(silent=True) or {}
        return data.get("url", "") or ""
    return request.args.get("url", default="")


# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: Shaked Gayer
@app.route("/predict-email-phishing-with-ai-human", methods=["GET", "POST"])
def predict_email_phishing_with_ai_human():
    subject, body = _email_subject_body()
    text = f"{subject} {body}".strip()

    if not text:
        return jsonify({"error": "subject/body cannot both be empty"}), 400

    prediction = int(ai_email_model_human.predict([text])[0])
    proba = ai_email_model_human.predict_proba([text])[0]
    legit_probability = float(proba[0])
    phishing_probability = float(proba[1])

    label = "phishing" if prediction == 1 else "legit"
    confidence = phishing_probability if prediction == 1 else legit_probability

    return jsonify(
        {
            "prediction": label,
            "confidence": confidence,
            "phishing_probability": phishing_probability,
            "legit_probability": legit_probability,
        }
    )

# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: -
@app.route("/predict-email-phishing-with-ai-llm", methods=["GET", "POST"])
def predict_email_phishing_with_ai_llm():
    subject, body = _email_subject_body()
    text = f"{subject} {body}".strip()

    if not text:
        return jsonify({"error": "subject/body cannot both be empty"}), 400

    prediction = int(ai_email_model_llm.predict([text])[0])
    proba = ai_email_model_llm.predict_proba([text])[0]
    legit_probability = float(proba[0])
    phishing_probability = float(proba[1])

    label = "phishing" if prediction == 1 else "legit"
    confidence = phishing_probability if prediction == 1 else legit_probability

    return jsonify(
        {
            "prediction": label,
            "confidence": confidence,
            "phishing_probability": phishing_probability,
            "legit_probability": legit_probability,
        }
    )

# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: Shaked Gayer
@app.route("/predict-url-phishing-with-ai", methods=["GET", "POST"])
def predict_url_phishing_with_ai():
    url = _url_param()
    if not url:
        return jsonify({"error": "url cannot be empty"}), 400
    
    raw_prediction = ai_url_model.predict([url])[0]
    proba = ai_url_model.predict_proba([url])[0]
    class_probabilities = dict(zip(ai_url_model.classes_, proba))

    phishing_probability = (
        class_probabilities.get("phishing", 0.0)
        + class_probabilities.get("defacement", 0.0)
        + class_probabilities.get("malware", 0.0)
    )
    legit_probability = class_probabilities.get("benign", 0.0)

    label = "legit" if raw_prediction == "benign" else "phishing"
    confidence = phishing_probability if label == "phishing" else legit_probability

    return jsonify(
        {
            "prediction": label,
            "confidence": confidence,
            "phishing_probability": phishing_probability,
            "legit_probability": legit_probability,
        }
    )

# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: Shaked Gayer
@app.route("/predict-email-phishing-with-deterministic", methods=["GET", "POST"])
def predict_email_phishing_with_deterministic():
    subject, body = _email_subject_body()
    text = f"{subject} {body}".strip()

    if not text:
        return jsonify({"error": "subject/body cannot both be empty"}), 400

    prediction_score, label = deterministic_email_model.classify_email(subject, body)
    return jsonify(
        {
            "prediction": label,
            "prediction_score": prediction_score,
            "phishing_probability": prediction_score / 100.0,
        }
    )

# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: Shaked Gayer
@app.route("/predict-url-phishing-with-deterministic", methods=["GET", "POST"])
def predict_url_phishing_with_deterministic():
    url = _url_param()
    if not url:
        return jsonify({"error": "url cannot be empty"}), 400

    try:
        result = deterministic_url_model.check_url(url)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify(
        {
            "prediction": result["label"],
            "phishing_probability": result["score"] / 100.0,
            "score": result["score"],
            "label": result["label"],
        }
    )
    
# Main writer: David Vasilev
# Reviewer: Shaked Gayer
# Contributor: Shaked Gayer
@app.route("/detect-llm-email", methods=["GET", "POST"])
def detect_llm_email():
    if request.method == "POST" and request.is_json:
        data = request.get_json(silent=True) or {}
        body = data.get("body", "") or ""
    else:
        body = request.args.get("body", default="")

    if not body:
        return jsonify({"error": "body cannot be empty"}), 400

    prediction = llm_detector_model.predict([body])[0]
    proba = llm_detector_model.predict_proba([body])[0]
    llm_probability = float(proba[1])

    label = "AI/LLM-generated" if prediction == 1 else "Human-written"
    confidence = llm_probability if prediction == 1 else 1 - llm_probability
    llm_percent = round(llm_probability * 100)

    return jsonify(
        {
            "prediction": llm_percent,
            "label": label,
            "confidence": confidence,
            "llm_probability": llm_probability,
        }
    )
    

if __name__ == '__main__':
    app.run(debug=True, port=8000)