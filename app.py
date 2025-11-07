import os
import pickle
import numpy as np
import pandas as pd
from flask import Flask, render_template, request, redirect
from werkzeug.utils import secure_filename
from features import extract_features

# -------------------------
# Flask App Setup
# -------------------------
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# -------------------------
# Load Model + Scaler + Encoder
# -------------------------
MODEL_PATH = "doc_classifier.pkl"
ENCODER_PATH = "label_encoder.pkl"
SCALER_PATH = "scaler.pkl"

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)
with open(ENCODER_PATH, "rb") as f:
    label_encoder = pickle.load(f)
with open(SCALER_PATH, "rb") as f:
    scaler = pickle.load(f)

# -------------------------
# Feature Columns
# -------------------------
feature_cols = [
    "file_size", "metadata size", "pages", "xref Length",
    "title characters", "isEncrypted", "embedded files", "images",
    "JS", "Javascript", "OpenAction", "Acroform",
    "url_count", "macro_keyword_count", "suspicious_api_count"
]

# -------------------------
# Routes
# -------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return redirect('/')
    file = request.files['file']
    if file.filename == '':
        return redirect('/')

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # -------------------------
    # Extract Features
    # -------------------------
    feature_values, _ = extract_features(filepath)
    if len(feature_values) != len(feature_cols):
        feature_values = (feature_values + [0]*len(feature_cols))[:len(feature_cols)]

    X_new = pd.DataFrame([feature_values], columns=feature_cols)
    X_new = (X_new - scaler["mean"]) / (scaler["std"] + 1e-8)

    # -------------------------
    # Prediction
    # -------------------------
    prediction = model.predict(X_new)[0]
    probs = model.predict_proba(X_new)[0]
    confidence = float(np.max(probs) * 100)
    label = label_encoder.inverse_transform([prediction])[0].lower()

    # -------------------------
    # Intelligent Classification Logic
    # -------------------------
    ext = os.path.splitext(filename)[1].lower()
    url_count = X_new["url_count"].iloc[0]
    macro_kw = X_new["macro_keyword_count"].iloc[0]
    api_kw = X_new["suspicious_api_count"].iloc[0]
    js = X_new["JS"].iloc[0] + X_new["Javascript"].iloc[0]
    open_action = X_new["OpenAction"].iloc[0]
    acroform = X_new["Acroform"].iloc[0]
    embedded = X_new["embedded files"].iloc[0]

    # Default reason
    reason = "No threats detected."

    # --- File-type aware logic ---
    if ext == ".pdf":
        if (js + open_action + acroform + embedded + url_count + macro_kw + api_kw) == 0:
            status = "Safe"
        elif confidence < 95:
            status = "Safe"
        else:
            status = "Malicious"
            reason = "PDF contains embedded elements or active code."

    elif ext == ".txt":
        if (url_count + macro_kw + api_kw) > 0 or confidence > 70:
            status = "Malicious"
            reason = "Suspicious keywords or patterns detected."
        else:
            status = "Safe"

    else:
        if (url_count + macro_kw + api_kw + js + open_action + acroform + embedded) == 0 and confidence < 97:
            status = "Safe"
        elif confidence < 85 or "ben" in label:
            status = "Safe"
        else:
            status = "Malicious"
            reason = "Active macros or embedded objects detected."

    # -------------------------
    # Render Result
    # -------------------------
    return render_template(
        'result.html',
        status=status,
        filename=filename,
        confidence=round(confidence, 2),
        reason=reason
    )


# -------------------------
# Run Flask App
# -------------------------
if __name__ == '__main__':
    app.run(debug=True)
