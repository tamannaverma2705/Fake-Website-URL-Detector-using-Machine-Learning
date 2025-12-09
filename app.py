from flask import Flask, render_template, request, redirect, url_for, session
import pickle
import numpy as np
import re
import socket
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Needed for sessions

# ---------------------------
# Dummy in-memory "user database"
# ---------------------------
users = {}

# ---------------------------
# Trusted domains whitelist (quick fix)
# Add domains you trust here. This will bypass the ML model and treat them as safe.
# Use root domains (e.g., "openai.com") — subdomains like "chat.openai.com" will be matched.
# ---------------------------
trusted_domains = [
    "openai.com",
    "chatgpt.com",
    "google.com",
    "github.com"
]

# ---------------------------
# Trusted TLD whitelist (new)
# Any URL ending with these TLDs will be treated as safe
# ---------------------------
trusted_tlds = [".org", ".edu", ".gov"]

# ---------------------------
# Load trained model + features
# ---------------------------
with open("phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("feature_columns.pkl", "rb") as f:
    feature_columns = pickle.load(f)

def zero_feature_vector():
    """
    Return a zero vector that matches the model's expected input ordering.
    We exclude any 'id' or 'CLASS_LABEL' columns which are not part of features.
    """
    return [0 for col in feature_columns if col not in ['id', 'CLASS_LABEL']]

# ---------------------------
# Full 49-feature extraction function
# ---------------------------
def extract_features_from_url(url):
    # Ensure the URL has a scheme for urlparse to work correctly.
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]  # strip any port
    path = parsed.path
    query = parsed.query

    # --- Trusted domain short-circuit ---
    domain_lower = hostname.lower()
    for td in trusted_domains:
        td = td.lower()
        if domain_lower == td or domain_lower.endswith('.' + td):
            return zero_feature_vector()  # Treat as safe

    # --- Trusted TLD short-circuit ---
    if any(domain_lower.endswith(tld) for tld in trusted_tlds):
        return zero_feature_vector()  # Treat as safe

    # ---------------------------
    # Feature extraction
    # ---------------------------
    features = {}
    features['NumDots'] = url.count('.')
    features['SubdomainLevel'] = hostname.count('.') - 1 if '.' in hostname else 0
    features['PathLevel'] = path.count('/')
    features['UrlLength'] = len(url)
    features['NumDash'] = url.count('-')
    features['NumDashInHostname'] = hostname.count('-')
    features['AtSymbol'] = 1 if '@' in url else 0
    features['TildeSymbol'] = 1 if '~' in url else 0
    features['NumUnderscore'] = url.count('_')
    features['NumPercent'] = url.count('%')
    features['NumQueryComponents'] = query.count('=') + 1 if query else 0
    features['NumAmpersand'] = query.count('&')
    features['NumHash'] = url.count('#')
    features['NumNumericChars'] = sum(c.isdigit() for c in url)
    features['NoHttps'] = 0 if parsed.scheme == "https" else 1

    # Random string detection (hostname part)
    features['RandomString'] = 1 if re.search(r'[bcdfghjklmnpqrstvwxyz0-9]{5,}', hostname.lower()) else 0

    # IP address in hostname
    try:
        socket.inet_aton(hostname)
        features['IpAddress'] = 1
    except:
        features['IpAddress'] = 0

    features['DomainInSubdomains'] = 1 if 'com' in hostname.split('.')[:-1] else 0
    features['DomainInPaths'] = 1 if re.search(r'\.com|\.net|\.org', path) else 0
    features['HttpsInHostname'] = 1 if 'https' in hostname else 0
    features['HostnameLength'] = len(hostname)
    features['PathLength'] = len(path)
    features['QueryLength'] = len(query)
    features['DoubleSlashInPath'] = 1 if '//' in path else 0

    # Sensitive keywords
    phishing_keywords = ['login', 'secure', 'bank', 'account', 'update', 'free', 'verify']
    features['NumSensitiveWords'] = sum(k in url.lower() for k in phishing_keywords)

    features['EmbeddedBrandName'] = 1 if re.search(r'facebook|google|paypal|amazon', url.lower()) else 0

    # The following features are set to 0 because they require HTML analysis
    html_based_features = [
        'PctExtHyperlinks', 'PctExtResourceUrls', 'ExtFavicon',
        'InsecureForms', 'RelativeFormAction', 'ExtFormAction',
        'AbnormalFormAction', 'PctNullSelfRedirectHyperlinks',
        'FrequentDomainNameMismatch', 'FakeLinkInStatusBar',
        'RightClickDisabled', 'PopUpWindow', 'SubmitInfoToEmail',
        'IframeOrFrame', 'MissingTitle', 'ImagesOnlyInForm',
        'SubdomainLevelRT', 'UrlLengthRT', 'PctExtResourceUrlsRT',
        'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT',
        'PctExtNullSelfRedirectHyperlinksRT'
    ]
    for feat in html_based_features:
        features[feat] = 0

    # Fill missing columns with 0 to match model
    for col in feature_columns:
        if col not in features:
            features[col] = 0

    # Return features in the same order used during model training
    return [features[col] for col in feature_columns if col not in ['id', 'CLASS_LABEL']]

# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def index():
    if "username" in session:
        return render_template("index.html", user=session["username"])
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username in users and users[username] == password:
            session["username"] = username
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username in users:
            return render_template("signup.html", error="User already exists")
        
        users[username] = password
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

@app.route("/predict", methods=["POST"])
def predict():
    if "username" not in session:
        return redirect(url_for("login"))

    url_input = request.form.get("url")

    try:
        features = extract_features_from_url(url_input)
        features = np.array(features).reshape(1, -1)
        prediction = model.predict(features)[0]

        if prediction == 1:
            result = "🚨 Phishing Website (Fake)"
        else:
            result = "✅ Legit Website"
    except Exception as e:
        result = f"Error: {str(e)}"

    return render_template("index.html", prediction=result, user=session["username"])

# ---------------------------
# Run Flask app
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)
