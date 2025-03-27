from flask import Flask, render_template, request, redirect, session
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
from urllib.parse import urlparse
import user_management as dbHandler

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-strong-secret-key'  # Replace with a secure key
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

csrf = CSRFProtect(app)
talisman = Talisman(app, content_security_policy=None)
limiter = Limiter(app=app, key_func=get_remote_address)

def is_safe_url(url):
    allowed_domains = ['localhost', 'yoursite.com']
    parsed = urlparse(url)
    return parsed.netloc in allowed_domains or parsed.netloc == ''

@app.route("/success.html", methods=["GET", "POST"])
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if is_safe_url(url):
            return redirect(url, code=302)
        return redirect("/", code=302)
    if request.method == "POST":
        feedback = request.form.get("feedback", "")[:500]  # Input sanitization
        dbHandler.insertFeedback(feedback)
        return render_template("/success.html", state=True, value="Back")
    return render_template("/success.html", state=True, value="Back")

@app.route("/signup.html", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        DoB = request.form.get("dob", "")
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        dbHandler.insertUser(username, hashed_pw, DoB)
        return redirect("/index.html")
    return render_template("/signup.html")

@app.route("/index.html", methods=["GET", "POST"])
@app.route("/", methods=["GET", "POST"])
@limiter.limit("5/minute")  # Rate limiting for login
def home():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        stored_hash = dbHandler.retrieve_password_hash(username)
        if stored_hash and bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            session['user'] = username
            return render_template("/success.html", value=username, state=True)
        return render_template("/index.html", error="Invalid credentials")
    return render_template("/index.html")

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
