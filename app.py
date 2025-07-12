from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
import bcrypt
import os
from flask_dance.contrib.google import make_google_blueprint, google

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")

#DATABASE_URL = os.environ.get("DATABASE_URL") or "your_neon_postgres_url"
DATABASE_URL = "postgresql://neondb_owner:npg_lJkA3eNaD2Bc@ep-damp-tree-a1dzcbcs-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"

# Google OAuth Config
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Dev only
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "your-client-id")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "your-client-secret")

google_bp = make_google_blueprint(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    redirect_url="/google_login/authorized",
    scope=["profile", "email"]
)
app.register_blueprint(google_bp, url_prefix="/login")

# DB connection
def get_db():
    return psycopg2.connect(DATABASE_URL)

@app.route("/")
def home():
    return redirect(url_for('login'))

@app.route("/login", methods=['GET'])
def login():
    return render_template("login.html")

@app.route("/signup", methods=['GET'])
def signup():
    return render_template("signup.html")

@app.route("/auth/signup", methods=['POST'])
def auth_signup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    confirm = request.form['confirm_password']

    if password != confirm:
        flash("Passwords do not match", "danger")
        return redirect(url_for('signup'))

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_pw))
        conn.commit()
        cur.close()
        conn.close()
        flash("Signup successful. Please log in.", "success")
        return redirect(url_for('login'))
    except Exception as e:
        print("Signup error:", e)
        flash("Signup failed. Email or username may already exist.", "danger")
        return redirect(url_for('signup'))

@app.route("/auth/login", methods=['POST'])
def auth_login():
    email = request.form['email']
    password = request.form['password']
    print(f"[LOGIN] Attempting login for: {email}")

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            print("[LOGIN] No user found.")
            flash("Invalid credentials", "danger")
            return redirect(url_for('login'))

        stored_hash = user[2]
        print("[LOGIN] Hash from DB:", stored_hash)

        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            session['user_id'] = user[0]
            session['username'] = user[1]
            print("[LOGIN] Login successful")
            return redirect("/dashboard")
        else:
            print("[LOGIN] Password mismatch.")
            flash("Invalid credentials", "danger")
            return redirect(url_for('login'))

    except Exception as e:
        print("[LOGIN ERROR]", str(e))
        return f"\u274c Internal Server Error: {str(e)}"

@app.route("/ask")
def ask_question():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template("ask.html", username=session['username'])

@app.route("/google_login/authorized")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "danger")
        return redirect(url_for("login"))

    user_info = resp.json()
    email = user_info["email"]
    username = user_info.get("name", email.split("@")[0])

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if not user:
            cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, "google_oauth"))
            conn.commit()
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

        cur.close()
        conn.close()

        session['user_id'] = user[0]
        session['username'] = username
        flash("Logged in with Google!", "success")
        return redirect("/dashboard")

    except Exception as e:
        print("[GOOGLE LOGIN ERROR]", str(e))
        flash("Login failed.", "danger")
        return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template("dashboard.html", username=session['username'])

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for('login'))

@app.route("/test-db")
def test_db():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        return "\u2705 Database connection successful!"
    except Exception as e:
        return f"\u274c Database connection failed: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True) 
