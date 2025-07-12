'''
from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
import bcrypt
from config import DATABASE_URL, SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Database connection
def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

@app.route('/')
def home():
    return redirect(url_for('login'))

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_pw)
            )
            conn.commit()
            flash("Signup successful. Please login.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash("Signup failed. Username/email might already exist.", "danger")
        finally:
            cur.close()
            conn.close()
    return render_template('signup.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.", "danger")
    return render_template('login.html')

# Dummy dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return f"Welcome {session['username']}!"

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
'''



from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
import bcrypt
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")

#DATABASE_URL = os.environ.get("DATABASE_URL") or "your_neon_postgres_url"
DATABASE_URL = "postgresql://neondb_owner:npg_lJkA3eNaD2Bc@ep-damp-tree-a1dzcbcs-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"

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

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
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
        flash("Signup failed. Email or username may already exist.", "danger")
        return redirect(url_for('signup'))

@app.route("/auth/login", methods=['POST'])
def auth_login():
    email = request.form['email']
    password = request.form['password']

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, password FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
        session['user_id'] = user[0]
        session['username'] = user[1]
        return redirect("/dashboard")
    else:
        flash("Invalid credentials", "danger")
        return redirect(url_for('login'))

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return f"Welcome {session['username']}!"

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
        return "✅ Database connection successful!"
    except Exception as e:
        return f"❌ Database connection failed: {str(e)}"


if __name__ == '__main__':
    app.run(debug=True)