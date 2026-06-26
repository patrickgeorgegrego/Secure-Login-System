import os
import re
from flask import Flask, render_template_string, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# --- Configuration & Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())

# Secure absolute pathing for SQLite
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'secure_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cookie Security Configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

# Safely initialize database tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Hardcoded Layout CSS Styling ---
STYLE_BLOCK = """
<style>
    :root {
        --bg-color: #0f172a;
        --container-bg: #1e293b;
        --text-color: #f8fafc;
        --primary-color: #3b82f6;
        --primary-hover: #2563eb;
        --error-color: #ef4444;
        --success-color: #10b981;
        --border-radius: 8px;
    }
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: var(--bg-color);
        color: var(--text-color);
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        margin: 0;
    }
    .container {
        background-color: var(--container-bg);
        padding: 2rem;
        border-radius: var(--border-radius);
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
        width: 100%;
        max-width: 400px;
    }
    h2 {
        text-align: center;
        margin-bottom: 1.5rem;
        color: var(--primary-color);
    }
    .form-group {
        margin-bottom: 1rem;
    }
    label {
        display: block;
        margin-bottom: 0.5rem;
        font-size: 0.9rem;
    }
    input[type="text"], input[type="password"] {
        width: 100%;
        padding: 0.75rem;
        border: 1px solid #334155;
        border-radius: var(--border-radius);
        background-color: #0f172a;
        color: white;
        box-sizing: border-box;
    }
    input:focus {
        outline: none;
        border-color: var(--primary-color);
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.5);
    }
    .btn {
        width: 100%;
        padding: 0.75rem;
        border: none;
        border-radius: var(--border-radius);
        background-color: var(--primary-color);
        color: white;
        font-size: 1rem;
        cursor: pointer;
        transition: background-color 0.2s;
        margin-top: 1rem;
    }
    .btn:hover { background-color: var(--primary-hover); }
    .btn-danger { background-color: var(--error-color); margin-top: 2rem; }
    .btn-danger:hover { background-color: #dc2626; }
    .alert {
        padding: 0.75rem;
        border-radius: var(--border-radius);
        margin-bottom: 0.5rem;
        font-size: 0.9rem;
        border: 1px solid var(--error-color);
        background-color: rgba(239, 68, 68, 0.2);
        color: #fca5a5;
    }
    .alert-success {
        border: 1px solid var(--success-color);
        background-color: rgba(16, 185, 129, 0.2);
        color: #6ee7b7;
    }
    .links { text-align: center; margin-top: 1rem; font-size: 0.9rem; }
    .links a { color: var(--primary-color); text-decoration: none; }
    .links a:hover { text-decoration: underline; }
    .security-badge {
        background-color: #334155;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 1.5rem;
        text-align: left;
        border-left: 4px solid var(--success-color);
    }
</style>
"""

# --- Explicit UI Templates ---
REGISTER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Secure App - Register</title>""" + STYLE_BLOCK + """</head>
<body>
    <div class="container">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <h2>Create Account</h2>
        <form method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required autocomplete="off" placeholder="Alphanumeric only">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required placeholder="Min 8 characters">
            </div>
            <button type="submit" class="btn">Register</button>
        </form>
        <div class="links"><a href="{{ url_for('login') }}">Login here</a></div>
    </div>
</body>
</html>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Secure App - Login</title>""" + STYLE_BLOCK + """</head>
<body>
    <div class="container">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <h2>Secure Login</h2>
        <form method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required autocomplete="off">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
        <div class="links"><a href="{{ url_for('register') }}">Register here</a></div>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Secure App - Dashboard</title>""" + STYLE_BLOCK + """</head>
<body>
    <div class="container">
        <h2>Welcome, {{ current_user.username }}!</h2>
        <div class="security-badge">
            <h4 style="margin-top: 0; color: #94a3b8;">Active Defenses:</h4>
            <ul style="margin: 0; padding-left: 1.5rem; color: #cbd5e1; font-size: 0.9rem;">
                <li><strong>SQLi Defense:</strong> SQLAlchemy ORM abstraction</li>
                <li><strong>Auth Integrity:</strong> Bcrypt password hashing</li>
                <li><strong>Session Security:</strong> Explicit Flask-Login tracking</li>
                <li><strong>Access Control:</strong> Protected by @login_required</li>
                <li><strong>Input Validation:</strong> Server-side regex & constraints</li>
            </ul>
        </div>
        <a href="{{ url_for('logout') }}" style="text-decoration: none;">
            <button class="btn btn-danger">Secure Logout</button>
        </a>
    </div>
</body>
</html>
"""

# --- Input Validation ---
def validate_auth_input(username, password):
    if not username or not password:
        return "Username and password are required."
    if len(username) < 3 or len(username) > 30:
        return "Username must be between 3 and 30 characters."
    if len(password) < 8 or len(password) > 128:
        return "Password must be between 8 and 128 characters."
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return "Username can only contain letters, numbers, and underscores."
    return None

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        error_msg = validate_auth_input(username, password)
        if error_msg:
            flash(error_msg)
            return render_template_string(REGISTER_TEMPLATE)
            
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return render_template_string(REGISTER_TEMPLATE)
            
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.add(User(username=username, password_hash=hashed_pw))
        db.session.commit()
        return redirect(url_for('login'))
        
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            session.permanent = True
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password.')
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear() 
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)