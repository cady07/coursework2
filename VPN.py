from flask import Flask, request, redirect, url_for, jsonify, session, send_file, make_response
import pyotp
import qrcode
import io
import re
import logging
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import nacl.public, nacl.encoding, nacl.utils
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DB_FILE = 'users.json'

# Initialize TinyDB with a human-readable JSON file
db = TinyDB(DB_FILE, storage=CachingMiddleware(JSONStorage))
users_table = db.table('users')

# Set up logging for audit trails
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set up rate limiting: maximum 10 requests per minute per IP
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10 per minute"]
)
# Check password strength: at least 8 characters, one letter, and one number.
def is_password_strong(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Za-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

# Generate a WireGuard key pair using PyNaCl.
def generate_wireguard_keypair():
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    client_private_key = private_key.encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8').strip()
    client_public_key = public_key.encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8').strip()
    return client_private_key, client_public_key

# Decorator to require login for certain routes.
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Add extra HTTP security headers.
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# Home Route with registration and login forms.
@app.route('/')
def home():
    return '''
        <h1>Secure VPN Connection Tool</h1>
        <h3>Register:</h3>
        <form action="/register" method="post">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username" required><br><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password" required><br><br>
            <input type="submit" value="Register">
        </form>
        <h3>Login:</h3>
        <form action="/login" method="post">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username" required><br><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password" required><br><br>
            <label for="otp">OTP:</label><br>
            <input type="text" id="otp" name="otp" required><br><br>
            <input type="submit" value="Login">
        </form>
    '''

# Register Route: validates input, creates a new user, and returns a QR code for TOTP setup.
@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    if not is_password_strong(password):
        return jsonify({'error': 'Password must be at least 8 characters long and include both letters and numbers'}), 400

    hashed_password = generate_password_hash(password)
    totp_secret = pyotp.random_base32()
    vpn_private_key, vpn_public_key = generate_wireguard_keypair()

    User = Query()
    if users_table.search(User.username == username):
        return jsonify({'error': 'Username already exists'}), 409

    users_table.insert({
        'username': username,
        'password': hashed_password,
        'totp_secret': totp_secret,
        'failed_attempts': 0,
        'lockout_until': None,
        'vpn_private_key': vpn_private_key,
        'vpn_public_key': vpn_public_key
    })

    logging.info(f"New user registered: {username}")

    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(username, issuer_name="SecureVPN")
    img = qrcode.make(uri)
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png')

# Login Route: verifies credentials, applies rate limiting and account lockout logic.
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    otp = request.form.get('otp')

    if not username or not password or not otp:
        return jsonify({'error': 'Username, password, and OTP are required'}), 400

    User = Query()
    user = users_table.get(User.username == username)
    if not user:
        logging.warning(f"Login failed for non-existent user: {username}")
        return jsonify({'error': 'Invalid username or password'}), 401

    stored_password = user.get('password')
    totp_secret = user.get('totp_secret')
    failed_attempts = user.get('failed_attempts', 0)
    lockout_until = user.get('lockout_until')

    now = datetime.utcnow()
    if lockout_until:
        try:
            lockout_until_dt = datetime.fromisoformat(lockout_until)
        except Exception:
            lockout_until_dt = None
        if lockout_until_dt and now < lockout_until_dt:
            logging.warning(f"Account locked for user: {username}")
            return jsonify({'error': f'Account locked. Try again after {lockout_until_dt.isoformat()}'}), 403

    if not check_password_hash(stored_password, password):
        failed_attempts += 1
        if failed_attempts >= 5:
            lockout_duration = timedelta(minutes=15)
            lockout_until_dt = now + lockout_duration
            users_table.update({'failed_attempts': failed_attempts, 'lockout_until': lockout_until_dt.isoformat()}, User.username == username)
            logging.warning(f"User {username} locked out due to too many failed attempts")
            return jsonify({'error': 'Too many failed attempts. Account locked for 15 minutes.'}), 403
        else:
            users_table.update({'failed_attempts': failed_attempts}, User.username == username)
            logging.warning(f"Login failed for user: {username}. Failed attempts: {failed_attempts}")
            return jsonify({'error': 'Invalid username or password'}), 401

    totp_obj = pyotp.TOTP(totp_secret)
    if not totp_obj.verify(otp):
        failed_attempts += 1
        if failed_attempts >= 5:
            lockout_duration = timedelta(minutes=15)
            lockout_until_dt = now + lockout_duration
            users_table.update({'failed_attempts': failed_attempts, 'lockout_until': lockout_until_dt.isoformat()}, User.username == username)
            logging.warning(f"User {username} locked out due to too many failed OTP attempts")
            return jsonify({'error': 'Too many failed attempts. Account locked for 15 minutes.'}), 403
        else:
            users_table.update({'failed_attempts': failed_attempts}, User.username == username)
            logging.warning(f"Invalid OTP for user: {username}. Failed attempts: {failed_attempts}")
            return jsonify({'error': 'Invalid OTP'}), 401

    # On successful login, reset failed_attempts and set session.
    users_table.update({'failed_attempts': 0, 'lockout_until': None}, User.username == username)
    session['username'] = username
    logging.info(f"User {username} logged in successfully")
    return redirect(url_for('dashboard'))

# Dashboard Route: accessible only after login, showing dynamic user info.
@app.route('/dashboard')
@login_required
def dashboard():
    username = session.get('username')
    return f'''
        <h1>Dashboard</h1>
        <p>Welcome, {username}!</p>
        <p><a href="/download_vpn">Download your VPN configuration</a></p>
        <p><a href="/logout">Logout</a></p>
    '''

# VPN Configuration Download Route: generates and provides a WireGuard config file.
@app.route('/download_vpn')
@login_required
def download_vpn():
    username = session.get('username')
    User = Query()
    user = users_table.get(User.username == username)
    if not user:
        return jsonify({'error': 'User VPN configuration not found'}), 404

    vpn_private_key = user.get('vpn_private_key')
    
    # Replace this with your actual server public key.
    # For demonstration, we're using a valid dummy base64 key.
    SERVER_PUBLIC_KEY = "V3Bl0dTihSg83W7zUb1ojLZynvEPEvruyBWeHOfN7IQ="
    SERVER_ENDPOINT = "203.0.113.1:51820"
    CLIENT_ADDRESS = "10.0.0.2/32"  # Assign a unique client IP in production.
    
    config = f"""[Interface]
PrivateKey = {vpn_private_key}
Address = {CLIENT_ADDRESS}
DNS = 1.1.1.1

[Peer]
PublicKey = {SERVER_PUBLIC_KEY}
Endpoint = {SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
"""
    response = make_response(config)
    response.headers["Content-Disposition"] = "attachment; filename=vpn_config.conf"
    response.headers["Content-Type"] = "text/plain"
    return response

# Logout Route: clears the session.
@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)