import sqlite3
import pyotp
import qrcode
import io
import re
import logging
from datetime import datetime, timedelta
import nacl.public, nacl.encoding, nacl.utils
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk  # For QR code display
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATABASE = 'users.db'

def get_db_connection():
    """Returns a connection to the SQLite database."""
    return sqlite3.connect(DATABASE)

def init_db():
    """Initializes the SQLite database and creates the users table if it doesn't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until TEXT,
            vpn_private_key TEXT,
            vpn_public_key TEXT
        )
    ''')
    conn.commit()
    conn.close()

def is_password_strong(password):
    """
    Checks that the password meets these criteria:
      - At least 8 characters
      - At least one uppercase letter
      - At least one lowercase letter
      - At least one digit
      - At least one special character
    """
    regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'
    return bool(re.match(regex, password))

def generate_wireguard_keypair():
    """
    Generates a WireGuard key pair using PyNaCl and returns base64-encoded strings.
    """
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    client_private_key = private_key.encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8').strip()
    client_public_key = public_key.encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8').strip()
    return client_private_key, client_public_key

# ---------------------------
# Tkinter GUI Application
# ---------------------------
class VPNApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure VPN Connection Tool")
        try:
            self.iconbitmap("icon.ico")  # Use a custom icon if available
        except Exception:
            pass
        self.geometry("400x300")
        self.resizable(False, False)
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self, padding=20)
        frame.pack(expand=True)
        ttk.Label(frame, text="Welcome to Secure VPN Tool", font=("Helvetica", 16)).pack(pady=10)
        ttk.Button(frame, text="Register", command=self.open_register_window).pack(pady=5, fill='x')
        ttk.Button(frame, text="Login", command=self.open_login_window).pack(pady=5, fill='x')

    def open_register_window(self):
        RegisterWindow(self)

    def open_login_window(self):
        LoginWindow(self)

class RegisterWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Register")
        self.geometry("400x300")
        self.resizable(False, False)
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self, padding=20)
        frame.pack(expand=True, fill='both')
        ttk.Label(frame, text="Register", font=("Helvetica", 14)).pack(pady=10)
        ttk.Label(frame, text="Username:").pack(anchor='w')
        self.username_entry = ttk.Entry(frame)
        self.username_entry.pack(fill='x', pady=5)
        ttk.Label(frame, text="Password:").pack(anchor='w')
        self.password_entry = ttk.Entry(frame, show="*")
        self.password_entry.pack(fill='x', pady=5)
        ttk.Button(frame, text="Submit", command=self.register).pack(pady=10)

    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Username and password are required.")
            return

        if not is_password_strong(password):
            messagebox.showerror("Weak Password",
                "Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.")
            return

        hashed_password = generate_password_hash(password)
        totp_secret = pyotp.random_base32()
        vpn_private_key, vpn_public_key = generate_wireguard_keypair()

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password, totp_secret, vpn_private_key, vpn_public_key)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, hashed_password, totp_secret, vpn_private_key, vpn_public_key))
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists. Please choose a different one.")
            return

        logging.info(f"New user registered: {username}")

        # Generate TOTP QR code using qrcode library
        totp = pyotp.TOTP(totp_secret)
        uri = totp.provisioning_uri(username, issuer_name="SecureVPN")
        qr_img = qrcode.make(uri)
        bio = io.BytesIO()
        qr_img.save(bio, format="PNG")
        bio.seek(0)
        # Resize QR code to 300x300 using LANCZOS resampling
        qr_image = Image.open(bio)
        qr_image = qr_image.resize((300, 300), Image.LANCZOS)
        qr_photo = ImageTk.PhotoImage(qr_image)

        # Create the QR window with the main app as parent so it stays visible
        QRWindow(self.master, qr_photo, totp)
        self.destroy()

class QRWindow(tk.Toplevel):
    def __init__(self, master, qr_photo, totp):
        super().__init__(master)
        self.title("Scan TOTP QR Code & See OTP")
        self.geometry("500x500")
        self.resizable(False, False)
        self.qr_photo = qr_photo  # Keep a reference to avoid garbage collection
        self.totp = totp
        self.create_widgets()
        self.update_otp()  # Start updating the OTP code

    def create_widgets(self):
        frame = ttk.Frame(self, padding=20)
        frame.pack(expand=True)
        ttk.Label(frame, text="Scan this QR code with your OTP App", font=("Helvetica", 14)).pack(pady=10)
        label = ttk.Label(frame, image=self.qr_photo)
        label.pack(pady=10)
        self.otp_label = ttk.Label(frame, text="", font=("Helvetica", 18))
        self.otp_label.pack(pady=10)
        ttk.Button(frame, text="Close", command=self.destroy).pack(pady=10)

    def update_otp(self):
        current_otp = self.totp.now()
        self.otp_label.config(text=f"Current OTP: {current_otp}")
        self.after(1000, self.update_otp)

class LoginWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Login")
        self.geometry("400x350")
        self.resizable(False, False)
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self, padding=20)
        frame.pack(expand=True, fill='both')
        ttk.Label(frame, text="Login", font=("Helvetica", 14)).pack(pady=10)
        ttk.Label(frame, text="Username:").pack(anchor='w')
        self.username_entry = ttk.Entry(frame)
        self.username_entry.pack(fill='x', pady=5)
        ttk.Label(frame, text="Password:").pack(anchor='w')
        self.password_entry = ttk.Entry(frame, show="*")
        self.password_entry.pack(fill='x', pady=5)
        ttk.Label(frame, text="OTP:").pack(anchor='w')
        self.otp_entry = ttk.Entry(frame)
        self.otp_entry.pack(fill='x', pady=5)
        ttk.Button(frame, text="Login", command=self.login).pack(pady=10)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        otp = self.otp_entry.get().strip()

        if not username or not password or not otp:
            messagebox.showerror("Error", "All fields are required.")
            return

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password, totp_secret, failed_attempts, lockout_until FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if not row:
            messagebox.showerror("Error", "Invalid username or password.")
            conn.close()
            return

        stored_password, totp_secret, failed_attempts, lockout_until = row
        now = datetime.utcnow()
        if lockout_until:
            lockout_until_dt = datetime.fromisoformat(lockout_until)
            if now < lockout_until_dt:
                messagebox.showerror("Locked", f"Account locked. Try again after {lockout_until_dt.isoformat()}")
                conn.close()
                return

        if not check_password_hash(stored_password, password):
            failed_attempts += 1
            if failed_attempts >= 5:
                lockout_until_time = now + timedelta(minutes=15)
                cursor.execute('UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE username = ?',
                               (failed_attempts, lockout_until_time.isoformat(), username))
                conn.commit()
                messagebox.showerror("Locked", "Too many failed attempts. Account locked for 15 minutes.")
                conn.close()
                return
            else:
                cursor.execute('UPDATE users SET failed_attempts = ? WHERE username = ?', (failed_attempts, username))
                conn.commit()
                messagebox.showerror("Error", "Invalid username or password.")
                conn.close()
                return

        totp_obj = pyotp.TOTP(totp_secret)
        if not totp_obj.verify(otp):
            failed_attempts += 1
            if failed_attempts >= 5:
                lockout_until_time = now + timedelta(minutes=15)
                cursor.execute('UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE username = ?',
                               (failed_attempts, lockout_until_time.isoformat(), username))
                conn.commit()
                messagebox.showerror("Locked", "Too many failed attempts. Account locked for 15 minutes.")
                conn.close()
                return
            else:
                cursor.execute('UPDATE users SET failed_attempts = ? WHERE username = ?', (failed_attempts, username))
                conn.commit()
                messagebox.showerror("Error", "Invalid OTP.")
                conn.close()
                return

        # Reset failed attempts on successful login
        cursor.execute('UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Login successful!")
        # Create DashboardWindow with the main app as parent so it persists
        DashboardWindow(self.master, username)
        self.destroy()

class DashboardWindow(tk.Toplevel):
    def __init__(self, master, username):
        super().__init__(master)
        self.title("Dashboard")
        self.geometry("400x300")
        self.resizable(False, False)
        self.username = username
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self, padding=20)
        frame.pack(expand=True, fill='both')
        ttk.Label(frame, text=f"Welcome, {self.username}!", font=("Helvetica", 16)).pack(pady=10)
        ttk.Button(frame, text="Download VPN Configuration", command=self.download_vpn).pack(pady=10)
        ttk.Button(frame, text="Logout", command=self.destroy).pack(pady=10)

    def download_vpn(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT vpn_private_key FROM users WHERE username = ?', (self.username,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            messagebox.showerror("Error", "VPN configuration not found.")
            return

        vpn_private_key = row[0]
        # Replace these with your actual server values as needed.
        SERVER_PUBLIC_KEY = "V3Bl0dTihSg83W7zUb1ojLZynvEPEvruyBWeHOfN7IQ="
        SERVER_ENDPOINT = "203.0.113.1:51820"
        CLIENT_ADDRESS = "10.0.0.2/32"
        config = f"""[Interface]
PrivateKey = {vpn_private_key}
Address = {CLIENT_ADDRESS}
DNS = 1.1.1.1

[Peer]
PublicKey = {SERVER_PUBLIC_KEY}
Endpoint = {SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/0, ::/0
"""
        file_path = filedialog.asksaveasfilename(defaultextension=".conf",
                                                 filetypes=[("Config Files", "*.conf")],
                                                 initialfile="vpn_config.conf")
        if file_path:
            with open(file_path, "w") as f:
                f.write(config)
            messagebox.showinfo("Success", "VPN configuration saved successfully!")

if __name__ == "__main__":
    init_db()
    app = VPNApp()
    app.mainloop()