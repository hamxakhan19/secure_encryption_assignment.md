import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# --- Constants ---
DATA_FILE = "stored_data.json"
LOCKOUT_TIME_SECONDS = 60  # 1 minute lockout
MASTER_PASSWORD = "admin123"  # for login page

# --- Key Generation ---
# Derive a key for Fernet (You can generate a static one and keep it hidden)
password_for_key = b"very_secret_key"
salt = b"static_salt_1234"
key = urlsafe_b64encode(pbkdf2_hmac('sha256', password_for_key, salt, 100000))
cipher = Fernet(key)

# --- In-memory Variables ---
stored_data = {}  # {"username": {"encrypted_text": ..., "passkey": ...}}
failed_attempts = {}
lockout_time = {}

# --- Functions ---

# Load stored data
def load_data():
    global stored_data
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            stored_data = json.load(f)

# Save stored data
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

# Hash passkey with PBKDF2
def hash_passkey(passkey, salt=b"salty_salt"):
    hashed = pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return hashed.hex()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Check lockout
def is_locked(username):
    if username in lockout_time:
        if datetime.now() < lockout_time[username]:
            return True, (lockout_time[username] - datetime.now()).seconds
    return False, 0

# Streamlit login system
def signup(username, password):
    if username in stored_data:
        return False
    stored_data[username] = {"password": hash_passkey(password)}
    save_data()
    return True

def login(username, password):
    if username in stored_data and stored_data[username]["password"] == hash_passkey(password):
        return True
    return False

# --- App Start ---
st.set_page_config(page_title="🔒 Secure Data Encryption System", layout="centered")
load_data()

# --- Session ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""

# --- UI ---

st.title("🔒 Secure Data Encryption System")

# Sidebar Navigation
menu = ["Home", "Login", "Sign Up", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Securely **store** and **retrieve** your data with encryption.")

# Login
elif choice == "Login":
    st.subheader("🔑 Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        locked, seconds_left = is_locked(username)
        if locked:
            st.error(f"⏳ Account locked! Try again in {seconds_left} seconds.")
        elif login(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            failed_attempts[username] = 0
            st.success(f"✅ Welcome back, {username}!")
        else:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            st.error("❌ Incorrect username or password.")
            if failed_attempts[username] >= 3:
                lockout_time[username] = datetime.now() + timedelta(seconds=LOCKOUT_TIME_SECONDS)
                st.warning("🔒 Too many attempts! Account locked for 1 minute.")

# Sign Up
elif choice == "Sign Up":
    st.subheader("🆕 Create New Account")

    username = st.text_input("New Username")
    password = st.text_input("New Password", type="password")

    if st.button("Sign Up"):
        if signup(username, password):
            st.success("✅ Account created! Please login.")
        else:
            st.error("⚠️ Username already exists. Try a different one.")

# Store Data
elif choice == "Store Data":
    if not st.session_state.logged_in:
        st.warning("⚠️ Please login first to store your data.")
    else:
        st.subheader("📂 Store Data")

        user_data = st.text_area("Enter Data to Encrypt")
        user_passkey = st.text_input("Set a Passkey for this data", type="password")

        if st.button("Encrypt & Save Data"):
            if user_data and user_passkey:
                encrypted_text = encrypt_data(user_data)
                hashed_passkey = hash_passkey(user_passkey)

                if "data" not in stored_data[st.session_state.username]:
                    stored_data[st.session_state.username]["data"] = []

                stored_data[st.session_state.username]["data"].append({
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                })
                save_data()
                st.success("✅ Data encrypted and saved securely!")
            else:
                st.error("⚠️ All fields are required!")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.logged_in:
        st.warning("⚠️ Please login first to retrieve your data.")
    else:
        st.subheader("🔍 Retrieve Data")

        if "data" not in stored_data.get(st.session_state.username, {}):
            st.info("ℹ️ No data stored yet.")
        else:
            entries = stored_data[st.session_state.username]["data"]
            encrypted_options = [entry["encrypted_text"] for entry in entries]

            selected_encrypted = st.selectbox("Select Encrypted Text to Decrypt", encrypted_options)
            input_passkey = st.text_input("Enter the Passkey", type="password")

            if st.button("Decrypt Data"):
                entry = next((item for item in entries if item["encrypted_text"] == selected_encrypted), None)
                if entry and entry["passkey"] == hash_passkey(input_passkey):
                    decrypted = decrypt_data(selected_encrypted)
                    st.success(f"✅ Decrypted Data: {decrypted}")
                else:
                    st.error("❌ Incorrect passkey.")


