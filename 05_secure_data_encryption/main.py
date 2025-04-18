import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ---- SETUP ----

# Generate encryption key (hardcoded here for demo)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory storage
stored_data = {}

# Track failed attempts using session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# ---- FUNCTIONS ----

def hash_passkey(passkey: str) -> str:
    """Hash the user's passkey using SHA-256"""
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text: str) -> str:
    """Encrypt plain text"""
    return cipher.encrypt(text.encode()).decode()

from typing import Optional

def decrypt_data(encrypted_text: str, passkey: str) -> Optional[str]:
    """Attempt to decrypt data if passkey matches"""
    hashed = hash_passkey(passkey)
    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed:
            st.session_state.failed_attempts = 0  # Reset on success
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# ---- UI ----

st.set_page_config(page_title="Secure Data System", layout="centered")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("📁 Navigation", menu)

# ---- HOME ----

if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.markdown("Use this app to securely **store and retrieve data** using a unique passkey.\n\n🔑 Your data is encrypted with Fernet and passkeys are hashed using SHA-256.")

# ---- STORE DATA ----

elif choice == "Store Data":
    st.subheader("📦 Store Your Data Securely")

    entry_id = st.text_input("Unique Name for Your Data (e.g., my_note1):")
    user_data = st.text_area("Enter the data you want to encrypt:")
    passkey = st.text_input("Enter a passkey to protect your data:", type="password")

    if st.button("🔐 Encrypt & Save"):
        if entry_id and user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)

            stored_data[entry_id] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }

            st.success("✅ Data stored successfully!")
            st.code(encrypted, language="text")
        else:
            st.error("❗ Please fill in all fields!")

# ---- RETRIEVE DATA ----

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    entry_id = st.text_input("Enter the name you saved the data with:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("🔓 Decrypt"):
        if entry_id and passkey:
            if entry_id in stored_data:
                encrypted_text = stored_data[entry_id]["encrypted_text"]
                decrypted = decrypt_data(encrypted_text, passkey)

                if decrypted:
                    st.success("✅ Your Decrypted Data:")
                    st.code(decrypted, language="text")
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🚫 Too many failed attempts. Redirecting to Login...")
                        st.experimental_rerun()
            else:
                st.error("❌ No data found with that name!")
        else:
            st.error("❗ Please enter both fields.")

# ---- LOGIN PAGE ----

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # You can customize this
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Go back to Retrieve Data.")
        else:
            st.error("❌ Incorrect password.")
