import streamlit as st
import socket
from encryption.aes import encrypt_aes
from encryption.fernet_encryptor import encrypt_fernet, generate_fernet_key
from utils.checksum import sha256_checksum

st.title("🔐 SecureShare - Encrypted File Transfer")

file = st.file_uploader("📁 Upload file to send", type=["txt", "pdf", "jpg", "png", "zip", "docx"])
algorithm = st.selectbox("🔑 Choose Encryption Algorithm", ["AES", "Fernet"])
ip = st.text_input("🖧 Receiver IP Address", value="127.0.0.1")
port = st.number_input("Port", value=9999, step=1)

if st.button("Encrypt & Send"):
    if file is not None:
        file_data = file.read()

        if algorithm == "AES":
            enc_data, key = encrypt_aes(file_data)
        else:
            key = generate_fernet_key()
            enc_data = encrypt_fernet(key, file_data)

        checksum = sha256_checksum(file_data)

        # send to server
        s = socket.socket()
        s.connect((ip, port))
        s.sendall(enc_data + b"<END>" + key + b"<KEY>" + checksum.encode())
        s.close()

        st.success("✅ File sent successfully!")
        st.write("Encryption Key:", key.decode())
        st.write("SHA256 Checksum:", checksum)
    else:
        st.error("❌ Please upload a file first.")
