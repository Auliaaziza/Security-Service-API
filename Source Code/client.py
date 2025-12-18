import requests #untuk melakukan HTTP requests ke API 
import base64 #untuk encoding/decoding base64
from cryptography.hazmat.primitives.asymmetric import ec #untuk operasi kriptografi asimetris (ECDSA)
from cryptography.hazmat.primitives import serialization, hashes #untuk serialisasi kunci dan hashing
import os
from datetime import datetime, timedelta #untuk operasi tanggal dan waktu
import time
import jwt #generate dan verifikasi JWT token
import hmac #membuat HMAC untuk integritas pesan
import hashlib #untuk hashing dalam HMAC
import uuid

#konfigurasi
API_URL = "https://pseudoviperously-untriced-mariana.ngrok-free.dev/" #link server
USERS = ["awul", "ciaw", "deby"] #daftar user untuk testing
#variabel simulasi
SESSIONS = {}
USER_KEYS = {}
TOKENS = {}
#secret untuk JWT
SECRET_KEY = "stella-secret-key"
ALGORITHM = "HS256"

#HELPER FUNCTIONS
def header(title): #awal header biar rapi
    print("\n" + "="*10 + f" {title} " + "="*10)

def now():#timestamp sekarang dalam format string
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sign_message(user, message): #menandatangani pesan dengan private key user
    priv_key = USER_KEYS[user]["private"]
    sig = priv_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()

def create_token(username): #membuat JWT token untuk user
    expire = datetime.utcnow() + timedelta(minutes=60)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def create_mac(session_key_b64, message, timestamp): #membuat HMAC untuk integritas pesan
    key = base64.b64decode(session_key_b64)
    data = f"{message}|{timestamp}".encode()
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(mac).decode()

#CLEAN USERS FILE
if os.path.exists("users.json"):
    os.remove("users.json")

#LANDING PAGE
header("LANDING PAGE")
resp = requests.get(f"{API_URL}/")
print(resp.text[:200] + "...")

#HEALTH CHECK
header("HEALTH CHECK")
print(requests.get(f"{API_URL}/health").json())

#GENERATE KEYS
header("KEY GENERATION (FULL PUBLIC KEYS)")
for u in USERS:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    USER_KEYS[u] = {"private": priv, "public": pub_pem}

    print(f"\nUser: {u}")
    print("Public Key:")
    print(pub_pem)

#STORE PUBLIC KEYS
header("STORE PUBLIC KEYS")
for u in USERS:
    r = requests.post(f"{API_URL}/store", params={
        "username": u,
        "public_key": USER_KEYS[u]["public"]
    })
    print(f"{u}: {r.json()}")

#LOGIN AND TOKEN
header("LOGIN / SESSION INIT")
for u in USERS:
    # generate token langsung, tanpa login server (agar secure relay valid)
    TOKENS[u] = create_token(u)
    print(f"\nUser: {u}")
    print("JWT Token:")
    print(TOKENS[u])

#SIGN & VERIFY
header("SIGN & VERIFY")
msg = "Ini pesan yang akan ditandatangani"
sig = sign_message("awul", msg)
print("Message:")
print(msg)
print("\nSignature (Base64):")
print(sig)

r = requests.post(f"{API_URL}/verify", params={
    "username": "awul",
    "message": msg,
    "signature": sig
})
print("\nVerify Result:")
print(r.json())

#RELAY MESSAGE
header("RELAY MESSAGE")
relay_msg = "kapan ya kita bisa tidur by, kepalaku udah ngedisko"
relay_sig = sign_message("awul", relay_msg)
print("Sender: awul")
print("Receiver: deby")
print("Message:")
print(relay_msg)
print("Signature:")
print(relay_sig)

r = requests.post(f"{API_URL}/relay", params={
    "sender": "awul",
    "receiver": "deby",
    "message": relay_msg,
    "signature": relay_sig
})
print("Response:", r.json())

#SECURE RELAY
header("SECURE RELAY (TOKEN + SIGNATURE)")
secure_msg = "ody ayo kita ayce minggu depan"
secure_sig = sign_message("awul", secure_msg)
print("Sender: awul")
print("Receiver: ciaw")
print("Message:")
print(secure_msg)
print("Signature:")
print(secure_sig)

TOKENS["awul"] = create_token("awul")

r = requests.post(
    f"{API_URL}/secure-relay",
    headers={"token": TOKENS["awul"]},
    params={
        "receiver": "ciaw",
        "message": secure_msg,
        "signature": secure_sig
    }
)
print("Response:", r.json())

#STELLA SESSION INIT (FINAL)
header("STELLA SESSION INIT")
for u in USERS:
    timestamp = now()
    signature = sign_message(u, timestamp)
    payload = {
        "username": u,
        "timestamp": timestamp,
        "signature": signature
    }
    r = requests.post(f"{API_URL}/session/init", params=payload)
    SESSIONS[u] = r.json()
    
    print(f"\nUser: {u}")
    print("Session Init Output:")
    print(f"Username: {payload['username']}")
    print(f"Timestamp: {payload['timestamp']}")
    print(f"Signature: {payload['signature']}")
    print("Server Response:", SESSIONS[u])

#RELAY SECURE STELLA (FINAL)
header("RELAY SECURE STELLA (SESSION + MAC)")
sender = "awul"
receiver = "ciaw"
message = "ody ayo kita ayce minggu depan"
timestamp = now()

# pastikan session key dari server Stella digunakan
session_key_b64 = SESSIONS[sender]["session_key"]
mac = create_mac(session_key_b64, message, timestamp)

payload = {
    "session_id": SESSIONS[sender]["session_id"],
    "receiver": receiver,
    "message": message,
    "timestamp": timestamp,
    "mac": mac
}

r = requests.post(f"{API_URL}/relay-secure", params=payload)

print("\nRelay Secure Stella Output:")
print(f"Session ID: {payload['session_id']}")
print(f"Receiver: {payload['receiver']}")
print(f"Message: {payload['message']}")
print(f"Timestamp: {payload['timestamp']}")
print(f"MAC: {payload['mac']}")
print("Server Response:", r.json())

print("\n TESTING COMPLETE ")

# FAILED SCENARIO TEST
header("FAILED SCENARIO 1 - USER TIDAK TERDAFTAR")

r = requests.post(f"{API_URL}/verify", params={
    "username": "hacker",
    "message": "halo ini attacker",
    "signature": "abc123"
})
print("Response:", r.json())

header("FAILED SCENARIO 2 - INVALID SIGNATURE")

fake_signature = "AAAAAAA"

r = requests.post(f"{API_URL}/verify", params={
    "username": "awul",
    "message": "pesan palsu",
    "signature": fake_signature
})
print("Response:", r.json())

header("FAILED SCENARIO 3 - INVALID / EXPIRED TOKEN")

r = requests.post(
    f"{API_URL}/secure-relay",
    headers={"token": "token_palsu"},
    params={
        "receiver": "ciaw",
        "message": "pesan tanpa otorisasi",
        "signature": fake_signature
    }
)
print("Response:", r.json())


header("FAILED SCENARIO 4 - INVALID SESSION ID (STELLA)")

r = requests.post(f"{API_URL}/relay-secure", params={
    "session_id": "session-palsu-123",
    "receiver": "ciaw",
    "message": "pesan palsu",
    "timestamp": now(),
    "mac": "AAAA"
})
print("Response:", r.json())


header("FAILED SCENARIO 5 - INVALID MAC (STELLA)")

sender = "awul"
receiver = "ciaw"
message = "pesan diubah attacker"
timestamp = now()

invalid_mac = "BBBBBBBB"

r = requests.post(f"{API_URL}/relay-secure", params={
    "session_id": SESSIONS[sender]["session_id"],
    "receiver": receiver,
    "message": message,
    "timestamp": timestamp,
    "mac": invalid_mac
})
print("Response:", r.json())

print("\n FAILED SCENARIO TEST COMPLETE ")