from fastapi import FastAPI, HTTPException, UploadFile, File, Header #pengambilan file dan header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse #tampilan HTML
from typing import Optional
import os, json, jwt, base64, hmac, hashlib, uuid #manajemen file, json web token, encoding dan decoding kripto, hashing, session id
from datetime import datetime, timedelta #timestamp dan durasi
from cryptography.hazmat.primitives import serialization, hashes #algoritma Elliptic Curve Digital Signature Algorithm (ECDSA)
from cryptography.hazmat.primitives.asymmetric import ec #algoritma kriptografi pub key
from cryptography.exceptions import InvalidSignature #penanganan error signature

SECRET_KEY = "stella-secret-key" #secret key untuk JWT
ALGORITHM = "HS256" #algoritma JWT
TOKEN_EXPIRE_MINUTES = 60 #durasi token berlaku
DATA_FILE = "users.json" #data user dan pub keyy
SESSION_FILE = "sessions.json"  #data stella session
PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1()) #membuatprivate key ECDSA untuk menandatangani hash dokumen pdf

app = FastAPI(title="Security Service", version="1.0.0") #inisialisasi aplikasi FastAPI

app.add_middleware( 
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
) #mengaktifkan CORS agar API dapat diakses dari client manapun (misalnya web testing, Postman, atau client Python)

#Helper Functions
def load_users(): #memuat data user dari file JSON
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_users(users): #menyimpan data user ke file JSON
    with open(DATA_FILE, "w") as f:
        json.dump(users, f, indent=2)

def load_sessions(): #memuat data session stella dari file JSON
    if not os.path.exists(SESSION_FILE):
        return {}
    with open(SESSION_FILE, "r") as f:
        return json.load(f)

def save_sessions(sessions): #menyimpan data session stella ke file JSON
    with open(SESSION_FILE, "w") as f:
        json.dump(sessions, f, indent=2)

def create_token(username: str): #membuat jwt token untuk identitas user dan waktu kedaluarsa
    expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": username, "exp": expire.timestamp()}, SECRET_KEY, algorithm=ALGORITHM)
    return token

def verify_token(token: str):#memverifikasi jwt token dan mengembalikan username jika valid
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except:
        return None

def verify_signature(public_key_pem: str, message: str, signature_b64: str):#memuat public key user , memverifikasi signature ECDSA, memastikan pesan tidak diubah
    try:
        pub_bytes = public_key_pem.encode()
        pub_key = serialization.load_pem_public_key(pub_bytes)
        sig = base64.b64decode(signature_b64)
        pub_key.verify(sig, message.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print("VERIFY ERROR:", e)
        return False
    
def hash_pdf_bytes(pdf_bytes: bytes): #menghitung hash SHA-256 dari isi file PDF
    return hashlib.sha256(pdf_bytes).digest()

def sign_pdf_hash(private_key, pdf_hash: bytes): #menandatangani hash PDF menggunakan private key ECDSA
    signature = private_key.sign(
        pdf_hash,
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode()

#ENDPOINTS LAMA
@app.get("/", response_class=HTMLResponse, tags=["System"]) #menapilkan halaman landing sebagai tanda API aktif
async def landing_page():
    return """
    <html><body>
    <h1>🔐 Security Service API</h1>
    <button onclick="window.open('/docs', '_blank')">Open API Docs</button>
    </body></html>
    """

@app.get("/health", tags=["System"]) #memastikan serveer berjalan normal
async def health_check():
    return {"status": "Security Service is running", "timestamp": datetime.now().isoformat()}

@app.post("/upload-pdf") #endpoint untuk mengunggah file PDF ke server
async def upload_pdf(file: UploadFile = File(...)):
    fname = file.filename
    contents = await file.read()
    with open(fname, "wb") as f:
        f.write(contents)
    return {"message": "File uploaded!", "filename": fname}

@app.post("/sign-pdf") #pdf di hash, hash ditandatangani dengan private key, mengembalikan signature dan info penandatanganan
async def sign_pdf(file: UploadFile = File(...)):
    pdf_bytes = await file.read()

    pdf_hash = hash_pdf_bytes(pdf_bytes)
    signature = sign_pdf_hash(PRIVATE_KEY, pdf_hash)

    signed_info = {
        "filename": file.filename,
        "hash": base64.b64encode(pdf_hash).decode(),
        "signature": signature,
        "signed_at": datetime.now().isoformat()
    }

    return signed_info

@app.post("/verify-pdf") #memverifikasi signature pdf dengan public key server
async def verify_pdf(file: UploadFile = File(...), signature: str = ""):
    pdf_bytes = await file.read()
    pdf_hash = hash_pdf_bytes(pdf_bytes)

    public_key = PRIVATE_KEY.public_key()

    try:
        public_key.verify(
            base64.b64decode(signature),
            pdf_hash,
            ec.ECDSA(hashes.SHA256())
        )
        return {"valid": True}
    except InvalidSignature:
        return {"valid": False}

@app.post("/store") #menyimpan public key user ke file JSON untuk verifikasi signature
async def store_pubkey(username: str, public_key: str):
    users = load_users()
    if username in users:
        msg = f"{username} sudah terdaftar, public key diperbarui"
    else:
        users[username] = {"public_key": public_key, "messages": []}
        msg = f"Public key {username} tersimpan"
    save_users(users)
    return {"message": msg}

@app.post("/verify") #memverifikasi signature pesan dari user menggunakan public key yang tersimpan
async def verify(username: str, message: str, signature: str):
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User tidak terdaftar")
    valid = verify_signature(users[username]["public_key"], message, signature)
    return {"message": "Signature valid" if valid else "Signature invalid", "valid": valid}

@app.post("/relay") #mengirim pesan dari satu user ke user lain setelah memverifikasi signature
async def relay(sender: str, receiver: str, message: str, signature: str):
    users = load_users()
    if sender not in users or receiver not in users:
        raise HTTPException(status_code=404, detail="User tidak terdaftar")
    if not verify_signature(users[sender]["public_key"], message, signature):
        raise HTTPException(status_code=400, detail="Signature invalid")
    users[receiver]["messages"].append({"from": sender, "message": message})
    save_users(users)
    return {"message": f"Pesan dari {sender} terkirim ke {receiver}"}

@app.post("/login") #menghasilkan jwt token untuk user yang terdaftar
async def login(username: str):
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User tidak terdaftar")
    token = create_token(username)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/secure-relay") #mengirim pesan aman dari satu user ke user lain dengan verifikasi token dan signature
async def secure_relay(token: str = Header(...), receiver: str = "", message: str = "", signature: str = ""):
    sender = verify_token(token)
    if not sender:
        raise HTTPException(status_code=401, detail="Token invalid / expired")
    users = load_users()
    if receiver not in users:
        raise HTTPException(status_code=404, detail="Receiver tidak terdaftar")
    if not verify_signature(users[sender]["public_key"], message, signature):
        raise HTTPException(status_code=400, detail="Signature invalid")
    users[receiver]["messages"].append({"from": sender, "message": message})
    save_users(users)
    return {"message": f"Pesan aman dari {sender} ke {receiver} terkirim"}

#STELLA
@app.post("/session/init") #inisialisasi session stella dengan verifikasi signature timestamp
async def session_init(username: str, timestamp: str, signature: str):
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User tidak terdaftar")
    if not verify_signature(users[username]["public_key"], timestamp, signature):
        raise HTTPException(status_code=400, detail="Invalid signature")
    sessions = load_sessions()
    session_id = str(uuid.uuid4())
    session_key = base64.b64encode(os.urandom(32)).decode()
    expired_at = (datetime.now() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)).isoformat()
    sessions[session_id] = {"user": username, "session_key": session_key, "expired_at": expired_at}
    save_sessions(sessions)
    return {"session_id": session_id, "session_key": session_key, "expired_at": expired_at}

@app.post("/relay-secure") #mengirim pesan aman dengan verifikasi session id dan mac
async def relay_secure(session_id: str, receiver: str, message: str, timestamp: str, mac: str):
    sessions = load_sessions()
    if session_id not in sessions:
        raise HTTPException(status_code=401, detail="Session invalid")
    users = load_users()
    if receiver not in users:
        raise HTTPException(status_code=404, detail="Receiver not terdaftar")
    session_key = base64.b64decode(sessions[session_id]["session_key"])
    data = f"{message}|{timestamp}".encode()
    expected_mac = hmac.new(session_key, data, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, base64.b64encode(expected_mac).decode()):
        raise HTTPException(status_code=400, detail="Invalid MAC")
    users[receiver]["messages"].append({"from": sessions[session_id]["user"], "message": message})
    save_users(users)
    return {"message": f"Pesan relayed securely dari {sessions[session_id]['user']} ke {receiver}"}