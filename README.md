# Punk Records-V1
Project ini dibuat untuk memenuhi nilai akhir semester Mata Kuliah Keamanan dan Integritas Data. Program api.py merupakan layanan keamanan berbasis FastAPI yang mengimplementasikan mekanisme digital signature, JWT authentication, serta session-based security menggunakan MAC.

# Anggota Kelompok:
1. Audy Alycia (24031554179)
2. Arimbi Deby Setyoningrum (24031554))
3. Aulia Aziza  (24031554102)

# Library
1. Python 3.10+
2. FastAPI
3. Uvicorn
4. cryptography
5. PyJWT (jwt)
6. requests
7. ngrok

# Setup Environment
1. Cek Versi Python
    python3 --version
2. Buat Virtual Environment
    python3 -m venv .venv
3. Aktifkan venv:
    source .venv/bin/activate
4. Update pip
    pip install --upgrade pip
5. Install Dependency
    pip install fastapi uvicorn cryptography pyjwt requests

# Menjalankan API Server
  uv run main.py
  Secara default API berjalan di: http://127.0.0.1:8000
# Cek API:
1. Landing page
2. Health check
3. Dokumentasi Swagger

# Menjalankan Ngrok
  ngrok http 8000
  Catatan: Pastikan authtoken ngrok sudah dikonfigurasi sekali seumur hidup:
  ngrok config add-authtoken <YOUR_TOKEN>
    
   Salin URL HTTPS dari ngrok, lalu masukkan ke variabel berikut di client.py:
    API_URL = "https://pseudoviperously-untriced-mariana.ngrok-free.dev/"

# Menjalankan Client
   Client berfungsi sebagai simulator user, mencakup:
    1. Generate key pair ECDSA
    2. Store public key
    3. Digital signature & verification
    4. Secure relay (JWT)
    5. STELLA session init
    6. Secure relay menggunakan MAC
    7.
    Failed scenario testing

   Jalankan client:
    uv run client.py
