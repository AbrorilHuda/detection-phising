# Sistem Pakar Deteksi Link Phishing

## Deskripsi Proyek

Sistem Pakar Deteksi Link Phishing adalah aplikasi web berbasis Flask yang menggunakan pendekatan expert system untuk mengidentifikasi dan menganalisis URL serta konten email yang berpotensi phishing. Sistem ini menggunakan basis pengetahuan dengan aturan-aturan terstruktur dan mesin inferensi yang dapat memberikan analisis mendalam terhadap ancaman phishing.

## ✨ Fitur Utama

### 🔍 Analisis URL Mendalam

- **Deteksi IP Address**: Mengidentifikasi URL yang menggunakan alamat IP langsung
- **Analisis Struktur Domain**: Mendeteksi typosquatting dan domain mirip situs resmi
- **SSL Certificate Validation**: Memverifikasi validitas sertifikat SSL
- **URL Shortener Detection**: Mengidentifikasi penggunaan layanan penyingkat URL
- **Homograph Attack Detection**: Mendeteksi karakter Unicode yang menyerupai huruf Latin

### 📧 Analisis Konten Email

- **Grammar Analysis**: Mendeteksi tata bahasa yang mencurigakan
- **Social Engineering Detection**: Mengidentifikasi teknik manipulasi psikologis
- **Urgency Pattern Recognition**: Mendeteksi konten yang mendesak atau mengancam
- **Credential Request Detection**: Mengidentifikasi permintaan kredensial

### 🧠 Sistem Pakar

- **Rule-Based Engine**: 11 aturan terstruktur dengan bobot dan prioritas
- **Probabilistic Scoring**: Sistem penilaian probabilitas phishing
- **Risk Level Classification**: Klasifikasi tingkat risiko (RENDAH/SEDANG/TINGGI/SANGAT_TINGGI)
- **Confidence Score**: Skor kepercayaan hasil analisis

### 🌐 Interface

- **Web Interface**: Antarmuka web yang user-friendly
- **REST API**: Endpoint API untuk integrasi dengan sistem lain
- **Real-time Analysis**: Analisis real-time dengan feedback visual

## 🏗️ Arsitektur Sistem

### Struktur Direktori

```bash
deteksi-link-phising/
├── app.py                          # Aplikasi utama Flask
├── requirements.txt                # Dependencies Python
├── README.md                       # Dokumentasi dasar
├── model/                          # Model sistem pakar
│   ├── BasisPengetahuanPhising.py  # Knowledge Base
│   └── MesinInferensiPhising.py    # Inference Engine
├── static/                         # File statis
│   ├── css/style.css              # Stylesheet
│   └── js/script.js               # JavaScript
└── templates/                      # Template HTML
    ├── index.html                 # Halaman utama
    ├── 404.html                   # Error 404
    └── huang.html                 # Template khusus
```

### Komponen Utama

#### 1. **app.py** - Aplikasi Flask Utama

- **Route Handlers**: Mengelola endpoint web dan API
- **Input Validation**: Validasi dan sanitasi input pengguna
- **Result Formatting**: Memformat hasil analisis untuk tampilan
- **Error Handling**: Penanganan error dan exception

#### 2. **BasisPengetahuanPhising.py** - Knowledge Base

- **Rule Definition**: 11 aturan deteksi dengan bobot dan prioritas
- **Domain Database**: Database domain resmi dan shortener URL
- **Blacklist Management**: Pengelolaan blacklist domain phishing
- **Pattern Matching**: Pola-pola karakteristik phishing

#### 3. **MesinInferensiPhising.py** - Inference Engine

- **URL Analysis**: Analisis mendalam struktur dan properti URL
- **SSL Verification**: Verifikasi sertifikat SSL dan keamanan
- **Domain Intelligence**: Analisis informasi domain dan WHOIS
- **Pattern Recognition**: Pengenalan pola phishing
- **Scoring Algorithm**: Algoritma penilaian risiko

## ⚙️ Instalasi dan Setup

### Persyaratan Sistem

- Python 3.8 atau lebih tinggi
- pip (Python package manager)
- Koneksi internet (untuk analisis domain dan SSL)

### Langkah Instalasi

#### 1. Clone Repository

```bash
git clone https://github.com/AbrorilHuda/detection-phising.git
cd deteksi-link-phising
```

#### 2. Buat Virtual Environment

```bash
# Windows
python -m venv .env
.env\Scripts\activate

# Linux/macOS
python -m venv .env
source .env/bin/activate
```

#### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 4. Jalankan Aplikasi

```bash
python app.py
```

Aplikasi akan berjalan di `http://localhost:5000`

### Dependencies Utama

```bash
Flask==3.1.1              # Web framework
requests==2.32.4          # HTTP client
python-whois==0.9.5       # WHOIS lookup
tldextract==5.3.0         # Domain extraction
python-Levenshtein==0.27.1 # String similarity
dnspython==2.7.0          # DNS operations
```

## 📊 Sistem Aturan dan Scoring

### Aturan Deteksi (Knowledge Base Rules)

| No  | Nama Aturan              | Kondisi                          | Bobot | Prioritas     |
| --- | ------------------------ | -------------------------------- | ----- | ------------- |
| 1   | URL Mencurigakan Tinggi  | IP/@ symbol/URL panjang          | 0.25  | TINGGI        |
| 2   | Domain Typosquatting     | Domain mirip situs resmi         | 0.30  | SANGAT_TINGGI |
| 3   | Domain Baru Mencurigakan | Domain baru + SSL invalid        | 0.20  | TINGGI        |
| 4   | Konten Phishing Klasik   | Meminta kredensial + mendesak    | 0.25  | TINGGI        |
| 5   | Subdomain Mencurigakan   | Subdomain berlebihan             | 0.15  | SEDANG        |
| 6   | Blacklist Domain         | Domain dalam blacklist           | 0.35  | SANGAT_TINGGI |
| 7   | Redirect Chains          | Redirect berlebihan              | 0.20  | TINGGI        |
| 8   | URL Shortener            | Shortener ke tujuan mencurigakan | 0.18  | SEDANG        |
| 9   | SSL Palsu                | SSL self-signed/expired          | 0.15  | SEDANG        |
| 10  | Social Engineering       | Manipulasi psikologis            | 0.22  | TINGGI        |
| 11  | Web Judi Online          | Kata kunci judi                  | 0.10  | RENDAH        |

### Sistem Scoring

#### Probabilitas Phishing

```python
probabilitas = (total_bobot_aturan_terpenuhi / total_bobot_maksimum) * 100
```

#### Level Risiko

- **RENDAH**: 0-25%
- **SEDANG**: 26-50%
- **TINGGI**: 51-75%
- **SANGAT_TINGGI**: 76-100%

#### Confidence Score

Dihitung berdasarkan jumlah fakta terdeteksi dan konsistensi aturan yang terpenuhi.

## 🔧 Penggunaan

### Web Interface

1. **Akses Aplikasi**: Buka `http://localhost:5000`
2. **Input Data**: Masukkan URL atau konten email yang ingin dianalisis
3. **Analisis**: Klik tombol "Analisis" untuk memulai deteksi
4. **Hasil**: Lihat hasil analisis dengan detail:
   - Probabilitas phishing
   - Level risiko
   - Aturan yang terpenuhi
   - Fakta yang terdeteksi
   - Rekomendasi tindakan

### REST API

#### Endpoint: POST `/api/detect`

**Request Body:**

```json
{
  "url": "https://example.com",
  "message_content": "Segera verifikasi akun Anda..."
}
```

**Response:**

```json
{
    "status": "success",
    "results": {
        "hasil_deteksi": [...],
        "probabilitas_phishing": 75.5,
        "level_risiko": "TINGGI",
        "confidence_score": 0.85,
        "aturan_terpenuhi": 3,
        "total_aturan": 11,
        "fakta_terdeteksi": [...],
        "rekomendasi": [...]
    },
    "timestamp": "2025-07-20T10:30:00"
}
```

## 🧪 Contoh Penggunaan

### Contoh 1: URL Mencurigakan

```bash
Input URL: http://192.168.1.100/login.php
Hasil:
- Probabilitas Phishing: 85%
- Level Risiko: SANGAT_TINGGI
- Aturan Terpenuhi: URL menggunakan IP address, tidak ada SSL
```

### Contoh 2: Email Phishing

```bash
Input Konten: "URGENT! Verifikasi akun Anda SEKARANG atau akun akan diblokir!"
Hasil:
- Probabilitas Phishing: 70%
- Level Risiko: TINGGI
- Aturan Terpenuhi: Konten mendesak, tata bahasa mencurigakan
```

## 🔒 Keamanan

### Fitur Keamanan

- **Input Sanitization**: Membersihkan input dari karakter berbahaya
- **Rate Limiting**: Dapat ditambahkan untuk mencegah abuse
- **SSL Verification**: Verifikasi sertifikat SSL target
- **Timeout Protection**: Timeout untuk request eksternal

### Rekomendasi Keamanan

1. Gunakan HTTPS untuk production
2. Implementasi rate limiting
3. Log aktivitas untuk monitoring
4. Update blacklist secara berkala
5. Validasi input yang ketat

## 📈 Pengembangan Lanjutan

### Fitur yang Dapat Ditambahkan

1. **Machine Learning Integration**: Model AI untuk deteksi yang lebih akurat
2. **Real-time Threat Intelligence**: Integrasi dengan feed ancaman terkini
3. **Batch Processing**: Analisis massal URL/email
4. **Report Generation**: Laporan analisis dalam format PDF/Excel
5. **User Management**: Sistem autentikasi dan otorisasi
6. **Dashboard Analytics**: Statistik dan visualisasi data

### Optimisasi

1. **Caching**: Cache hasil analisis domain
2. **Async Processing**: Analisis asinkron untuk performa
3. **Database Integration**: Penyimpanan hasil di database
4. **Load Balancing**: Distribusi beban untuk skalabilitas

## 🐛 Troubleshooting

### Masalah Umum

#### 1. Error SSL Certificate

```bash
Solusi: Periksa koneksi internet dan validitas URL target
```

#### 2. Timeout Error

```bash
Solusi: Tingkatkan timeout atau periksa koneksi jaringan
```

#### 3. Module Import Error

```bash
Solusi: Pastikan semua dependencies terinstall dengan benar
pip install -r requirements.txt
```

### Debug Mode

Untuk debugging, jalankan dengan:

```bash
export FLASK_ENV=development
python app.py
```

## 📝 Kontribusi

### Guidelines Kontribusi

1. Fork repository
2. Buat branch untuk fitur baru
3. Ikuti coding standards Python (PEP 8)
4. Tambahkan test untuk fitur baru
5. Update dokumentasi
6. Submit pull request

### Coding Standards

- Gunakan type hints
- Dokumentasi docstring untuk fungsi
- Error handling yang proper
- Logging untuk debugging

## 📄 Lisensi

Proyek ini menggunakan lisensi [MIT License]. Silakan merujuk ke file LICENSE untuk detail lengkap.

## 👥 Tim Pengembang

- **Developer**: abrordc
- **Contact**: ....

## 📞 Support

Untuk pertanyaan atau dukungan:

- **Email**: ....
- **GitHub Issues**: [repository-issues-url](https://github.com/AbrorilHuda/detection-phising/issues)

---

**Catatan**: Sistem ini dikembangkan untuk tujuan edukasi dan penelitian. Untuk penggunaan produksi, disarankan untuk melakukan pengujian lebih lanjut dan implementasi fitur keamanan tambahan.

fun fact: documentasi ini di buat AI
