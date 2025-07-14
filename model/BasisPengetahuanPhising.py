class BasisPengetahuanPhishing:
    def __init__(self):
        self.aturan = [
            {
                "nama": "Aturan_1_URL_Mencurigakan_Tinggi",
                "kondisi": ["url_mengandung_ip", "url_mengandung_at_symbol", "url_terlalu_panjang"],
                "hasil": "URL menggunakan format yang sangat mencurigakan (IP/@ symbol/terlalu panjang)",
                "bobot": 0.25,
                "prioritas": "TINGGI"
            },
            {
                "nama": "Aturan_2_Domain_Typosquatting",
                "kondisi": ["domain_mirip_domain_resmi"],
                "hasil": "Terdeteksi typosquatting - domain mirip dengan situs resmi",
                "bobot": 0.30,
                "prioritas": "SANGAT_TINGGI"
            },
            {
                "nama": "Aturan_3_Domain_Baru_Mencurigakan",
                "kondisi": ["domain_sangat_baru", "ssl_tidak_valid"],
                "hasil": "Domain baru dengan sertifikat SSL tidak valid",
                "bobot": 0.20,
                "prioritas": "TINGGI"
            },
            {
                "nama": "Aturan_4_Konten_Phishing_Klasik",
                "kondisi": ["email_meminta_kredensial", "konten_mendesak_atau_mengancam"],
                "hasil": "Konten email menunjukkan pola phishing klasik",
                "bobot": 0.25,
                "prioritas": "TINGGI"
            },
            {
                "nama": "Aturan_5_Subdomain_Mencurigakan",
                "kondisi": ["subdomain_berlebihan", "url_mengandung_karakter_tidak_umum"],
                "hasil": "Struktur subdomain dan karakter URL mencurigakan",
                "bobot": 0.15,
                "prioritas": "SEDANG"
            },
            {
                "nama": "Aturan_6_Blacklist_Domain",
                "kondisi": ["domain_dalam_blacklist"],
                "hasil": "Domain terdaftar dalam blacklist phishing",
                "bobot": 0.35,
                "prioritas": "SANGAT_TINGGI"
            },
            {
                "nama": "Aturan_7_Redirect_Chains",
                "kondisi": ["redirect_berlebihan", "redirect_ke_domain_mencurigakan"],
                "hasil": "Terdeteksi redirect chains yang mencurigakan",
                "bobot": 0.20,
                "prioritas": "TINGGI"
            },
            {
                "nama": "Aturan_8_URL_Shortener_Mencurigakan",
                "kondisi": ["menggunakan_url_shortener", "destination_url_mencurigakan"],
                "hasil": "URL shortener mengarah ke destinasi mencurigakan",
                "bobot": 0.18,
                "prioritas": "SEDANG"
            },
            {
                "nama": "Aturan_9_Sertifikat_SSL_Palsu",
                "kondisi": ["ssl_self_signed", "ssl_expired"],
                "hasil": "Sertifikat SSL tidak valid atau sudah expired",
                "bobot": 0.15,
                "prioritas": "SEDANG"
            },
            {
                "nama": "Aturan_10_Konten_Sosial_Engineering",
                "kondisi": ["konten_meminta_tindakan_segera", "konten_menggunakan_brand_palsu"],
                "hasil": "Konten menggunakan teknik social engineering",
                "bobot": 0.22,
                "prioritas": "TINGGI"
            },
            {
                "nama": "Aturan_11_web_judi_online",
                "kondisi": ["domain_mengandung_unsur_judi"],
                "hasil": "Domain mengandung kata kunci terkait judi online",
                "bobot": 0.10,
                "prioritas": "RENDAH"
            }
        ]
        
        # Expanded knowledge base
        self.domain_resmi = [
            "google.com", "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
            "microsoft.com", "apple.com", "amazon.com", "netflix.com", "youtube.com",
            "bca.co.id", "bri.co.id", "bni.co.id", "mandiri.co.id", "cimb.co.id",
            "paypal.com", "ebay.com", "spotify.com", "dropbox.com", "github.com",
            "stackoverflow.com", "reddit.com", "wikipedia.org", "whatsapp.com", "dana.id", "shopee.co.id"
        ]
        
        self.url_shorteners = [
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "short.link",
            "ow.ly", "buff.ly", "rebrand.ly", "is.gd", "v.gd"
        ]
        
        # Simulated blacklist - in production, this would be from threat intelligence feeds
        self.blacklist_domains = [
            "phishing-example.com", "fake-bank.net", "scam-site.org"
        ]
        
        self.regex_judol_blacklist = [
            r"[a-z]*[0-9]{2,}$",   
            r"^(slot|judi|casino).*",
        ]
        
        self.suspicious_keywords = {
            "urgent": ["urgent", "darurat", "segera", "immediately", "act now"],
            "credentials": ["password", "pin", "username", "login", "verifikasi", "konfirmasi"],
            "threats": ["suspend", "block", "blokir", "tutup", "expired", "kadaluarsa"],
            "actions": ["click here", "klik di sini", "download", "unduh", "update now"],
            "brands": ["bank", "paypal", "google", "microsoft", "apple", "amazon"]
        }
