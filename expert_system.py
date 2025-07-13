import ssl
import socket
import requests
from urllib.parse import urlparse
import tldextract
import whois
from datetime import datetime
import Levenshtein

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

class MesinInferensiPhishing:
    def __init__(self, basis_pengetahuan):
        self.basis_pengetahuan = basis_pengetahuan
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def analisis_url_mendalam(self, url):
        """Analisis mendalam terhadap URL"""
        hasil_analisis = {}
        
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            # Analisis struktur URL
            hasil_analisis['ip_address'] = self._is_ip_address(parsed.netloc)
            hasil_analisis['url_length'] = len(url)
            hasil_analisis['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            hasil_analisis['path_depth'] = len([p for p in parsed.path.split('/') if p])
            hasil_analisis['has_port'] = ':' in parsed.netloc and not parsed.netloc.endswith(':80') and not parsed.netloc.endswith(':443')
            
            # Analisis domain
            domain = f"{extracted.domain}.{extracted.suffix}"
            hasil_analisis['domain'] = domain
            hasil_analisis['full_domain'] = parsed.netloc
            hasil_analisis['is_shortener'] = domain in self.basis_pengetahuan.url_shorteners
            
            # Analisis karakter mencurigakan
            hasil_analisis['suspicious_chars'] = self._count_suspicious_chars(url)
            hasil_analisis['homograph_attack'] = self._detect_homograph(domain)
            
            return hasil_analisis
            
        except Exception as e:
            print(f"Error dalam analisis URL: {e}")
            return {}
    
    def _is_ip_address(self, netloc):
        """Cek apakah netloc adalah IP address"""
        import ipaddress
        try:
            # Remove port if present
            host = netloc.split(':')[0]
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
    
    def _count_suspicious_chars(self, url):
        """Hitung karakter mencurigakan dalam URL"""
        suspicious_chars = ['-', '_', '%', '$', '&', '=', '?', '#']
        return sum(url.count(char) for char in suspicious_chars)
    
    def _detect_homograph(self, domain):
        """Deteksi serangan homograph"""
        # Karakter yang sering digunakan untuk homograph attack
        homograph_chars = ['а', 'е', 'о', 'р', 'х', 'у', 'с', 'в', 'н', 'к']
        return any(char in domain for char in homograph_chars)
    
    def get_common_name(self, cert_entity):
        """Ekstrak commonName dari issuer/subject"""
        for item in cert_entity:
            if isinstance(item, tuple) and item[0][0] == 'commonName':
                return item[0][1]
        return 'Unknown'
    
    def analisis_ssl(self, url):
        """Analisis sertifikat SSL"""
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return {'has_ssl': False, 'valid_ssl': False}
            
            hostname = parsed.netloc.split(':')[0]
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Cek validitas sertifikat
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    now = datetime.now()
                    #now = datetime.utcnow() #utc                    
                    return {
                        'has_ssl': True,
                        'valid_ssl': not_before <= now <= not_after,
                        'self_signed': cert.get('issuer') == cert.get('subject'),
                        'expired': now > not_after,
                        'issuer': self.get_common_name(cert.get('issuer', []))
                    }
                    
        except Exception as e:
            return {'has_ssl': False, 'valid_ssl': False, 'error': str(e)}
    
    def analisis_redirect(self, url):
        """Analisis redirect chains"""
        try:
            redirects = []
            current_url = url
            
            for i in range(10):  # Maksimal 10 redirect
                response = self.session.head(current_url, allow_redirects=False, timeout=10)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    redirect_url = response.headers.get('Location')
                    if redirect_url:
                        redirects.append(redirect_url)
                        current_url = redirect_url
                    else:
                        break
                else:
                    break
            
            return {
                'redirect_count': len(redirects),
                'redirect_chain': redirects,
                'final_url': current_url
            }
            
        except Exception as e:
            return {'redirect_count': 0, 'error': str(e)}
    
    def analisis_domain_age(self, domain):
        """Analisis umur domain"""
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                age_days = (datetime.now() - creation_date).days
                return {
                    'age_days': age_days,
                    'creation_date': creation_date,
                    'registrar': domain_info.registrar
                }
        except Exception as e:
            return {'age_days': None, 'error': str(e)}
        
        return {'age_days': None}
    
    def hitung_kemiripan_domain_advanced(self, input_domain):
        """Algoritma advanced untuk deteksi typosquatting"""
        # Normalisasi domain
        clean_domain = input_domain.lower().replace('www.', '')
        
        for domain_resmi in self.basis_pengetahuan.domain_resmi:
            # Levenshtein distance
            distance = Levenshtein.distance(clean_domain, domain_resmi)
            similarity = 1 - (distance / max(len(clean_domain), len(domain_resmi)))
            
            # Jika similarity tinggi (>0.8) tapi tidak sama persis
            if 0.8 < similarity < 1.0:
                return True
            
            # Cek common typosquatting patterns
            if self._check_typosquatting_patterns(clean_domain, domain_resmi):
                return True
                
        return False
    
    def _check_typosquatting_patterns(self, test_domain, original_domain):
        """Cek pola typosquatting yang umum"""
        patterns = [
            # Character substitution
            lambda x, y: x.replace('o', '0') == y or x.replace('0', 'o') == y,
            # Character insertion
            lambda x, y: any(x[:i] + x[i+1:] == y for i in range(len(x))),
            # Character deletion
            lambda x, y: any(x[:i] + c + x[i:] == y for i in range(len(x)+1) for c in 'abcdefghijklmnopqrstuvwxyz'),
            # Common misspellings
            lambda x, y: x.replace('gmail', 'gmai1') == y or x.replace('paypal', 'paypa1') == y
        ]
        
        return any(pattern(test_domain, original_domain) for pattern in patterns)
    
    def analisis_konten_email(self, konten):
        """Analisis konten email untuk pola phishing"""
        konten_lower = konten.lower()
        hasil = {
            'urgency_score': 0,
            'credential_requests': 0,
            'threat_level': 0,
            'social_engineering_score': 0
        }
        
        # Hitung skor berdasarkan keyword
        for category, keywords in self.basis_pengetahuan.suspicious_keywords.items():
            count = sum(konten_lower.count(keyword) for keyword in keywords)
            hasil[f'{category}_count'] = count
            
            if category == 'urgent':
                hasil['urgency_score'] = min(count * 0.3, 1.0)
            elif category == 'credentials':
                hasil['credential_requests'] = min(count * 0.4, 1.0)
            elif category == 'threats':
                hasil['threat_level'] = min(count * 0.35, 1.0)
        
        # Hitung skor social engineering
        hasil['social_engineering_score'] = (
            hasil['urgency_score'] + 
            hasil['credential_requests'] + 
            hasil['threat_level']
        ) / 3
        
        return hasil
    
    def ekstraksi_fakta_advanced(self, data):
        """Ekstraksi fakta dengan analisis mendalam"""
        fakta = set()
        
        url = data.get("url", "")
        print(f"Analisis URL: {url}")
        if not url:
            return fakta
        
        # Analisis URL mendalam
        url_analysis = self.analisis_url_mendalam(url)
        
        # Fakta berdasarkan analisis URL
        if url_analysis.get('ip_address'):
            fakta.add("url_mengandung_ip")
        
        if "@" in url:
            fakta.add("url_mengandung_at_symbol")
        
        if url_analysis.get('url_length', 0) > 75:
            fakta.add("url_terlalu_panjang")
        
        if url_analysis.get('subdomain_count', 0) > 3:
            fakta.add("subdomain_berlebihan")
        
        if url_analysis.get('suspicious_chars', 0) > 5:
            fakta.add("url_mengandung_karakter_tidak_umum")
        
        if url_analysis.get('homograph_attack'):
            fakta.add("homograph_attack")
        
        # Analisis SSL
        ssl_info = self.analisis_ssl(url)
        if not ssl_info.get('valid_ssl', False):
            fakta.add("ssl_tidak_valid")
        
        if ssl_info.get('self_signed', False):
            fakta.add("ssl_self_signed")
        
        if ssl_info.get('expired', False):
            fakta.add("ssl_expired")
        
        # Analisis redirect
        redirect_info = self.analisis_redirect(url)
        if redirect_info.get('redirect_count', 0) > 2:
            fakta.add("redirect_berlebihan")
        
        # Analisis domain
        domain = url_analysis.get('domain', '')
        if domain:
            
            print("="*10)
            print("DEBUG DOMAIN ")
            print(f"Domain: {domain}")
            print("="*10)
            
            # Cek blacklist
            if domain in self.basis_pengetahuan.blacklist_domains:
                fakta.add("domain_dalam_blacklist")
            
            # belum fiks masih di development
            import re
            for pattern in self.basis_pengetahuan.regex_judol_blacklist:
                print("="*10)
                print("DEBUG DOMAIN ")
                print(f"Domain: {domain}")
                print("="*10)
                if re.search(pattern, domain.split('.')[0]):
                    fakta.add("domain_mengandung_unsur_judi")
                    break  
            
            # Cek umur domain
            domain_age = self.analisis_domain_age(domain)
            if domain_age.get('age_days') is not None and domain_age['age_days'] < 30:
                fakta.add("domain_sangat_baru")
            
            # Cek typosquatting
            if self.hitung_kemiripan_domain_advanced(domain):
                fakta.add("domain_mirip_domain_resmi")
        
        # Analisis URL shortener
        if url_analysis.get('is_shortener'):
            fakta.add("menggunakan_url_shortener")
            # Analisis destinasi URL shortener bisa ditambahkan di sini
        
        # Analisis konten email
        konten_email = data.get("konten_email", "")
        if konten_email:
            konten_analysis = self.analisis_konten_email(konten_email)
            
            if konten_analysis.get('credential_requests', 0) > 0.3:
                fakta.add("email_meminta_kredensial")
            
            if konten_analysis.get('urgency_score', 0) > 0.3:
                fakta.add("konten_mendesak_atau_mengancam")
            
            if konten_analysis.get('social_engineering_score', 0) > 0.4:
                fakta.add("konten_meminta_tindakan_segera")
            
            if konten_analysis.get('brands_count', 0) > 0:
                fakta.add("konten_menggunakan_brand_palsu")
        
        # Fakta tambahan dari input
        if data.get("tata_bahasa_buruk"):
            fakta.add("tata_bahasa_buruk")
        
        if data.get("domain_tidak_dikenal"):
            fakta.add("domain_tidak_dikenal")
        
        return fakta
    
    def hitung_confidence_score(self, fakta_terpenuhi, total_fakta_tersedia):
        """Hitung confidence score berdasarkan fakta yang terpenuhi"""
        if total_fakta_tersedia == 0:
            return 0.0
        return (fakta_terpenuhi / total_fakta_tersedia) * 100
    
    def jalankan_inferensi_advanced(self, data_input):
        """Inferensi advanced dengan weighted scoring dan confidence"""
        fakta_input = self.ekstraksi_fakta_advanced(data_input)
        hasil_deteksi = []
        total_skor_risiko = 0.0
        aturan_terpenuhi = 0
        total_aturan = len(self.basis_pengetahuan.aturan)
        
        # Evaluasi setiap aturan
        for aturan in self.basis_pengetahuan.aturan:
            kondisi_terpenuhi = all(kondisi in fakta_input for kondisi in aturan["kondisi"])
            
            if kondisi_terpenuhi:
                # Bobot berbeda berdasarkan prioritas
                multiplier = {
                    "SANGAT_TINGGI": 1.5,
                    "TINGGI": 1.2,
                    "SEDANG": 1.0,
                    "RENDAH": 0.8
                }.get(aturan.get("prioritas", "SEDANG"), 1.0)
                
                weighted_score = aturan["bobot"] * multiplier
                total_skor_risiko += weighted_score
                aturan_terpenuhi += 1
                
                hasil_deteksi.append({
                    "aturan": aturan['nama'],
                    "hasil": aturan['hasil'],
                    "skor": weighted_score,
                    "prioritas": aturan.get("prioritas", "SEDANG")
                })
        
        # Hitung probabilitas dengan normalisasi
        max_possible_score = sum(aturan["bobot"] * 1.5 for aturan in self.basis_pengetahuan.aturan)
        probabilitas_phishing = min(100.0, (total_skor_risiko / max_possible_score) * 100)
        
        # Hitung confidence score
        confidence = self.hitung_confidence_score(len(fakta_input), 20)  # 20 adalah jumlah fakta yang mungkin
        
        # Tentukan level risiko
        if probabilitas_phishing >= 80:
            level_risiko = "SANGAT TINGGI"
        elif probabilitas_phishing >= 60:
            level_risiko = "TINGGI"
        elif probabilitas_phishing >= 40:
            level_risiko = "SEDANG"
        elif probabilitas_phishing >= 20:
            level_risiko = "RENDAH"
        else:
            level_risiko = "SANGAT RENDAH"
        
        if not hasil_deteksi:
            hasil_deteksi.append({
                "aturan": "Tidak ada aturan yang terpenuhi",
                "hasil": "Tidak ada indikasi phishing yang terdeteksi",
                "skor": 0.0,
                "prioritas": "INFO"
            })
            probabilitas_phishing = 0.0
            level_risiko = "AMAN"
        
        return {
            "hasil_deteksi": hasil_deteksi,
            "probabilitas_phishing": probabilitas_phishing,
            "level_risiko": level_risiko,
            "confidence_score": confidence,
            "aturan_terpenuhi": aturan_terpenuhi,
            "total_aturan": total_aturan,
            "fakta_terdeteksi": list(fakta_input),
            "total_skor": total_skor_risiko,
            "rekomendasi": self._generate_recommendations(level_risiko, hasil_deteksi)
        }
    
    def _generate_recommendations(self, level_risiko, hasil_deteksi):
        """Generate rekomendasi berdasarkan level risiko"""
        recommendations = []
        
        if level_risiko in ["SANGAT TINGGI", "TINGGI"]:
            recommendations.extend([
                "JANGAN klik link atau download attachment",
                "Laporkan email ini sebagai phishing",
                "Verifikasi langsung dengan organisasi terkait melalui channel resmi",
                "Scan sistem untuk malware jika sudah mengklik link"
            ])
        elif level_risiko == "SEDANG":
            recommendations.extend([
                "Verifikasi keaslian email melalui channel resmi",
                "Jangan masukkan informasi pribadi atau kredensial",
                "Periksa URL dengan teliti sebelum mengklik"
            ])
        elif level_risiko == "RENDAH":
            recommendations.extend([
                "Tetap waspada dan verifikasi jika diminta informasi sensitif",
                "Periksa sender dan konten dengan teliti"
            ])
        else:
            recommendations.append("terlihat aman, namun tetap waspada")
        
        return recommendations



## Debug Mode 
# Contoh penggunaan
if __name__ == "__main__":
    # Inisialisasi sistem
    basis_pengetahuan = BasisPengetahuanPhishing()
    mesin_inferensi = MesinInferensiPhishing(basis_pengetahuan)
    
    # Contoh data input
    data_test = {
        "url": "https://fnatix-layananfr.paypaL.biz.id/kaget=s3eygtewj&r=cZPhfp/",
        "konten_email": "Urgent: Your PayPal account will be suspended if you don't verify your login details immediately. Click here to confirm your account.",
        "tata_bahasa_buruk": False,
        "domain_tidak_dikenal": True
    }
    
    # Jalankan inferensi
    hasil = mesin_inferensi.jalankan_inferensi_advanced(data_test)
    
    # Tampilkan hasil
    print(f"=== HASIL ANALISIS PHISHING ===")
    print(f"Probabilitas Phishing: {hasil['probabilitas_phishing']:.2f}%")
    print(f"Level Risiko: {hasil['level_risiko']}")
    print(f"Confidence Score: {hasil['confidence_score']:.2f}%")
    print(f"Aturan Terpenuhi: {hasil['aturan_terpenuhi']}/{hasil['total_aturan']}")
    print(f"\nDeteksi:")
    for deteksi in hasil['hasil_deteksi']:
        print(f"- {deteksi['hasil']} (Skor: {deteksi['skor']:.2f}, Prioritas: {deteksi['prioritas']})")
    
    print(f"\nRekomendasi:")
    for rekomendasi in hasil['rekomendasi']:
        print(f"- {rekomendasi}")