from flask import Flask, render_template, request, jsonify
import traceback
from datetime import datetime

# Import sistem pakar yang telah ditingkatkan
from expert_system import BasisPengetahuanPhishing, MesinInferensiPhishing

app = Flask(__name__)

# Inisialisasi Sistem Pakar
kb = BasisPengetahuanPhishing()
engine = MesinInferensiPhishing(kb)
@app.route('/')
def index():
    return render_template('index.html',time=datetime.now())

@app.route('/detect', methods=['POST'])
def detect_phishing():
    try:
        # Mengambil input dari form
        input_url = request.form.get('url', '').strip()
        input_konten_pesan = request.form.get('message_content', '').strip()
        
        # Validasi input
        if not input_url and not input_konten_pesan:
            return render_template('index.html', 
                                 error="Masukkan URL atau konten pesan untuk dianalisis")
        
        # Input data untuk mesin inferensi advanced
        data_input = {
            "url": input_url,
            "konten_email": input_konten_pesan,
            "tata_bahasa_buruk": detect_bad_grammar(input_konten_pesan),
            "domain_tidak_dikenal": True  # Default assumption
        }
        
        # Menjalankan mesin inferensi advanced
        hasil_inferensi = engine.jalankan_inferensi_advanced(data_input)
        
        # Format hasil untuk tampilan
        formatted_results = format_results_for_display(hasil_inferensi)
        
        return render_template('index.html',
                             input_url=input_url,
                             input_konten=input_konten_pesan,
                             hasil_deteksi=formatted_results['hasil_deteksi'],
                             probabilitas=formatted_results['probabilitas'],
                             level_risiko=formatted_results['level_risiko'],
                             confidence_score=formatted_results['confidence_score'],
                             aturan_terpenuhi=formatted_results['aturan_terpenuhi'],
                             total_aturan=formatted_results['total_aturan'],
                             fakta_terdeteksi=formatted_results['fakta_terdeteksi'],
                             rekomendasi=formatted_results['rekomendasi'],
                             timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                             time=datetime.now())
    
    except Exception as e:
        error_msg = f"Terjadi kesalahan dalam analisis: {str(e)}"
        print(f"Error: {error_msg}")
        print(traceback.format_exc())
        return render_template('index.html', error=error_msg)

@app.route('/api/detect', methods=['POST'])
def api_detect_phishing():
    """API endpoint untuk deteksi phishing"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        input_url = data.get('url', '').strip()
        input_konten_pesan = data.get('message_content', '').strip()
        
        if not input_url and not input_konten_pesan:
            return jsonify({"error": "URL or message content is required"}), 400
        
        # Input data untuk mesin inferensi
        data_input = {
            "url": input_url,
            "konten_email": input_konten_pesan,
            "tata_bahasa_buruk": detect_bad_grammar(input_konten_pesan),
            "domain_tidak_dikenal": True
        }
        
        # Menjalankan mesin inferensi
        hasil_inferensi = engine.jalankan_inferensi_advanced(data_input)
        
        # Return JSON response
        return jsonify({
            "status": "success",
            "results": hasil_inferensi,
            "timestamp": datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

def detect_bad_grammar(text):
    """Deteksi tata bahasa buruk sederhana"""
    if not text:
        return False
    
    # Indikator tata bahasa buruk (dapat diperluas)
    bad_grammar_indicators = [
        "mohon" not in text.lower() and "urgent" in text.lower(),
        text.count("!") > 3,
        "segera" in text.lower() and "sekarang" in text.lower(),
        len([word for word in text.split() if word.isupper()]) > 2
    ]
    
    return sum(bad_grammar_indicators) >= 2

def format_results_for_display(hasil_inferensi):
    """Format hasil inferensi untuk tampilan web"""
    return {
        'hasil_deteksi': hasil_inferensi.get('hasil_deteksi', []),
        'probabilitas': round(hasil_inferensi.get('probabilitas_phishing', 0), 2),
        'level_risiko': hasil_inferensi.get('level_risiko', 'UNKNOWN'),
        'confidence_score': round(hasil_inferensi.get('confidence_score', 0), 2),
        'aturan_terpenuhi': hasil_inferensi.get('aturan_terpenuhi', 0),
        'total_aturan': hasil_inferensi.get('total_aturan', 0),
        'fakta_terdeteksi': hasil_inferensi.get('fakta_terdeteksi', []),
        'rekomendasi': hasil_inferensi.get('rekomendasi', [])
    }


# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)