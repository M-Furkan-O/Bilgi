from flask import Flask, render_template, request, jsonify
import random

app = Flask(__name__)

# Merkezi Veritabanı Simülasyonu (Policy Engine için)
USERS = {
    'admin': {'id': 'admin', 'name': 'Ahmet Yılmaz', 'role': 'Sistem Yöneticisi', 'clearance': 'L3', 'mfa': True, 'device': 'şirket', 'location': 'ofis', 'tags': ['yönetici', 'MFA', 'şirket cihazı']},
    'dev': {'id': 'dev', 'name': 'Büşra Kaya', 'role': 'Yazılım Geliştirici', 'clearance': 'L2', 'mfa': True, 'device': 'şirket', 'location': 'uzak', 'tags': ['geliştirici', 'MFA', 'uzaktan']},
    'intern': {'id': 'intern', 'name': 'Can Demir', 'role': 'Stajyer', 'clearance': 'L1', 'mfa': False, 'device': 'kişisel', 'location': 'ofis', 'tags': ['stajyer', 'kişisel cihaz']},
    'attacker': {'id': 'attacker', 'name': 'Bilinmeyen Kullanıcı', 'role': 'Doğrulanmamış', 'clearance': 'none', 'mfa': False, 'device': 'yabancı', 'location': 'harici', 'tags': ['tanımsız', 'şüpheli', 'harici']},
}

SERVICES = {
    'dashboard': {'id': 'dashboard', 'name': 'Dashboard', 'icon': 'ti-layout-dashboard', 'level': 'L1', 'mfa_req': False, 'desc': 'Temel panel'},
    'devtools': {'id': 'devtools', 'name': 'Dev Araçları', 'icon': 'ti-code', 'level': 'L2', 'mfa_req': True, 'desc': 'Geliştirme ortamı'},
    'database': {'id': 'database', 'name': 'Veritabanı', 'icon': 'ti-database', 'level': 'L2', 'mfa_req': True, 'desc': 'Üretim DB'},
    'adminpanel': {'id': 'adminpanel', 'name': 'Admin Panel', 'icon': 'ti-settings', 'level': 'L3', 'mfa_req': True, 'desc': 'Sistem yönetimi'},
    'ci': {'id': 'ci', 'name': 'CI/CD Pipeline', 'icon': 'ti-git-merge', 'level': 'L2', 'mfa_req': True, 'desc': 'Dağıtım hattı'},
    'logs': {'id': 'logs', 'name': 'Güvenlik Logları', 'icon': 'ti-file-text', 'level': 'L3', 'mfa_req': True, 'desc': 'Denetim kayıtları'},
}

# Geçici MFA oturumlarını tutacağımız sözlük
mfa_sessions = {}

def get_level(level_str):
    if level_str == 'none': return 0
    return int(level_str.replace('L', ''))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/init', methods=['GET'])
def init_data():
    return jsonify({'users': list(USERS.values()), 'services': list(SERVICES.values())})

@app.route('/api/evaluate', methods=['POST'])
def evaluate_access():
    data = request.json
    user_id = data.get('userId')
    service_id = data.get('serviceId')

    user = USERS.get(user_id)
    service = SERVICES.get(service_id)

    if not user or not service:
        return jsonify({'ok': False, 'reason': 'Geçersiz istek', 'status': 'deny'})

    # Zero Trust Politika Kuralları (Kesinlikle Sunucu Tarafında Kontrol Edilmeli)
    if user['clearance'] == 'none':
        return jsonify({'ok': False, 'reason': 'Kimlik doğrulanamadı', 'status': 'deny'})
    
    if get_level(user['clearance']) < get_level(service['level']):
        return jsonify({'ok': False, 'reason': f"Yetki seviyesi yetersiz ({user['clearance']} < {service['level']})", 'status': 'deny'})
    
    if user['device'] == 'yabancı':
        return jsonify({'ok': False, 'reason': 'Kayıtsız cihaz reddedildi', 'status': 'deny'})

    # MFA Kontrolü
    if service['mfa_req']:
        if not user['mfa']:
            return jsonify({'ok': False, 'reason': 'MFA gerekli ama kullanıcıda kayıtlı değil', 'status': 'deny'})
        
        # Sunucuda dinamik MFA kodu üret
        code = str(random.randint(100000, 999999))
        mfa_sessions[user_id] = code
        return jsonify({'ok': True, 'mfa_required': True, 'mfa_code': code})

    # Her şey tamamsa erişim ver
    return jsonify({'ok': True, 'mfa_required': False, 'status': 'allow'})

@app.route('/api/verify_mfa', methods=['POST'])
def verify_mfa():
    data = request.json
    user_id = data.get('userId')
    code = data.get('code')

    # Sunucuda saklanan kod ile frontend'den gelen kodu karşılaştır
    if mfa_sessions.get(user_id) == code:
        del mfa_sessions[user_id] 
        return jsonify({'ok': True, 'status': 'allow'})
    
    return jsonify({'ok': False, 'reason': 'Yanlış MFA kodu', 'status': 'deny'})

if __name__ == '__main__':
    app.run(debug=True)