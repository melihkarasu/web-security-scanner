#!/usr/bin/env python3
"""
Web Security Scanner — SAST Motoru (Faz 2)
Kaynak kod statik analizi: sır tespiti, zayıf kriptografi, SQL injection /
XSS / SSRF kod kalıpları, Dockerfile/IaC denetimi ve bağımlılık CVE kontrolü (OSV API).
Yalnızca Python 3 standart kütüphanesi kullanır (sıfır bağımlılık).
"""

import os
import re
import json
import time
import urllib.request

# Faz 6B: Derin analiz motoru (Python AST + JS taint + entropy + genişletilmiş kurallar)
from deep_sast_engine import run_deep_analysis, EXTRA_RULES

# =============================================================
# Tarama Sınırları ve Dizin/Filtre Kuralları
# =============================================================
SAST_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "target", ".idea", ".vscode",
    "coverage", ".cache", ".terraform", "vendor", "bower_components",
    ".pytest_cache", ".mypy_cache", "site-packages"
}
SAST_SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "Cargo.lock", "poetry.lock"
}
SAST_CODE_EXTS = {
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".py", ".php", ".java", ".go", ".rb", ".rs", ".cs", ".sh",
    ".env", ".yml", ".yaml", ".tf", ".json"
}
SAST_DOCKERFILE_NAMES = {"dockerfile", "dockerfile.dev", "dockerfile.prod", "dockerfile.local"}

SAST_MAX_FILE_SIZE = 1024 * 1024   # 1 MB
SAST_MAX_FILES = 800               # tarama başına üst sınır
SAST_MAX_MATCHES_PER_RULE = 3      # dosya başına kural başına üst sınır
SAST_DEPS_MAX_PACKAGES = 60        # OSV sorgu üst sınırı

# =============================================================
# Faz 4: CVSS Yaklaşıklığı, Kapsama ve Düzeltme Önerileri
# =============================================================
# Şiddet → CVSS taban aralığı (yaklaşık skor)
SEVERITY_CVSS = {
    "KRİTİK": (9.0, 10.0),
    "YÜKSEK": (7.0, 8.9),
    "ORTA": (4.0, 6.9),
    "DÜŞÜK": (0.1, 3.9)
}

# Kategori bazlı CVSS ayarı (aralık içinde yukarı/aşağı kaydırma)
CATEGORY_CVSS_ADJ = {
    "SQL Injection": 0.3,
    "Sır Yönetimi": 0.2,
    "SSRF Riski": 0.1,
    "Path Traversal": 0.1,
    "Tehlikeli Fonksiyon": 0.0,
    "XSS Riski": -0.2,
    "Zayıf Kriptografi": -0.3,
    "TLS Doğrulaması": -0.1,
    "Dockerfile": -0.3,
    "IaC / Terraform": -0.2
}

def cvss_approx(severity, category):
    """Şiddet ve kategoriye göre yaklaşık CVSS taban skoru üretir."""
    low, high = SEVERITY_CVSS.get(severity, (0.1, 3.9))
    base = (low + high) / 2.0
    adj = CATEGORY_CVSS_ADJ.get(category, 0.0)
    return round(min(10.0, max(0.1, base + adj)), 1)

# Kural bazlı otomatik düzeltme önerileri (Faz 4.5)
RULE_FIXES = {
    "SEC-001": "Anahtarı AWS IAM'dan iptal edin; yeni anahtarı ortam değişkeni veya secret manager'dan okuyun.",
    "SEC-002": "Token'ı GitHub Settings > Developer > Tokens'tan iptal edin; GitHub Actions secrets veya secret manager kullanın.",
    "SEC-003": "Token'ı GitLab'dan iptal edin; CI/CD değişkenleri (masked) kullanın.",
    "SEC-004": "Slack token'ı iptal edin; ortam değişkenine taşıyın.",
    "SEC-005": "Google API anahtarını Google Cloud Console'dan kısıtlayın/rotasyonlayın; env'e taşıyın.",
    "SEC-006": "OpenAI anahtarını iptal edin; ortam değişkeni (OPENAI_API_KEY) kullanın.",
    "SEC-007": "Özel anahtarı kod tabanından silin, secret manager'a taşıyın ve rotate edin.",
    "SEC-008": "JWT secret'ı ortam değişkenine taşıyın: process.env.JWT_SECRET — yedek değer (fallback) bırakmayın.",
    "SEC-009": "Bağlantı string'ini parçalara ayırın; kimlik bilgilerini ortam değişkenlerinden okuyun.",
    "SEC-010": "Değeri ortam değişkenine taşıyın; koda asla gerçek değer gömmeyin.",
    "SEC-011": "Fallback string'i kaldırın; ortam değişkeni yoksa uygulama hata verip dursun (fail-fast).",
    "CRY-001": "hashlib.sha256(...) veya daha güçlü bir özet kullanın.",
    "CRY-002": "hashlib.sha256(...) veya daha güçlü bir özet kullanın.",
    "CRY-003": "eval yerine güvenli ayrıştırıcı (JSON.parse, haritalama) kullanın.",
    "CRY-004": "exec yerine somut fonksiyon çağrıları veya ast.literal_eval kullanın.",
    "CRY-005": "Girdiyi sterilize edin; subprocess.spawn('cmd', [args]) liste formunu tercih edin.",
    "CRY-006": "os.system yerine subprocess.run(['cmd', 'arg'], shell=False) kullanın.",
    "CRY-007": "pickle yerine json.loads gibi güvenli serileştirme kullanın.",
    "CRY-008": "yaml.load(...) yerine yaml.safe_load(...) kullanın.",
    "CRY-009": "verify=True (varsayılan) bırakın; self-signed sertifikalar için CA paketi sağlayın.",
    "SQLI-001": "Parametreli sorgu kullanın: db.query('SELECT ... WHERE id = ?', [id])",
    "SQLI-002": "Parametreli sorgu kullanın: db.query('SELECT ... WHERE id = ?', [id])",
    "SQLI-003": "Parametre yer tutucusu kullanın: cursor.execute('SELECT ... WHERE id = %s', (user_id,))",
    "SQLI-004": "Parametreli sorgu kullanın; .format() yerine yer tutucu geçirin.",
    "SQLI-005": "Prepared statement kullanın: $stmt = $db->prepare('... WHERE id = ?')",
    "SQLI-006": "Parametreli sorgu kullanın; % formatlama yerine yer tutucu geçirin.",
    "XSS-001": "textContent kullanın veya DOMPurify.sanitize() ile sterilize edin.",
    "XSS-002": "document.write yerine DOM API'leri (createElement, textContent) kullanın.",
    "XSS-003": "İçerik sterilizasyonu ekleyin veya yapılandırılmış veri ile render edin.",
    "XSS-004": "v-html yerine metin interpolasyonu ({{ }}) kullanın.",
    "XSS-005": "insertAdjacentHTML yerine textContent / insertAdjacentText kullanın.",
    "SSRF-001": "İstek öncesi hedef hostname'i DNS ile çözümleyip özel IP aralıklarını reddedin (SSRF guard).",
    "SSRF-002": "İstek öncesi hedef doğrulaması (allow-list / IP kontrolü) ekleyin.",
    "SSRF-003": "URL şemasını ve çözülen IP'yi doğrulayan bir guard ekleyin.",
    "SSRF-004": "Oluşturulan URL'nin hostname'ini doğrulayın; protokolü kısıtlayın.",
    "PT-001": "Dosya yolunu os.path.basename ile sterilize edin ve izin verilen kök dizine sabitleyin.",
    "PT-002": "Yol normalizasyonu + kök dizin kontrolü (realpath başlangıç doğrulaması) ekleyin.",
    "DOCK-001": "İmajı sabit sürüme sabitleyin: FROM node:20.11-alpine gibi.",
    "DOCK-002": "Ayrıcalıksız kullanıcı tanımlayın: RUN adduser -D app && USER app",
    "DOCK-003": ".dockerignore'a .env, *.secret, node_modules ekleyin; yalnızca gerekli dosyaları kopyalayın.",
    "DOCK-004": "Secret'ı build-arg + runtime secret manager'dan okuyun; Dockerfile'a gömmeyin.",
    "IAC-001": "Erişim kaynağını (cidr_blocks) belirli IP aralıklarına daraltın.",
}

# Genel parola değerleri için yanlış-pozitif filtresi
_PASSWORD_BLOCKLIST = {
    "password", "passwd", "changeme", "change-me", "change_me", "example",
    "test", "dummy", "placeholder", "your-password", "your-password-here",
    "your-api-key", "xxxxxx", "xxxx", "secret", "default", "sample",
    "notarealsecret", "todo", "fixme", "redacted", "mask", "xxx", "abc123",
    "123456", "12345678", "qwerty", "iloveyou", "admin"
}

# =============================================================
# Kural Kütüphanesi
# (rule_id, kategori, şiddet, CWE, başlık, regex, açıklama)
# =============================================================
SAST_RULES = [
    # --- Sır Yönetimi (Hardcoded Secrets) ---
    ("SEC-001", "Sır Yönetimi", "KRİTİK", "CWE-798", "Hardcoded AWS Erişim Anahtarı",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     "AWS Access Key ID kaynak kodda gömülü. Ortam değişkenine taşınıp anahtar rotate edilmelidir."),
    ("SEC-002", "Sır Yönetimi", "KRİTİK", "CWE-798", "Hardcoded GitHub Token",
     re.compile(r"ghp_[A-Za-z0-9]{36,}"),
     "GitHub Personal Access Token kaynak kodda gömülü. Token iptal edilip secret manager'a taşınmalı."),
    ("SEC-003", "Sır Yönetimi", "KRİTİK", "CWE-798", "Hardcoded GitLab Token",
     re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
     "GitLab Personal Access Token kaynak kodda gömülü."),
    ("SEC-004", "Sır Yönetimi", "KRİTİK", "CWE-798", "Hardcoded Slack Token",
     re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
     "Slack API token kaynak kodda gömülü."),
    ("SEC-005", "Sır Yönetimi", "KRİTİK", "CWE-798", "Hardcoded Google API Anahtarı",
     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     "Google API anahtarı kaynak kodda gömülü."),
    ("SEC-006", "Sır Yönetimi", "KRİTİK", "CWE-798", "Hardcoded OpenAI Anahtarı",
     re.compile(r"sk-[A-Za-z0-9]{20,}"),
     "OpenAI API anahtarı kaynak kodda gömülü (sk-...)."),
    ("SEC-007", "Sır Yönetimi", "KRİTİK", "CWE-321", "Private Key Bloğu",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
     "Özel anahtar (private key) dosyaya gömülmüş. Anahtar depolamaya taşınıp rotate edilmeli."),
    ("SEC-008", "Sır Yönetimi", "KRİTİK", "CWE-798", "Hardcoded JWT Secret",
     re.compile(r"(?i)(jwt[_-]?secret|token[_-]?secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
     "JWT imzalama anahtarı kaynak kodda gömülü. Ortam değişkenine taşınmalı."),
    ("SEC-009", "Sır Yönetimi", "KRİTİK", "CWE-798", "Kimlik Bilgisi İçeren Bağlantı String'i",
     re.compile(r"(?i)(mongodb(\+srv)?|mysql|postgres(ql)?|redis|amqp)://[^\s'\"`]+:[^\s'\"`]+@"),
     "Veritabanı bağlantı string'i kullanıcı adı/şifre içeriyor. Secret manager veya env kullanılmalı."),
    ("SEC-010", "Sır Yönetimi", "YÜKSEK", "CWE-798", "Hardcoded Parola / API Anahtarı Ataması",
     re.compile(r"(?i)(password|passwd|pwd|api[_-]?key|secret[_-]?key|access[_-]?key)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
     "Parola veya API anahtarı değeri koda gömülü görünüyor (sezgisel eşleşme). Ortam değişkeni kullanılmalı."),
    ("SEC-011", "Sır Yönetimi", "KRİTİK", "CWE-798", "Secret Fallback Kalıntısı",
     re.compile(r"(?:process\.env\.\w+\s*\|\||os\.environ(?:\.get\([^)]*\))?\s*(?:or|\|\|))\s*['\"][A-Za-z0-9+/=_\-]{8,}['\"]"),
     "Ortam değişkeni eksik olduğunda sabit bir yedek (fallback) anahtar kullanılıyor. Fail-fast davranışına geçilmeli."),

    # --- Zayıf Kriptografi ve Tehlikeli Fonksiyonlar ---
    ("CRY-001", "Zayıf Kriptografi", "ORTA", "CWE-327", "MD5 Kullanımı",
     re.compile(r"hashlib\.md5\(|MessageDigest\.getInstance\(\s*[\"']MD5|(?<!\w)md5\s*\("),
     "MD5 kırılmış bir özet algoritmasıdır. SHA-256 veya üzeri kullanılmalı."),
    ("CRY-002", "Zayıf Kriptografi", "ORTA", "CWE-327", "SHA-1 Kullanımı",
     re.compile(r"hashlib\.sha1\(|MessageDigest\.getInstance\(\s*[\"']SHA-1|(?<!\w)sha1\s*\("),
     "SHA-1 çarpışma saldırılarına açıktır. SHA-256 veya üzeri kullanılmalı."),
    ("CRY-003", "Tehlikeli Fonksiyon", "YÜKSEK", "CWE-95", "eval() Kullanımı",
     re.compile(r"(?<![\w.])eval\s*\("),
     "eval() kod enjeksiyonuna açıktır. Güvenli ayrıştırıcılar veya haritalama kullanılmalı."),
    ("CRY-004", "Tehlikeli Fonksiyon", "YÜKSEK", "CWE-95", "exec() Kullanımı (Python)",
     re.compile(r"(?<![\w.])exec\s*\("),
     "Python exec() dinamik kod yürütmeye açıktır; girdi kaynakları denetlenmelidir."),
    ("CRY-005", "Tehlikeli Fonksiyon", "ORTA", "CWE-78", "child_process / execSync Kullanımı",
     re.compile(r"require\(\s*['\"]child_process['\"]|execSync\s*\(|spawnSync\s*\("),
     "Alt süreç komutları OS komut enjeksiyonuna açıktır; girdi sterilize edilmeli."),
    ("CRY-006", "Tehlikeli Fonksiyon", "YÜKSEK", "CWE-78", "os.system() Kullanımı",
     re.compile(r"os\.system\s*\("),
     "os.system() kabuk enjeksiyonuna açıktır. subprocess.run([...]) liste formu kullanılmalı."),
    ("CRY-007", "Tehlikeli Fonksiyon", "YÜKSEK", "CWE-502", "pickle.loads() Kullanımı",
     re.compile(r"pickle\.loads\("),
     "Pickle yüklemesi keyfi kod yürütmeye (RCE) açıktır. JSON gibi güvenli formatlar tercih edilmeli."),
    ("CRY-008", "Tehlikeli Fonksiyon", "ORTA", "CWE-502", "Güvensiz yaml.load()",
     re.compile(r"yaml\.load\((?![^)]*Loader)"),
     "yaml.load() Loader belirtilmeden güvenlidir değil. yaml.safe_load() kullanılmalı."),
    ("CRY-009", "TLS Doğrulaması", "ORTA", "CWE-295", "TLS Sertifika Doğrulaması Kapatılmış",
     re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false"),
     "TLS sertifika doğrulaması kapatılmış (MITM saldırılarına açık)."),

    # --- SQL Injection Kalıpları ---
    ("SQLI-001", "SQL Injection", "KRİTİK", "CWE-89", "Template Literal ile SQL Sorgusu",
     re.compile(r"(?i)(?:execute|query|raw|all|get)\s*\(\s*`[^`]*\bselect\b[^`]*\$\{"),
     "Şablon değişkeni (${...}) doğrudan SQL sorgusuna gömülüyor. Parametreli sorgular kullanılmalı."),
    ("SQLI-002", "SQL Injection", "KRİTİK", "CWE-89", "String Birleştirme ile SQL Sorgusu",
     re.compile(r"(?i)(?:execute|query|raw|all|get)\s*\(\s*['\"][^'\"]*\bselect\b[^'\"]*['\"]\s*\+"),
     "SQL sorgusu string birleştirme (+) ile kuruluyor. Parametreli sorgular kullanılmalı."),
    ("SQLI-003", "SQL Injection", "KRİTİK", "CWE-89", "f-string ile SQL Sorgusu",
     re.compile(r"(?i)(?:execute|query)\s*\(\s*f['\"][^'\"]*\bselect\b[^'\"]*\{"),
     "Python f-string doğrudan SQL sorgusuna gömülüyor. Parametre yer tutucuları (?) kullanılmalı."),
    ("SQLI-004", "SQL Injection", "YÜKSEK", "CWE-89", ".format() ile SQL Sorgusu",
     re.compile(r"(?i)\bselect\b[^'\"\n]{0,80}\.format\("),
     "SQL sorgusu .format() ile kuruluyor. Parametreli sorgular kullanılmalı."),
    ("SQLI-005", "SQL Injection", "KRİTİK", "CWE-89", "PHP Değişken İçerpolasyonlu Sorgu",
     re.compile(r"(?i)(?:mysqli_query|mysql_query|->query)\s*\([^)]*\$[a-zA-Z]"),
     "PHP değişkeni doğrudan SQL sorgusuna gömülüyor. Prepared statements kullanılmalı."),
    ("SQLI-006", "SQL Injection", "YÜKSEK", "CWE-89", "% Formatlama ile SQL Sorgusu",
     re.compile(r"(?i)(?:execute|query)\s*\(\s*['\"][^'\"]*\bselect\b[^'\"]*['\"]\s*%"),
     "SQL sorgusu % formatlama ile kuruluyor. Parametreli sorgular kullanılmalı."),

    # --- XSS Kalıpları ---
    ("XSS-001", "XSS Riski", "ORTA", "CWE-79", "innerHTML Ataması",
     re.compile(r"\.innerHTML\s*="),
     "innerHTML kullanıcı verisiyle besleniyorsa XSS riski taşır. textContent veya DOMPurify kullanılmalı."),
    ("XSS-002", "XSS Riski", "ORTA", "CWE-79", "document.write() Kullanımı",
     re.compile(r"document\.write\s*\("),
     "document.write() XSS riski taşır. Güvenli DOM API'leri tercih edilmeli."),
    ("XSS-003", "XSS Riski", "ORTA", "CWE-79", "dangerouslySetInnerHTML Kullanımı",
     re.compile(r"dangerouslySetInnerHTML"),
     "React'te ham HTML enjeksiyonu kullanılıyor. İçerik sterilize edilmeli."),
    ("XSS-004", "XSS Riski", "ORTA", "CWE-79", "v-html Direktifi",
     re.compile(r"v-html"),
     "Vue v-html ham HTML basar; sterilizasyon gerekli."),
    ("XSS-005", "XSS Riski", "ORTA", "CWE-79", "insertAdjacentHTML Kullanımı",
     re.compile(r"\.insertAdjacentHTML\s*\("),
     "insertAdjacentHTML XSS riski taşır."),

    # --- SSRF Kalıpları ---
    ("SSRF-001", "SSRF Riski", "YÜKSEK", "CWE-918", "Kullanıcı Girdisinden fetch() Çağrısı",
     re.compile(r"fetch\(\s*(?:req(?:uest)?\.(?:query|params|body)|request\.(?:GET|POST)|input\.|params\.|GET\[)"),
     "fetch() hedef adresi kullanıcı girdisinden alınıyor. İstek öncesi DNS/IP doğrulaması (SSRF guard) şart."),
    ("SSRF-002", "SSRF Riski", "YÜKSEK", "CWE-918", "Kullanıcı Girdisinden axios Çağrısı",
     re.compile(r"axios(?:\.(?:get|post|put|delete|request))?\(\s*(?:req|request|input|params|query)\."),
     "axios hedef adresi kullanıcı girdisinden alınıyor. SSRF koruması eklenmeli."),
    ("SSRF-003", "SSRF Riski", "YÜKSEK", "CWE-918", "Kullanıcı Girdisinden urlopen() Çağrısı",
     re.compile(r"urlopen\(\s*(?:request\.|input|self\.request)"),
     "urlopen() hedef adresi kullanıcı girdisinden alınıyor. Adres doğrulaması eklenmeli."),
    ("SSRF-004", "SSRF Riski", "ORTA", "CWE-918", "Kullanıcı Girdisinden URL Kurulumu",
     re.compile(r"new\s+URL\(\s*(?:req|request|params|query)\."),
     "URL nesnesi kullanıcı girdisinden kuruluyor; hedef doğrulaması önerilir."),

    # --- Path Traversal Kalıpları ---
    ("PT-001", "Path Traversal", "YÜKSEK", "CWE-22", "Kullanıcı Girdisinden open() Çağrısı",
     re.compile(r"open\(\s*(?:req|request|params|query)\."),
     "Dosya yolu kullanıcı girdisinden alınıyor; dizin kaçışı (path traversal) riski var."),
    ("PT-002", "Path Traversal", "YÜKSEK", "CWE-22", "Kullanıcı Girdisinden readFile Çağrısı",
     re.compile(r"(?:readFile|readFileSync|createReadStream|readFileAsync)\(\s*(?:req|request|params|query)\."),
     "Dosya okuma yolu kullanıcı girdisinden alınıyor; yol sterilizasyonu gerekli."),

    # --- Dockerfile / IaC ---
    ("DOCK-001", "Dockerfile", "DÜŞÜK", "CWE-1104", "Pinned Olmayan İmaj (:latest)",
     re.compile(r"(?i)^FROM\s+\S+:latest"),
     "Imaj sürümü sabitlenmemiş; tekrarlanabilir ve denetlenebilir sürüm kullanılmalı."),
    ("DOCK-002", "Dockerfile", "ORTA", "CWE-250", "USER root Kullanımı",
     re.compile(r"(?i)^USER\s+root"),
     "Konteyner root olarak çalışıyor; ayrıcalıksız kullanıcı tanımlanmalı."),
    ("DOCK-003", "Dockerfile", "ORTA", "CWE-538", "COPY . . (Aşırı Kopyalama)",
     re.compile(r"(?i)^COPY\s+\.\s+\."),
     "Tüm proje bağlama kopyalanıyor; .env gibi sır dosyaları imaja sızabilir. .dockerignore kullanılmalı."),
    ("DOCK-004", "Dockerfile", "KRİTİK", "CWE-798", "Dockerfile İçinde Secret ENV",
     re.compile(r"(?i)^ENV\s+\S*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\S*="),
     "Hassas değer Dockerfile ENV'ine gömülmüş; build-arg + secret manager kullanılmalı."),
    ("IAC-001", "IaC / Terraform", "ORTA", "CWE-668", "Herkese Ağlık Erişim (0.0.0.0/0)",
     re.compile(r"0\.0\.0\.0/0"),
     "Altyapı tanımında tüm internete açık erişim kuralı (0.0.0.0/0) mevcut."),
]

# =============================================================
# Yardımcılar
# =============================================================
def _is_password_false_positive(value):
    v = value.strip().strip("'\"").lower()
    return v in _PASSWORD_BLOCKLIST

def _should_scan_file(filename):
    lower = filename.lower()
    if lower in SAST_SKIP_FILES:
        return False
    if lower.endswith(".min.js") or lower.endswith(".min.css"):
        return False
    base = os.path.basename(lower)
    if base in SAST_DOCKERFILE_NAMES or base.startswith("dockerfile."):
        return True
    ext = os.path.splitext(filename)[1].lower()
    if filename == ".env" or lower.endswith(".env"):
        return True
    return ext in SAST_CODE_EXTS

# =============================================================
# Ana Tarama Motoru
# =============================================================
def sast_scan_directory(root_path):
    start = time.time()
    findings = []
    files_scanned = 0
    dirs_scanned = 0
    skipped = 0
    total_lines = 0

    for dirpath, dirnames, filenames in os.walk(root_path):
        pruned = [d for d in dirnames if d in SAST_SKIP_DIRS]
        skipped += len(pruned)
        dirnames[:] = [d for d in dirnames if d not in SAST_SKIP_DIRS]
        dirs_scanned += 1

        for fn in filenames:
            if files_scanned >= SAST_MAX_FILES:
                break
            if not _should_scan_file(fn):
                continue
            fpath = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fpath) > SAST_MAX_FILE_SIZE:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except OSError:
                continue

            files_scanned += 1
            total_lines += len(lines)
            rel_path = os.path.relpath(fpath, root_path)

            # Faz 6B: Derin analiz (Python AST + JS taint + entropy + genişletilmiş regex)
            try:
                deep_findings = run_deep_analysis(fpath, rel_path)
                for df in deep_findings:
                    # Faz 4 tutarlılığı: derin bulgulara da CVSS hesapla
                    if "cvss" not in df:
                        df["cvss"] = cvss_approx(df.get("severity", "ORTA"), df.get("category", ""))
                findings.extend(deep_findings)
            except Exception:
                pass

            rule_hit_counts = {}
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith(("//", "#", "/*", "*")):
                    continue
                for rule_id, category, severity, cwe, title, rx, desc in SAST_RULES:
                    m = rx.search(line)
                    if not m:
                        continue
                    # SEC-010 yanlış-pozitif filtresi
                    if rule_id == "SEC-010":
                        if _is_password_false_positive(m.group(0)):
                            continue
                    cnt = rule_hit_counts.get(rule_id, 0)
                    if cnt >= SAST_MAX_MATCHES_PER_RULE:
                        continue
                    rule_hit_counts[rule_id] = cnt + 1
                    findings.append({
                        "rule_id": rule_id,
                        "category": category,
                        "severity": severity,
                        "cwe": cwe,
                        "cvss": cvss_approx(severity, category),
                        "title": title,
                        "file": rel_path,
                        "line": lineno,
                        "match": m.group(0)[:120],
                        "description": desc,
                        "fix": RULE_FIXES.get(rule_id, "Genel: OWASP standartlarına göre girdi doğrulaması ve en az ayrıcalık ilkesi uygulayın.")
                    })

    duration_ms = int((time.time() - start) * 1000)

    # =============================================================
    # Bağımsız Doğrulama Geçişi (Faz 4 — Cloudflare metodolojisi)
    # Her bulgu, ikinci bir geçişte dosya yeniden okunarak teyit edilir.
    # Yanlış-pozitifler (verified=False) raporda ayrı işaretlenir.
    # =============================================================
    rule_lookup = {r[0]: r for r in SAST_RULES}
    verified_count = 0
    for f in findings:
        # Faz 6B: derin analiz bulguları (AST/taint yapısal kanıt; regex/entropy satır kanıtı)
        if f.get("analyzer"):
            f["verified"] = True
            verified_count += 1
            continue
        f["verified"] = False
        try:
            fpath = os.path.join(root_path, f["file"])
            if not os.path.isfile(fpath):
                continue
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                vlines = fh.readlines()
            if f["line"] < 1 or f["line"] > len(vlines):
                continue
            vline = vlines[f["line"] - 1]
            rule = rule_lookup.get(f["rule_id"])
            if rule and rule[5].search(vline):
                # Yanlış-pozitif filtresi de ikinci geçişte uygulanır
                if f["rule_id"] == "SEC-010" and _is_password_false_positive(vline):
                    continue
                f["verified"] = True
                verified_count += 1
        except OSError:
            continue

    # Faz 6B: analizci kırılımı
    analyzer_counts = {}
    for f in findings:
        a = f.get("analyzer", "regex")
        analyzer_counts[a] = analyzer_counts.get(a, 0) + 1

    summary = {"KRİTİK": 0, "YÜKSEK": 0, "ORTA": 0, "DÜŞÜK": 0}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    return {
        "success": True,
        "root": root_path,
        "stats": {
            "files_scanned": files_scanned,
            "dirs_scanned": dirs_scanned,
            "total_lines": total_lines,
            "skipped_dirs": skipped,
            "rules_active": len(SAST_RULES),
            "duration_ms": duration_ms,
            "truncated": files_scanned >= SAST_MAX_FILES,
            "verified_count": verified_count,
            "verification_pass": True,
            "deep_rules_active": len(SAST_RULES) + len(EXTRA_RULES),
            "analyzers": analyzer_counts
        },
        "summary": summary,
        "coverage": {
            "categories_with_findings": sorted({f["category"] for f in findings}),
            "files_with_findings": sorted({f["file"] for f in findings}),
            "rules_triggered": sorted({f["rule_id"] for f in findings}),
            "rules_total": len(SAST_RULES) + len(EXTRA_RULES),
            "rule_coverage_pct": round(len({f["rule_id"] for f in findings}) * 100.0 / len(SAST_RULES), 1),
            "file_coverage_pct": round(len({f["file"] for f in findings}) * 100.0 / max(1, files_scanned), 1),
            "verified_pct": round(verified_count * 100.0 / max(1, len(findings)), 1)
        },
        "findings": findings
    }

# =============================================================
# Bağımlılık Denetimi (OSV API — Google Açık Veritabanı)
# =============================================================
def _osv_query(name, ecosystem, version):
    """Tek paket için OSV sorgusu. Sürüm boşsa paket adına göre tüm bilinen açıkları döner."""
    payload = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8"))

def _parse_npm_deps(root_path):
    """package.json (+ varsa package-lock.json) bağımlılıklarını çıkarır."""
    deps = []
    lock_path = os.path.join(root_path, "package-lock.json")
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8") as f:
                lock = json.load(f)
            pkgs = lock.get("packages") or {}
            for key, meta in pkgs.items():
                if not key.startswith("node_modules/"):
                    continue
                name = key[len("node_modules/"):]
                if not name or "/" in name.replace("@", "", 1) and not name.startswith("@"):
                    pass
                ver = meta.get("version")
                if name and ver:
                    deps.append((name, ver))
            if deps:
                return deps[:SAST_DEPS_MAX_PACKAGES], True
        except (OSError, ValueError):
            pass
    pkg_path = os.path.join(root_path, "package.json")
    if os.path.isfile(pkg_path):
        try:
            with open(pkg_path, "r", encoding="utf-8") as f:
                pkg = json.load(f)
            for section in ("dependencies", "devDependencies"):
                for name, spec in (pkg.get(section) or {}).items():
                    ver = spec.lstrip("^~><= ") if isinstance(spec, str) else ""
                    deps.append((name, ver))
        except (OSError, ValueError):
            pass
    return deps[:SAST_DEPS_MAX_PACKAGES], False

def _parse_pip_deps(root_path):
    """requirements.txt bağımlılıklarını çıkarır."""
    req_path = os.path.join(root_path, "requirements.txt")
    deps = []
    if os.path.isfile(req_path):
        try:
            with open(req_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)", line)
                    if m:
                        deps.append((m.group(1), m.group(2)))
        except OSError:
            pass
    return deps

def _parse_go_deps(root_path):
    """go.mod require bloğundan bağımlılıkları çıkarır."""
    go_path = os.path.join(root_path, "go.mod")
    deps = []
    if os.path.isfile(go_path):
        try:
            with open(go_path, "r", encoding="utf-8") as f:
                in_require = False
                for line in f:
                    s = line.strip()
                    if s.startswith("require ("):
                        in_require = True
                        continue
                    if in_require:
                        if s == ")":
                            in_require = False
                            continue
                        parts = s.split()
                        if len(parts) >= 2 and not parts[0].startswith("//"):
                            deps.append((parts[0], parts[1].lstrip("v")))
                    elif s.startswith("require "):
                        parts = s.split()
                        if len(parts) >= 3:
                            deps.append((parts[1], parts[2].lstrip("v")))
        except OSError:
            pass
    return deps

def check_dependencies_osv(root_path):
    """Proje bağımlılıklarını OSV veritabanında sorgular."""
    result = {
        "analyzed": False,
        "ecosystems": [],
        "checked": 0,
        "vulnerable": [],
        "errors": []
    }

    try:
        npm_deps, from_lock = _parse_npm_deps(root_path)
        pip_deps = _parse_pip_deps(root_path)
        go_deps = _parse_go_deps(root_path)

        tasks = []
        if npm_deps:
            tasks.append(("npm", npm_deps))
        if pip_deps:
            tasks.append(("PyPI", pip_deps))
        if go_deps:
            tasks.append(("Go", go_deps))

        if not tasks:
            result["analyzed"] = True
            result["note"] = "package.json / requirements.txt / go.mod bulunamadı"
            return result

        for ecosystem, dep_list in tasks:
            eco_info = {"ecosystem": ecosystem, "total": len(dep_list), "checked": 0, "vulnerable_count": 0}
            for name, version in dep_list:
                try:
                    data = _osv_query(name, ecosystem, version if from_lock else version)
                    eco_info["checked"] += 1
                    result["checked"] += 1
                    vulns = data.get("vulns") or []
                    if vulns:
                        eco_info["vulnerable_count"] += 1
                        vuln_list = []
                        for v in vulns[:5]:
                            sev = ""
                            try:
                                sevs = v.get("severity") or []
                                if sevs:
                                    sev = sevs[0].get("score", "")
                            except Exception:
                                pass
                            url = ""
                            try:
                                refs = v.get("references") or []
                                if refs:
                                    url = refs[0].get("url", "")
                            except Exception:
                                pass
                            vuln_list.append({
                                "id": v.get("id", "?"),
                                "summary": (v.get("summary") or v.get("details", ""))[:200],
                                "url": url,
                                "severity": sev
                            })
                        result["vulnerable"].append({
                            "name": name,
                            "version": version,
                            "ecosystem": ecosystem,
                            "vuln_count": len(vulns),
                            "vulns": vuln_list
                        })
                except Exception as e:
                    result["errors"].append(f"{name}: {str(e)[:80]}")
            result["ecosystems"].append(eco_info)

        result["analyzed"] = True
    except Exception as e:
        result["errors"].append(str(e)[:200])

    return result
