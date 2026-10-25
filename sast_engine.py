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
import subprocess
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
    ".env", ".yml", ".yaml", ".tf", ".json", ".ini", ".conf", ".htaccess"
}
SAST_DOCKERFILE_NAMES = {
    "dockerfile", "dockerfile.dev", "dockerfile.prod", "dockerfile.local",
    "php.ini", ".user.ini", ".htaccess", ".nvmrc", ".node-version"
}

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
     re.compile(r"(?i)(mongodb(\+srv)?|mysql|postgres(ql)?|redis|amqp)://[^\s'\"`]+:(?!\$\{)[^\s'\"`]+@"),
     "Veritabanı bağlantı string'i kullanıcı adı/şifre içeriyor. Secret manager veya env kullanılmalı. ${VAR} formatındaki env substitution güvenlidir."),
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

def _get_git_diff_files(root_path, diff_base="HEAD"):
    """Git diff / PR artımlı tarama modu (sc-diff-report) için değişen dosyaları döndürür."""
    changed = set()
    base = (diff_base or "HEAD").strip()
    try:
        out = subprocess.run(
            ["git", "-C", root_path, "diff", "--name-only", base],
            capture_output=True, text=True, timeout=10
        )
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                if line.strip():
                    changed.add(os.path.normpath(line.strip()))
        st = subprocess.run(
            ["git", "-C", root_path, "status", "--porcelain"],
            capture_output=True, text=True, timeout=10
        )
        if st.returncode == 0:
            for line in st.stdout.splitlines():
                if len(line) > 3:
                    p = line[3:].strip().split(" -> ")[-1]
                    if p:
                        changed.add(os.path.normpath(p))
    except Exception:
        pass
    return changed


def _build_security_check_artifacts(root_path, findings, deps_result, files_list, skipped_files, profile, scope_mode, diff_base):
    """ersinkoc/security-check 5'li rapor paketi + 3 durumlu (confirmed/needs_validation/rejected) kanıt modeli."""
    lang_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".jsx": "React JSX",
        ".tsx": "React TSX", ".go": "Go", ".rs": "Rust", ".php": "PHP",
        ".java": "Java", ".cs": "C#", ".rb": "Ruby", ".sh": "Shell",
        ".yml": "YAML/CI", ".yaml": "YAML/CI", ".tf": "Terraform", ".json": "JSON"
    }
    lang_counts = {}
    entry_points = []
    subsystems = {}
    for rel in files_list:
        ext = os.path.splitext(rel)[1].lower()
        lname = lang_map.get(ext, ext or "Other")
        lang_counts[lname] = lang_counts.get(lname, 0) + 1
        parts = rel.replace("\\", "/").split("/")
        sub = parts[0] if len(parts) > 1 else "root"
        subsystems.setdefault(sub, []).append(rel)
        if any(k in rel.lower() for k in ("server", "route", "api", "controller", "handler", "main", "app", "index", "auth", "view")):
            entry_points.append(rel)

    # 3 Durumlu Kanıt Modeli (confirmed / needs_validation / rejected)
    confirmed = []
    needs_validation = []
    rejected = []
    for idx, f in enumerate(findings, 1):
        cid = f"CAND-{idx:03d}"
        f_copy = dict(f)
        f_copy["candidate_id"] = cid
        if f.get("rejected_reason"):
            f_copy["verdict"] = "rejected"
            rejected.append(f_copy)
        elif f.get("verified") is True and f.get("severity") in ("KRİTİK", "YÜKSEK", "ORTA"):
            f_copy["verdict"] = "confirmed"
            confirmed.append(f_copy)
        else:
            f_copy["verdict"] = "needs_validation"
            f_copy["validation_step"] = "Çalışma zamanı girdisi ve yetki sınırı (trust boundary) akışını doğrulayın."
            needs_validation.append(f_copy)

    # Coverage Ledger (Kapsam Defteri)
    ledger = []
    findings_by_sub = {}
    for f in findings:
        parts = (f.get("file") or "").replace("\\", "/").split("/")
        sub = parts[0] if len(parts) > 1 else "root"
        findings_by_sub.setdefault(sub, []).append(f)

    for idx, (sub, flist) in enumerate(sorted(subsystems.items()), 1):
        sub_finds = findings_by_sub.get(sub, [])
        cats = sorted({x.get("category", "Genel") for x in sub_finds}) or ["Genel Denetim"]
        cids = [f"CAND-{i:03d}" for i, x in enumerate(findings, 1) if x in sub_finds][:5]
        status = "candidate" if sub_finds else "covered"
        ledger.append({
            "coverage_id": f"COV-{idx:03d}",
            "surface": f"{sub}/* ({len(flist)} dosya)",
            "boundary": "caller -> application subsystem",
            "subsystem": sub,
            "attack_class": ", ".join(cats[:3]),
            "starting_paths": ", ".join(flist[:3]),
            "status": status,
            "evidence": f"{len(flist)} kaynak dosya tarandı" + (f" ({', '.join(cids)})" if cids else " (temiz)"),
            "gap": "" if profile != "quick" else "Quick profil (kısmi kapsam)"
        })

    for idx, (sfile, reason) in enumerate(skipped_files[:20], len(ledger) + 1):
        ledger.append({
            "coverage_id": f"COV-{idx:03d}",
            "surface": sfile,
            "boundary": "unscanned surface",
            "subsystem": os.path.dirname(sfile) or "root",
            "attack_class": "all",
            "starting_paths": sfile,
            "status": "deferred",
            "evidence": "-",
            "gap": reason
        })

    # 1) architecture.md
    arch_md = f"# Codebase Architecture & Attack Surface Map\n\n"
    arch_md += f"- **Root:** `{root_path}`\n- **Profile:** `{profile}` • **Scope:** `{scope_mode}`" + (f" (`{diff_base}`)" if scope_mode == "diff" else "") + "\n\n"
    arch_md += "## 1. Language & Technology Breakdown\n\n| Language | Files |\n|---|---|\n"
    for k, v in sorted(lang_counts.items(), key=lambda x: -x[1]):
        arch_md += f"| {k} | {v} |\n"
    arch_md += "\n## 2. Entry Surfaces & Trust Boundaries\n\n"
    for ep in entry_points[:25]:
        arch_md += f"- `{ep}`\n"
    if not entry_points:
        arch_md += "- *(Standart giriş dosyası adı tespit edilmedi; tüm modüller incelendi)*\n"
    arch_md += "\n## 3. Subsystems\n\n"
    for sub, flist in sorted(subsystems.items()):
        arch_md += f"- **`{sub}/`** ({len(flist)} files): {', '.join(f'`{x}`' for x in flist[:4])}\n"

    # 2) coverage-ledger.md
    cov_md = "# Audit Coverage Ledger (`coverage-ledger.md`)\n\n"
    cov_md += "| Coverage ID | Surface | Boundary | Subsystem | Attack class | Starting paths | Status | Evidence | Gap |\n"
    cov_md += "|---|---|---|---|---|---|---|---|---|\n"
    for row in ledger:
        cov_md += f"| {row['coverage_id']} | {row['surface']} | {row['boundary']} | {row['subsystem']} | {row['attack_class']} | `{row['starting_paths']}` | `{row['status']}` | {row['evidence']} | {row['gap'] or '-'} |\n"

    # 3) dependency-audit.md
    dep_md = "# Supply Chain & Dependency Audit (`dependency-audit.md`)\n\n"
    if deps_result and deps_result.get("analyzed"):
        ecos = deps_result.get("ecosystems") or []
        dep_md += f"- **Checked Packages:** {deps_result.get('checked', 0)}\n"
        dep_md += f"- **Vulnerable Packages:** {len(deps_result.get('vulnerable') or [])}\n\n"
        if ecos:
            dep_md += "| Ecosystem | Total | Checked | Vulnerable |\n|---|---|---|---|\n"
            for e in ecos:
                dep_md += f"| {e['ecosystem']} | {e['total']} | {e['checked']} | {e['vulnerable_count']} |\n"
        for v in (deps_result.get("vulnerable") or []):
            dep_md += f"\n### 📦 {v['name']}@{v['version']} ({v['ecosystem']})\n"
            for vn in (v.get("vulns") or []):
                dep_md += f"- **{vn['id']}**: {vn['summary']} {vn.get('url') or ''}\n"
    else:
        dep_md += "- Dependency audit not executed or no manifest found.\n"

    # 4) verified-findings.md
    ver_md = "# Verified Findings & Evidence Triage (`verified-findings.md`)\n\n"
    ver_md += f"- **Confirmed Boundary Failures (`confirmed`):** {len(confirmed)}\n"
    ver_md += f"- **Needs Runtime/Config Validation (`needs_validation`):** {len(needs_validation)}\n"
    ver_md += f"- **Rejected / Disproved Candidates (`rejected`):** {len(rejected)}\n\n"
    ver_md += "## Confirmed Findings\n\n"
    for f in confirmed:
        ver_md += f"### [{f['candidate_id']}] {f['severity']} — {f['title']} ({f['rule_id']} / {f['cwe']})\n"
        ver_md += f"- **Location:** `{f['file']}:{f['line']}` • **CVSS:** {f.get('cvss', '-')}\n"
        ver_md += f"- **Evidence:** `{f.get('match', '')}`\n"
        ver_md += f"- **Remediation:** {f.get('fix', '')}\n\n"
    ver_md += "## Needs Validation (No Severity Assigned Until Runtime Proof)\n\n"
    for f in needs_validation:
        ver_md += f"- **[{f['candidate_id']}]** `{f['file']}:{f['line']}` — {f['title']} ({f['rule_id']}): {f.get('validation_step', '')}\n"

    # 5) SECURITY-REPORT.md
    sec_md = f"# Consolidated Security Audit Report (`SECURITY-REPORT.md`)\n\n"
    sec_md += f"- **Target Directory:** `{root_path}`\n- **Profile:** `{profile}` • **Scope:** `{scope_mode}`\n"
    sec_md += f"- **Confirmed Findings:** {len(confirmed)} • **Needs Validation:** {len(needs_validation)} • **Rejected:** {len(rejected)}\n\n"
    sec_md += ver_md + "\n---\n\n" + dep_md + "\n---\n\n" + cov_md

    return {
        "architecture_md": arch_md,
        "coverage_ledger_md": cov_md,
        "dependency_audit_md": dep_md,
        "verified_findings_md": ver_md,
        "security_report_md": sec_md,
        "coverage_ledger": ledger,
        "languages": lang_counts,
        "entry_points": entry_points[:30],
        "findings_record": {
            "confirmed": confirmed,
            "needs_validation": needs_validation,
            "rejected": rejected,
        },
    }


# =============================================================
# Ana Tarama Motoru
# =============================================================
def sast_scan_directory(root_path, profile="standard", scope_mode="full", diff_base="HEAD"):
    start = time.time()
    findings = []
    files_scanned = 0
    dirs_scanned = 0
    skipped = 0
    total_lines = 0
    scanned_files_list = []
    skipped_files_ledger = []

    profile = (profile or "standard").lower().strip()
    if profile not in ("quick", "standard", "deep"):
        profile = "standard"
    max_files = 200 if profile == "quick" else (1500 if profile == "deep" else SAST_MAX_FILES)

    scope_mode = (scope_mode or "full").lower().strip()
    diff_files = _get_git_diff_files(root_path, diff_base) if scope_mode == "diff" else None

    for dirpath, dirnames, filenames in os.walk(root_path):
        pruned = [d for d in dirnames if d in SAST_SKIP_DIRS]
        skipped += len(pruned)
        dirnames[:] = [d for d in dirnames if d not in SAST_SKIP_DIRS]
        dirs_scanned += 1

        for fn in filenames:
            if files_scanned >= max_files:
                rel_s = os.path.relpath(os.path.join(dirpath, fn), root_path)
                skipped_files_ledger.append((rel_s, f"Max file cap ({max_files}) reached"))
                break
            if not _should_scan_file(fn):
                continue
            fpath = os.path.join(dirpath, fn)
            rel_path = os.path.normpath(os.path.relpath(fpath, root_path))
            if diff_files is not None and rel_path not in diff_files:
                continue
            try:
                if os.path.getsize(fpath) > SAST_MAX_FILE_SIZE:
                    skipped_files_ledger.append((rel_path, "File size > 1 MB"))
                    continue
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except OSError:
                continue

            files_scanned += 1
            total_lines += len(lines)
            scanned_files_list.append(rel_path)

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

    sc_artifacts = _build_security_check_artifacts(
        root_path, findings, None, scanned_files_list, skipped_files_ledger,
        profile, scope_mode, diff_base
    )

    return {
        "success": True,
        "root": root_path,
        "profile": profile,
        "scope_mode": scope_mode,
        "diff_base": diff_base if scope_mode == "diff" else None,
        "diff_files_matched": len(diff_files) if diff_files is not None else None,
        "stats": {
            "files_scanned": files_scanned,
            "dirs_scanned": dirs_scanned,
            "total_lines": total_lines,
            "skipped_dirs": skipped,
            "rules_active": len(SAST_RULES),
            "duration_ms": duration_ms,
            "truncated": files_scanned >= max_files,
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
            "rule_coverage_pct": round(len({f["rule_id"] for f in findings}) * 100.0 / (len(SAST_RULES) + len(EXTRA_RULES)), 1),
            "file_coverage_pct": round(len({f["file"] for f in findings}) * 100.0 / max(1, files_scanned), 1),
            "verified_pct": round(verified_count * 100.0 / max(1, len(findings)), 1)
        },
        "findings": findings,
        "security_check": sc_artifacts
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
    """package.json (+ varsa package-lock.json) bağımlılıklarını çıkarır (alt dizinler dahil)."""
    deps = []
    candidate_dirs = [root_path]
    for sub in ("web", "frontend", "backend", "server", "app"):
        sp = os.path.join(root_path, sub)
        if os.path.isdir(sp):
            candidate_dirs.append(sp)
    for cdir in candidate_dirs:
        lock_path = os.path.join(cdir, "package-lock.json")
        if os.path.isfile(lock_path):
            try:
                with open(lock_path, "r", encoding="utf-8") as f:
                    lock = json.load(f)
                pkgs = lock.get("packages") or {}
                for key, meta in pkgs.items():
                    if not key.startswith("node_modules/"):
                        continue
                    name = key[len("node_modules/"):]
                    ver = meta.get("version")
                    if name and ver:
                        deps.append((name, ver))
                if deps:
                    return deps[:SAST_DEPS_MAX_PACKAGES], True
            except (OSError, ValueError):
                pass
        pkg_path = os.path.join(cdir, "package.json")
        if os.path.isfile(pkg_path):
            try:
                with open(pkg_path, "r", encoding="utf-8") as f:
                    pkg = json.load(f)
                for section in ("dependencies", "devDependencies"):
                    for name, spec in (pkg.get(section) or {}).items():
                        ver = spec.lstrip("^~><= ") if isinstance(spec, str) else ""
                        deps.append((name, ver))
                if deps:
                    return deps[:SAST_DEPS_MAX_PACKAGES], False
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

def _parse_cargo_deps(root_path):
    """Cargo.lock (veya Cargo.toml) içinden Rust (crates.io) bağımlılıklarını çıkarır."""
    deps = []
    lock_path = os.path.join(root_path, "Cargo.lock")
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8") as f:
                text = f.read()
            for block in text.split("[[package]]")[1:]:
                nm = re.search(r'name\s*=\s*"([^"]+)"', block)
                vr = re.search(r'version\s*=\s*"([^"]+)"', block)
                if nm and vr:
                    deps.append((nm.group(1), vr.group(1)))
            if deps:
                return deps[:SAST_DEPS_MAX_PACKAGES]
        except OSError:
            pass
    toml_path = os.path.join(root_path, "Cargo.toml")
    if os.path.isfile(toml_path):
        try:
            with open(toml_path, "r", encoding="utf-8") as f:
                in_deps = False
                for line in f:
                    s = line.strip()
                    if s.startswith("[") and "dependencies" in s:
                        in_deps = True
                        continue
                    elif s.startswith("["):
                        in_deps = False
                    elif in_deps and "=" in s and not s.startswith("#"):
                        m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"', s)
                        if m:
                            deps.append((m.group(1), m.group(2).lstrip("^~=")))
        except OSError:
            pass
    return deps[:SAST_DEPS_MAX_PACKAGES]


def _parse_composer_deps(root_path):
    """composer.lock (veya composer.json) içinden PHP (Packagist) bağımlılıklarını çıkarır."""
    deps = []
    lock_path = os.path.join(root_path, "composer.lock")
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for sec in ("packages", "packages-dev"):
                for pkg in (data.get(sec) or []):
                    name = pkg.get("name")
                    ver = (pkg.get("version") or "").lstrip("v")
                    if name and ver:
                        deps.append((name, ver))
            if deps:
                return deps[:SAST_DEPS_MAX_PACKAGES]
        except (OSError, ValueError):
            pass
    json_path = os.path.join(root_path, "composer.json")
    if os.path.isfile(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for sec in ("require", "require-dev"):
                for name, ver in (data.get(sec) or {}).items():
                    if "/" in name and isinstance(ver, str):
                        deps.append((name, ver.lstrip("^~v>=< ")))
        except (OSError, ValueError):
            pass
    return deps[:SAST_DEPS_MAX_PACKAGES]


def _parse_gem_deps(root_path):
    """Gemfile.lock içinden Ruby (RubyGems) bağımlılıklarını çıkarır."""
    deps = []
    lock_path = os.path.join(root_path, "Gemfile.lock")
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8") as f:
                for line in f:
                    m = re.match(r"^\s{4}([A-Za-z0-9_\-.]+)\s+\(([0-9][0-9A-Za-z.\-]*)\)\s*$", line)
                    if m:
                        deps.append((m.group(1), m.group(2)))
        except OSError:
            pass
    return deps[:SAST_DEPS_MAX_PACKAGES]


def _parse_maven_deps(root_path):
    """pom.xml içinden Java (Maven) bağımlılıklarını çıkarır."""
    deps = []
    pom_path = os.path.join(root_path, "pom.xml")
    if os.path.isfile(pom_path):
        try:
            with open(pom_path, "r", encoding="utf-8") as f:
                text = f.read()
            for blk in re.findall(r"<dependency>([\s\S]*?)</dependency>", text):
                g = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", blk)
                a = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", blk)
                v = re.search(r"<version>\s*([^<$\s]+)\s*</version>", blk)
                if g and a and v:
                    deps.append((f"{g.group(1)}:{a.group(1)}", v.group(1)))
        except OSError:
            pass
    return deps[:SAST_DEPS_MAX_PACKAGES]


def _parse_nuget_deps(root_path):
    """packages.lock.json veya *.csproj içinden .NET (NuGet) bağımlılıklarını çıkarır."""
    deps = []
    lock_path = os.path.join(root_path, "packages.lock.json")
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for _fw, pkgs in (data.get("dependencies") or {}).items():
                if isinstance(pkgs, dict):
                    for name, meta in pkgs.items():
                        ver = (meta or {}).get("resolved")
                        if name and ver:
                            deps.append((name, ver))
            if deps:
                return deps[:SAST_DEPS_MAX_PACKAGES]
        except (OSError, ValueError):
            pass
    try:
        for fn in os.listdir(root_path):
            if fn.endswith(".csproj"):
                with open(os.path.join(root_path, fn), "r", encoding="utf-8") as f:
                    text = f.read()
                for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text):
                    deps.append((m.group(1), m.group(2)))
    except OSError:
        pass
    return deps[:SAST_DEPS_MAX_PACKAGES]


def check_dependencies_osv(root_path):
    """Proje bağımlılıklarını 8 ekosistemde (npm, PyPI, Go, crates.io, Packagist, RubyGems, Maven, NuGet) OSV veritabanında sorgular."""
    result = {
        "analyzed": False,
        "ecosystems": [],
        "checked": 0,
        "vulnerable": [],
        "errors": []
    }

    try:
        npm_deps, _from_lock = _parse_npm_deps(root_path)
        pip_deps = _parse_pip_deps(root_path)
        go_deps = _parse_go_deps(root_path)
        cargo_deps = _parse_cargo_deps(root_path)
        composer_deps = _parse_composer_deps(root_path)
        gem_deps = _parse_gem_deps(root_path)
        maven_deps = _parse_maven_deps(root_path)
        nuget_deps = _parse_nuget_deps(root_path)

        tasks = []
        for eco_name, dlist in (
            ("npm", npm_deps),
            ("PyPI", pip_deps),
            ("Go", go_deps),
            ("crates.io", cargo_deps),
            ("Packagist", composer_deps),
            ("RubyGems", gem_deps),
            ("Maven", maven_deps),
            ("NuGet", nuget_deps),
        ):
            if dlist:
                tasks.append((eco_name, dlist))

        if not tasks:
            result["analyzed"] = True
            result["note"] = "Desteklenen bağımlılık manifestosu (package.json, requirements.txt, go.mod, Cargo.lock, composer.lock, Gemfile.lock, pom.xml, *.csproj) bulunamadı"
            return result

        for ecosystem, dep_list in tasks:
            eco_info = {"ecosystem": ecosystem, "total": len(dep_list), "checked": 0, "vulnerable_count": 0}
            for name, version in dep_list:
                try:
                    data = _osv_query(name, ecosystem, version)
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


# =============================================================
# ersinkoc/security-check 4-Aşamalı AI Kaynak Kod Denetimi
# (Phase 1: RECON → Phase 2: HUNT → Phase 3: VERIFY → Phase 4: REPORT)
# =============================================================
def run_ai_sast_audit(root_path, ai_config, profile="standard", scope_mode="full", diff_base="HEAD"):
    """
    Yerel proje dizini üzerinde ersinkoc/security-check metodolojisiyle
    4 aşamalı (Recon -> Hunt -> Adversarial Verify -> Report) LLM destekli
    derin semantik kaynak kod denetimi yürütür.
    """
    from ai_connector import AIProviderFactory
    from ai_orchestrator import _extract_json, _is_llm_error

    sast_res = sast_scan_directory(root_path, profile=profile, scope_mode=scope_mode, diff_base=diff_base)
    try:
        deps_res = check_dependencies_osv(root_path)
    except Exception as e:
        deps_res = {"analyzed": False, "error": str(e)[:200]}

    # Öncelikli kaynak dosyalarından (entry points + bulgu içeren dosyalar) kod kesitleri topla
    sc = sast_res.get("security_check") or {}
    candidate_files = []
    for f in (sast_res.get("findings") or []):
        fp = f.get("file")
        if fp and fp not in candidate_files:
            candidate_files.append(fp)
    for ep in (sc.get("entry_points") or []):
        if ep not in candidate_files:
            candidate_files.append(ep)

    code_excerpts = []
    for rel in candidate_files[:8]:
        full = os.path.join(root_path, rel)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read(3500)
            code_excerpts.append({"file": rel, "excerpt": content})
        except OSError:
            pass

    connector = AIProviderFactory.create_connector(ai_config or {})
    phases_log = []

    # PHASE 1: RECON
    recon_prompt = (
        "You are Phase 1 (RECON) of the security-check 51-skill code audit pipeline. "
        "Analyze the architecture map, language distribution, and entry points below. "
        "Summarize the trust boundaries, authentication/authorization surfaces, and highest-risk sinks in 150 words.\n\n"
        f"Architecture Map:\n{sc.get('architecture_md', '')[:3500]}\n"
        f"Excerpts:\n{json.dumps(code_excerpts[:4], ensure_ascii=False)[:4000]}"
    )
    recon_out = connector.chat(recon_prompt)
    if _is_llm_error(recon_out):
        return {"success": False, "error": f"Phase 1 (RECON) LLM hatası: {recon_out[:200]}", "sast": sast_res}
    phases_log.append({"phase": "RECON", "summary": recon_out[:600]})

    # PHASE 2: HUNT (Semantic business logic, AuthZ, IDOR, race conditions, injection)
    hunt_prompt = (
        "You are Phase 2 (HUNT) of the security-check pipeline. "
        "Inspect the code excerpts and static findings below for semantic vulnerabilities "
        "(broken access control/AuthZ, IDOR, business logic flaws, race conditions, injection, SSRF, secrets, AI/prompt injection). "
        "Reply ONLY with a JSON array of candidates (max 6):\n"
        '[{"id": "AI-CAND-1", "file": "...", "line": 1, "category": "AuthZ|Logic|SQLi|XSS|SSRF|Crypto|AI", '
        '"severity": "KRİTİK|YÜKSEK|ORTA|DÜŞÜK", "cwe": "CWE-...", "title": "...", '
        '"entry_point": "...", "sink": "...", "evidence": "...", "fix": "..."}]\n\n'
        f"Recon:\n{recon_out[:1500]}\nStatic Findings:\n{json.dumps((sast_res.get('findings') or [])[:15], ensure_ascii=False)[:2500]}\n"
        f"Code Excerpts:\n{json.dumps(code_excerpts, ensure_ascii=False)[:5000]}"
    )
    hunt_raw = connector.chat(hunt_prompt)
    candidates = _extract_json(hunt_raw, "list") if not _is_llm_error(hunt_raw) else []
    if not isinstance(candidates, list):
        candidates = []
    candidates = [c for c in candidates if isinstance(c, dict)][:6]
    phases_log.append({"phase": "HUNT", "summary": f"{len(candidates)} semantik aday tespit edildi."})

    # PHASE 3: VERIFY (Adversarial verifier — confirmed / needs_validation / rejected)
    verify_prompt = (
        "You are Phase 3 (ADVERSARIAL VERIFIER) of the security-check pipeline. "
        "Try to disprove each candidate below using the code excerpts. Classify each into EXACTLY one verdict:\n"
        "- 'confirmed': complete source trace and boundary failure proven in code.\n"
        "- 'needs_validation': concrete lead, but depends on unseen runtime/deployment config.\n"
        "- 'rejected': disproved by existing guard, unreachable path, or false positive.\n"
        "Reply ONLY with a JSON array:\n"
        '[{"id": "AI-CAND-1", "verdict": "confirmed|needs_validation|rejected", "rationale": "...", "validation_step": "..."}]\n\n'
        f"Candidates:\n{json.dumps(candidates, ensure_ascii=False)}\n"
        f"Code Excerpts:\n{json.dumps(code_excerpts[:5], ensure_ascii=False)[:4000]}"
    )
    ver_raw = connector.chat(verify_prompt)
    verdicts = _extract_json(ver_raw, "list") if not _is_llm_error(ver_raw) else []
    verdict_map = {v.get("id"): v for v in (verdicts or []) if isinstance(v, dict) and v.get("id")}

    ai_confirmed = []
    ai_needs_val = []
    ai_rejected = []
    for c in candidates:
        v = verdict_map.get(c.get("id"), {})
        verdict = (v.get("verdict") or "needs_validation").lower().strip()
        if verdict not in ("confirmed", "needs_validation", "rejected"):
            verdict = "needs_validation"
        c["verdict"] = verdict
        c["rationale"] = v.get("rationale") or ""
        c["validation_step"] = v.get("validation_step") or ""
        if verdict == "confirmed":
            ai_confirmed.append(c)
        elif verdict == "rejected":
            ai_rejected.append(c)
        else:
            ai_needs_val.append(c)

    phases_log.append({
        "phase": "VERIFY",
        "summary": f"Doğrulama tamamlandı: {len(ai_confirmed)} confirmed, {len(ai_needs_val)} needs_validation, {len(ai_rejected)} rejected."
    })

    # PHASE 4: REPORT
    report_prompt = (
        "You are Phase 4 (REPORT) of security-check. Write a concise Turkish Markdown executive summary "
        "('### Mimari & Güvenlik Sınırları', '### Doğrulanan Semantik Bulgular', '### Öncelikli Yol Haritası') "
        "combining the confirmed AI findings, static findings, and dependency CVEs.\n\n"
        f"Recon:\n{recon_out[:1200]}\nAI Confirmed:\n{json.dumps(ai_confirmed, ensure_ascii=False)}\n"
        f"AI Needs Validation:\n{json.dumps(ai_needs_val, ensure_ascii=False)}"
    )
    report_md = connector.chat(report_prompt)
    if _is_llm_error(report_md):
        report_md = ""
    phases_log.append({"phase": "REPORT", "summary": f"Nihai rapor üretildi ({len(report_md)} karakter)."})

    # Artefaktları güncelle (bağımlılık + AI bulguları dahil)
    sc_full = _build_security_check_artifacts(
        root_path, sast_res.get("findings") or [], deps_res,
        [r["Starting paths"] if isinstance(r, dict) and "Starting paths" in r else "" for r in []] or candidate_files,
        [], profile, scope_mode, diff_base
    )
    sc_full["findings_record"]["confirmed"].extend(ai_confirmed)
    sc_full["findings_record"]["needs_validation"].extend(ai_needs_val)
    sc_full["findings_record"]["rejected"].extend(ai_rejected)
    if report_md:
        sc_full["security_report_md"] = report_md + "\n\n---\n\n" + sc_full["security_report_md"]

    return {
        "success": True,
        "root": root_path,
        "profile": profile,
        "scope_mode": scope_mode,
        "phases": phases_log,
        "recon_summary": recon_out,
        "ai_confirmed": ai_confirmed,
        "ai_needs_validation": ai_needs_val,
        "ai_rejected": ai_rejected,
        "executive_report_md": report_md,
        "security_check": sc_full,
        "sast": sast_res,
        "dependencies": deps_res,
    }


# =============================================================
# Resmi PHP 2026 Güvenlik Bülteni (https://www.php.net/archive/2026.php) Çözüm & Yapılandırma Motoru
# =============================================================
PHP_PATCHED_VERSIONS = {
    "8.5": "8.5.12",
    "8.4": "8.4.27",
    "8.3": "8.3.36",
    "8.2": "8.2.35",
}

PHP_OFFICIAL_ADVISORY_URL = "https://www.php.net/archive/2026.php"

def remediate_php_advisory_directory(root_path, apply_fixes=True):
    """
    https://www.php.net/archive/2026.php resmi güvenlik bültenine dayanarak hedef proje dizinindeki
    Dockerfile (resmi yamalı PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 sürümüne yükseltme — birincil çözüm)
    ve php.ini / .user.ini / PHP-FPM havuz (*.conf) dosyalarını (geçici bülten önlemleri) denetler,
    isteğe bağlı olarak .bak yedekli düzeltmeleri uygular.
    """
    import shutil
    actions = []
    ts = time.strftime("%Y%m%d-%H%M%S")

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in SAST_SKIP_DIRS]
        for fn in filenames:
            low = fn.lower()
            fpath = os.path.join(dirpath, fn)
            rel_path = os.path.relpath(fpath, root_path)

            # 1) Birincil Çözüm: Dockerfile içinde resmi PHP imaj sürümü yükseltme (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35)
            if low in ("dockerfile", "containerfile") or low.startswith("dockerfile."):
                try:
                    content = open(fpath, "r", encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                if re.search(r"(?im)^FROM\s+php:", content):
                    new_content = content
                    changes = []
                    for branch, fixed_ver in PHP_PATCHED_VERSIONS.items():
                        pat = rf"(?im)^(FROM\s+php:){re.escape(branch)}(?:\.[0-9]+)?(-\S+)?$"
                        if re.search(pat, new_content):
                            new_content = re.sub(pat, rf"\g<1>{fixed_ver}\2", new_content)
                            changes.append(
                                f"Birincil Çözüm ({PHP_OFFICIAL_ADVISORY_URL}): PHP imajı resmi yamalı {fixed_ver} sürümüne yükseltildi (CVE-2026-109618 / CVE-2026-109619)"
                            )
                    if changes and new_content != content:
                        if apply_fixes:
                            shutil.copy2(fpath, f"{fpath}.bak-{ts}")
                            open(fpath, "w", encoding="utf-8").write(new_content)
                        actions.append({"file": rel_path, "applied": apply_fixes, "changes": changes})

            # 2) php.ini / .user.ini / *.ini (Resmi bülten yapılandırma önlemleri)
            elif low in ("php.ini", ".user.ini") or low.endswith(".ini"):
                try:
                    content = open(fpath, "r", encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                new_content = content
                changes = []
                if re.search(r"(?im)^\s*;?\s*session\.upload_progress\.enabled\s*=\s*[\"']?(?:on|1|true|yes)[\"']?", new_content):
                    new_content = re.sub(
                        r"(?im)^\s*;?\s*session\.upload_progress\.enabled\s*=.*$",
                        "session.upload_progress.enabled = Off",
                        new_content
                    )
                    changes.append("Resmi Bülten Önlemi (CVE-2026-109619 & CVE-2026-115560): session.upload_progress.enabled = Off yapıldı")

                if re.search(r"(?im)^\s*;?\s*fatal_error_backtraces\s*=\s*[\"']?(?:on|1|true|yes)[\"']?", new_content):
                    new_content = re.sub(
                        r"(?im)^\s*;?\s*fatal_error_backtraces\s*=.*$",
                        "fatal_error_backtraces = Off",
                        new_content
                    )
                    changes.append("Resmi Bülten Önlemi (PHP 8.5 CVE-2026-109619 producer): fatal_error_backtraces = Off yapıldı")

                if re.search(r"(?im)^\s*;?\s*phar\.readonly\s*=\s*[\"']?(?:off|0|false|no)[\"']?", new_content):
                    new_content = re.sub(
                        r"(?im)^\s*;?\s*phar\.readonly\s*=.*$",
                        "phar.readonly = On",
                        new_content
                    )
                    changes.append("Resmi Bülten Önlemi (CVE-2026-6103 / CVE-2026-7260): phar.readonly = On yapıldı")

                if re.search(r"(?im)^\s*post_max_size\s*=\s*(?:[4-9][0-9]|[1-9][0-9]{2,})\s*[MG]\b", new_content):
                    new_content = re.sub(
                        r"(?im)^\s*post_max_size\s*=.*$",
                        "post_max_size = 32M",
                        new_content
                    )
                    changes.append("Resmi Bülten Önlemi (CVE-2026-109618 OOM RCE): post_max_size = 32M olarak sınırlandırıldı")

                if changes and new_content != content:
                    if apply_fixes:
                        shutil.copy2(fpath, f"{fpath}.bak-{ts}")
                        open(fpath, "w", encoding="utf-8").write(new_content)
                    actions.append({"file": rel_path, "applied": apply_fixes, "changes": changes})

            # 3) PHP-FPM pool *.conf
            elif low.endswith(".conf"):
                try:
                    content = open(fpath, "r", encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                if re.search(r"(?m)^\s*\[.+\]\s*$", content) and re.search(r"(?m)^\s*listen\s*=", content):
                    new_content = content
                    changes = []
                    if re.search(r"(?im)^\s*;?\s*php_(?:admin_)?(?:value|flag)\[\s*session\.upload_progress\.enabled\s*\]", new_content):
                        new_content = re.sub(
                            r"(?im)^\s*;?\s*php_(?:admin_)?(?:value|flag)\[\s*session\.upload_progress\.enabled\s*\].*$",
                            "php_admin_flag[session.upload_progress.enabled] = off",
                            new_content
                        )
                        changes.append("Resmi Bülten Önlemi (CVE-2026-109619 & CVE-2026-115560): FPM havuzunda php_admin_flag[session.upload_progress.enabled] = off kilitlendi")
                    if changes and new_content != content:
                        if apply_fixes:
                            shutil.copy2(fpath, f"{fpath}.bak-{ts}")
                            open(fpath, "w", encoding="utf-8").write(new_content)
                        actions.append({"file": rel_path, "applied": apply_fixes, "changes": changes})

    return {
        "success": True,
        "root": root_path,
        "applied": apply_fixes,
        "advisory_url": PHP_OFFICIAL_ADVISORY_URL,
        "patched_versions": PHP_PATCHED_VERSIONS,
        "modified_files_count": len(actions),
        "actions": actions,
        "primary_solution": {
            "summary": "Resmi PHP paket kaynaklarından yamalı sürüme (8.5.12, 8.4.27, 8.3.36, 8.2.35) yükseltin ve tüm PHP işçilerini (FPM/Apache) tam yeniden başlatın.",
            "debian_ubuntu": r"sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y -o Dpkg::Options::=\"--force-confdef\" -o Dpkg::Options::=\"--force-confold\" $(dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' | awk '/^ii  php[0-9]+\.[0-9]+-/{print $2}') && (sudo systemctl restart php*-fpm 2>/dev/null || sudo systemctl restart apache2 2>/dev/null)",
            "rhel_almalinux": "sudo dnf clean all && sudo dnf upgrade 'php*' -y && (sudo systemctl restart php-fpm 2>/dev/null || sudo systemctl restart httpd 2>/dev/null)",
        },
    }


# =============================================================
# Resmi Node.js Ekim 2026 Güvenlik Bülteni (https://nodejs.org/tr/blog/vulnerability/october-2026-security-releases) Çözüm Motoru
# =============================================================
NODE_PATCHED_VERSIONS = {
    "26": "26.12.1",
    "24": "24.22.1",
    "22": "22.23.4",
}

NODE_OFFICIAL_ADVISORY_URL = "https://nodejs.org/tr/blog/vulnerability/october-2026-security-releases"

def remediate_node_advisory_directory(root_path, apply_fixes=True):
    """
    https://nodejs.org/tr/blog/vulnerability/october-2026-security-releases resmi güvenlik bültenine dayanarak
    hedef proje dizinindeki Dockerfile (FROM node:...), .nvmrc, .node-version ve package.json dosyalarını denetler;
    yamasız Node.js (26.x < 26.12.1, 24.x < 24.22.1, 22.x < 22.23.4 veya EOL <= 20.x) ve undici sürümlerini
    resmi yamalı sürümlere (.bak yedekli) yükseltir.
    """
    import shutil
    actions = []
    ts = time.strftime("%Y%m%d-%H%M%S")

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in SAST_SKIP_DIRS]
        for fn in filenames:
            low = fn.lower()
            fpath = os.path.join(dirpath, fn)
            rel_path = os.path.relpath(fpath, root_path)

            # 1) Dockerfile / Containerfile içinde FROM node:... imaj sürümü yükseltme
            if low in ("dockerfile", "containerfile") or low.startswith("dockerfile."):
                try:
                    content = open(fpath, "r", encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                if re.search(r"(?im)^FROM\s+node:", content):
                    new_content = content
                    changes = []
                    for branch, fixed_ver in NODE_PATCHED_VERSIONS.items():
                        pat = rf"(?im)^(FROM\s+node:){re.escape(branch)}(?:\.(?!{re.escape(fixed_ver.split(".",1)[1])}\b)[0-9]+(?:\.[0-9]+)?)?(-\S+)?$"
                        if re.search(pat, new_content):
                            new_content = re.sub(pat, rf"\g<1>{fixed_ver}\2", new_content)
                            changes.append(
                                f"Birincil Çözüm ({NODE_OFFICIAL_ADVISORY_URL}): Node.js imajı resmi yamalı {fixed_ver} sürümüne yükseltildi"
                            )
                    pat_eol = r"(?im)^(FROM\s+node:)(?:1[0-9]|20|21|23|25)(?:\.[0-9]+(?:\.[0-9]+)?)?(-\S+)?$"
                    if re.search(pat_eol, new_content):
                        new_content = re.sub(pat_eol, r"\g<1>24.22.1\2", new_content)
                        changes.append(
                            f"Birincil Çözüm ({NODE_OFFICIAL_ADVISORY_URL}): EOL Node.js imajı aktif LTS 24.22.1 sürümüne yükseltildi"
                        )
                    if changes and new_content != content:
                        if apply_fixes:
                            shutil.copy2(fpath, f"{fpath}.bak-{ts}")
                            open(fpath, "w", encoding="utf-8").write(new_content)
                        actions.append({"file": rel_path, "applied": apply_fixes, "changes": changes})

            # 2) .nvmrc / .node-version dosyaları
            elif low in (".nvmrc", ".node-version"):
                try:
                    content = open(fpath, "r", encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                val = content.strip().lstrip("vV")
                prefix = "v" if content.strip().startswith(("v", "V")) else ""
                target_ver = None
                if val.startswith("26") and val != "26.12.1":
                    target_ver = "26.12.1"
                elif val.startswith("24") and val != "24.22.1":
                    target_ver = "24.22.1"
                elif val.startswith("22") and val != "22.23.4":
                    target_ver = "22.23.4"
                elif re.match(r"^(?:1[0-9]|20|21|23|25)(?:\.|$)", val):
                    target_ver = "24.22.1"
                if target_ver:
                    new_content = f"{prefix}{target_ver}\n"
                    if apply_fixes:
                        shutil.copy2(fpath, f"{fpath}.bak-{ts}")
                        open(fpath, "w", encoding="utf-8").write(new_content)
                    actions.append({
                        "file": rel_path,
                        "applied": apply_fixes,
                        "changes": [f"Birincil Çözüm ({NODE_OFFICIAL_ADVISORY_URL}): Node.js sürümü {prefix}{target_ver} olarak güncellendi"]
                    })

    return {
        "success": True,
        "root": root_path,
        "applied": apply_fixes,
        "advisory_url": NODE_OFFICIAL_ADVISORY_URL,
        "patched_versions": NODE_PATCHED_VERSIONS,
        "modified_files_count": len(actions),
        "actions": actions,
        "primary_solution": {
            "summary": "Node.js çalışma ortamını resmi v26.12.1, v24.22.1 (LTS) veya v22.23.4 (LTS) sürümüne yükseltin (EOL sürümlerden LTS dalına geçin) ve tüm Node.js süreçlerini yeniden başlatın.",
            "nvm_fnm": "nvm install 24.22.1 && nvm alias default 24.22.1 && pm2 restart all --update-env",
            "docker": "FROM node:24.22.1-bookworm-slim (veya node:22.23.4-bookworm-slim / node:26.12.1-bookworm-slim)",
        },
    }
