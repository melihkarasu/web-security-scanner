#!/usr/bin/env python3
"""
Web Security Scanner — Derin SAST Motoru (Faz 6B)
Regex üstü derin analiz katmanı:
1. Python AST analizi (stdlib `ast`): eval/exec/pickle/SQL veri akışı takibi
2. JS bağlam-farkında taint analizi: kaynak → sink eşleştirme (çok satırlı)
3. Shannon entropy tabanlı secret tespiti (bilinmeyen formatlı anahtarlar)
4. Genişletilmiş kural seti: deserialization, JWT, CORS, K8s, GraphQL, crypto

Yalnızca Python 3 standart kütüphanesi kullanır.
"""

import os
import re
import ast
import math
import json

# =============================================================
# 1. PYTHON AST ANALİZ MOTORU
# Gerçek sözdizimi ağacı üzerinden veri akışı takibi.
# Regex'in yanlış-pozitiflerini eler; gerçek çağrı zincirlerini bulur.
# =============================================================

# Tehlikeli Python çağrıları (fonksiyon adı → bulgu şablonu)
PY_DANGEROUS_CALLS = {
    "eval": ("CRY-AST-001", "YÜKSEK", "CWE-95", "eval() çağrısı (AST doğrulandı)",
             "eval() kod enjeksiyonuna açıktır; güvenli ayrıştırıcı kullanın."),
    "exec": ("CRY-AST-002", "YÜKSEK", "CWE-95", "exec() çağrısı (AST doğrulandı)",
             "exec() dinamik kod yürütmeye açıktır."),
    "compile": ("CRY-AST-003", "ORTA", "CWE-95", "compile() ile dinamik kod derleme",
                "Dinamik kod derlemesi girdi kaynağına göre risk taşır."),
}

PY_DANGEROUS_ATTRS = {
    ("pickle", "loads"): ("CRY-AST-004", "YÜKSEK", "CWE-502", "pickle.loads() çağrısı (AST doğrulandı)",
                          "Pickle keyfi kod yürütmeye (RCE) açıktır; JSON kullanın."),
    ("yaml", "load"): ("CRY-AST-005", "ORTA", "CWE-502", "yaml.load() çağrısı (AST doğrulandı, Loader yok)",
                       "yaml.safe_load() kullanın."),
    ("os", "system"): ("CRY-AST-006", "YÜKSEK", "CWE-78", "os.system() çağrısı (AST doğrulandı)",
                       "subprocess.run([...], shell=False) kullanın."),
    ("subprocess", "call"): ("CRY-AST-007", "ORTA", "CWE-78", "subprocess.call() çağrısı",
                             "shell=True olup olmadığını ve girdi kaynağını denetleyin."),
    ("hashlib", "md5"): ("CRY-AST-008", "ORTA", "CWE-327", "hashlib.md5() çağrısı (AST doğrulandı)",
                         "Kırılmış özet; SHA-256+ kullanın."),
    ("hashlib", "sha1"): ("CRY-AST-009", "ORTA", "CWE-327", "hashlib.sha1() çağrısı (AST doğrulandı)",
                          "Çarpışma riski; SHA-256+ kullanın."),
    ("requests", "verify"): ("CRY-AST-010", "ORTA", "CWE-295", "requests çağrısında TLS doğrulaması",
                             "verify=False kullanımını arar."),
}

# SQL çalıştırma çağrıları — argüman f-string/%/+ ise SQLi veri akışı
PY_SQL_CALLS = {"execute", "executemany", "executescript"}


def _py_finding(rule_tuple, file, lineno, evidence):
    rid, sev, cwe, title, fix = rule_tuple
    return {
        "rule_id": rid, "category": "Python AST", "severity": sev, "cwe": cwe,
        "title": title, "file": file, "line": lineno,
        "match": evidence[:120], "description": fix, "fix": fix,
        "analyzer": "python_ast"
    }


def analyze_python_ast(fpath, rel_path):
    """Python dosyasını AST ile ayrıştırır ve veri akışı tabanlı bulgular üretir."""
    findings = []
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        tree = ast.parse(source)
    except (SyntaxError, ValueError, OSError):
        return findings  # Ayrıştırılamayan dosya: regex katmanı zaten taradı

    # Basit taint kaynakları: fonksiyon parametreleri ve request-benzeri isimler
    taint_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.args:
                if re.search(r"req|input|param|query|data|user|value|payload", arg.arg, re.IGNORECASE):
                    taint_names.add(arg.arg)
        if isinstance(node, ast.Name):
            if re.search(r"^(req(uest)?|params?|query|data|user_input|payload)$", node.id, re.IGNORECASE):
                taint_names.add(node.id)

    def is_tainted(node):
        """Düğüm tainted kaynağa mı bağlanıyor?"""
        if isinstance(node, ast.Name):
            return node.id in taint_names
        if isinstance(node, ast.JoinedStr):  # f-string
            return any(is_tainted(v) for v in node.values if isinstance(v, ast.FormattedValue))
        if isinstance(node, ast.BinOp):  # string birleştirme
            return is_tainted(node.left) or is_tainted(node.right)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            # request.GET.get('x') benzeri zincirler
            return is_tainted(node.func.value)
        return False

    for node in ast.walk(tree):
        # 1. Tehlikeli doğrudan çağrılar: eval(x), exec(x)
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            if func_name and func_name in PY_DANGEROUS_CALLS:
                rule = PY_DANGEROUS_CALLS[func_name]
                tainted = any(is_tainted(a) for a in node.args)
                sev_override = "KRİTİK" if tainted and rule[1] == "YÜKSEK" else rule[1]
                title = rule[3] + (" — TAINTED GİRDİ!" if tainted else "")
                f = _py_finding(rule, rel_path, node.lineno, ast.dump(node)[:100])
                if tainted:
                    f["severity"] = sev_override
                    f["title"] = title
                    f["description"] = "Tehlikeli fonksiyon, kullanıcı kontrollü girdiyle çağrılıyor — doğrudan enjeksiyon riski."
                findings.append(f)

            # 2. Nitelik çağrıları: pickle.loads(x), os.system(x), hashlib.md5(x)
            if isinstance(node.func, ast.Attribute):
                attr_key = None
                if isinstance(node.func.value, ast.Name):
                    attr_key = (node.func.value.id, node.func.attr)
                if attr_key and attr_key in PY_DANGEROUS_ATTRS:
                    rule = PY_DANGEROUS_ATTRS[attr_key]
                    findings.append(_py_finding(rule, rel_path, node.lineno, "%s.%s(...)" % attr_key))

                # 3. SQL veri akışı: cursor.execute(f"...{tainted}") veya execute("..." + tainted)
                if node.func.attr in PY_SQL_CALLS and node.args:
                    arg = node.args[0]
                    # f-string SQL
                    if isinstance(arg, ast.JoinedStr):
                        has_taint = any(isinstance(v, ast.FormattedValue) and is_tainted(v.value) for v in arg.values)
                        findings.append({
                            "rule_id": "SQLI-AST-001", "category": "SQL Injection", "severity": "KRİTİK",
                            "cwe": "CWE-89",
                            "title": "f-string SQL sorgusu (AST veri akışı%s)" % (" — TAINTED GİRDİ!" if has_taint else ""),
                            "file": rel_path, "line": node.lineno,
                            "match": "execute(f\"...\") @ satır %d" % node.lineno,
                            "description": "f-string ile kurulan SQL sorgusu%s." % (" Kullanıcı girdisi doğrudan akıyor — enjeksiyon kesin risk." if has_taint else ""),
                            "fix": "Parametre yer tutucusu kullanın: execute('SELECT ... WHERE id=%s', (user_id,))",
                            "analyzer": "python_ast"
                        })
                    # String birleştirme SQL
                    elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        has_taint = is_tainted(arg)
                        if has_taint:
                            findings.append({
                                "rule_id": "SQLI-AST-002", "category": "SQL Injection", "severity": "KRİTİK",
                                "cwe": "CWE-89", "title": "String birleştirmeli SQL — TAINTED GİRDİ (AST)",
                                "file": rel_path, "line": node.lineno,
                                "match": "execute(... + tainted) @ satır %d" % node.lineno,
                                "description": "Kullanıcı girdisi + operatörüyle SQL sorgusuna birleştiriliyor.",
                                "fix": "Parametreli sorgular kullanın.",
                                "analyzer": "python_ast"
                            })
                    # % formatlama SQL
                    elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                        findings.append({
                            "rule_id": "SQLI-AST-003", "category": "SQL Injection", "severity": "YÜKSEK",
                            "cwe": "CWE-89", "title": "% formatlamalı SQL sorgusu (AST)",
                            "file": rel_path, "line": node.lineno,
                            "match": "execute('...' % ...) @ satır %d" % node.lineno,
                            "description": "% formatlama ile kurulan SQL sorgusu.",
                            "fix": "Parametreli sorgular kullanın.",
                            "analyzer": "python_ast"
                        })

    return findings


# =============================================================
# 2. JS BAĞLAM-FARKINDA TAINT ANALİZİ
# Kaynak (user input) → sink (dangerous API) eşleştirme,
# değişken atama takibi ile çok satırlı akış yakalama.
# =============================================================

JS_SOURCES = re.compile(
    r'(?:req(?:uest)?\.(?:query|params|body|headers)|location\.(?:hash|search|href|pathname)|'
    r'document\.(?:URL|referrer|cookie)|window\.name|params\.|GET\[|POST\[|input\.|'
    r'URLSearchParams|localStorage\.getItem|sessionStorage\.getItem)',
    re.IGNORECASE
)

JS_SINKS = {
    "eval": ("JST-001", "YÜKSEK", "CWE-95", "eval() çağrısı"),
    "Function(": ("JST-002", "YÜKSEK", "CWE-95", "new Function() yapıcı çağrısı"),
    "setTimeout(\"": ("JST-003", "ORTA", "CWE-95", "setTimeout string argümanı"),
    "setInterval(\"": ("JST-004", "ORTA", "CWE-95", "setInterval string argümanı"),
    ".innerHTML": ("JST-005", "ORTA", "CWE-79", "innerHTML ataması"),
    ".outerHTML": ("JST-006", "ORTA", "CWE-79", "outerHTML ataması"),
    "document.write": ("JST-007", "ORTA", "CWE-79", "document.write() çağrısı"),
    "document.writeln": ("JST-008", "ORTA", "CWE-79", "document.writeln() çağrısı"),
    ".insertAdjacentHTML": ("JST-009", "ORTA", "CWE-79", "insertAdjacentHTML çağrısı"),
    "dangerouslySetInnerHTML": ("JST-010", "ORTA", "CWE-79", "React dangerouslySetInnerHTML"),
}

# Değişken atama: var x = req.query.foo (taint kaynağından)
JS_ASSIGN_PATTERN = re.compile(
    r'(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(.*?)(?:;|$)'
)


def analyze_js_taint(fpath, rel_path):
    """JS dosyasında kaynak→sink taint akışını izler (satırlar arası değişken takibi)."""
    findings = []
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return findings

    # 1. Tainted değişkenleri topla (kaynak atamaları)
    tainted_vars = {}  # isim -> tanım satırı
    for lineno, line in enumerate(lines, 1):
        for m in JS_ASSIGN_PATTERN.finditer(line):
            var_name, rhs = m.group(1), m.group(2)
            if JS_SOURCES.search(rhs):
                tainted_vars[var_name] = lineno

    # 2. Sink çağrılarını tara ve tainted kullanım kontrolü yap
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("*"):
            continue
        for sink_key, (rid, sev, cwe, title) in JS_SINKS.items():
            idx = line.find(sink_key)
            if idx == -1:
                continue
            # Sink satırındaki tüm argüman bölgesi
            arg_region = line[idx:idx + 120]
            # Tainted değişken kullanımı var mı?
            tainted_used = [v for v in tainted_vars if re.search(r'\b' + re.escape(v) + r'\b', arg_region)]
            # Doğrudan kaynak kullanımı var mı?
            direct_source = bool(JS_SOURCES.search(arg_region))

            if tainted_used or direct_source:
                src_var = tainted_used[0] if tainted_used else "(doğrudan)"
                src_line = tainted_vars.get(tainted_used[0], lineno) if tainted_used else lineno
                findings.append({
                    "rule_id": rid + "-TAINT", "category": "Taint Akışı",
                    "severity": "KRİTİK" if sev == "YÜKSEK" else "YÜKSEK",
                    "cwe": cwe,
                    "title": "%s — TAINTED VERİ AKIŞI (kaynak→sink eşleşti)" % title,
                    "file": rel_path, "line": lineno,
                    "match": arg_region.strip()[:120],
                    "description": "Kullanıcı girdisi (satır %d: %s) işlenmeden doğrudan tehlikeli sink'e akıyor: %s" % (src_line, src_var, sink_key),
                    "fix": "Kaynağı sterilize edin (DOMPurify/textContent) veya girdiyi doğrulayın; sink'ten kaçının.",
                    "analyzer": "js_taint"
                })
            break  # satır başına bir sink yeter

    return findings


# =============================================================
# 3. SHANNON ENTROPY SECRET TESPİTİ
# Bilinmeyen formatlı anahtarlar: yüksek entropy'li uzun string'ler.
# =============================================================

# Bilinen yüksek-riskli entropy taşıyıcıları (bağlam ipuçlı)
ENTROPY_CONTEXT_HINTS = re.compile(
    r'(?:key|secret|token|password|passwd|pwd|auth|credential|api|private|bearer)',
    re.IGNORECASE
)

# String sabiti yakalama (JS/Python/Go/Java ortak)
STRING_LITERAL = re.compile(r'["\']([A-Za-z0-9+/=_\-]{20,128})["\']')

# Test/dummy değerleri (entropy'li ama zararsız)
ENTROPY_BLOCKLIST = re.compile(
    r'^(?:x{20,}|0{20,}|a{20,}|test|example|dummy|placeholder|your|change|'
    r'[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$',  # düz hex hash'ler değil anahtarlar
    re.IGNORECASE
)

def shannon_entropy(s):
    """String'in Shannon entropy'si (bit/karakter)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def _is_sequential_string(s, min_run=8):
    """Sırla değil, sıralı karakter dizisi mi? (ABCDEF..., 123456..., abc...)
    Alfabe/rakam string'leri yüksek entropy gösterir ama sırra değildir."""
    if len(s) < min_run:
        return False
    run = 1
    max_run = 1
    for i in range(1, len(s)):
        if ord(s[i]) == ord(s[i - 1]) + 1:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 1
    return max_run >= min_run


def analyze_entropy(fpath, rel_path):
    """Yüksek entropy'li string sabitlerini tespit eder (bilinmeyen formatlı secret'lar)."""
    findings = []
    try:
        if os.path.getsize(fpath) > 1024 * 1024:
            return findings
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return findings

    seen_values = set()
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
            continue
        for m in STRING_LITERAL.finditer(line):
            value = m.group(1)
            if value in seen_values:
                continue
            seen_values.add(value)
            if ENTROPY_BLOCKLIST.match(value):
                continue
            # Faz 6B FP düzeltmesi: sıralı alfabe/rakam dizileri sırla değildir
            if _is_sequential_string(value):
                continue
            ent = shannon_entropy(value)
            # Eşik: 4.5 bit/karakter (rastgele anahtarlar ~4.5-6.5; İngilizce metin ~3.5)
            # VE uzunluk >= 25
            if ent >= 4.5 and len(value) >= 25:
                has_context = bool(ENTROPY_CONTEXT_HINTS.search(line))
                sev = "YÜKSEK" if has_context else "ORTA"
                findings.append({
                    "rule_id": "ENT-001", "category": "Sır Yönetimi", "severity": sev,
                    "cwe": "CWE-798",
                    "title": "Yüksek entropy'li olası sır (entropy=%.2f, uzunluk=%d%s)" % (
                        ent, len(value), ", bağlam ipucu: anahtar adı" if has_context else ""),
                    "file": rel_path, "line": lineno,
                    "match": value[:40] + "..." if len(value) > 40 else value,
                    "description": "String sabiti rastgele-anahtar benzeri entropy taşıyor (%.2f bit/karakter). Bu bir API anahtarı, token veya şifre olabilir." % ent,
                    "fix": "Değerin gerçek bir sır olup olmadığını doğrulayın; ise ortam değişkenine taşıyın ve rotate edin.",
                    "analyzer": "entropy"
                })
    return findings


# =============================================================
# 4. GENİŞLETİLMİŞ REGEX KURAL SETİ (42 → ~100)
# Yeni kategoriler: deserialization, JWT, CORS, K8s, GraphQL, crypto, header
# =============================================================

EXTRA_RULES = [
    # --- Java/PHP Deserialization ---
    ("DES-001", "Deserialization", "KRİTİK", "CWE-502", "Java ObjectInputStream Kullanımı",
     re.compile(r"ObjectInputStream|readObject\s*\("),
     "Java nesne deserialization'ı RCE'ye açıktır; look-ahead deserialization koruması kullanın."),
    ("DES-002", "Deserialization", "KRİTİK", "CWE-502", "PHP unserialize() Kullanımı",
     re.compile(r"unserialize\s*\("),
     "PHP unserialize() POP zinciri saldırılarına açıktır; JSON kullanın."),
    ("DES-003", "Deserialization", "YÜKSEK", "CWE-502", ".NET BinaryFormatter / LosFormatter",
     re.compile(r"BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer"),
     ".NET eski serializer'ları RCE'ye açıktır; DataContractSerializer/JsonSerializer kullanın."),
    ("DES-004", "Deserialization", "ORTA", "CWE-502", "Ruby Marshal.load",
     re.compile(r"Marshal\.load|Marshal\.restore"),
     "Ruby Marshal deserialization RCE riski taşır; JSON kullanın."),
    ("DES-005", "Deserialization", "ORTA", "CWE-502", "Python eval-literal Deserialization (shelve/dill)",
     re.compile(r"import\s+(?:shelve|dill)\b"),
     "shelve/dill pickle tabanlıdır; güvenli alternatifler kullanın."),

    # --- JWT Güvenliği ---
    ("JWT-001", "JWT", "KRİTİK", "CWE-347", "JWT alg:none Kullanımı",
     re.compile(r"alg['\"]?\s*[:=]\s*['\"]none['\"]|verify.*alg.*none|allow.*none"),
     "alg:none JWT imzasız bırakır — token forgery doğrudan mümkündür."),
    ("JWT-002", "JWT", "YÜKSEK", "CWE-327", "Zayıf JWT Algoritması (HS256 önerilmez yüksek güvenlikte)",
     re.compile(r"jwt\.(?:sign|decode)\([^)]*HS256"),
     "Yüksek güvenlik senaryolarında RS256/ES256 tercih edin."),
    ("JWT-003", "JWT", "YÜKSEK", "CWE-757", "JWT Doğrulamasız decode (verify: false)",
     re.compile(r"jwt\.decode\([^)]*(?:verify\s*[:=]\s*false|verify\s*[:=]\s*0)"),
     "verify:false imza kontrolünü kapatır; token forgery mümkün olur."),
    ("JWT-004", "JWT", "ORTA", "CWE-331", "Sabit JWT Secret Kullanımı",
     re.compile(r"jwt\.sign\([^,]+,\s*['\"][^'\"]{8,}['\"]"),
     "JWT imza anahtarı koda gömülü; env değişkenine taşıyın."),

    # --- CORS Kod İçi ---
 ("COR-001", "CORS", "YÜKSEK", "CWE-942", "Kod İçi CORS Wildcard (*)",
     re.compile(r"(?:Access-Control-Allow-Origin|origin|origins?)\s*[:=]\s*['\"]\*['\"]|cors\(\s*\{\s*origin\s*:\s*['\"]\*['\"]"),
     "Wildcard CORS tüm sitelere erişim verir; allow-list kullanın."),
    ("COR-002", "CORS", "KRİTİK", "CWE-942", "Reflect Origin + Credentials",
     re.compile(r"(?:setHeader|header)\s*\(\s*['\"]Access-Control-Allow-Origin['\"]\s*,\s*(?:req\.headers\.origin|origin|request\.headers\.origin)\b[^)]*(?:credentials|Credentials)"),
     "Origin yansıtma + credentials kombinasyonu herhangi bir siteden kimlik doğrulamalı erişim sağlar."),

    # --- Kubernetes Manifest ---
    ("K8S-001", "Kubernetes", "YÜKSEK", "CWE-250", "K8s Pod privileged: true",
     re.compile(r"privileged\s*:\s*true"),
     "Privileged konteyner host çekirdeğine tam erişim alır."),
    ("K8S-002", "Kubernetes", "ORTA", "CWE-798", "K8s Secret Düz Metin (stringData)",
     re.compile(r"stringData\s*:"),
     "stringData düz metin sır depolar;Secrets yine de base64'dir — encrypt at rest sağlayın."),
    ("K8S-003", "Kubernetes", "ORTA", "CWE-668", "K8s NodePort / 0.0.0.0 Expose",
     re.compile(r"type\s*:\s*NodePort|hostPort\s*:\s*\d+"),
     "NodePort/hostPort servisi küme dışına açar."),
    ("K8S-004", "Kubernetes", "ORTA", "CWE-1188", "K8s runAsRoot / capabilities Ekleme",
     re.compile(r"runAsNonRoot\s*:\s*false|capabilities\s*:\s*\n?\s*add\s*:\s*\n?\s*-\s*NET_ADMIN|SYS_ADMIN"),
     "Root çalıştırma veya tehlikeli capabilities ekleme tespit edildi."),
    ("K8S-005", "Kubernetes", "DÜŞÜK", "CWE-1104", "K8s latest Tag",
     re.compile(r"image\s*:\s*[\w/.-]+:latest"),
     "Imaj sürümü sabitlenmemiş."),

    # --- GraphQL ---
    ("GQL-001", "GraphQL", "ORTA", "CWE-200", "GraphQL Introspection Açık",
     re.compile(r"introspection\s*:\s*true|__schema|__type\("),
     "Introspection API şemasını sızdırır; üretimde kapatın."),
    ("GQL-002", "GraphQL", "ORTA", "CWE-770", "GraphQL Derinlik Limiti Yok (maxDepth)",
     re.compile(r"graphql\s*[\({][^)]*depth|maxDepth"),
     "Sorgu derinlik limiti yoksa nested sorgu DoS'u mümkündür."),
    ("GQL-003", "GraphQL", "YÜKSEK", "CWE-284", "GraphQL GraphiQL Üretimde",
     re.compile(r"graphiql\s*:\s*true"),
     "GraphiQL playground üretimde açık — şema keşfini kolaylaştırır."),

    # --- Ek Crypto ---
    ("CRX-001", "Zayıf Kriptografi", "ORTA", "CWE-327", "ECB Modu Kullanımı",
     re.compile(r"AES\.MODE_ECB|\/mode\/ecb|encrypt.*ecb"),
     "ECB modu desen sızıntırır; GCM/CBC kullanın."),
    ("CRX-002", "Zayıf Kriptografi", "ORTA", "CWE-326", "Kısa RSA Anahtarı (<2048)",
     re.compile(r"generateKey\(\s*['\"]rsa['\"]\s*,\s*(?:\d{3,3})\s*\)|rsa.*(?:1024|1536)"),
     "RSA anahtar boyutu <2048 bit; modern standart yetersiz."),
    ("CRX-003", "Zayıf Kriptografi", "YÜKSEK", "CWE-798", "Hardcoded IV / Nonce",
     re.compile(r"(?:iv|nonce)\s*[:=]\s*b?['\"][A-Za-z0-9+/=]{8,}['\"]"),
     "Sabit IV/nonce aynı plaintext'e aynı ciphertext üretir (semantic security kaybı)."),
    ("CRX-004", "Zayıf Kriptografi", "ORTA", "CWE-329", "Şifrelemede Math.random / random",
     re.compile(r"(?:Math\.random\(\)|[^_\w]random\(\))[^;\n]*(?:token|key|secret|password|iv|salt)",
                re.IGNORECASE),
     "Kriptografik amaçla tahmin edilebilir rastgelelik kullanılıyor; crypto/rand kullanın."),

    # --- Ek Güvenlik Başlıkları (kod içi) ---
    ("HDR-001", "HTTP Başlığı", "ORTA", "CWE-693", "Kodda X-Frame-Options Eksik + iframe Kullanımı",
     re.compile(r"res\.setHeader\(\s*['\"]X-Frame-Options['\"]\s*,\s*['\"]ALLOW"),
     "X-Frame-Options ALLOW-FROM clickjacking'e izin verir."),
    ("HDR-002", "HTTP Başlığı", "ORTA", "CWE-693", "Kodda CSP script-src 'unsafe-eval'",
     re.compile(r"script-src[^;]*unsafe-eval"),
     "unsafe-eval CSP'yi zayıflatır."),

    # --- Command Injection Ekleri ---
    ("CMD-001", "Command Injection", "KRİTİK", "CWE-78", "Shell=True Kullanımı",
     re.compile(r"shell\s*=\s*True"),
     "subprocess shell=True girdi enjeksiyonuna açıktır."),
    ("CMD-002", "Command Injection", "YÜKSEK", "CWE-78", "Template Literal ile Komut Çalıştırma",
     re.compile(r"(?:exec|execSync|spawnSync)\s*\(\s*`[^`]*\$\{"),
     "Şablon değişkeni komut satırına gömülüyor."),

    # --- Protokol / Ağ ---
    ("NET-001", "Ağ Güvenliği", "ORTA", "CWE-319", "Düz HTTP Kullanımı (Kritik URL'ler)",
     re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-z0-9.-]+"),
     "Düz HTTP bağlantısı — veri transitte şifresiz."),
    ("NET-002", "Ağ Güvenliği", "ORTA", "CWE-1188", "Sunucu 0.0.0.0 Dinlemesi (debug)",
     re.compile(r"(?:host|bind|listen)[^\n]*0\.0\.0\.0"),
     "0.0.0.0 tüm arayüzlerde dinler; üretimde 127.0.0.1 veya reverse-proxy arkası kullanın."),

    # --- XXE (XML External Entity) ---
    ("XXE-001", "XXE", "KRİTİK", "CWE-611", "Java DocumentBuilderFactory Güvenli Değil",
     re.compile(r"DocumentBuilderFactory(?![^;]*secureProcessing)"),
     "XML ayrıştırıcısı harici entity yükleyebilir; setFeature ile DTD/external entity kapatın."),
    ("XXE-002", "XXE", "KRİTİK", "CWE-611", "Python lxml resolve_entities/DTD Açık",
     re.compile(r"resolve_entities\s*=\s*True|XMLParser\([^)]*load_dtd\s*=\s*True|no_network\s*=\s*False"),
     "lxml ayrıştırıcısı entity çözümlemesine açık; resolve_entities=False + no_network=True kullanın."),
    ("XXE-003", "XXE", "YÜKSEK", "CWE-611", ".NET XmlDocument DtdProcessing",
     re.compile(r"DtdProcessing\s*=\s*(?:DtdProcessing\.)?Parse|XmlResolver"),
     ".NET XML ayrıştırıcısı DTD işliyor; DtdProcessing.Ignore kullanın, XmlResolver=null yapın."),
    ("XXE-004", "XXE", "ORTA", "CWE-611", "PHP simplexml/libxml Açık Entity",
     re.compile(r"simplexml_load_(?:string|file)(?![^)]*LIBXML_NOENT)|LIBXML_DTDLOAD"),
     "PHP XML ayrıştırıcısında entity çözümlemesi kısıtlanmamış; LIBXML_NONET kullanın."),

    # --- LDAP Injection ---
    ("LDAP-001", "LDAP Injection", "KRİTİK", "CWE-90", "LDAP Sorgusunda Kullanıcı Girdisi",
     re.compile(r"(?:ldap_search|ldap_search_s|ldap\.search_s|search_s|LDAPSearch|ldap\.search)[^;]*(?:\$|\{|req|params|query|input|username|user_id|user_name|form)",
                re.IGNORECASE),
     "LDAP filtresine kullanıcı girdisi gömülüyor; ldap_escape / parametrik filtre kullanın."),
    ("LDAP-002", "LDAP Injection", "YÜKSEK", "CWE-90", "LDAP Filter String Birleştirme",
     re.compile(r'filter\s*[:=]\s*["\'][^"\']*(?:\+|%s|%d|\$\{|\$[a-z])["\']'),
     "LDAP filtresi string birleştirmeyle kuruluyor; girdi önce kaçışlanmalı."),

    # --- Dosya Yükleme Güvenliği ---
    ("UPL-001", "Dosya Yükleme", "YÜKSEK", "CWE-434", "Dosya Yüklemede Uzantı Doğrulaması Yok",
     re.compile(r"(?:multer|formidable|bodyParser)[^;]*(?:file|upload)|(?:file\.name|filename)[^;]*(?:path|write|save)",
                re.IGNORECASE),
     "Yüklenen dosyanın türü/uzantısı doğrulanmıyor görünüyor; allow-list + MIME kontrolü ekleyin."),
    ("UPL-002", "Dosya Yükleme", "KRİTİK", "CWE-434", "Yüklenen Dosya Web Root'a Yazılıyor",
     re.compile(r"(?:writeFile|move|rename)[^;]*(?:public|wwwroot|static|htdocs|webroot)",
                re.IGNORECASE),
     "Yüklenen dosya doğrudan web root altına yazılıyor — web shell yükleme riski; içerik ve isim sterilizasyonu şart."),

    # --- Host/Referer Header Enjeksiyonu ---
    ("HOST-001", "Header Enjeksiyonu", "ORTA", "CWE-113", "Host Header Yanıta Gömülüyor",
     re.compile(r'(?:res\.redirect|redirect)\s*\(\s*[^)]*req\.headers\.(?:host|origin)|Location["\']\s*[,+]\s*req\.headers\.host'),
     "Host/Origin başlığı doğrulanmadan yönlendirmede/yanıtta kullanılıyor (cache poisoning / password reset poisoning)."),
    ("HOST-002", "Header Enjeksiyonu", "ORTA", "CWE-113", "Referer Header Log/Çıktıda Kullanımı",
     re.compile(r"(?:log|logger|console|print)[^;]*(?:req\.headers\.(?:referer|referrer|user-agent))|(?:req\.headers\.(?:referer|referrer|user-agent))[^;]*(?:log|render|send|json|redirect)"),
     "İstemci kontrollü başlıklar doğrulanmadan kullanılıyor."),

    # --- Logging / Bilgi Sızıntısı ---
    ("LOG-001", "Log Hijyeni", "ORTA", "CWE-532", "Şifre/Token Loglanıyor",
     re.compile(r"(?:log|logger|print|console)\w*\([^)]*(?:password|passwd|secret|token|api[_-]?key)",
                re.IGNORECASE),
     "Hassas alanlar log kaydına yazılıyor."),
    ("LOG-002", "Log Hijyeni", "DÜŞÜK", "CWE-209", "Stack Trace Kullanıcıya Döndürülüyor",
     re.compile(r"(?:catch[^{]*\{[^}]*)(?:res\.send|res\.json|response\.write)[^;]*err(?:or)?\s*(?:\.\s*(?:stack|message))?"),
     "Hata detayları istemciye sızdırılıyor; genel hata mesajı döndürün."),

    # --- 7-Dil Derin Tarayıcı Kuralları (Go, Rust, PHP, Java, C#, TS, Python) ---
    ("LANG-GO-001", "Go Güvenliği", "YÜKSEK", "CWE-295", "Go TLS InsecureSkipVerify Aktif",
     re.compile(r"InsecureSkipVerify\s*:\s*true"),
     "Go tls.Config içinde InsecureSkipVerify: true sertifika doğrulamasını devre dışı bırakır (MITM riski)."),
    ("LANG-GO-002", "Go Güvenliği", "KRİTİK", "CWE-78", "Go exec.Command Kullanıcı Girdisi",
     re.compile(r"exec\.Command(?:Context)?\s*\(\s*(?:[\"'](?:sh|bash|cmd)[\"']\s*,\s*[\"']-(?:c|C)[\"']|r\.URL|r\.Form|req\.)"),
     "Go exec.Command kabuk üzerinden veya doğrudan HTTP isteğiyle çağrılıyor."),
    ("LANG-RUST-001", "Rust Güvenliği", "ORTA", "CWE-119", "Rust unsafe Bloğu Kullanımı",
     re.compile(r"\bunsafe\s*\{"),
     "Rust bellek güvenliği garantilerini devre dışı bırakan unsafe bloğu; sınır ve FFI kontrollerini doğrulayın."),
    ("LANG-RUST-002", "Rust Güvenliği", "KRİTİK", "CWE-78", "Rust std::process::Command Kabuk Çağrısı",
     re.compile(r"Command::new\s*\(\s*[\"'](?:sh|bash|cmd)[\"']\s*\)"),
     "Rust Command::new ile kabuk çalıştırılıyor; argümanları doğrudan dizi olarak geçin."),
    ("LANG-PHP-001", "PHP Güvenliği", "KRİTİK", "CWE-98", "PHP Dinamik Dosya Dahil Etme (LFI/RFI)",
     re.compile(r"\b(?:include|include_once|require|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)"),
     "PHP include/require içinde doğrudan kullanıcı girdisi kullanılıyor (LFI/RFI -> RCE)."),
    ("LANG-PHP-002", "PHP Güvenliği", "KRİTİK", "CWE-502", "PHP Güvensiz unserialize()",
     re.compile(r"\bunserialize\s*\(\s*\$"),
     "PHP unserialize() kullanıcı girdisiyle çağrıldığında PHP Object Injection / RCE yol açar; json_decode kullanın."),
    ("LANG-JAVA-001", "Java Güvenliği", "KRİTİK", "CWE-502", "Java ObjectInputStream.readObject Deserialization",
     re.compile(r"\bObjectInputStream\b[^;]*\.readObject\s*\("),
     "Java ObjectInputStream.readObject güvensiz serileştirme çözümü RCE riski taşır."),
    ("LANG-JAVA-002", "Java Güvenliği", "KRİTİK", "CWE-917", "Spring SpEL Expression Güvensiz Değerlendirme",
     re.compile(r"SpelExpressionParser\s*\(\s*\)[^;]*\.parseExpression\s*\([^\"')]"),
     "Spring Expression Language (SpEL) kullanıcı girdisiyle değerlendirildiğinde RCE oluşur."),
    ("LANG-CS-001", "C# / .NET Güvenliği", "KRİTİK", "CWE-502", ".NET BinaryFormatter / NetDataContractSerializer Kullanımı",
     re.compile(r"\b(?:BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter)\b"),
     ".NET BinaryFormatter ve türevleri güvensizdir (RCE); System.Text.Json kullanın."),
    ("LANG-CS-002", "C# / .NET Güvenliği", "KRİTİK", "CWE-89", ".NET FromSqlRaw / ExecuteSqlRaw Birleştirme",
     re.compile(r"\b(?:FromSqlRaw|ExecuteSqlRaw)\s*\(\s*(?:\$\"|[^)]*\+)"),
     "Entity Framework FromSqlRaw/ExecuteSqlRaw içinde dize birleştirme SQLi oluşturur; FromSqlInterpolated kullanın."),

    # --- Özel Yüzeyler: AI/Agents, WebSocket, Mass Assignment, CI/CD, Local IPC ---
    ("AI-SEC-001", "AI & Ajan Güvenliği", "YÜKSEK", "CWE-77", "LLM Çıktısının Doğrudan Kod/Kabuk Olarak Yürütülmesi",
     re.compile(r"(?:eval|exec|subprocess\.(?:run|Popen)|os\.system)\s*\([^)]*(?:completion|llm_output|ai_response|chat_res|choices\[0\])", re.IGNORECASE),
     "LLM yanıtı doğrulanmadan kod veya kabuk komutu olarak yürütülüyor (Prompt Injection -> RCE)."),
    ("WS-SEC-001", "WebSocket Güvenliği", "ORTA", "CWE-346", "WebSocket Origin Kontrolü Eksik (CheckOrigin: true)",
     re.compile(r"CheckOrigin\s*:\s*func\([^)]*\)\s*bool\s*\{\s*return\s+true\s*\}|origins\s*:\s*[\"']\*[\"']"),
     "WebSocket bağlantılarında tüm Origin'lere izin veriliyor (Cross-Site WebSocket Hijacking)."),
    ("MASS-001", "Mass Assignment", "YÜKSEK", "CWE-915", "ORM Create/Update İçine Doğrudan req.body Geçilmesi",
     re.compile(r"\.(?:create|update|findOneAndUpdate|updateMany|assign)\s*\(\s*req\.(?:body|query)\s*[,)]"),
     "İstemci gövdesi (req.body) alan filtrelemesi (DTO/allowlist) olmadan doğrudan ORM modeline yazılıyor."),
    ("CICD-001", "CI/CD Güvenliği", "KRİTİK", "CWE-78", "GitHub Actions Workflow Script Injection",
     re.compile(r"run\s*:.*\$\{\{\s*github\.event\.(?:issue|pull_request|comment|commits|head_commit|discussion)\.[^}]*(?:title|body|message|ref|label)"),
     "GitHub Actions run bloğunda güvenilmeyen event verisi doğrudan kabuğa enjekte ediliyor; ortam değişkeni üzerinden geçirin."),
    ("IPC-001", "Masaüstü & Yerel IPC", "KRİTİK", "CWE-94", "Electron nodeIntegration Aktif veya contextIsolation Kapalı",
     re.compile(r"nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false"),
     "Electron penceresinde nodeIntegration:true veya contextIsolation:false XSS'i doğrudan RCE'ye dönüştürür."),
]

# =============================================================
# Ana Entegrasyon: Derin Analiz Çağrısı
# =============================================================

def run_deep_analysis(fpath, rel_path):
    """Tek dosya için tüm derin analizcileri çalıştırır."""
    findings = []

    ext = os.path.splitext(fpath)[1].lower()
    base = os.path.basename(fpath).lower()

    # Python AST
    if ext == ".py":
        findings += analyze_python_ast(fpath, rel_path)

    # JS taint
    if ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
        findings += analyze_js_taint(fpath, rel_path)

    # Entropy (tüm kod dosyaları)
    if ext in (".js", ".ts", ".jsx", ".tsx", ".py", ".php", ".java", ".go", ".rb", ".rs", ".cs", ".env", ".yml", ".yaml") or ".env" in base:
        findings += analyze_entropy(fpath, rel_path)

    # Genişletilmiş regex kuralları
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return findings

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "*", "/*")):
            continue
        for rule_id, category, severity, cwe, title, rx, desc in EXTRA_RULES:
            m = rx.search(line)
            if m:
                # ENT blocklist kontrolü CMD için değil; genel
                findings.append({
                    "rule_id": rule_id, "category": category, "severity": severity,
                    "cwe": cwe, "title": title,
                    "file": rel_path, "line": lineno,
                    "match": m.group(0)[:120],
                    "description": desc,
                    "fix": desc,
                    "analyzer": "extended_regex"
                })

    return findings
