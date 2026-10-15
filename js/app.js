/**
 * Web Security Scanner (Web Security Scanner)
 * Pasif Güvenlik Başlıkları, DoH DNS, E-posta Savunması & SSL Denetim Motoru
 * Sıfır Backend - %100 İstemci Taraflı (CORS-Açık DoH & Header Taraması)
 */

// =============================================================
// 1. Durum Yönetimi & Sabitler
// =============================================================
const STATE = {
  currentDomain: '',
  targetUrl: '',
  score: 0,
  grade: '?',
  mode: 'checking', // 'local_api' veya 'github_pages'
  results: {
    dns: {},
    headers: {},
    headersSource: 'none', // 'local_live', 'manual', 'doh_fallback'
    deepScan: null, // Faz 1: cookies, tls, robots, mixed_content, tech_fingerprint
    sast: null, // Faz 2: kaynak kod analizi sonuçları
    activeScan: null, // Faz 3: aktif güvenlik testi sonuçları
    email: {},
    fingerprint: []
  },
  activeTab: 'audit' // 'audit', 'headers', 'checklist', 'report'
};

// Güvenlik Başlıkları Kural Kütüphanesi
const HEADER_RULES = {
  'content-security-policy': {
    name: 'Content-Security-Policy (CSP)',
    weight: 25,
    critical: true,
    desc: 'XSS (Siteler Arası Betik Çalıştırma) ve veri enjeksiyonu saldırılarını tarayıcı düzeyinde kısıtlar.',
    fix: {
      nginx: "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;\" always;",
      apache: "Header set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;\"",
      express: "app.use(helmet.contentSecurityPolicy());"
    },
    evaluate: (val) => {
      if (!val) return { pass: false, score: 0, note: 'CSP başlığı eksik. XSS saldırılarına karşı tarayıcı koruması yok.' };
      let s = 25;
      let notes = [];
      if (val.includes("'unsafe-inline'")) { s -= 5; notes.push("'unsafe-inline' kullanımı riski artırır"); }
      if (val.includes("'unsafe-eval'")) { s -= 10; notes.push("'unsafe-eval' betik enjeksiyonuna açıktır"); }
      if (val.includes("*")) { s -= 5; notes.push("Geniş wildcard (*) alanları kısıtlayın"); }
      return {
        pass: true,
        score: Math.max(5, s),
        note: notes.length ? `CSP mevcut ancak zayıflıklar var: ${notes.join(', ')}.` : 'Güçlü ve sıkı CSP politikası tanımlı.'
      };
    }
  },
  'strict-transport-security': {
    name: 'Strict-Transport-Security (HSTS)',
    weight: 20,
    critical: true,
    desc: 'Tarayıcıyı yalnızca HTTPS ile bağlanmaya zorlar; SSL-stripping ve Man-in-the-Middle saldırılarını engeller.',
    fix: {
      nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
      apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
      express: 'app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));'
    },
    evaluate: (val) => {
      if (!val) return { pass: false, score: 0, note: 'HSTS eksik. Bağlantı güvensiz HTTP üzerinden düşürülebilir (SSL-strip).' };
      const maxAgeMatch = val.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      let s = 10;
      let notes = [];
      if (maxAge >= 31536000) { s += 5; } else { notes.push('max-age en az 1 yıl (31536000) olmalı'); }
      if (val.toLowerCase().includes('includesubdomains')) s += 3;
      if (val.toLowerCase().includes('preload')) s += 2;
      return { pass: true, score: s, note: notes.length ? notes.join(', ') : 'HSTS tam ve güvenli yapılandırılmış.' };
    }
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    weight: 15,
    critical: false,
    desc: 'Sayfanın iframe içine gömülmesini engelleyerek Clickjacking (Tıklama Sahtekarlığı) saldırılarını önler.',
    fix: {
      nginx: 'add_header X-Frame-Options "SAMEORIGIN" always;',
      apache: 'Header always set X-Frame-Options "SAMEORIGIN"',
      express: 'app.use(helmet.frameguard({ action: "sameorigin" }));'
    },
    evaluate: (val) => {
      if (!val) return { pass: false, score: 0, note: 'Eksik. Sayfa kötü niyetli sitelerce iframe içine gömülebilir (Clickjacking).' };
      const upper = val.toUpperCase().trim();
      if (upper === 'DENY' || upper === 'SAMEORIGIN') {
        return { pass: true, score: 15, note: `Güvenli (${upper}). Sayfa dışarıdan iframe içine alınamaz.` };
      }
      return { pass: false, score: 5, note: 'Geçersiz veya zayıf değer.' };
    }
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    weight: 10,
    critical: false,
    desc: 'Tarayıcının MIME türlerini tahmin etmesini (sniffing) engelleyerek zararlı dosya yürütülmesini durdurur.',
    fix: {
      nginx: 'add_header X-Content-Type-Options "nosniff" always;',
      apache: 'Header always set X-Content-Type-Options "nosniff"',
      express: 'app.use(helmet.noSniff());'
    },
    evaluate: (val) => {
      if (!val || val.toLowerCase().trim() !== 'nosniff') {
        return { pass: false, score: 0, note: 'Eksik. Tarayıcı dosyaların MIME türünü tahmin etmeye çalışabilir (MIME Sniffing).' };
      }
      return { pass: true, score: 10, note: "Doğru yapılandırılmış ('nosniff')." };
    }
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    weight: 10,
    critical: false,
    desc: 'Kullanıcı bağlantıya tıkladığında giden istekte hangi referans adresinin iletileceğini kontrol eder.',
    fix: {
      nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
      apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
      express: 'app.use(helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" }));'
    },
    evaluate: (val) => {
      if (!val) return { pass: false, score: 0, note: 'Eksik. URL içindeki hassas query parametreleri dış sitelere sızabilir.' };
      const safeValues = ['strict-origin-when-cross-origin', 'no-referrer', 'same-origin', 'strict-origin'];
      if (safeValues.includes(val.toLowerCase().trim())) {
        return { pass: true, score: 10, note: `Güvenli Referrer politikası: ${val}` };
      }
      return { pass: true, score: 5, note: `Kısmen güvenli değer: ${val}` };
    }
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    weight: 10,
    critical: false,
    desc: 'Tarayıcının donanım ve API özelliklerine (kamera, mikrofon, konum) erişimini kısıtlar.',
    fix: {
      nginx: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
      apache: 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
      express: 'app.use(helmet.permittedCrossDomainPolicies());'
    },
    evaluate: (val) => {
      if (!val) return { pass: false, score: 0, note: 'Eksik. İstemci donanım özellikleri (kamera, konum) kısıtlanmamış.' };
      return { pass: true, score: 10, note: 'Permissions-Policy kısıtlamaları aktif.' };
    }
  }
};

// Sızıntı Yapan Bilgi Başlıkları (Cezalandırılanlar)
const LEAK_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime'];

// =============================================================
// 2. DNS-over-HTTPS (DoH) Sorgulama Motoru
// =============================================================
async function queryDoH(domain, type) {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;
  try {
    const res = await fetch(url, {
      headers: { 'Accept': 'application/dns-json' },
      signal: AbortSignal.timeout(6000)
    });
    if (!res.ok) throw new Error('DoH yanıt vermedi');
    return await res.json();
  } catch (err) {
    // Google DoH Fallback
    try {
      const gUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;
      const gRes = await fetch(gUrl, { signal: AbortSignal.timeout(6000) });
      return await gRes.json();
    } catch (e) {
      return null;
    }
  }
}

// =============================================================
// 3. Güvenlik Denetim Mantığı
// =============================================================
async function performDnsSecurityAudit(cleanDomain) {
  const dnsReport = {
    domain: cleanDomain,
    spf: { status: 'missing', record: null, note: '' },
    dmarc: { status: 'missing', record: null, note: '' },
    dnssec: false,
    caa: { status: 'missing', records: [] },
    ipv6: false,
    mx: []
  };

  // 1. DMARC Sorgusu (_dmarc.domain TXT)
  const dmarcData = await queryDoH(`_dmarc.${cleanDomain}`, 'TXT');
  if (dmarcData && dmarcData.Answer) {
    const dmarcRecord = dmarcData.Answer.map(a => a.data.replace(/^"|"$/g, '')).find(d => d.startsWith('v=DMARC1'));
    if (dmarcRecord) {
      dnsReport.dmarc.record = dmarcRecord;
      if (dmarcRecord.includes('p=reject')) {
        dnsReport.dmarc.status = 'strong';
        dnsReport.dmarc.note = 'En yüksek koruma seviyesi (p=reject). Sahte e-postalar doğrudan reddedilir.';
      } else if (dmarcRecord.includes('p=quarantine')) {
        dnsReport.dmarc.status = 'medium';
        dnsReport.dmarc.note = 'Orta seviye koruma (p=quarantine). Şüpheli e-postalar spam klasörüne yönlendirilir.';
      } else {
        dnsReport.dmarc.status = 'weak';
        dnsReport.dmarc.note = 'Yalnızca izleme modu (p=none). Sahte e-postalar engellenmez!';
      }
    }
  }

  // 2. SPF Sorgusu (domain TXT)
  const txtData = await queryDoH(cleanDomain, 'TXT');
  if (txtData && txtData.Answer) {
    const spfRecord = txtData.Answer.map(a => a.data.replace(/^"|"$/g, '')).find(d => d.startsWith('v=spf1'));
    if (spfRecord) {
      dnsReport.spf.record = spfRecord;
      if (spfRecord.includes('-all')) {
        dnsReport.spf.status = 'strong';
        dnsReport.spf.note = 'Katı SPF kuralı (-all). Yetkisiz sunuculardan giden e-postalar reddedilir.';
      } else if (spfRecord.includes('~all')) {
        dnsReport.spf.status = 'medium';
        dnsReport.spf.note = 'Esnek SPF kuralı (~all SoftFail).';
      } else {
        dnsReport.spf.status = 'weak';
        dnsReport.spf.note = 'Zayıf SPF kuralı (+all veya ?all). Sahteciliğe karşı koruma zayıf.';
      }
    }
    // DNSSEC Kontrolü (Authenticated Data flag)
    if (txtData.AD === true) dnsReport.dnssec = true;
  }

  // 3. CAA (Sertifika Yetkilisi Kısıtlaması)
  const caaData = await queryDoH(cleanDomain, 'CAA');
  if (caaData && caaData.Answer && caaData.Answer.length > 0) {
    dnsReport.caa.status = 'configured';
    dnsReport.caa.records = caaData.Answer.map(a => a.data);
  }

  // 4. IPv6 Desteği (AAAA Kaydı)
  const aaaaData = await queryDoH(cleanDomain, 'AAAA');
  if (aaaaData && aaaaData.Answer && aaaaData.Answer.length > 0) {
    dnsReport.ipv6 = true;
  }

  // 5. MX Kayıtları
  const mxData = await queryDoH(cleanDomain, 'MX');
  if (mxData && mxData.Answer) {
    dnsReport.mx = mxData.Answer.map(a => a.data);
  }

  return dnsReport;
}

// Ham Headers Metnini Ayrıştırma
function parseRawHeaders(rawText) {
  const headers = {};
  if (!rawText) return headers;

  const lines = rawText.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('HTTP/')) continue;
    const colonIdx = trimmed.indexOf(':');
    if (colonIdx > 0) {
      const key = trimmed.slice(0, colonIdx).trim().toLowerCase();
      const val = trimmed.slice(colonIdx + 1).trim();
      headers[key] = val;
    }
  }
  return headers;
}

// Güvenlik Başlıklarını Değerlendirme
function evaluateHeaders(headerMap) {
  const report = {};
  let earnedScore = 0;
  let totalPossible = 0;
  const leaks = [];

  for (const [key, rule] of Object.entries(HEADER_RULES)) {
    totalPossible += rule.weight;
    const val = headerMap[key];
    const evaluation = rule.evaluate(val);
    earnedScore += evaluation.score;

    report[key] = {
      name: rule.name,
      present: !!val,
      value: val || null,
      score: evaluation.score,
      maxScore: rule.weight,
      pass: evaluation.pass,
      note: evaluation.note,
      fix: rule.fix
    };
  }

  // Sızıntı kontrolü (Server, X-Powered-By)
  for (const leakKey of LEAK_HEADERS) {
    if (headerMap[leakKey]) {
      leaks.push({ header: leakKey, value: headerMap[leakKey] });
      earnedScore = Math.max(0, earnedScore - 5); // Ceza
    }
  }

  return {
    headers: report,
    score: earnedScore,
    maxScore: totalPossible,
    leaks: leaks
  };
}

// Toplam Skor ve Harf Notu Hesaplama
function calculateFinalGrade(headerScore, headerMax, dnsReport) {
  let score = Math.round((headerScore / headerMax) * 65); // %65 Başlıklar

  // DNS & E-posta Katkısı (%35)
  if (dnsReport.dmarc.status === 'strong') score += 12;
  else if (dnsReport.dmarc.status === 'medium') score += 8;
  else if (dnsReport.dmarc.status === 'weak') score += 3;

  if (dnsReport.spf.status === 'strong') score += 10;
  else if (dnsReport.spf.status === 'medium') score += 7;

  if (dnsReport.dnssec) score += 5;
  if (dnsReport.caa.status === 'configured') score += 5;
  if (dnsReport.ipv6) score += 3;

  score = Math.min(100, Math.max(0, score));

  let grade = 'F';
  let badgeColor = 'bg-rose-500 text-white';
  let summary = 'Kritik güvenlik eksiklikleri tespit edildi.';

  if (score >= 90) {
    grade = 'A+';
    badgeColor = 'bg-emerald-600 text-white';
    summary = 'Kusursuz güvenlik duruşu. Tüm kritik başlıklar ve e-posta kalkanları devrede.';
  } else if (score >= 80) {
    grade = 'A';
    badgeColor = 'bg-emerald-500 text-white';
    summary = 'Çok güçlü savunma. Yalnızca birkaç ince ayar gerekli.';
  } else if (score >= 70) {
    grade = 'B';
    badgeColor = 'bg-blue-600 text-white';
    summary = 'İyi seviyede güvenlik, ancak eksik başlıklar tıklama sahtekarlığı veya XSS riski yaratabilir.';
  } else if (score >= 55) {
    grade = 'C';
    badgeColor = 'bg-amber-500 text-white';
    summary = 'Orta seviye. CSP veya HSTS eksikliği önemli açıklar bırakıyor.';
  } else if (score >= 40) {
    grade = 'D';
    badgeColor = 'bg-orange-500 text-white';
    summary = 'Zayıf koruma. Temel güvenlik standartları uygulanmalı.';
  }

  return { score, grade, badgeColor, summary };
}

// =============================================================
// 4. Kullanıcı Arayüzü & Etkileşimler
// =============================================================
function sanitizeInputDomain(raw) {
  return raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');
}

async function startSecurityScan() {
  const inputEl = document.getElementById('target-input');
  const rawDomain = inputEl ? inputEl.value : '';
  const cleanDomain = sanitizeInputDomain(rawDomain);

  if (!cleanDomain || !cleanDomain.includes('.')) {
    showToast('Lütfen geçerli bir alan adı girin (örn: siteniz.com)', 'warning');
    return;
  }

  STATE.currentDomain = cleanDomain;
  STATE.targetUrl = 'https://' + cleanDomain;

  // UI Durumu: Yükleniyor
  toggleLoading(true);
  document.getElementById('scan-empty-state').classList.add('hidden');
  document.getElementById('scan-results').classList.remove('hidden');

  try {
    // 1. DNS & E-posta Savunma Taraması (DoH ile canlı)
    const dnsReport = await performDnsSecurityAudit(cleanDomain);
    STATE.results.dns = dnsReport;

    // 2. HTTP Başlıkları Taraması
    const manualHeadersText = document.getElementById('manual-headers-input').value.trim();
    let headerMap = {};
    let sourceLabel = '';

    if (manualHeadersText) {
      headerMap = parseRawHeaders(manualHeadersText);
      STATE.results.headersSource = 'manual';
      sourceLabel = 'Elle Yapıştırılan cURL Başlıkları';
    } else if (STATE.mode === 'local_api') {
      try {
        headerMap = await fetchLocalApiHeaders(STATE.targetUrl);
        STATE.results.headersSource = 'local_live';
        sourceLabel = 'Lokal Sunucu Canlı Yanıtı (127.0.0.1)';
      } catch (apiErr) {
        console.warn('Lokal API hatası, fallback devrede:', apiErr);
        headerMap = await probePublicHeadersFallback(cleanDomain);
        STATE.results.headersSource = 'doh_fallback';
        sourceLabel = 'DoH Fallback (Yerel API Hatası: ' + apiErr.message + ')';
      }
    } else {
      headerMap = await probePublicHeadersFallback(cleanDomain);
      STATE.results.headersSource = 'doh_fallback';
      sourceLabel = 'DoH / Pasif Fallback Modu';
    }

    const headerEval = evaluateHeaders(headerMap);
    STATE.results.headers = headerEval;

    // 3. Nihai Puanlama
    const final = calculateFinalGrade(headerEval.score, headerEval.maxScore, dnsReport);
    STATE.score = final.score;
    STATE.grade = final.grade;

    // 4. Render
    renderScoreCard(final);
    renderHeaderResults(headerEval);
    renderDnsResults(dnsReport);
    renderLeaks(headerEval.leaks);

    // Faz 1: Derin Pasif Tarama (yalnızca lokal modda)
    const deepScanCard = document.getElementById('deep-scan-card');
    if (STATE.mode === 'local_api') {
      try {
        const deepRes = await fetch(`/api/deep-scan?url=${encodeURIComponent(STATE.targetUrl)}`, { signal: AbortSignal.timeout(20000) });
        const deepData = await deepRes.json();
        if (deepData && deepData.success) {
          STATE.results.deepScan = deepData;
          renderDeepScanResults(deepData);
        } else if (deepScanCard) {
          deepScanCard.classList.add('hidden');
        }
      } catch (deepErr) {
        console.warn('Derin tarama atlandı:', deepErr);
        if (deepScanCard) deepScanCard.classList.add('hidden');
      }
    } else if (deepScanCard) {
      deepScanCard.classList.add('hidden');
    }

    showToast(`Denetim tamamlandı! Güvenlik Notu: ${final.grade} (${final.score}/100)`, 'success');
  } catch (err) {
    console.error('Scan Error:', err);
    showToast('Tarama sırasında hata oluştu: ' + err.message, 'error');
  } finally {
    toggleLoading(false);
  }
}

// Canlı Yerel API'den Gerçek HTTP Başlıklarını Çekme (Lokal Mod)
async function fetchLocalApiHeaders(targetUrl) {
  const apiUrl = `/api/headers?url=${encodeURIComponent(targetUrl)}`;
  const res = await fetch(apiUrl, { signal: AbortSignal.timeout(10000) });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.error || `Yerel API yanıt vermedi (HTTP ${res.status})`);
  }
  const data = await res.json();
  if (!data.success) {
    throw new Error(data.error || 'Başlıklar alınamadı.');
  }
  return data.headers || {};
}

// Canlı/Fallback Header Tespiti (GitHub Pages / Fallback Modu)
async function probePublicHeadersFallback(domain) {
  const detected = {};
  try {
    // DoH üzerinden HTTPS / SVCB kaydı sorgula
    const httpsRecord = await queryDoH(domain, 'HTTPS');
    if (httpsRecord && httpsRecord.Answer) {
      detected['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
    }
  } catch (e) {}

  return detected;
}

// Çalışma Modunu Otomatik Algılama (Lokal Sunucu vs GitHub Pages)
async function detectScannerMode() {
  const modePillEl = document.getElementById('scanner-mode-pill');
  const modeBadgeEl = document.getElementById('scanner-mode-badge');
  const modeNoticeEl = document.getElementById('scanner-mode-notice');
  const statusLocalBadge = document.getElementById('status-local-badge');
  const statusDeepBadge = document.getElementById('status-deep-badge');
  const modDeepPill = document.getElementById('mod-deep-pill');
  const localDirRow = document.getElementById('local-dir-row');

  try {
    const res = await fetch('/api/status', { signal: AbortSignal.timeout(1500) });
    if (res.ok) {
      const data = await res.json();
      if (data.mode === 'local_server') {
        STATE.mode = 'local_api';
        const srvEdition = (data.edition || '').toLowerCase() === 'lite' ? 'lite' : (localStorage.getItem('wss_edition') || 'full');
        setScannerEdition(srvEdition, false);
        if (modePillEl) {
          modePillEl.className = 'inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border border-emerald-200 bg-emerald-50 text-[11px] font-mono text-emerald-800 font-semibold';
          modePillEl.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shrink-0"></span><span class="truncate">Yerel Mod & Derin Tarama Aktif</span>';
        }
        if (statusLocalBadge) {
          statusLocalBadge.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 font-bold';
          statusLocalBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-500 shrink-0"></span><span>Yerel Mod: Aktif</span>';
        }
        if (statusDeepBadge) {
          statusDeepBadge.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 font-bold';
          statusDeepBadge.innerHTML = '<svg class="w-3.5 h-3.5 text-emerald-600 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg><span>Derin Tarama & SAST: Aktif</span>';
        }
        if (modDeepPill) {
          modDeepPill.className = 'px-1.5 py-0.2 rounded text-[9px] font-mono bg-emerald-100 text-emerald-800 border border-emerald-200';
          modDeepPill.innerText = 'Aktif';
        }
        if (localDirRow) {
          localDirRow.classList.remove('hidden');
        }
        if (modeBadgeEl) {
          modeBadgeEl.innerHTML = '<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300 font-bold text-[11px] font-mono shadow-xs"><span class="w-2 h-2 rounded-full bg-emerald-500"></span><span>Lokal Mod (Tam Başlık & Dizin Taraması Aktif)</span></span>';
        }
        if (modeNoticeEl) {
          modeNoticeEl.className = 'p-3.5 rounded-2xl bg-emerald-50/90 border border-emerald-200 text-xs text-emerald-950 mb-5 flex items-center justify-between gap-3 shadow-xs';
          modeNoticeEl.innerHTML = `
            <div class="flex items-start sm:items-center gap-3 min-w-0">
              <span class="w-8 h-8 rounded-xl bg-emerald-100 border border-emerald-200 text-emerald-700 inline-flex items-center justify-center shrink-0">
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
              </span>
              <div class="min-w-0 leading-relaxed">
                <strong class="font-bold text-emerald-900">Yerel Sunucu & Derin Tarama Aktif (127.0.0.1:8765):</strong>
                <span class="text-emerald-800 text-[11px] block sm:inline"> Alan adı + alt dizin (<code class="font-mono">site.com/dizin</code>), yerel proje dizini (SAST), derin pasif analiz, etik onaylı aktif testler, AI Red Team ve Strix hazır.</span>
              </div>
            </div>
            <span class="hidden md:inline-flex items-center px-2.5 py-1 rounded-lg bg-emerald-100 text-emerald-800 font-mono text-[10px] font-bold border border-emerald-300 shrink-0">TAM YETKİ</span>
          `;
        }
        loadStrixCapabilities();
        loadStrixPastRuns();
        return;
      }
    }
  } catch (e) {}

  // GitHub Pages veya Statik Barındırma Modu
  STATE.mode = 'github_pages';
  if (modePillEl) {
    modePillEl.className = 'inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border border-amber-300 bg-amber-50 text-[11px] font-mono text-amber-900 font-semibold';
    modePillEl.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-500 shrink-0"></span><span class="truncate">Statik Mod (Pasif Önizleme)</span>';
  }
  if (statusLocalBadge) {
    statusLocalBadge.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-amber-50 border border-amber-300 text-amber-900 font-bold';
    statusLocalBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-500 shrink-0"></span><span>Yerel Mod: Pasif (GitHub Pages)</span>';
  }
  if (statusDeepBadge) {
    statusDeepBadge.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-stone-100 border border-stone-200 text-stone-600 font-bold';
    statusDeepBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-stone-400 shrink-0"></span><span>Derin Tarama: Pasif (Lokal Sunucu Gerekli)</span>';
  }
  if (modDeepPill) {
    modDeepPill.className = 'px-1.5 py-0.2 rounded text-[9px] font-mono bg-amber-100 text-amber-800 border border-amber-200';
    modDeepPill.innerText = 'Lokal Mod';
  }
  if (modeNoticeEl) {
    modeNoticeEl.className = 'p-3.5 rounded-2xl bg-amber-50/70 border border-amber-300 text-xs text-amber-950 mb-5 flex items-center justify-between gap-3 shadow-xs';
    modeNoticeEl.innerHTML = `
      <div class="flex items-start sm:items-center gap-3 min-w-0">
        <span class="w-8 h-8 rounded-xl bg-amber-100 border border-amber-300 text-amber-800 inline-flex items-center justify-center shrink-0">
          <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
        </span>
        <div class="min-w-0 leading-relaxed">
          <strong class="font-bold text-amber-900">Tarayıcı Önizleme Modu (Yerel Mod Pasif):</strong>
          <span class="text-amber-800 text-[11px] block sm:inline"> Şu an yalnızca DoH üzerinden pasif DNS denetimi aktiftir. Derin pasif tarama, yerel dizin (SAST), aktif testler ve AI/Strix için yerel sunucuyu (<code class="font-mono">python3 server.py</code>) çalıştırın.</span>
        </div>
      </div>
      <span class="hidden md:inline-flex items-center px-2.5 py-1 rounded-lg bg-amber-100 text-amber-900 font-mono text-[10px] font-bold border border-amber-300 shrink-0">PASİF ÖNİZLEME</span>
    `;
  }
  if (modeBadgeEl) {
    modeBadgeEl.innerHTML = '<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-300 font-bold text-[11px] font-mono shadow-xs"><span class="w-2 h-2 rounded-full bg-amber-500"></span><span>GitHub Pages Modu (Pasif DoH Önizlemesi)</span></span>';
  }
}

// Skor Kartını Render Et
function renderScoreCard(final) {
  const scoreNumEl = document.getElementById('score-number');
  const gradeBadgeEl = document.getElementById('score-grade-badge');
  const summaryEl = document.getElementById('score-summary');
  const domainEl = document.getElementById('score-domain');

  if (scoreNumEl) scoreNumEl.innerText = final.score;
  if (gradeBadgeEl) {
    gradeBadgeEl.innerText = final.grade;
    gradeBadgeEl.className = `px-3.5 py-1 rounded-full text-base font-bold font-mono tracking-wider shadow-sm ${final.badgeColor}`;
  }
  if (summaryEl) summaryEl.innerText = final.summary;
  if (domainEl) domainEl.innerText = STATE.currentDomain;
}

// Başlık Sonuçlarını Render Et
function renderHeaderResults(headerEval) {
  const container = document.getElementById('headers-list-container');
  if (!container) return;
  container.innerHTML = '';

  for (const [key, item] of Object.entries(headerEval.headers)) {
    const card = document.createElement('div');
    card.className = `p-4 rounded-xl border transition-all ${
      item.pass 
        ? 'bg-white border-emerald-200/80 shadow-xs' 
        : 'bg-rose-50/40 border-rose-200/80 shadow-xs'
    }`;

    const statusBadge = item.pass
      ? '<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">✓ Güvenli (' + item.score + '/' + item.maxScore + ')</span>'
      : '<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-rose-100 text-rose-800 border border-rose-200">✕ Eksik / Zayıf (0/' + item.maxScore + ')</span>';

    const fixSnippet = !item.pass ? `
      <div class="mt-3 pt-3 border-t border-rose-100">
        <div class="flex items-center justify-between mb-1.5">
          <span class="text-[11px] font-semibold text-mistral-slate uppercase tracking-wider">Önerilen Nginx Çözümü:</span>
          <button type="button" onclick="copyToClipboard('${escapeAttr(item.fix.nginx)}')" class="btn btn-xs btn-secondary !py-1 !px-2 text-mistral-orange">Kopyala</button>
        </div>
        <pre class="bg-stone-900 text-stone-100 p-2.5 rounded-xl text-xs font-mono overflow-x-auto select-all"><code>${escapeHtml(item.fix.nginx)}</code></pre>
      </div>
    ` : '';

    card.innerHTML = `
      <div class="flex items-start justify-between gap-2 mb-1.5">
        <h4 class="font-bold text-sm text-mistral-ink font-mono">${escapeHtml(item.name)}</h4>
        ${statusBadge}
      </div>
      <p class="text-xs text-mistral-slate mb-2">${escapeHtml(HEADER_RULES[key].desc)}</p>
      <div class="text-xs font-mono p-2 rounded bg-stone-50 border border-stone-200/60 break-all">
        ${item.value ? `<span class="text-emerald-700">${escapeHtml(item.value)}</span>` : '<span class="text-rose-500 italic">Başlık tanımlanmamış</span>'}
      </div>
      <div class="mt-2 text-xs text-stone-600">${escapeHtml(item.note)}</div>
      ${fixSnippet}
    `;

    container.appendChild(card);
  }
}

// DNS & E-posta Savunmasını Render Et
function renderDnsResults(dns) {
  const container = document.getElementById('dns-list-container');
  if (!container) return;
  container.innerHTML = '';

  const items = [
    {
      title: 'DMARC E-posta Kalkanı',
      status: dns.dmarc.status === 'strong' ? 'pass' : dns.dmarc.status === 'medium' ? 'warn' : 'fail',
      value: dns.dmarc.record || 'DMARC kaydı bulunamadı',
      note: dns.dmarc.note || 'Alan adı adına sahte e-posta gönderimi engellenemiyor.',
      fix: `v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@${dns.domain};`
    },
    {
      title: 'SPF (Sender Policy Framework)',
      status: dns.spf.status === 'strong' ? 'pass' : dns.spf.status === 'medium' ? 'warn' : 'fail',
      value: dns.spf.record || 'SPF kaydı bulunamadı',
      note: dns.spf.note || 'Alan adı IP adreslerini yetkilendiren SPF kaydı eksik.',
      fix: 'v=spf1 mx ~all'
    },
    {
      title: 'DNSSEC (Alan Adı İmzası)',
      status: dns.dnssec ? 'pass' : 'warn',
      value: dns.dnssec ? 'DNSSEC Aktif (AD=1)' : 'DNSSEC Yapılandırılmamış',
      note: dns.dnssec ? 'DNS önbellek zehirlenmesine (DNS Poisoning) karşı korumalı.' : 'DNSSEC açılarak alan adı sahteciliği engellenebilir.'
    },
    {
      title: 'CAA (Sertifika Yetkilisi Kısıtı)',
      status: dns.caa.status === 'configured' ? 'pass' : 'warn',
      value: dns.caa.records.length ? dns.caa.records.join(', ') : 'CAA kaydı yok (Her CA sertifika üretebilir)',
      note: dns.caa.records.length ? 'Sadece izin verilen CA yetkilileri SSL sertifikası üretebilir.' : 'CAA eklenerek yetkisiz SSL sertifikası üretimi engellenmelidir.'
    },
    {
      title: 'IPv6 Desteği (AAAA)',
      status: dns.ipv6 ? 'pass' : 'info',
      value: dns.ipv6 ? 'IPv6 Adresi Mevcut' : 'Yalnızca IPv4',
      note: dns.ipv6 ? 'Modern yeni nesil IP protokolü devrede.' : 'Geleceğe hazır ağ desteği için IPv6 önerilir.'
    }
  ];

  for (const item of items) {
    const card = document.createElement('div');
    const isPass = item.status === 'pass';
    const isWarn = item.status === 'warn';

    const badge = isPass
      ? '<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">✓ Doğrulandı</span>'
      : isWarn
      ? '<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-amber-100 text-amber-800 border border-amber-200">! İyileştirilmeli</span>'
      : '<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-rose-100 text-rose-800 border border-rose-200">✕ Eksik</span>';

    card.className = `p-4 rounded-xl border ${isPass ? 'bg-white border-stone-200' : 'bg-stone-50 border-stone-200'}`;
    card.innerHTML = `
      <div class="flex items-center justify-between gap-2 mb-1.5">
        <h4 class="font-bold text-sm text-mistral-ink">${escapeHtml(item.title)}</h4>
        ${badge}
      </div>
      <div class="text-xs font-mono p-2 rounded-lg bg-white border border-stone-200/80 break-all mb-1.5 text-stone-700">
        ${escapeHtml(item.value)}
      </div>
      <p class="text-xs text-mistral-slate">${escapeHtml(item.note)}</p>
      ${item.fix ? `
        <div class="mt-2 text-right">
          <button type="button" onclick="copyToClipboard('${escapeAttr(item.fix)}')" class="btn btn-xs btn-secondary !py-1 !px-2 text-mistral-orange">Örnek TXT Kopyala</button>
        </div>
      ` : ''}
    `;

    container.appendChild(card);
  }
}

// Sızıntıları Render Et
function renderLeaks(leaks) {
  const container = document.getElementById('leaks-container');
  const card = document.getElementById('leaks-card');
  if (!container || !card) return;

  if (!leaks || leaks.length === 0) {
    card.classList.add('hidden');
    return;
  }

  card.classList.remove('hidden');
  container.innerHTML = leaks.map(l => `
    <div class="p-2.5 rounded-lg bg-rose-50 border border-rose-200 text-xs">
      <span class="font-bold font-mono text-rose-800">${escapeHtml(l.header)}:</span>
      <span class="font-mono text-rose-700 ml-1">${escapeHtml(l.value)}</span>
      <p class="text-[11px] text-rose-600 mt-1">Sunucu sürüm bilgisi saldırganlara teknoloji yığını ifşa ediyor. Gizlenmesi önerilir.</p>
    </div>
  `).join('');
}

// Faz 1: Derin Pasif Tarama Sonuçlarını Render Et
function renderDeepScanResults(deep) {
  const container = document.getElementById('deep-scan-container');
  const card = document.getElementById('deep-scan-card');
  if (!container || !card) return;

  card.classList.remove('hidden');
  let html = '';

  // 1.1 Çerez Güvenliği
  if (deep.cookies && deep.cookies.analyzed) {
    const cookies = deep.cookies.findings || [];
    html += '<div class="p-4 rounded-xl border border-stone-200 bg-white">';
    html += '<div class="flex items-center justify-between gap-2 mb-2"><h4 class="font-bold text-sm text-mistral-ink">🍪 Çerez Güvenlik Analizi</h4>';
    html += '<span class="text-[11px] font-mono text-stone-500">' + (deep.cookies.count || 0) + ' çerez</span></div>';
    if (cookies.length === 0) {
      html += '<p class="text-xs text-mistral-slate">Çerez tespit edilmedi veya analiz edilemedi.</p>';
    }
    for (const c of cookies) {
      const okCount = (c.httponly ? 1 : 0) + (c.secure ? 1 : 0) + (['strict', 'lax'].includes((c.samesite || '').toLowerCase()) ? 1 : 0);
      const badge = okCount === 3
        ? '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-100 text-emerald-800">✅ Güvenli</span>'
        : '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-100 text-amber-800">⚠️ Eksik Bayrak</span>';
      html += '<div class="mb-2 p-2.5 rounded-lg bg-stone-50 border border-stone-200/70">';
      html += '<div class="flex items-center justify-between gap-2 mb-1"><span class="font-mono text-xs font-bold text-mistral-ink">' + escapeHtml(c.name) + '</span>' + badge + '</div>';
      html += '<div class="text-[11px] font-mono text-stone-500">HttpOnly: ' + (c.httponly ? '✅' : '❌') + ' • Secure: ' + (c.secure ? '✅' : '❌') + ' • SameSite: ' + escapeHtml(c.samesite) + '</div>';
      if (c.issues && c.issues.length > 0) {
        html += '<ul class="mt-1 text-[11px] text-rose-600 list-disc list-inside">';
        for (const iss of c.issues) html += '<li>' + escapeHtml(iss) + '</li>';
        html += '</ul>';
      }
      html += '</div>';
    }
    html += '</div>';
  }

  // 1.2 TLS / Sertifika
  if (deep.tls && deep.tls.analyzed) {
    const tls = deep.tls;
    const hasIssues = (tls.findings || []).length > 0;
    html += '<div class="p-4 rounded-xl border ' + (hasIssues ? 'border-rose-200 bg-rose-50/40' : 'border-emerald-200 bg-emerald-50/30') + '">';
    html += '<div class="flex items-center justify-between gap-2 mb-2"><h4 class="font-bold text-sm text-mistral-ink">🔒 TLS / Sertifika Analizi</h4>';
    html += (hasIssues ? '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-100 text-rose-800">⚠️ Bulgular Var</span>' : '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-100 text-emerald-800">✅ Sağlıklı</span>') + '</div>';
    if (tls.protocol) {
      html += '<div class="text-[11px] font-mono text-stone-600 mb-1">Protokol: <span class="' + (tls.protocol === 'TLSv1.3' || tls.protocol === 'TLSv1.2' ? 'text-emerald-700' : 'text-rose-700') + '">' + escapeHtml(tls.protocol) + '</span></div>';
    }
    if (tls.issuer) html += '<div class="text-[11px] font-mono text-stone-600 mb-1">Sertifika Yetkilisi: ' + escapeHtml(tls.issuer) + '</div>';
    if (tls.valid_until) html += '<div class="text-[11px] font-mono text-stone-600 mb-1">Geçerlilik: ' + escapeHtml(tls.valid_until) + (tls.expiry_days !== null && tls.expiry_days !== undefined ? ' (' + tls.expiry_days + ' gün kaldı)' : '') + '</div>';
    for (const f of (tls.findings || [])) {
      html += '<div class="mt-1.5 p-2 rounded bg-rose-50 border border-rose-200 text-[11px] text-rose-700"><strong>' + escapeHtml(f.level) + ':</strong> ' + escapeHtml(f.issue) + '</div>';
    }
    html += '</div>';
  }

  // 1.3 robots.txt İfşası
  if (deep.robots && deep.robots.analyzed) {
    const rb = deep.robots;
    const issues = rb.findings || [];
    html += '<div class="p-4 rounded-xl border border-stone-200 bg-white">';
    html += '<div class="flex items-center justify-between gap-2 mb-2"><h4 class="font-bold text-sm text-mistral-ink">🤖 robots.txt İfşası</h4>';
    html += (rb.exists ? '<span class="text-[11px] font-mono text-stone-500">' + (issues.length > 0 ? issues.length + ' bulgu' : 'temiz') + '</span>' : '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-stone-100 text-stone-600">Dosya yok</span>') + '</div>';
    if (!rb.exists && rb.note) html += '<p class="text-xs text-mistral-slate">' + escapeHtml(rb.note) + '</p>';
    for (const f of issues) {
      html += '<div class="mb-1.5 p-2 rounded bg-amber-50 border border-amber-200 text-[11px] text-amber-800"><strong>' + escapeHtml(f.level) + ':</strong> ' + escapeHtml(f.issue) + ' <code class="font-mono">' + escapeHtml(f.evidence || '') + '</code></div>';
    }
    html += '</div>';
  }

  // 1.4 Mixed Content
  if (deep.mixed_content && deep.mixed_content.analyzed) {
    const mc = deep.mixed_content;
    const findings = mc.findings || [];
    html += '<div class="p-4 rounded-xl border ' + (findings.length > 0 ? 'border-rose-200 bg-rose-50/40' : 'border-emerald-200 bg-emerald-50/30') + '">';
    html += '<div class="flex items-center justify-between gap-2 mb-2"><h4 class="font-bold text-sm text-mistral-ink">🔗 Mixed Content</h4>';
    html += (findings.length > 0 ? '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-100 text-rose-800">⚠️ ' + findings.length + ' bulgu</span>' : '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-100 text-emerald-800">✅ Temiz</span>') + '</div>';
    for (const f of findings) {
      html += '<div class="mb-1.5 p-2 rounded bg-rose-50 border border-rose-200 text-[11px] text-rose-700"><strong>' + escapeHtml(f.level) + ':</strong> ' + escapeHtml(f.issue) + ' <code class="font-mono break-all">' + escapeHtml(f.evidence || '') + '</code></div>';
    }
    html += '</div>';
  }

  // 1.5 Teknoloji Parmak İzi
  if (deep.tech_fingerprint && deep.tech_fingerprint.analyzed) {
    const techs = deep.tech_fingerprint.technologies || [];
    html += '<div class="p-4 rounded-xl border border-stone-200 bg-white">';
    html += '<div class="flex items-center justify-between gap-2 mb-2"><h4 class="font-bold text-sm text-mistral-ink">🧩 Teknoloji Parmak İzi</h4>';
    html += '<span class="text-[11px] font-mono text-stone-500">' + techs.length + ' tespit</span></div>';
    if (techs.length === 0) {
      html += '<p class="text-xs text-mistral-slate">Teknoloji ifşası tespit edilmedi (iyi iş!).</p>';
    } else {
      html += '<div class="flex flex-wrap gap-1.5">';
      for (const t of techs) {
        html += '<span class="px-2.5 py-1 rounded-lg bg-stone-100 border border-stone-200 text-[11px] font-mono text-stone-700" title="' + escapeHtml(t.source) + '">' + escapeHtml(t.category) + ': <strong>' + escapeHtml(t.value) + '</strong></span>';
      }
      html += '</div>';
      html += '<p class="text-[11px] text-mistral-slate mt-2">Bu bilgiler saldırganlara hedefe yönelik exploit aramada yol gösterir; başlıklarda gizlenmesi önerilir.</p>';
    }
    html += '</div>';
  }

  container.innerHTML = html;
}

// =============================================================
// FAZ 2: SAST — Kaynak Kod Analizi Mantığı
// =============================================================
async function startSastScan() {
  const pathInput = document.getElementById('sast-path-input');
  const btn = document.getElementById('sast-btn');
  const spinner = document.getElementById('sast-spinner');
  const btnText = document.getElementById('sast-btn-text');
  const resultsEl = document.getElementById('sast-results');
  const pagesNotice = document.getElementById('sast-pages-notice');

  // Mod kontrolü: SAST yalnızca lokal sunucuda çalışır
  if (STATE.mode !== 'local_api') {
    if (pagesNotice) pagesNotice.classList.remove('hidden');
    showToast('SAST taraması yalnızca lokal sunucu modunda çalışır. python3 server.py ile çalıştırın.', 'warning');
    return;
  }
  if (pagesNotice) pagesNotice.classList.add('hidden');

  const targetPath = pathInput ? pathInput.value.trim() : '';
  if (!targetPath) {
    showToast('Lütfen bir proje dizin yolu girin.', 'warning');
    return;
  }

  // UI: yükleniyor
  if (btn) btn.disabled = true;
  if (spinner) spinner.classList.remove('hidden');
  if (btnText) btnText.innerText = 'Taranıyor...';
  if (resultsEl) resultsEl.classList.remove('hidden');

  try {
    const res = await fetch(`/api/sast?path=${encodeURIComponent(targetPath)}`, { signal: AbortSignal.timeout(120000) });
    const data = await res.json();

    if (!data.success) {
      showToast('SAST hatası: ' + (data.error || 'Bilinmeyen hata'), 'error');
      return;
    }

    STATE.results.sast = data;
    renderSastStats(data);
    renderSastFindings();
    renderSastDeps(data.dependencies);

    const s = data.summary;
    showToast(`SAST tamamlandı: ${data.findings.length} bulgu (K:${s['KRİTİK'] || 0} Y:${s['YÜKSEK'] || 0} O:${s['ORTA'] || 0} D:${s['DÜŞÜK'] || 0})`, 'success');
  } catch (err) {
    console.error('SAST Error:', err);
    showToast('SAST taraması başarısız: ' + err.message, 'error');
  } finally {
    if (btn) btn.disabled = false;
    if (spinner) spinner.classList.add('hidden');
    if (btnText) btnText.innerText = 'Kodu Tara';
  }
}

function renderSastStats(data) {
  const grid = document.getElementById('sast-stats-grid');
  if (!grid) return;

  const st = data.stats || {};
  const cards = [
    { label: 'Taranan Dosya', value: st.files_scanned || 0 },
    { label: 'Toplam Satır', value: (st.total_lines || 0).toLocaleString('tr-TR') },
    { label: 'Aktif Kural', value: st.deep_rules_active || st.rules_active || 0, title: 'Regex + yapısal (AST/taint/entropy) kuralları' },
    { label: 'Süre', value: ((st.duration_ms || 0) / 1000).toFixed(1) + ' sn' }
  ];

  grid.innerHTML = cards.map(c => `
    <div class="p-3.5 rounded-xl bg-stone-50 border border-stone-200 text-center">
      <div class="text-lg font-extrabold font-mono text-mistral-ink">${escapeHtml(String(c.value))}</div>
      <div class="text-[10px] text-mistral-slate font-semibold uppercase tracking-wider mt-0.5">${c.label}</div>
    </div>
  `).join('');

  // Faz 6B: Analizci kırılımı (hangi motor kaç bulgu üretti)
  const statsCard = document.getElementById('sast-stats-card');
  if (statsCard) {
    const analyzers = data.stats && data.stats.analyzers || {};
    const ANALYZER_NAMES = {
      regex: 'Regex (42 kural)',
      extended_regex: 'Genişletilmiş Regex',
      python_ast: '🐍 Python AST',
      js_taint: 'JS Taint Akışı',
      entropy: 'Entropy Analizi'
    };
    const entries = Object.entries(analyzers);
    const oldBreak = statsCard.querySelector('.sast-analyzer-breakdown');
    if (oldBreak) oldBreak.remove();
    if (entries.length > 0) {
      let badgeHtml = '<div class="sast-analyzer-breakdown mt-3 pt-3 border-t border-stone-100"><div class="text-[10px] font-bold text-mistral-slate uppercase tracking-wider mb-1.5">Analizci Kırılımı</div><div class="flex flex-wrap gap-1.5">';
      for (const [aKey, aCount] of entries) {
        badgeHtml += '<span class="px-2 py-0.5 rounded-full bg-stone-100 border border-stone-200 text-[10px] font-mono text-stone-700">' + (ANALYZER_NAMES[aKey] || aKey) + ': <strong>' + aCount + '</strong></span>';
      }
      badgeHtml += '</div></div>';
      statsCard.insertAdjacentHTML('beforeend', badgeHtml);
    }
  }

  // Şiddet özeti
  const sevGrid = document.getElementById('sast-severity-summary');
  if (sevGrid) {
    const s = data.summary || {};
    const sevs = [
      { key: 'KRİTİK', color: 'bg-rose-100 text-rose-800 border-rose-200' },
      { key: 'YÜKSEK', color: 'bg-orange-100 text-orange-800 border-orange-200' },
      { key: 'ORTA', color: 'bg-amber-100 text-amber-800 border-amber-200' },
      { key: 'DÜŞÜK', color: 'bg-stone-100 text-stone-700 border-stone-200' }
    ];
    sevGrid.innerHTML = sevs.map(sv => `
      <div class="p-3 rounded-xl border text-center ${sv.color}">
        <div class="text-2xl font-bold font-mono">${s[sv.key] || 0}</div>
        <div class="text-[10px] font-bold tracking-wider">${sv.key}</div>
      </div>
    `).join('');
  }

  // ersinkoc/security-check %100: 3 Durumlu Kanıt Modeli + Mimari Harita + Kapsam Defteri + 6'lı İndirme Çubuğu
  renderSecurityCheckPanels(data.security_check);
}

function renderSecurityCheckPanels(sc) {
  const dlBar = document.getElementById('sast-sc-dl-bar');
  const verdictGrid = document.getElementById('sast-verdict-summary');
  const scPanels = document.getElementById('sast-sc-panels');
  const archBody = document.getElementById('sast-arch-body');
  const ledgerTable = document.getElementById('sast-ledger-table');

  if (!sc) {
    dlBar?.classList.add('hidden');
    verdictGrid?.classList.add('hidden');
    scPanels?.classList.add('hidden');
    return;
  }

  dlBar?.classList.remove('hidden');
  const rec = sc.findings_record || {};
  const confCount = (rec.confirmed || []).length;
  const needsCount = (rec.needs_validation || []).length;
  const rejCount = (rec.rejected || []).length;

  if (verdictGrid) {
    verdictGrid.classList.remove('hidden');
    verdictGrid.innerHTML = `
      <div class="p-3 rounded-xl border border-emerald-200 bg-emerald-50/50 flex items-center justify-between">
        <div>
          <div class="text-[10px] font-bold uppercase text-emerald-900">✅ Confirmed (Sınır İhlali Kanıtlı)</div>
          <div class="text-[11px] text-emerald-800">Tam kaynak izi ile doğrulandı</div>
        </div>
        <span class="text-xl font-bold font-mono text-emerald-900">${confCount}</span>
      </div>
      <div class="p-3 rounded-xl border border-amber-200 bg-amber-50/50 flex items-center justify-between">
        <div>
          <div class="text-[10px] font-bold uppercase text-amber-900">⚠️ Needs Validation (Çalışma Zamanı)</div>
          <div class="text-[11px] text-amber-800">Ortam/yapılandırma teyidi bekliyor</div>
        </div>
        <span class="text-xl font-bold font-mono text-amber-900">${needsCount}</span>
      </div>
      <div class="p-3 rounded-xl border border-stone-200 bg-stone-50 flex items-center justify-between">
        <div>
          <div class="text-[10px] font-bold uppercase text-stone-700">🛡️ Rejected (Elenen / Yanlış Pozitif)</div>
          <div class="text-[11px] text-stone-500">Bağımsız doğrulamada elendi</div>
        </div>
        <span class="text-xl font-bold font-mono text-stone-700">${rejCount}</span>
      </div>
    `;
  }

  if (scPanels) {
    scPanels.classList.remove('hidden');
    if (archBody) archBody.textContent = sc.architecture_md || '';
    if (ledgerTable) {
      const rows = sc.coverage_ledger || [];
      if (!rows.length) {
        ledgerTable.innerHTML = '<p class="text-stone-500">Kapsam kaydı yok.</p>';
      } else {
        ledgerTable.innerHTML = '<table class="w-full border-collapse text-left font-mono text-[10px]">' +
          '<thead><tr class="border-b border-stone-200 text-stone-600"><th class="p-1.5">ID</th><th class="p-1.5">Yüzey</th><th class="p-1.5">Alt Sistem</th><th class="p-1.5">Saldırı Sınıfı</th><th class="p-1.5">Durum</th><th class="p-1.5">Kanıt / Boşluk</th></tr></thead><tbody>' +
          rows.map(r => '<tr class="border-b border-stone-100">' +
            '<td class="p-1.5 font-bold">' + escapeHtml(r.coverage_id) + '</td>' +
            '<td class="p-1.5">' + escapeHtml(r.surface) + '</td>' +
            '<td class="p-1.5">' + escapeHtml(r.subsystem) + '</td>' +
            '<td class="p-1.5">' + escapeHtml(r.attack_class) + '</td>' +
            '<td class="p-1.5"><span class="px-1.5 py-0.2 rounded bg-stone-100 border border-stone-200">' + escapeHtml(r.status) + '</span></td>' +
            '<td class="p-1.5 text-stone-600">' + escapeHtml((r.evidence || '') + (r.gap ? ' (' + r.gap + ')' : '')) + '</td>' +
          '</tr>').join('') + '</tbody></table>';
      }
    }
  }
}

function downloadSecurityCheckArtifact(field, filename) {
  const sc = STATE.results.sast?.security_check;
  if (!sc) {
    showToast('Önce bir yerel proje dizini (SAST) taraması çalıştırın.', 'warning');
    return;
  }
  if (field === 'findings_json') {
    downloadFile(filename, JSON.stringify(sc.findings_record || {}, null, 2), 'application/json');
    showToast(filename + ' indirildi!', 'success');
    return;
  }
  const content = sc[field] || '';
  if (!content) {
    showToast(filename + ' içeriği bulunamadı.', 'warning');
    return;
  }
  downloadFile(filename, content, 'text/markdown');
  showToast(filename + ' indirildi!', 'success');
}

async function startAISastAudit() {
  if (STATE.mode !== 'local_api') {
    showToast('4-Aşamalı AI Kod Denetimi yalnızca yerel sunucu modunda çalışır.', 'warning');
    return;
  }
  const dirInput = document.getElementById('unified-dir-input');
  const mainInput = document.getElementById('unified-target-input');
  let targetDir = (dirInput?.value || '').trim() || STATE.targetDir || '';
  if (!targetDir && mainInput && isLocalDirectoryInput(mainInput.value)) {
    targetDir = mainInput.value.trim();
  }
  if (!targetDir) {
    showToast('Önce 📂 Yerel proje dizini kutusuna taranacak klasör yolunu (örn: /sarjharitasi.tr) girin.', 'warning');
    dirInput?.focus();
    return;
  }

  const profile = document.getElementById('sast-profile')?.value || 'standard';
  const scopeMode = document.getElementById('sast-scope-mode')?.value || 'full';
  const diffBase = (document.getElementById('sast-diff-base')?.value || 'HEAD').trim();
  const btn = document.getElementById('sast-ai-btn');
  if (btn) { btn.disabled = true; btn.innerText = '⏳ 4-Aşama Çalışıyor…'; }

  try {
    const res = await fetch('/api/sast-ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        path: targetDir,
        profile: profile,
        scope_mode: scopeMode,
        diff_base: diffBase,
        ai_config: strixAIConfig()
      }),
      signal: AbortSignal.timeout(600000)
    });
    const d = await res.json();
    if (!d.success) {
      showToast('AI Kod Denetimi hatası: ' + (d.error || 'Bilinmeyen hata'), 'error');
      return;
    }

    if (d.sast) {
      d.sast.security_check = d.security_check || d.sast.security_check;
      d.sast.dependencies = d.dependencies || d.sast.dependencies;
      STATE.results.sast = d.sast;
      renderSastStats(d.sast);
      renderSastFindings();
      renderSastDeps(d.sast.dependencies);
    }

    const aiCard = document.getElementById('sast-ai-card');
    const aiMeta = document.getElementById('sast-ai-meta');
    const aiPhases = document.getElementById('sast-ai-phases');
    const aiReport = document.getElementById('sast-ai-report');
    if (aiCard) aiCard.classList.remove('hidden');
    if (aiMeta) aiMeta.innerText = `Profil: ${d.profile} · Kapsam: ${d.scope_mode} · Doğrulanan Semantik Bulgu: ${(d.ai_confirmed || []).length}`;
    if (aiPhases) {
      aiPhases.innerHTML = (d.phases || []).map(p =>
        '<div class="p-2.5 rounded-xl bg-white border border-amber-200 text-[11px]">' +
        '<div class="font-bold font-mono text-amber-900">⚡ ' + escapeHtml(p.phase) + '</div>' +
        '<div class="text-[10px] text-stone-600 mt-0.5">' + escapeHtml(p.summary || '') + '</div>' +
        '</div>'
      ).join('');
    }
    if (aiReport) {
      aiReport.innerHTML = '<div class="font-mono text-[11px] whitespace-pre-wrap">' + escapeHtml(d.executive_report_md || d.recon_summary || 'Tamamlandı.') + '</div>';
    }
    document.getElementById('scan-empty-state')?.classList.add('hidden');
    document.getElementById('scan-results-dashboard')?.classList.remove('hidden');
    switchDetailTab('tab-sast');
    showToast('4-Aşamalı AI Kaynak Kod Denetimi tamamlandı!', 'success');
  } catch (e) {
    showToast('AI Kod Denetimi başarısız: ' + e.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.innerText = '🤖 4-Aşamalı AI Kod Denetimi'; }
  }
}

function renderSastFindings() {
  const list = document.getElementById('sast-findings-list');
  if (!list) return;
  const data = STATE.results.sast;
  if (!data || !data.findings) return;

  const filterSel = document.getElementById('sast-severity-filter');
  const filter = filterSel ? filterSel.value : 'all';

  const filtered = filter === 'all' ? data.findings : data.findings.filter(f => f.severity === filter);

  if (filtered.length === 0) {
    list.innerHTML = '<div class="p-4 text-center text-xs text-mistral-slate">Bu filtreye uygun bulgu yok. 🎉</div>';
    return;
  }

  const sevColors = {
    'KRİTİK': 'border-rose-300 bg-rose-50/60',
    'YÜKSEK': 'border-orange-300 bg-orange-50/60',
    'ORTA': 'border-amber-300 bg-amber-50/60',
    'DÜŞÜK': 'border-stone-300 bg-stone-50/60'
  };
  const sevBadges = {
    'KRİTİK': 'bg-rose-600 text-white',
    'YÜKSEK': 'bg-orange-500 text-white',
    'ORTA': 'bg-amber-500 text-white',
    'DÜŞÜK': 'bg-stone-500 text-white'
  };

  list.innerHTML = filtered.map(f => `
    <div class="p-3 rounded-xl border ${sevColors[f.severity] || 'border-stone-200'}">
      <div class="flex items-start justify-between gap-2 mb-1.5">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono ${sevBadges[f.severity] || 'bg-stone-500 text-white'}">${f.severity}</span>
          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-stone-200/70 text-stone-700">${f.rule_id}</span>
          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-stone-100 border border-stone-200 text-stone-600">${f.cwe}</span>
          ${f.cvss !== undefined ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-100 border border-indigo-200 text-indigo-700 font-bold">CVSS ${f.cvss}</span>` : ''}
          ${f.verified === true ? '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-100 border border-emerald-200 text-emerald-700 font-bold" title="İkinci geçişte bağımsız olarak teyit edildi">✓ Doğrulandı</span>' : ''}
        </div>
        <span class="text-[10px] font-mono text-stone-500 whitespace-nowrap">${escapeHtml(f.category)}</span>
      </div>
      <div class="text-xs font-bold text-mistral-ink mb-1">${escapeHtml(f.title)}</div>
      <div class="text-[11px] font-mono text-stone-600 mb-1.5">📍 ${escapeHtml(f.file)}:${f.line}</div>
      <pre class="text-[10px] font-mono bg-stone-900 text-amber-200 p-2 rounded-lg overflow-x-auto mb-1.5"><code>${escapeHtml(f.match)}</code></pre>
      <p class="text-[11px] text-mistral-slate leading-relaxed">${escapeHtml(f.description)}</p>
      ${f.fix ? `
        <div class="mt-1.5 pt-1.5 border-t border-stone-200/70 flex items-start gap-1.5">
          <span class="text-[11px]">🛠️</span>
          <p class="text-[11px] text-emerald-800 bg-emerald-50 rounded-lg px-2 py-1 leading-relaxed flex-1"><strong>Çözüm:</strong> ${escapeHtml(f.fix)}</p>
        </div>
      ` : ''}
    </div>
  `).join('');
}

function renderSastDeps(deps) {
  const card = document.getElementById('sast-deps-card');
  const container = document.getElementById('sast-deps-container');
  if (!card || !container) return;

  if (!deps || !deps.analyzed) {
    card.classList.add('hidden');
    return;
  }

  const vuln = deps.vulnerable || [];
  if (vuln.length === 0 && (deps.note || '').includes('bulunamadı')) {
    card.classList.remove('hidden');
    container.innerHTML = `<div class="p-3 rounded-xl bg-stone-50 border border-stone-200 text-xs text-mistral-slate">${escapeHtml(deps.note || 'Bağımlılık manifestosu bulunamadı.')}</div>`;
    return;
  }

  if (vuln.length === 0) {
    card.classList.remove('hidden');
    container.innerHTML = '<div class="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-800">✅ Bilinen CVE\u2019si olan bağımlılık tespit edilmedi.</div>';
    return;
  }

  card.classList.remove('hidden');
  container.innerHTML = vuln.map(v => `
    <div class="p-3 rounded-xl bg-rose-50/60 border border-rose-200">
      <div class="flex items-center justify-between gap-2 mb-1.5">
        <span class="text-xs font-bold font-mono text-mistral-ink">📦 ${escapeHtml(v.name)} <span class="text-stone-500">@${escapeHtml(v.version)}</span></span>
        <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white">${v.vuln_count} CVE</span>
      </div>
      ${v.vulns.map(vn => `
        <div class="mb-1 p-2 rounded-lg bg-white border border-rose-100 text-[11px]">
          <span class="font-mono font-bold text-rose-700">${escapeHtml(vn.id)}</span>
          ${vn.url ? `<a href="${escapeAttr(vn.url)}" target="_blank" rel="noopener" class="text-mistral-orange hover:underline ml-1 text-[10px]">↗ detay</a>` : ''}
          <p class="text-stone-600 mt-0.5 leading-relaxed">${escapeHtml(vn.summary)}</p>
        </div>
      `).join('')}
    </div>
  `).join('');

  if (deps.errors && deps.errors.length > 0) {
    container.innerHTML += `<div class="p-2 text-[10px] text-stone-400 font-mono">${deps.errors.length} paket sorgulanamadı (ağ hatası)</div>`;
  }
}

// =============================================================
// FAZ 3: Aktif Güvenlik Testi Mantığı (Etik Onay + Rate-Limited Tarama)
// =============================================================
async function startActiveScan(options = {}) {
  const targetInput = document.getElementById('active-target-input');
  const btn = document.getElementById('active-btn');
  const spinner = document.getElementById('active-spinner');
  const btnText = document.getElementById('active-btn-text');
  const aiBtn = document.getElementById('active-ai-btn');
  const aiSpinner = document.getElementById('active-ai-spinner');
  const aiBtnText = document.getElementById('active-ai-btn-text');
  const resultsEl = document.getElementById('active-results');
  const pagesNotice = document.getElementById('active-pages-notice');
  const ethicalCheck = document.getElementById('active-ethical-check');
  const aiOrchestration = options.aiOrchestration === true;

  // Mod kontrolü
  if (STATE.mode !== 'local_api') {
    if (pagesNotice) pagesNotice.classList.remove('hidden');
    showToast('Aktif test yalnızca lokal sunucu modunda çalışır. python3 server.py ile çalıştırın.', 'warning');
    return;
  }
  if (pagesNotice) pagesNotice.classList.add('hidden');

  const rawUrl = targetInput ? targetInput.value.trim() : '';
  if (!rawUrl) {
    showToast('Lütfen bir hedef URL girin (örn: https://siteniz.com/page?id=1)', 'warning');
    return;
  }

  // Etik onay kontrolü
  if (!ethicalCheck || !ethicalCheck.checked) {
    showToast('Devam etmek için etik sorumluluk beyanını onaylamanız gerekiyor.', 'warning');
    if (ethicalCheck) ethicalCheck.focus();
    return;
  }

  // Seçili modülleri topla
  const moduleChecks = document.querySelectorAll('.active-module-check:checked');
  const modules = Array.from(moduleChecks).map(c => c.value);
  if (modules.length === 0) {
    showToast('En az bir test modülü seçmelisiniz.', 'warning');
    return;
  }

  // UI: yükleniyor
  if (aiOrchestration) {
    if (aiBtn) aiBtn.disabled = true;
    if (aiSpinner) aiSpinner.classList.remove('hidden');
    if (aiBtnText) aiBtnText.innerText = 'AI Çalışıyor...';
  } else {
    if (btn) btn.disabled = true;
    if (spinner) spinner.classList.remove('hidden');
    if (btnText) btnText.innerText = 'Test Ediliyor...';
  }
  if (resultsEl) resultsEl.classList.remove('hidden');

  try {
    // 1. Etik onayı sunucuya gönder (domain bazlı)
    const confirmRes = await fetch('/api/active-confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: rawUrl, confirmed: true }),
      signal: AbortSignal.timeout(5000)
    });
    const confirmData = await confirmRes.json();
    if (!confirmData.success) {
      showToast('Onay kaydedilemedi: ' + (confirmData.error || '?'), 'error');
      return;
    }

    // 2. Aktif taramayı başlat
    const scanUrl = '/api/active-scan?url=' + encodeURIComponent(rawUrl) + '&modules=' + encodeURIComponent(modules.join(','));
    const res = await fetch(scanUrl, { signal: AbortSignal.timeout(300000) });
    const data = await res.json();

    if (!data.success) {
      if (data.error === 'ETIK_ONAY_YOK') {
        showToast('Etik onay bulunamadı. Beyanı işaretleyip tekrar deneyin.', 'warning');
      } else {
        showToast('Aktif test hatası: ' + (data.error || data.message || 'Bilinmeyen hata'), 'error');
      }
      return;
    }

    if (aiOrchestration) {
      // AI Orkestrasyon modu: /api/ai-scan endpoint'ini çağır
      const aiData = await startAIOrchestrationScan(rawUrl, modules);
      if (aiData) {
        STATE.results.aiScan = aiData;
        renderActiveResults(aiData);
      }
    } else {
      // Normal aktif tarama
      // 1. Etik onayı sunucuya gönder (domain bazlı)
      const confirmRes = await fetch('/api/active-confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: rawUrl, confirmed: true }),
        signal: AbortSignal.timeout(5000)
      });
      const confirmData = await confirmRes.json();
      if (!confirmData.success) {
        showToast('Onay kaydedilemedi: ' + (confirmData.error || '?'), 'error');
        return;
      }

      // 2. Aktif taramayı başlat
      const scanUrl = '/api/active-scan?url=' + encodeURIComponent(rawUrl) + '&modules=' + encodeURIComponent(modules.join(','));
      const res = await fetch(scanUrl, { signal: AbortSignal.timeout(300000) });
      const data = await res.json();

      if (!data.success) {
        if (data.error === 'ETIK_ONAY_YOK') {
          showToast('Etik onay bulunamadı. Beyanı işaretleyip tekrar deneyin.', 'warning');
        } else {
          showToast('Aktif test hatası: ' + (data.error || data.message || 'Bilinmeyen hata'), 'error');
        }
        return;
      }

      STATE.results.activeScan = data;
      renderActiveResults(data);

      const s = data.summary;
      const chainCount = (data.chains || []).length;
      showToast('Aktif test tamamlandı: ' + data.findings.length + ' bulgu' + (chainCount > 0 ? ' + ' + chainCount + ' risk zinciri' : '') + ' (K:' + (s['KRİTİK'] || 0) + ' Y:' + (s['YÜKSEK'] || 0) + ' O:' + (s['ORTA'] || 0) + ') — ' + data.requests_sent + ' istek', 'success');
    }
  } catch (err) {
    console.error('Active Scan Error:', err);
    showToast('Aktif test başarısız: ' + err.message, 'error');
  } finally {
    if (btn) btn.disabled = false;
    if (spinner) spinner.classList.add('hidden');
    if (btnText) btnText.innerText = 'Aktif Testi Başlat';
    if (aiBtn) aiBtn.disabled = false;
    if (aiSpinner) aiSpinner.classList.add('hidden');
    if (aiBtnText) aiBtnText.innerText = '🤖 AI Orkestrasyon';
  }
}

function renderActiveResults(data) {
  // İstatistik kartı
  const statsGrid = document.getElementById('active-stats-grid');
  if (statsGrid) {
    const cards = [
      { label: 'Gönderilen İstek', value: data.requests_sent || 0 },
      { label: 'Rate Limit', value: (data.rate_limit_seconds || 1.5) + ' sn' },
      { label: 'Toplam Bulgu', value: data.findings.length },
      { label: 'Süre', value: ((data.duration_ms || 0) / 1000).toFixed(1) + ' sn' },
      { label: 'Modül', value: Object.keys(data.modules || {}).length }
    ];
    statsGrid.innerHTML = cards.map(c => '<div class="p-3.5 rounded-xl bg-stone-50 border border-stone-200 text-center"><div class="text-lg font-extrabold font-mono text-mistral-ink">' + escapeHtml(String(c.value)) + '</div><div class="text-[10px] text-mistral-slate font-semibold uppercase tracking-wider mt-0.5">' + c.label + '</div></div>').join('');
  }

  // Şiddet özeti
  const sevGrid = document.getElementById('active-severity-summary');
  if (sevGrid) {
    const s = data.summary || {};
    const sevs = [
      { key: 'KRİTİK', color: 'bg-rose-100 text-rose-800 border-rose-200' },
      { key: 'YÜKSEK', color: 'bg-orange-100 text-orange-800 border-orange-200' },
      { key: 'ORTA', color: 'bg-amber-100 text-amber-800 border-amber-200' },
      { key: 'DÜŞÜK', color: 'bg-stone-100 text-stone-700 border-stone-200' },
      { key: 'BİLGİ', color: 'bg-sky-100 text-sky-800 border-sky-200' }
    ];
    sevGrid.innerHTML = sevs.map(sv => '<div class="p-3 rounded-xl border text-center ' + sv.color + '"><div class="text-2xl font-bold font-mono">' + (s[sv.key] || 0) + '</div><div class="text-[10px] font-bold tracking-wider">' + sv.key + '</div></div>').join('');
  }

  // Modül durumu
  const modulesEl = document.getElementById('active-modules-status');
  if (modulesEl) {
    const MODULE_NAMES = {
      sqli: 'SQL Injection', nosqli: 'NoSQL Injection', ssti: 'SSTI',
      open_redirect: 'Open Redirect', xss: 'XSS', csrf: 'CSRF', ssrf: 'SSRF',
      idor: 'IDOR', ports: 'Port Taraması', deep_headers: 'Derin Başlık',
      browser: 'Tarayıcı Simülasyonu'
    };
    modulesEl.innerHTML = Object.entries(data.modules || {}).map(([mid, m]) => {
      const statusHtml = m.ran
        ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-100 text-emerald-800">✓ ' + (m.findings || 0) + ' bulgu</span>'
        : (m.skipped
          ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-amber-100 text-amber-800">atlandı</span>'
          : '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-100 text-rose-800">hata</span>');
      return '<div class="p-2.5 rounded-xl border border-stone-200 bg-stone-50 flex items-center justify-between gap-2"><span class="text-xs font-mono font-semibold text-mistral-ink">' + (MODULE_NAMES[mid] || mid) + '</span>' + statusHtml + '</div>';
    }).join('');
  }

  // Faz 6E: Site haritası (tarayıcı simülasyonu crawler çıktısı)
  const sitemapCard = document.getElementById('active-sitemap-card');
  const sitemapList = document.getElementById('active-sitemap-list');
  if (sitemapCard && sitemapList) {
    const siteMap = data.site_map || [];
    if (siteMap.length === 0) {
      sitemapCard.classList.add('hidden');
    } else {
      sitemapCard.classList.remove('hidden');
      sitemapList.innerHTML = siteMap.map(p => {
        const statusColor = p.status === 200 ? 'bg-emerald-100 text-emerald-800' : (p.status ? 'bg-amber-100 text-amber-800' : 'bg-rose-100 text-rose-800');
        return '<div class="flex items-center gap-2 p-2 rounded-lg bg-stone-50 border border-stone-200 text-[11px]">' +
          '<span class="font-mono text-stone-400 w-12">d' + (p.depth || 0) + '</span>' +
          '<span class="font-mono px-1.5 py-0.5 rounded text-[10px] font-bold ' + statusColor + '">' + (p.status || 'ERR') + '</span>' +
          '<span class="font-mono text-mistral-ink truncate flex-1" title="' + escapeHtml(p.url) + '">' + escapeHtml(p.url) + '</span>' +
          (p.forms > 0 ? '<span class="font-mono text-[10px] text-stone-500">' + p.forms + ' form</span>' : '') +
          '</div>';
      }).join('');
    }
  }

  // Zincirleme korelasyon sonuçları (Faz 6A)
  const chainsCard = document.getElementById('active-chains-card');
  const chainsList = document.getElementById('active-chains-list');
  if (chainsCard && chainsList) {
    const chains = data.chains || [];
    if (chains.length === 0) {
      chainsCard.classList.add('hidden');
    } else {
      chainsCard.classList.remove('hidden');
      const chainSevBadges = {
        'KRİTİK': 'bg-rose-600 text-white',
        'YÜKSEK': 'bg-orange-500 text-white',
        'ORTA': 'bg-amber-500 text-white',
        'DÜŞÜK': 'bg-stone-500 text-white'
      };
      chainsList.innerHTML = chains.map(c => '<div class="p-3 rounded-xl bg-white border border-rose-200 shadow-xs">' +
        '<div class="flex items-start justify-between gap-2 mb-1.5">' +
        '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono ' + (chainSevBadges[c.severity] || 'bg-stone-500 text-white') + '">' + escapeHtml(c.severity) + '</span>' +
        '<span class="text-[10px] font-mono text-stone-500">' + escapeHtml((c.components || []).join(' + ')) + '</span>' +
        '</div>' +
        '<div class="text-xs font-bold text-rose-900 mb-1">' + escapeHtml(c.title) + '</div>' +
        '<p class="text-[11px] text-rose-700 leading-relaxed mb-1.5">' + escapeHtml(c.description) + '</p>' +
        '<p class="text-[11px] text-emerald-800 bg-emerald-50 rounded-lg px-2 py-1 leading-relaxed"><strong>Çözüm:</strong> ' + escapeHtml(c.fix) + '</p>' +
        '</div>').join('');
    }
  }

  // Bulgular
  const list = document.getElementById('active-findings-list');
  const countEl = document.getElementById('active-findings-count');
  if (countEl) countEl.innerText = (data.findings.length) + ' bulgu';
  if (list) {
    if (data.findings.length === 0) {
      list.innerHTML = '<div class="p-4 text-center text-xs text-mistral-slate">Bulgu tespit edilmedi. 🎉</div>';
    } else {
      const sevColors = {
        'KRİTİK': 'border-rose-300 bg-rose-50/60',
        'YÜKSEK': 'border-orange-300 bg-orange-50/60',
        'ORTA': 'border-amber-300 bg-amber-50/60',
        'DÜŞÜK': 'border-stone-300 bg-stone-50/60',
        'BİLGİ': 'border-sky-300 bg-sky-50/60'
      };
      const sevBadges = {
        'KRİTİK': 'bg-rose-600 text-white',
        'YÜKSEK': 'bg-orange-500 text-white',
        'ORTA': 'bg-amber-500 text-white',
        'DÜŞÜK': 'bg-stone-500 text-white',
        'BİLGİ': 'bg-sky-500 text-white'
      };
      list.innerHTML = data.findings.map(f => '<div class="p-3 rounded-xl border ' + (sevColors[f.severity] || 'border-stone-200') + '">' +
        '<div class="flex items-start justify-between gap-2 mb-1.5">' +
        '<div class="flex items-center gap-2 flex-wrap">' +
        '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono ' + (sevBadges[f.severity] || 'bg-stone-500 text-white') + '">' + escapeHtml(f.severity) + '</span>' +
        '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-stone-100 border border-stone-200 text-stone-600">' + escapeHtml(f.cwe || '-') + '</span>' +
        '</div>' +
        '<span class="text-[10px] font-mono text-stone-500 whitespace-nowrap">' + escapeHtml(f.test || '') + '</span>' +
        '</div>' +
        '<div class="text-xs font-bold text-mistral-ink mb-1.5">' + escapeHtml(f.title) + '</div>' +
        '<div class="text-[10px] font-mono bg-stone-900 text-emerald-300 p-2 rounded-lg overflow-x-auto mb-1.5"><code>' + escapeHtml(f.evidence || '') + '</code></div>' +
        (f.fix && f.fix !== '-' ? '<p class="text-[11px] text-emerald-800 bg-emerald-50 rounded-lg px-2 py-1 leading-relaxed"><strong>Çözüm:</strong> ' + escapeHtml(f.fix) + '</p>' : '') +
        '</div>').join('');
    }
  }
}

// Markdown Denetim Raporunu Dışa Aktarma
function exportMarkdownReport() {
  if (!STATE.currentDomain) {
    showToast('Önce bir alan adı taramalısınız.', 'warning');
    return;
  }

  const dateStr = new Date().toISOString().split('T')[0];
  let md = `# Web Güvenlik Taraması Raporu\n\n`;
  md += `**Taranan Hedef:** \`${STATE.currentDomain}\`  \n`;
  md += `**Tarih:** ${dateStr}  \n`;
  md += `**Güvenlik Puanı:** **${STATE.score ?? 'Hesaplanmadı'} / 100** (Not: **${STATE.grade}**)  \n\n`;

  // 10 Analiz Maddesi Sonuç, Durum, Yapılması Gerekenler ve Atlanan Testler Raporu
  const itemsRep = STATE.analysisItemsReport || [];
  if (itemsRep.length) {
    md += `---\n\n## 📋 0A. Analiz Maddeleri Sonuç, Durum ve Aksiyon Raporu (10/10 Madde)\n\n`;
    for (const r of itemsRep) {
      md += `### ${r.num}. ${r.title} — ${r.statusBadge}\n`;
      md += `- **Grup:** ${r.group}\n`;
      md += `- **Tespit Edilen Durum:** ${r.detected}\n`;
      md += `- **Yapılması Gerekenler:** ${r.action}\n\n`;
    }
  }

  // Cloudflare Security Audit Skill — Kanıt Yaşam Döngüsü & Birleşik Kapsam Defteri Özeti
  const uFindings = STATE.unifiedFindings || [];
  const uRejected = STATE.unifiedRejected || [];
  const uLedger = STATE.unifiedCoverageLedger || [];
  if (uFindings.length || uLedger.length) {
    const cConf = uFindings.filter(f => f.verdict === 'confirmed').length;
    const cNeeds = uFindings.filter(f => f.verdict === 'needs_validation').length;
    const cHard = uFindings.filter(f => f.verdict === 'hardening_note').length;
    md += `---\n\n## 🧭 0. Kanıt Yaşam Döngüsü & Birleşik Kapsam Defteri (Cloudflare Audit Methodology)\n\n`;
    md += `- **✅ Confirmed (Kanıtlı Sınır İhlali):** ${cConf}\n`;
    md += `- **⚠️ Needs Validation (Çalışma Zamanı / Yetki Teyidi Gereken):** ${cNeeds}\n`;
    md += `- **🛡️ Hardening Notes (Derinlemesine Savunma Notu):** ${cHard}\n`;
    md += `- **🚫 Rejected / Disproved (Elenen Hipotez):** ${uRejected.length}\n\n`;
    if (uLedger.length) {
      md += `### 📋 Birleşik Denetim Kapsam Defteri (Unified Coverage Ledger)\n\n`;
      md += `| ID | Yüzey | Güven Sınırı | Modül | Durum | Kanıt | Boşluk (Gap) |\n|---|---|---|---|---|---|---|\n`;
      for (const r of uLedger) {
        md += `| ${r.id} | \`${r.surface}\` | \`${r.boundary}\` | ${r.module} | \`${r.status}\` | ${r.evidence} | ${r.gap || '-'} |\n`;
      }
      md += `\n`;
    }
  }
  md += `---\n\n## 🛡️ 1. HTTP Güvenlik Başlıkları Analizi\n\n`;
  md += `| Başlık | Durum | Skor | Değer / Not |\n|---|---|---|---|\n`;

  for (const [k, v] of Object.entries(STATE.results.headers.headers || {})) {
    const st = v.pass ? '✅ Güvenli' : '❌ Eksik/Zayıf';
    const val = v.value ? `\`${v.value.slice(0, 40)}...\`` : '_Yok_';
    md += `| ${v.name} | ${st} | ${v.score}/${v.maxScore} | ${val} (${v.note}) |\n`;
  }

  md += `\n---\n\n## 🌐 2. DNS & E-posta Savunma Kayıtları\n\n`;
  const dns = STATE.results.dns;
  md += `- **DMARC:** ${dns.dmarc.record ? `\`${dns.dmarc.record}\`` : '_Yok_'} (${dns.dmarc.note})\n`;
  md += `- **SPF:** ${dns.spf.record ? `\`${dns.spf.record}\`` : '_Yok_'} (${dns.spf.note})\n`;
  md += `- **DNSSEC:** ${dns.dnssec ? '✅ Aktif' : '⚠️ Yapılandırılmamış'}\n`;
  md += `- **CAA:** ${dns.caa.records.length ? `✅ Aktif (${dns.caa.records.join(', ')})` : '⚠️ Kayıt Yok'}\n`;

  md += `\n---\n\n## 🚀 3. Tavsiye Edilen Sertleştirme Çözümleri\n\n`;
  for (const [k, v] of Object.entries(STATE.results.headers.headers || {})) {
    if (!v.pass && v.fix) {
      md += `### ${v.name} Onarımı\n\`\`\`nginx\n${v.fix.nginx}\n\`\`\`\n\n`;
    }
  }

  // Faz 1: Derin Pasif Tarama bölümü
  const deep = STATE.results.deepScan;
  if (deep && deep.success) {
    md += `\n---\n\n## 🔬 4. Derin Pasif Tarama Bulguları\n\n`;

    if (deep.cookies && deep.cookies.analyzed && deep.cookies.findings) {
      md += `### 🍪 Çerez Güvenliği (${deep.cookies.count || 0} çerez)\n\n`;
      for (const c of deep.cookies.findings) {
        const okCount = (c.httponly ? 1 : 0) + (c.secure ? 1 : 0) + (['strict', 'lax'].includes((c.samesite || '').toLowerCase()) ? 1 : 0);
        md += `- **\`${c.name}\`** ${okCount === 3 ? '✅ Güvenli' : '⚠️ Eksik bayrak'} — HttpOnly: ${c.httponly ? '✅' : '❌'} • Secure: ${c.secure ? '✅' : '❌'} • SameSite: ${c.samesite}\n`;
      }
      md += `\n`;
    }

    if (deep.tls && deep.tls.analyzed) {
      md += `### 🔒 TLS / Sertifika\n\n`;
      md += `- **Protokol:** ${deep.tls.protocol || 'Bilinmiyor'}\n`;
      md += `- **Sertifika Yetkilisi:** ${deep.tls.issuer || 'Bilinmiyor'}\n`;
      const expiryNote = (deep.tls.expiry_days !== undefined && deep.tls.expiry_days !== null) ? ` (${deep.tls.expiry_days} gün kaldı)` : '';
      md += `- **Geçerlilik:** ${deep.tls.valid_until || 'Bilinmiyor'}${expiryNote}\n`;
      for (const f of (deep.tls.findings || [])) {
        md += `- ⚠️ **${f.level}:** ${f.issue}\n`;
      }
      md += `\n`;
    }

    if (deep.robots && deep.robots.analyzed) {
      md += `### 🤖 robots.txt İfşası\n\n`;
      if (!deep.robots.exists) {
        md += `- robots.txt dosyası mevcut değil.\n`;
      } else if ((deep.robots.findings || []).length === 0) {
        md += `- ✅ Hassas dizin ifşası tespit edilmedi.\n`;
      } else {
        for (const f of deep.robots.findings) {
          md += `- ⚠️ **${f.level}:** ${f.issue} (\`${f.evidence}\`)\n`;
        }
      }
      md += `\n`;
    }

    if (deep.mixed_content && deep.mixed_content.analyzed) {
      md += `### 🔗 Mixed Content\n\n`;
      if ((deep.mixed_content.findings || []).length === 0) {
        md += `- ✅ Mixed content tespit edilmedi.\n`;
      } else {
        for (const f of deep.mixed_content.findings) {
          md += `- ⚠️ **${f.level}:** ${f.issue} — \`${(f.evidence || '').slice(0, 80)}\`\n`;
        }
      }
      md += `\n`;
    }

    if (deep.tech_fingerprint && deep.tech_fingerprint.analyzed) {
      md += `### 🧩 Teknoloji Parmak İzi\n\n`;
      const techs = deep.tech_fingerprint.technologies || [];
      if (techs.length === 0) {
        md += `- ✅ Teknoloji ifşası tespit edilmedi.\n`;
      } else {
        for (const t of techs) {
          md += `- **${t.category}:** ${t.value} _(kaynak: ${t.source})_\n`;
        }
      }
      md += `\n`;
    }
  }

  // Faz 2: SAST bulguları (varsa)
  const sast = STATE.results.sast;
  if (sast && sast.success) {
    md += `\n---\n\n## 🧪 5. Kaynak Kod Analizi (SAST) — \`${sast.root}\`\n\n`;
    md += `**Taranan dosya:** ${sast.stats.files_scanned} • **Satır:** ${sast.stats.total_lines} • **Doğrulanan bulgu:** ${sast.stats.verified_count}/${sast.findings.length} • **Kural kapsamı:** ${sast.coverage.rule_coverage_pct}%\n\n`;
    md += `| Şiddet | Kural | CVSS | CWE | Doğrulandı | Dosya:Satır | Başlık |\n|---|---|---|---|---|---|---|\n`;
    for (const f of sast.findings) {
      md += `| ${f.severity} | ${f.rule_id} | ${f.cvss} | ${f.cwe} | ${f.verified ? '✓' : '—'} | \`${f.file}:${f.line}\` | ${f.title} |\n`;
    }
    if (sast.dependencies && sast.dependencies.analyzed) {
      const vulnDeps = sast.dependencies.vulnerable || [];
      md += `\n### 📦 Bağımlılık CVE Denetimi (OSV)\n\n`;
      if (vulnDeps.length === 0) {
        md += `- ✅ Bilinen CVE içeren bağımlılık tespit edilmedi.\n`;
      } else {
        for (const v of vulnDeps) {
          md += `- **${v.name}@${v.version}** (${v.ecosystem}) — ${v.vuln_count} CVE: ${v.vulns.map(x => x.id).join(', ')}\n`;
        }
      }
    }
  }

  // ⚡ Faz 3: Aktif Güvenlik Testi bulguları
  const act = STATE.results.activeScan;
  if (act && act.success) {
    md += `\n---\n\n## ⚡ 6. Aktif Güvenlik Testi Bulguları\n\n`;
    md += `**Gönderilen istek:** ${act.requests_sent || 0} • **Süre:** ${((act.duration_ms || 0) / 1000).toFixed(1)} sn • **Rate limit:** ${act.rate_limit_seconds || 1.5} sn/istek\n\n`;
    if ((act.findings || []).length === 0) {
      md += `- ✅ Aktif test bulgusu tespit edilmedi.\n`;
    } else {
      for (const f of act.findings) {
        md += `- **${f.severity}** [${f.test} · ${f.cwe || '-'}] ${f.title}\n`;
        md += `  - Kanıt: \`${(f.evidence || '').slice(0, 160).replace(/\n/g, ' ')}\`\n`;
        if (f.fix && f.fix !== '-') md += `  - Çözüm: ${f.fix}\n`;
      }
    }
    if ((act.chains || []).length) {
      md += `\n### 🔗 Risk Zincirleri (Korelasyon)\n\n`;
      for (const c of act.chains) {
        md += `- **${c.severity}** ${c.title} — ${c.description}\n  - Çözüm: ${c.fix}\n`;
      }
    }
  }

  // 🤖 AI Red Team (kanıt doğrulamalı hat)
  const ai = STATE.results.aiScan;
  if (ai && ai.success) {
    const rep = ai.ai_report || {};
    md += `\n---\n\n## 🤖 7. AI Red Team Orkestrasyonu (Scout → Strategist → Analyst → Reporter)\n\n`;
    md += `**Tur:** ${rep.loops || 0} • **Çalıştırılan AI testi:** ${rep.tests_executed || 0} • **Kanıtı doğrulanmış bulgu:** ${(ai.findings || []).length} • **Toplam istek:** ${ai.requests_sent || 0}\n\n`;
    if (ai.narrative_report) md += `${ai.narrative_report}\n\n`;
    if ((ai.findings || []).length) {
      md += `### Kanıtı Doğrulanmış AI Bulguları\n\n`;
      for (const f of ai.findings) {
        md += `- **${f.severity}** [${f.cwe || '-'}] ${f.title}\n`;
        md += `  - Kanıt: \`${(f.evidence || '').slice(0, 200).replace(/\n/g, ' ')}\`\n`;
        if (f.verdict_detail && f.verdict_detail.reasoning) md += `  - Gerekçe: ${f.verdict_detail.reasoning}\n`;
        if (f.fix && f.fix !== '-') md += `  - Çözüm: ${f.fix}\n`;
      }
    }
    if ((ai.baseline_findings || []).length) {
      md += `\n### Deterministik Motor Bulguları (AI bağlam kaynağı)\n\n`;
      for (const f of ai.baseline_findings) {
        md += `- **${f.severity}** [${f.test} · ${f.cwe || '-'}] ${f.title}\n`;
      }
    }
    if ((rep.executed_tests || []).length) {
      md += `\n### Çalıştırılan AI Testleri\n\n`;
      for (const t of rep.executed_tests) {
        md += `- ${t.verdict === 'VULNERABLE' ? '✅' : '⬜'} \`${(t.url || '').slice(0, 90)}\` param=\`${t.param}\` payload=\`${String(t.payload).slice(0, 50)}\` → ${t.verdict}\n`;
      }
    }
  }

  // ⚔️ Strix otonom pentest (gerçek araç çıktısı)
  const sx = STATE.results.strixScan;
  if (sx && sx.success) {
    const sc = sx.scan || {};
    md += `\n---\n\n## ⚔️ 8. Strix Otonom AI Pentest Raporu\n\n`;
    md += `**Çalıştırma:** \`${sc.run_name || '-'}\` • **Mod:** ${sc.mode || '-'} • **Durum:** ${sc.run_status || '-'} • **Süre:** ${sc.elapsed_sec || 0} sn${sc.llm_cost_usd ? ` • **LLM maliyeti:** $${sc.llm_cost_usd}` : ''}\n\n`;
    if ((sx.findings || []).length === 0) {
      md += `- ✅ Strix doğrulanmış bulgu üretmedi.\n`;
    } else {
      for (const f of sx.findings) {
        md += `### ${f.severity} — ${(f.title || '').replace(/^\[STRIX\]\s*/, '')}\n\n`;
        const ep = `${(f.method || '').trim()} ${(f.endpoint || '').trim()}`.trim();
        md += `- **CVSS:** ${f.cvss != null ? f.cvss : '-'} • **CWE:** ${f.cwe || '-'} • **Endpoint:** ${ep ? '\`' + ep + '\`' : '-'}\n`;
        if (f.description) md += `- **Açıklama:** ${f.description}\n`;
        if (f.impact) md += `- **Etki:** ${f.impact}\n`;
        if (f.evidence) md += `- **Kanıt:** \`${f.evidence.slice(0, 250).replace(/\n/g, ' ')}\`\n`;
        if (f.confidence) md += `- **Güven:** ${f.confidence}\n`;
        if (f.poc) md += `- **PoC:**\n\n\`\`\`\n${f.poc.slice(0, 800)}\n\`\`\`\n`;
        if (f.fix && f.fix !== '-') md += `- **Çözüm:** ${f.fix}\n`;
        md += `\n`;
      }
    }
  }

  md += `\n---\n\n*Rapor, [Web Security Scanner](https://melihkarasu.github.io/web-security-scanner/) tarafından üretilmiştir. Tarama tarihi: ${new Date().toISOString()}.*`;

  STATE.reportMarkdown = md;
  downloadFile(`${STATE.currentDomain}-guvenlik-raporu.md`, md, 'text/markdown');
  showToast('Markdown raporu indirildi!', 'success');
}

// JSON Rapor Dışa Aktarma (Faz 4 — makine okunabilir format)
function exportJsonReport() {
  if (!STATE.currentDomain && !STATE.results.sast) {
    showToast('Önce bir tarama yapmalısınız.', 'warning');
    return;
  }

  const report = {
    tool: 'Web Security Scanner',
    version: '1.0.0',
    generated_at: new Date().toISOString(),
    mode: STATE.mode,
    target: {
      domain: STATE.currentDomain || null,
      url: STATE.targetUrl || null,
      score: STATE.score,
      grade: STATE.grade
    },
    results: STATE.results
  };

  const name = STATE.currentDomain || 'sast-taramasi';
  downloadFile(`${name}-guvenlik-raporu.json`, JSON.stringify(report, null, 2), 'application/json');
  showToast('JSON raporu indirildi!', 'success');
}

// HTML Rapor Dışa Aktarma (Faz 4 — compliance-ready format)
function exportHtmlReport() {
  if (!STATE.reportMarkdown && !STATE.currentDomain) {
    showToast('Önce bir tarama yapmalısınız.', 'warning');
    return;
  }

  let src = STATE.reportMarkdown || '';
  // 1) HTML escape
  let body = src.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  // 2) Kod blokları (korumalı — diğer dönüşümlerden önce)
  const codeBlocks = [];
  body = body.replace(/```[a-z]*\n([\s\S]*?)```/g, (m, code) => {
    codeBlocks.push(code);
    return `@@CODEBLOCK${codeBlocks.length - 1}@@`;
  });

  // 3) Başlıklar
  body = body.replace(/^# (.+)$/gm, '<h1>$1</h1>');
  body = body.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  body = body.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  body = body.replace(/^---$/gm, '<hr>');

  // 4) Tablolar
  body = body.replace(/((?:^\|.*\|\s*\n)+)/gm, (block) => {
    const rows = block.trim().split('\n');
    let out = '<table>';
    rows.forEach((row, idx) => {
      if (row.includes('---')) return;
      const cells = row.split('|').slice(1, -1).map(c => c.trim());
      const tag = idx === 0 ? 'th' : 'td';
      out += '<tr>' + cells.map(c => `<${tag}>${c}</${tag}>`).join('') + '</tr>';
    });
    return out + '</table>';
  });

  // 5) Satır içi biçimlendirme
  body = body.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  body = body.replace(/_([^_]+)_/g, '<em>$1</em>');
  body = body.replace(/`([^`\n]+)`/g, '<code>$1</code>');

  // 6) Listeler
  body = body.replace(/((?:^- .+\n?)+)/gm, (block) => {
    const items = block.trim().split('\n').map(l => `<li>${l.replace(/^- /, '')}</li>`).join('');
    return `<ul>${items}</ul>`;
  });

  // 7) Kod bloklarını geri yerleştir
  body = body.replace(/@@CODEBLOCK(\d+)@@/g, (m, idx) => `<pre><code>${codeBlocks[parseInt(idx, 10)]}</code></pre>`);

  const fullHtml = `<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <title>Web Güvenlik Taraması Raporu — ${STATE.currentDomain || 'SAST'}</title>
  <style>
    body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 24px; color: #1c1917; background: #fdfaf6; line-height: 1.6; }
    h1 { border-bottom: 3px solid #fa520f; padding-bottom: 8px; }
    h2 { margin-top: 28px; }
    h3 { margin-top: 20px; }
    code { background: #f5f5f4; padding: 2px 5px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 0.9em; }
    pre { background: #1c1917; color: #fbbf24; padding: 12px; border-radius: 8px; overflow-x: auto; }
    pre code { background: transparent; color: inherit; padding: 0; }
    table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 13px; }
    th, td { border: 1px solid #e7e5e4; padding: 6px 10px; text-align: left; }
    th { background: #f5f5f4; }
    hr { border: none; border-top: 1px solid #e7e5e4; margin: 24px 0; }
    ul { padding-left: 22px; }
    li { margin: 4px 0; }
  </style>
</head>
<body>
${body}
</body>
</html>`;

  const name = STATE.currentDomain || 'sast-taramasi';
  downloadFile(`${name}-guvenlik-raporu.html`, fullHtml, 'text/html');
  showToast('HTML raporu indirildi!', 'success');
}
// 5. Yardımcı Fonksiyonlar & Başlatma
// =============================================================
function toggleLoading(isLoading) {
  const btn = document.getElementById('scan-btn');
  const spinner = document.getElementById('scan-spinner');
  const btnText = document.getElementById('scan-btn-text');

  if (btn) btn.disabled = isLoading;
  if (spinner) spinner.classList.toggle('hidden', !isLoading);
  if (btnText) btnText.innerText = isLoading ? 'Denetleniyor...' : 'Güvenlik Taramasıni Başlat';
}

function selectPreset(domain) {
  const inputEl = document.getElementById('target-input');
  if (inputEl) {
    inputEl.value = domain;
    startSecurityScan();
  }
}

function showToast(msg, type = 'info') {
  const toast = document.createElement('div');
  const bg = type === 'success' ? 'bg-emerald-600' : type === 'warning' ? 'bg-amber-600' : type === 'error' ? 'bg-rose-600' : 'bg-stone-900';
  toast.className = `fixed bottom-6 right-6 z-50 text-white px-4 py-3 rounded-xl shadow-lg text-xs font-medium flex items-center gap-2 transition-all transform translate-y-2 opacity-0 ${bg}`;
  toast.innerHTML = `<span>${escapeHtml(msg)}</span>`;
  document.body.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  });

  setTimeout(() => {
    toast.classList.add('translate-y-2', 'opacity-0');
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      showToast('Koda kopyalandı!', 'success');
    }).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try {
    document.execCommand('copy');
    showToast('Koda kopyalandı!', 'success');
  } catch (err) {
    showToast('Kopyalama başarısız', 'error');
  }
  document.body.removeChild(ta);
}

function downloadFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function escapeAttr(str) {
  if (!str) return '';
  return String(str).replace(/"/g, '&quot;').replace(/'/g, "\\'");
}

// Sekme Değiştirme
function switchTab(tabId) {
  STATE.activeTab = tabId;
  const tabs = ['audit', 'headers', 'sast', 'active', 'checklist'];
  for (const t of tabs) {
    const el = document.getElementById(`tab-content-${t}`);
    const btn = document.getElementById(`tab-btn-${t}`);
    if (el) el.classList.toggle('hidden', t !== tabId);
    if (btn) {
      if (t === tabId) {
        btn.className = 'px-4 py-2 rounded-lg text-xs font-bold bg-white text-mistral-ink shadow-xs border border-stone-200 transition-all';
      } else {
        btn.className = 'px-4 py-2 rounded-lg text-xs font-semibold text-mistral-slate hover:text-mistral-ink transition-all';
      }
    }
  }
}

// =============================================================
// AI Red Team Orkestrasyon Fonksiyonları
// =============================================================

function toggleAIConfig() {
  const panel = document.getElementById('ai-config-panel');
  if (!panel) return;
  const isHidden = panel.classList.contains('hidden');
  panel.classList.toggle('hidden', !isHidden);
  if (isHidden) {
    updateAIStatusUI();
  }
}

function setModelPreset(name) {
  const modelInput = document.getElementById('ai-model');
  if (modelInput) {
    modelInput.value = name;
    saveAIConfig(false);
  }
}

function onAIProviderChange() {
  const provider = document.getElementById('ai-provider')?.value || 'openai';
  const baseUrlContainer = document.getElementById('ai-base-url-container');
  const projectIdContainer = document.getElementById('ai-project-id-container');
  const regionContainer = document.getElementById('ai-region-container');
  const authTypeContainer = document.getElementById('ai-auth-type-container');
  const authLabel = document.getElementById('ai-auth-label');
  const authInput = document.getElementById('ai-auth');
  const modelInput = document.getElementById('ai-model');
  const baseUrlInput = document.getElementById('ai-base-url');
  const regionInput = document.getElementById('ai-region');

  // Varsayılan görünürlükleri sıfırla
  baseUrlContainer?.classList.add('hidden');
  projectIdContainer?.classList.add('hidden');
  regionContainer?.classList.add('hidden');
  authTypeContainer?.classList.add('hidden');

  if (provider === 'openai') {
    baseUrlContainer?.classList.remove('hidden');
    if (authLabel) authLabel.innerText = 'OpenAI Compatible API Key (sk-...)';
    if (authInput) authInput.placeholder = 'sk-... (veya yerel model için boş / anahtarınız)';
    if (baseUrlInput && (!baseUrlInput.value || baseUrlInput.value.includes('localhost:11434'))) {
      baseUrlInput.value = 'https://api.openai.com/v1';
    }
  } else if (provider === 'gemini') {
    if (authLabel) authLabel.innerText = 'Google AI Studio Gemini API Key (AIza...)';
    if (authInput) authInput.placeholder = 'AIzaSy...';
    if (modelInput && (!modelInput.value || modelInput.value === 'gpt-4o')) {
      modelInput.value = 'gemini-3.1-pro';
    }
  } else if (provider === 'vertex') {
    projectIdContainer?.classList.remove('hidden');
    regionContainer?.classList.remove('hidden');
    authTypeContainer?.classList.remove('hidden');
    if (regionInput && (!regionInput.value || regionInput.value === 'us-central1')) {
      regionInput.value = 'global';
    }
    if (modelInput && (!modelInput.value || modelInput.value === 'gpt-4o')) {
      modelInput.value = 'gemini-3.1-pro';
    }
    onAuthTypeChange();
  } else if (provider === 'openrouter') {
    if (authLabel) authLabel.innerText = 'OpenRouter API Key (sk-or-...)';
    if (authInput) authInput.placeholder = 'sk-or-v1-...';
    if (modelInput && (!modelInput.value || modelInput.value === 'gpt-4o')) {
      modelInput.value = 'google/gemini-3.1-pro';
    }
  } else if (provider === 'ollama') {
    baseUrlContainer?.classList.remove('hidden');
    if (authLabel) authLabel.innerText = 'Kimlik Doğrulama (İsteğe bağlı)';
    if (authInput) authInput.placeholder = 'Yerel Ollama için genellikle boş bırakılır';
    if (baseUrlInput && (!baseUrlInput.value || baseUrlInput.value.includes('api.openai.com'))) {
      baseUrlInput.value = 'http://localhost:11434';
    }
    if (modelInput && (!modelInput.value || modelInput.value.includes('gemini') || modelInput.value === 'gpt-4o')) {
      modelInput.value = 'gemma2';
    }
  }

  updateAIStatusUI();
  saveAIConfig(false);
}

function onAuthTypeChange() {
  const authType = document.getElementById('ai-auth-type')?.value || 'service_account';
  const authLabel = document.getElementById('ai-auth-label');
  const authInput = document.getElementById('ai-auth');
  if (!authLabel || !authInput) return;

  if (authType === 'service_account') {
    authLabel.innerText = 'Vertex Service Account JSON İçeriği (veya JSON Dosya Yolu)';
    authInput.placeholder = '{\n  "type": "service_account",\n  "project_id": "...",\n  "private_key": "-----BEGIN PRIVATE KEY-----..."\n}';
  } else {
    authLabel.innerText = 'Vertex AI API Key';
    authInput.placeholder = 'AQ.Ab... veya API Key';
  }
}

function saveAIConfig(notify = true) {
  try {
    const config = {
      provider: document.getElementById('ai-provider')?.value || 'openai',
      model: document.getElementById('ai-model')?.value || 'gemini-3.1-pro',
      base_url: document.getElementById('ai-base-url')?.value || '',
      project_id: document.getElementById('ai-project-id')?.value || '',
      region: document.getElementById('ai-region')?.value || 'global',
      auth_type: document.getElementById('ai-auth-type')?.value || 'service_account',
      auth: document.getElementById('ai-auth')?.value || ''
    };
    localStorage.setItem('wss_ai_config', JSON.stringify(config));
    updateAIStatusUI();
    if (notify) showToast('AI ayarları tarayıcı hafızasına (LocalStorage) kaydedildi.', 'success');
  } catch (e) {
    console.error('AI ayarları kaydedilemedi:', e);
  }
}

function loadAIConfig() {
  try {
    const raw = localStorage.getItem('wss_ai_config');
    if (!raw) {
      onAIProviderChange();
      return;
    }
    const config = JSON.parse(raw);
    if (config.provider && document.getElementById('ai-provider')) document.getElementById('ai-provider').value = config.provider;
    if (config.model && document.getElementById('ai-model')) document.getElementById('ai-model').value = config.model;
    if (config.base_url && document.getElementById('ai-base-url')) document.getElementById('ai-base-url').value = config.base_url;
    if (config.project_id && document.getElementById('ai-project-id')) document.getElementById('ai-project-id').value = config.project_id;
    if (config.region && document.getElementById('ai-region')) document.getElementById('ai-region').value = config.region;
    if (config.auth_type && document.getElementById('ai-auth-type')) document.getElementById('ai-auth-type').value = config.auth_type;
    if (config.auth && document.getElementById('ai-auth')) document.getElementById('ai-auth').value = config.auth;
    onAIProviderChange();
  } catch (e) {
    console.error('AI ayarları yüklenemedi:', e);
  }
}

function updateAIStatusUI() {
  const indicator = document.getElementById('ai-status-indicator');
  const text = document.getElementById('ai-status-text');
  const provider = document.getElementById('ai-provider');
  const model = document.getElementById('ai-model')?.value || '';
  if (!indicator || !text || !provider) return;
  
  const val = provider.value;
  if (val === 'openai') {
    indicator.className = 'w-2.5 h-2.5 rounded-full bg-emerald-500';
    text.innerText = `OpenAI Compatible Aktif (${model || 'Endpoint'})`;
  } else if (val === 'gemini') {
    indicator.className = 'w-2.5 h-2.5 rounded-full bg-amber-500';
    text.innerText = `Gemini API Aktif (${model || 'gemini-3.1-pro'})`;
  } else if (val === 'vertex') {
    indicator.className = 'w-2.5 h-2.5 rounded-full bg-indigo-500';
    text.innerText = `Vertex AI (Bölge: global, Model: ${model || 'gemini-3.1-pro'})`;
  } else if (val === 'openrouter') {
    indicator.className = 'w-2.5 h-2.5 rounded-full bg-purple-500';
    text.innerText = `OpenRouter Aktif (${model || 'Modeller'})`;
  } else if (val === 'ollama') {
    indicator.className = 'w-2.5 h-2.5 rounded-full bg-sky-500';
    text.innerText = `Ollama Aktif (${model || 'Lokal Model'})`;
  }
}

async function testAIConnection() {
  const btn = document.getElementById('ai-test-btn');
  const spinner = document.getElementById('ai-test-spinner');
  const btnText = document.getElementById('ai-test-btn-text');
  
  const provider = document.getElementById('ai-provider')?.value || 'openai';
  const model = document.getElementById('ai-model')?.value.trim() || '';
  const baseUrl = document.getElementById('ai-base-url')?.value.trim() || '';
  const projectId = document.getElementById('ai-project-id')?.value.trim() || '';
  const region = document.getElementById('ai-region')?.value.trim() || 'global';
  const authType = document.getElementById('ai-auth-type')?.value || 'service_account';
  const auth = document.getElementById('ai-auth')?.value.trim() || '';

  if (!model) {
    showToast('Lütfen test edilecek model adını belirtin.', 'warning');
    return;
  }

  saveAIConfig(false);

  if (btn) btn.disabled = true;
  spinner?.classList.remove('hidden');
  if (btnText) btnText.innerText = 'Test Ediliyor...';

  try {
    const res = await fetch('/api/ai-test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ai_config: {
          provider: provider,
          model: model,
          base_url: baseUrl,
          project_id: projectId,
          region: region,
          auth: {
            type: authType,
            value: auth
          },
          api_key: auth
        }
      }),
      signal: AbortSignal.timeout(30000)
    });

    const data = await res.json();
    if (data.success) {
      showToast(data.message || 'LLM Bağlantısı Başarılı!', 'success');
      appendAILog(`[Test] ${provider} (${model}) bağlantısı başarılı: ${data.message || 'OK'}`, 'success');
    } else {
      showToast(`Bağlantı Başarısız: ${data.error || 'Bilinmeyen hata'}`, 'error');
      appendAILog(`[Test Hatası] ${data.error || 'Bilinmeyen hata'}`, 'error');
    }
  } catch (err) {
    showToast(`Test isteği başarısız: ${err.message}`, 'error');
    appendAILog(`[Test İstek Hatası] ${err.message}`, 'error');
  } finally {
    if (btn) btn.disabled = false;
    spinner?.classList.add('hidden');
    if (btnText) btnText.innerText = 'Bağlantıyı Test Et';
  }
}

function clearAILog() {
  const logEl = document.getElementById('ai-thought-log');
  if (logEl) {
    logEl.innerHTML = '<div class="text-stone-600">[Sistem] Log temizlendi. Yeni AI taraması başlatıldığında buraya yazılacak.</div>';
  }
}

function appendAILog(message, type = 'info') {
  const logEl = document.getElementById('ai-thought-log');
  if (!logEl) return;
  
  const colors = {
    'system': 'text-stone-500',
    'scout': 'text-cyan-400',
    'strategist': 'text-amber-400',
    'analyst': 'text-emerald-400',
    'error': 'text-rose-400',
    'info': 'text-stone-300',
    'success': 'text-emerald-400'
  };
  
  const icons = {
    'system': '⚙️',
    'scout': '🔍',
    'strategist': '🎯',
    'analyst': '🧠',
    'error': '❌',
    'info': 'ℹ️',
    'success': '✅'
  };
  
  const timestamp = new Date().toLocaleTimeString('tr-TR', { hour12: false });
  const color = colors[type] || colors.info;
  const icon = icons[type] || icons.info;
  
  const entry = document.createElement('div');
  entry.className = color + ' border-l-2 border-stone-700 pl-2';
  entry.innerHTML = '<span class="text-stone-600">[' + timestamp + ']</span> <span class="font-bold">' + icon + ' ' + type.toUpperCase() + ':</span> ' + escapeHtml(message);
  
  logEl.appendChild(entry);
  logEl.scrollTop = logEl.scrollHeight;
}

function setAIThinking(state, agentName = '') {
  const indicator = document.getElementById('ai-thinking-indicator');
  const text = document.getElementById('ai-thinking-text');
  if (!indicator || !text) return;
  
  if (state === 'thinking') {
    indicator.className = 'w-2 h-2 rounded-full bg-amber-500 animate-pulse';
    text.innerText = agentName ? agentName + ' düşünüyor...' : 'AI ajanları çalışıyor...';
  } else if (state === 'idle') {
    indicator.className = 'w-2 h-2 rounded-full bg-stone-600';
    text.innerText = 'Beklemede';
  } else if (state === 'complete') {
    indicator.className = 'w-2 h-2 rounded-full bg-emerald-500';
    text.innerText = 'Analiz tamamlandı';
  } else if (state === 'error') {
    indicator.className = 'w-2 h-2 rounded-full bg-rose-500';
    text.innerText = 'Hata oluştu';
  }
}

async function startAIOrchestrationScan(targetUrl, modules) {
  const aiProvider = document.getElementById('ai-provider')?.value || 'openai';
  const aiModel = document.getElementById('ai-model')?.value.trim() || 'gemini-3.1-pro';
  const aiBaseUrl = document.getElementById('ai-base-url')?.value.trim() || '';
  const aiProjectId = document.getElementById('ai-project-id')?.value.trim() || '';
  const aiRegion = document.getElementById('ai-region')?.value.trim() || 'global';
  const aiAuthType = document.getElementById('ai-auth-type')?.value || 'service_account';
  const aiAuth = document.getElementById('ai-auth')?.value.trim() || '';
  
  if (!aiModel) {
    showToast('Model adı boş olamaz.', 'warning');
    return null;
  }
  
  if (aiProvider === 'vertex' && (!aiProjectId || !aiAuth)) {
    showToast('Vertex AI için Project ID ve Service Account JSON/API Key gereklidir.', 'warning');
    return null;
  }
  
  if ((aiProvider === 'gemini' || aiProvider === 'openrouter') && !aiAuth) {
    showToast(`${aiProvider} için API Key gereklidir.`, 'warning');
    return null;
  }

  saveAIConfig(false);
  
  // UI: AI düşünce akışı sekmesine geç ve başlat
  if (typeof switchDetailTab === 'function') switchDetailTab('tab-ai');
  clearAILog();
  appendAILog('AI Red Team orkestrasyonu başlatılıyor...', 'system');
  appendAILog('Sağlayıcı: ' + aiProvider + ' | Model: ' + aiModel + (aiProvider === 'vertex' ? ' (Bölge: ' + aiRegion + ')' : ''), 'info');
  setAIThinking('thinking', 'The Scout');
  
  try {
    const res = await fetch('/api/ai-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: targetUrl,
        modules: modules,
        ai_config: {
          provider: aiProvider,
          model: aiModel,
          base_url: aiBaseUrl,
          project_id: aiProjectId,
          region: aiRegion,
          auth: {
            type: aiAuthType,
            value: aiAuth
          },
          api_key: aiAuth
        }
      }),
      signal: AbortSignal.timeout(900000) // 15 dk: keşif fazı + AI döngüleri (rate-limit'li)
    });
    
    const data = await res.json();
    
    if (!data.success) {
      appendAILog('Orkestrasyon hatası: ' + (data.error || data.message || 'Bilinmeyen hata'), 'error');
      setAIThinking('error');
      showToast('AI tarama hatası: ' + (data.error || 'Bilinmeyen hata'), 'error');
      return null;
    }
    
    // AI thought chain loglarını işle (sunucu tüm aşamaları biriktirip döndürür)
    if (data.thought_chain && Array.isArray(data.thought_chain)) {
      for (const entry of data.thought_chain) {
        appendAILog(entry.message, entry.agent || 'info');
      }
    }
    
    appendAILog('AI orkestrasyonu tamamlandı: ' + (data.findings?.length || 0) + ' doğrulanmış bulgu (' + (data.requests_sent || 0) + ' istek).', 'success');
    setAIThinking('complete');
    renderAIReportCard(data);
    
    return data;
    
  } catch (err) {
    appendAILog('İstek hatası: ' + err.message, 'error');
    setAIThinking('error');
    showToast('AI orkestrasyon isteği başarısız: ' + err.message, 'error');
    return null;
  }
}

// =============================================================
// UNIFIED SCANNER CONTROLLER (TEK MERKEZLİ TARAMA YÖNETİCİSİ)
// =============================================================

function setScannerEdition(edition, save = true) {
  const ed = edition === 'lite' ? 'lite' : 'full';
  STATE.edition = ed;
  if (save) {
    try { localStorage.setItem('wss_edition', ed); } catch (e) {}
  }

  const badge = document.getElementById('header-edition-badge');
  const btnLite = document.getElementById('edition-btn-lite');
  const btnFull = document.getElementById('edition-btn-full');
  const headerAiBtn = document.getElementById('header-ai-btn');
  const aiPanel = document.getElementById('ai-config-panel');
  const aiGroupBox = document.getElementById('ai-analysis-group-box');
  const tabAiBtn = document.getElementById('btn-tab-ai');
  const tabStrixBtn = document.getElementById('btn-tab-strix');
  const sastAiBtn = document.getElementById('sast-ai-btn');

  if (ed === 'lite') {
    if (badge) {
      badge.innerText = 'v2.0 Lite';
      badge.className = 'text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200 font-bold';
    }
    if (btnLite) btnLite.className = 'segmented-item is-active-emerald';
    if (btnFull) btnFull.className = 'segmented-item';
    headerAiBtn?.classList.add('hidden');
    aiPanel?.classList.add('hidden');
    aiGroupBox?.classList.add('hidden');
    tabAiBtn?.classList.add('hidden');
    tabStrixBtn?.classList.add('hidden');
    sastAiBtn?.classList.add('hidden');
    toggleAnalysisGroup('ai', false);
  } else {
    if (badge) {
      badge.innerText = 'v2.0 Full';
      badge.className = 'text-[10px] font-mono px-2 py-0.5 rounded-full bg-orange-100 text-mistral-orange border border-orange-200 font-bold';
    }
    if (btnFull) btnFull.className = 'segmented-item is-active-orange';
    if (btnLite) btnLite.className = 'segmented-item';
    headerAiBtn?.classList.remove('hidden');
    aiGroupBox?.classList.remove('hidden');
    tabAiBtn?.classList.remove('hidden');
    tabStrixBtn?.classList.remove('hidden');
    sastAiBtn?.classList.remove('hidden');
  }
}

function toggleAnalysisGroup(group, checked) {
  const cls = group === 'ai' ? '.group-ai' : '.group-standard';
  document.querySelectorAll(cls).forEach(el => { el.checked = Boolean(checked); });
  syncLegacyModuleFlags();
}

function syncLegacyModuleFlags() {
  const cHeaders = document.getElementById('chk-headers')?.checked ?? true;
  const cDns = document.getElementById('chk-dns')?.checked ?? true;
  const cDeep = document.getElementById('chk-deep')?.checked ?? true;
  const cSast = document.getElementById('chk-sast')?.checked ?? true;
  const cActInj = document.getElementById('chk-active-inj')?.checked ?? true;
  const cActAcc = document.getElementById('chk-active-access')?.checked ?? true;
  const cActCrawl = document.getElementById('chk-active-crawl')?.checked ?? true;
  const cAiRed = document.getElementById('chk-ai-redteam')?.checked ?? false;
  const cAiSast = document.getElementById('chk-ai-sast')?.checked ?? false;
  const cAiPen = document.getElementById('chk-ai-pentest')?.checked ?? false;

  const setChk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = v; };
  setChk('mod-passive', cHeaders || cDns);
  setChk('mod-deep', cDeep);
  setChk('mod-sast', cSast);
  setChk('mod-active', cActInj || cActAcc || cActCrawl);
  setChk('mod-ai', cAiRed || cAiSast || cAiPen);

  document.querySelectorAll('.module-card').forEach(card => {
    const chk = card.querySelector('input[type="checkbox"]');
    if (chk) card.classList.toggle('is-checked', chk.checked);
  });

  onActiveModuleToggle();
}

function isAICredentialsConfigured() {
  const provider = document.getElementById('ai-provider')?.value || 'openai';
  const model = (document.getElementById('ai-model')?.value || '').trim();
  const auth = (document.getElementById('ai-auth')?.value || '').trim();
  const projectId = (document.getElementById('ai-project-id')?.value || '').trim();
  if (!model) return false;
  if (provider === 'ollama') return true;
  if (provider === 'vertex') return Boolean(projectId && auth);
  return Boolean(auth);
}

function onActiveModuleToggle() {
  const modActive = document.getElementById('mod-active')?.checked;
  const modAi = document.getElementById('mod-ai')?.checked;
  const eth = document.getElementById('unified-ethical-container');
  if (eth) {
    eth.style.display = (modActive || modAi) ? 'block' : 'none';
  }
}

function onAIModuleToggle() {
  onActiveModuleToggle();
}

function switchDetailTab(tabId) {
  document.querySelectorAll('.detail-tab-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.detail-tab-btn').forEach(btn => {
    btn.classList.remove('active');
  });

  const target = document.getElementById(tabId);
  if (target) target.classList.remove('hidden');

  const btn = document.getElementById('btn-' + tabId);
  if (btn) {
    btn.classList.add('active');
  }
}

function selectPreset(domain) {
  const input = document.getElementById('unified-target-input');
  if (input) {
    input.value = domain;
    input.focus();
  }
}

function showScanError(title, message, steps = []) {
  const card = document.getElementById('scan-error-card');
  const t = document.getElementById('scan-error-title');
  const m = document.getElementById('scan-error-message');
  const ul = document.getElementById('scan-error-steps');

  if (!card) return;
  card.classList.remove('hidden');
  if (t) t.innerText = title;
  if (m) m.innerText = message;
  if (ul) {
    ul.innerHTML = steps.map(s => `<li>${escapeHtml(s)}</li>`).join('');
  }
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideScanError() {
  const card = document.getElementById('scan-error-card');
  if (card) card.classList.add('hidden');
}

function updateProgressBar(percent, statusText) {
  const pContainer = document.getElementById('scan-progress-container');
  const pBar = document.getElementById('scan-progress-bar');
  const pText = document.getElementById('scan-progress-percent');
  const pStatus = document.getElementById('scan-progress-status');

  if (pContainer) pContainer.classList.remove('hidden');
  if (pBar) pBar.style.width = percent + '%';
  if (pText) pText.innerText = Math.round(percent) + '%';
  if (pStatus) {
    pStatus.innerHTML = `<span class="w-2 h-2 rounded-full bg-mistral-orange animate-ping"></span><span>${escapeHtml(statusText)}</span>`;
  }
}

function completeProgressBar() {
  updateProgressBar(100, 'Tarama başarıyla tamamlandı.');
  setTimeout(() => {
    const pContainer = document.getElementById('scan-progress-container');
    if (pContainer) pContainer.classList.add('hidden');
  }, 1200);
}

function renderUnifiedDashboard(domain, findings, reqCount, elapsedSec) {
  const dashDomain = document.getElementById('dash-score-domain');
  const dashScoreBadge = document.getElementById('dash-score-badge');
  const dashScorePoints = document.getElementById('dash-score-points');
  const dashCritical = document.getElementById('dash-critical-count');
  const dashWarning = document.getElementById('dash-warning-count');
  const dashRequests = document.getElementById('dash-requests-count');
  const dashTime = document.getElementById('dash-time-elapsed');
  const badgeFindings = document.getElementById('badge-findings-count');
  const listEl = document.getElementById('unified-findings-list');

  if (dashDomain) dashDomain.innerText = domain;
  if (dashRequests) dashRequests.innerText = reqCount;
  if (dashTime) dashTime.innerText = `Süre: ${elapsedSec}s`;

  // Skor (Yalnızca en az bir modül gerçek skor ürettiyse göster; sahte 85 puan üretme!)
  const hasValidScore = typeof STATE.score === 'number' && !isNaN(STATE.score);
  const score = hasValidScore ? STATE.score : null;
  const grade = (hasValidScore && STATE.grade && STATE.grade !== '?') ? STATE.grade : '—';
  if (dashScorePoints) dashScorePoints.innerText = hasValidScore ? `${score} / 100 Puan` : 'Hesaplanmadı';
  if (dashScoreBadge) {
    dashScoreBadge.innerText = grade;
    if (!hasValidScore) {
      dashScoreBadge.className = 'w-14 h-14 rounded-2xl bg-stone-100 text-stone-500 flex items-center justify-center text-2xl font-black font-editorial border border-stone-300';
    } else if (grade.startsWith('A')) {
      dashScoreBadge.className = 'w-14 h-14 rounded-2xl bg-emerald-100 text-emerald-800 flex items-center justify-center text-2xl font-black font-editorial border border-emerald-300';
    } else if (grade.startsWith('B')) {
      dashScoreBadge.className = 'w-14 h-14 rounded-2xl bg-amber-100 text-amber-800 flex items-center justify-center text-2xl font-black font-editorial border border-amber-300';
    } else {
      dashScoreBadge.className = 'w-14 h-14 rounded-2xl bg-rose-100 text-rose-800 flex items-center justify-center text-2xl font-black font-editorial border border-rose-300';
    }
  }

  // Tehdit sayıları (Cloudflare Audit Methodology: Yalnızca confirmed bulgular kritik/yüksek tehdit sayacını artırır)
  let crit = 0;
  let warn = 0;
  let countConfirmed = 0;
  let countNeeds = 0;
  let countHardening = 0;
  const rejectedList = STATE.unifiedRejected || [];

  findings.forEach((f, idx) => {
    if (!f.candidate_id) f.candidate_id = 'CF-' + String(idx + 1).padStart(3, '0');
    if (!f.verdict) {
      const sevUpper = (f.severity || '').toUpperCase();
      if (sevUpper === 'BİLGİ' || sevUpper === 'DÜŞÜK') f.verdict = 'hardening_note';
      else f.verdict = 'confirmed';
    }
    if (f.verdict === 'confirmed') {
      countConfirmed++;
      const s = (f.severity || '').toUpperCase();
      if (s.includes('KRİTİK') || s.includes('YÜKSEK')) crit++;
      else warn++;
    } else if (f.verdict === 'needs_validation') {
      countNeeds++;
      warn++;
    } else if (f.verdict === 'hardening_note') {
      countHardening++;
    }
  });

  if (dashCritical) dashCritical.innerText = crit;
  if (dashWarning) dashWarning.innerText = warn;
  if (badgeFindings) badgeFindings.innerText = findings.length;

  STATE.unifiedFindings = findings;
  STATE.unifiedVerdictFilter = STATE.unifiedVerdictFilter || 'all';

  // Cloudflare Kanıt Yaşam Döngüsü sayaçlarını güncelle
  const vBar = document.getElementById('unified-verdict-bar');
  if (vBar) {
    vBar.classList.remove('hidden');
    const setTxt = (id, v) => { const el = document.getElementById(id); if (el) el.innerText = v; };
    setTxt('vcount-all', findings.length);
    setTxt('vcount-confirmed', countConfirmed);
    setTxt('vcount-needs', countNeeds);
    setTxt('vcount-hardening', countHardening);
    setTxt('vcount-rejected', rejectedList.length);
  }

  renderFilteredUnifiedFindings();
}

function setUnifiedVerdictFilter(filter) {
  STATE.unifiedVerdictFilter = filter || 'all';
  ['all', 'confirmed', 'needs_validation', 'hardening_note', 'rejected'].forEach(k => {
    const btn = document.getElementById('vfilter-' + k);
    if (!btn) return;
    if (k === STATE.unifiedVerdictFilter) {
      btn.className = 'btn btn-xs btn-primary';
    } else {
      btn.className = 'btn btn-xs btn-secondary';
    }
  });
  renderFilteredUnifiedFindings();
}

function renderFilteredUnifiedFindings() {
  const listEl = document.getElementById('unified-findings-list');
  if (!listEl) return;
  const filter = STATE.unifiedVerdictFilter || 'all';
  const findings = STATE.unifiedFindings || [];
  const rejected = STATE.unifiedRejected || [];

  const activeItems = filter === 'rejected'
    ? rejected
    : (filter === 'all' ? findings : findings.filter(f => f.verdict === filter));

  if (activeItems.length === 0) {
    listEl.innerHTML = `
      <div class="p-8 text-center rounded-2xl border border-emerald-200 bg-emerald-50/50">
        <span class="text-3xl">${filter === 'rejected' ? '🛡️' : '🎉'}</span>
        <h4 class="font-bold text-emerald-950 mt-2">${filter === 'rejected' ? 'Bu Taramada Elenen (Rejected) Aday Kaydı Yok' : 'Bu Kategoride Bulgu Tespit Edilmedi!'}</h4>
        <p class="text-xs text-emerald-800 mt-1">Cloudflare Kanıt Yaşam Döngüsü filtresini değiştirerek diğer kategorileri inceleyebilirsiniz.</p>
      </div>
    `;
    return;
  }

  const verdictBadges = {
    confirmed: '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-100 text-emerald-900 border border-emerald-300">✅ CONFIRMED</span>',
    needs_validation: '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-amber-100 text-amber-900 border border-amber-300">⚠️ NEEDS VALIDATION</span>',
    hardening_note: '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-sky-100 text-sky-900 border border-sky-300">🛡️ HARDENING NOTE</span>',
    rejected: '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-stone-200 text-stone-700 border border-stone-300">🚫 REJECTED / DISPROVED</span>'
  };

  listEl.innerHTML = activeItems.map(f => {
    const sev = f.severity || 'ORTA';
    const isHigh = sev.includes('KRİTİK') || sev.includes('YÜKSEK');
    const badgeBg = isHigh ? 'bg-rose-100 text-rose-800 border-rose-200' : 'bg-amber-100 text-amber-800 border-amber-200';
    const vBadge = verdictBadges[f.verdict] || verdictBadges.confirmed;

    return `
      <div class="p-4 rounded-2xl border border-stone-200 bg-white shadow-xs hover:border-stone-300 transition">
        <div class="flex items-start justify-between gap-3 mb-2">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-stone-100 border border-stone-200 text-stone-600">${escapeHtml(f.candidate_id || 'CF')}</span>
            ${vBadge}
            ${f.verdict !== 'needs_validation' && f.verdict !== 'rejected' ? `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono border ${badgeBg}">${escapeHtml(sev)}</span>` : ''}
            <span class="text-xs font-mono text-stone-400">[${escapeHtml(f.type || 'AUDIT')}]</span>
            <h4 class="text-xs sm:text-sm font-bold text-mistral-ink">${escapeHtml(f.title || '')}</h4>
          </div>
          ${f.trust_boundary ? `<span class="text-[10px] font-mono text-stone-500 whitespace-nowrap">${escapeHtml(f.trust_boundary)}</span>` : ''}
        </div>
        <p class="text-xs text-mistral-slate leading-relaxed mb-2">${escapeHtml(f.desc || '')}</p>
        ${f.evidence ? `
          <div class="p-2.5 rounded-xl bg-stone-900 text-stone-200 font-mono text-[11px] mb-2 overflow-x-auto">
            <span class="text-stone-400 font-bold"># Kanıt / Yanıt:</span> ${escapeHtml(f.evidence)}
          </div>
        ` : ''}
        ${f.validation_step ? `
          <div class="p-2 rounded-xl bg-amber-50 border border-amber-200 text-[11px] text-amber-900 mb-2">
            <strong>🔬 Doğrulama Adımı (Needs Validation):</strong> ${escapeHtml(f.validation_step)}
          </div>
        ` : ''}
        ${f.fix ? `
          <div class="p-2.5 rounded-xl bg-stone-50 border border-stone-200 text-[11px] text-stone-700">
            <strong class="text-mistral-ink">🛠️ Çözüm & İyileştirme:</strong> ${escapeHtml(f.fix)}
          </div>
        ` : ''}
      </div>
    `;
  }).join('');
}

function buildAndRenderAnalysisItemsReport(itemTracker, ctx) {
  const { cleanUrl, rawDir, aiCredsOk } = ctx || {};
  const defaultRemediation = {
    1: 'Eksik güvenlik başlıklarını (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) web sunucusu yapılandırmanıza ekleyin ve Server/X-Powered-By başlıklarını gizleyin.',
    2: 'Alan adınız için katı DMARC (p=reject), SPF (-all), DNSSEC ve CAA kayıtlarını DNS yönetim panelinizden tanımlayın.',
    3: 'Oturum çerezlerine Secure, HttpOnly ve SameSite=Lax/Strict bayraklarını ekleyin; TLS 1.2/1.3 zorunluluğu getirin ve hassas yolları robots.txt yerine kimlik doğrulama ile koruyun.',
    4: 'Kaynak koddaki güvensiz çağrıları parametrik alternatiflerle değiştirin, gömülü sırları ortam değişkenlerine taşıyın ve CVE barındıran bağımlılık paketlerini güncelleyin.',
    5: 'Tüm kullanıcı girdilerini parametreli sorgularla (Prepared Statements) işleyin, şablon motorlarında kullanıcı verisini kod olarak değerlendirmeyin ve çıktıları bağlama uygun encode edin.',
    6: 'Durum değiştiren tüm formlara anti-CSRF token ekleyin, dış URL parametrelerinde özel IP aralıklarını (SSRF guard) ve harici yönlendirme alan adlarını allow-list ile kısıtlayın.',
    7: 'Harici JS dosyalarında DOM sink (innerHTML/eval) kullanımını sterilize edin, iş mantığı sınır değerlerini (negatif/taşma) sunucu tarafında doğrulayın ve veritabanı portlarını dış ağa kapatın.',
    8: 'AI Red Team tarafından kanıtlanan uç nokta ve parametrelerde girdi doğrulaması, çıktı kodlaması ve sıkı WAF kuralları uygulayın.',
    9: '4-Aşamalı AI Semantik Kod Denetiminde tespit edilen yetkilendirme (AuthZ), iş mantığı ve güven sınırı ihlallerini kaynak kodda onarın.',
    10: 'Otonom Sandbox Sızma Testinde üretilen PoC scriptlerini inceleyerek ilgili uç noktalardaki açıkları önerilen yama (fix_pr_body) doğrultusunda kapatın.'
  };

  const reportItems = [];
  const maxItemIndex = STATE.edition === 'lite' ? 7 : 10;
  for (let i = 1; i <= maxItemIndex; i++) {
    const it = itemTracker[i];
    const needsUrl = [1, 2, 3, 5, 6, 7, 8].includes(i);
    const needsDir = [4, 9].includes(i);
    const needsLocalServer = [3, 4, 5, 6, 7, 8, 9, 10].includes(i);
    const needsAiKey = [8, 9, 10].includes(i);

    let statusKey = 'completed_clean';
    let statusBadge = '✅ Tamamlandı (Sorun Bulunmadı)';
    let detected = '';
    let action = '';

    if (!it.selected) {
      statusKey = 'not_selected';
      statusBadge = '⚪ Seçilmedi (Kullanıcı Tarafından Atlandı)';
      detected = 'Bu analiz maddesi tarama başlatılırken seçilmediği için çalıştırılmadı.';
      action = 'Bu analizi dahil etmek için üstteki listeden "' + it.title + '" kutucuğunu işaretleyip taramayı yeniden başlatın.';
    } else if (needsLocalServer && STATE.mode !== 'local_api') {
      statusKey = 'skipped_prereq';
      statusBadge = '⏭️ Atlandı (Yerel Sunucu Modu Gerekli)';
      detected = 'Tarayıcı (statik önizleme) modunda CORS ve soket kısıtları nedeniyle bu analiz gerçekleştirilemez.';
      action = 'Bu testi çalıştırmak için uygulamayı yerel sunucu modunda (python3 server.py veya Docker) başlatın.';
    } else if (needsUrl && !cleanUrl) {
      statusKey = 'skipped_prereq';
      statusBadge = '⏭️ Atlandı (Hedef Alan Adı / URL Girilmedi)';
      detected = 'Yalnızca yerel proje dizini girildiği için web/ağ tabanlı bu analiz atlandı.';
      action = 'Web/ağ analizlerini çalıştırmak için üstteki hedef kutusuna bir alan adı veya URL girin.';
    } else if (needsDir && !rawDir) {
      statusKey = 'skipped_prereq';
      statusBadge = '⏭️ Atlandı (Yerel Proje Dizini Girilmedi)';
      detected = 'Herhangi bir yerel proje dizini (klasör adı/yolu) belirtilmediği için kaynak kod analizi atlandı.';
      action = 'Kaynak kod analizini çalıştırmak için 📂 Yerel proje dizini kutusuna bir klasör adı veya yolu girin.';
    } else if (needsAiKey && !aiCredsOk) {
      statusKey = 'skipped_prereq';
      statusBadge = '⏭️ Atlandı (API Anahtarı / Service Account Eksik)';
      detected = it.note || 'Seçili analiz LLM bağlantısı gerektiriyor ancak AI Ayarları panelinde geçerli bir API anahtarı / Service Account tanımlanmamış.';
      action = 'Üstteki "🤖 AI Ayarları" (veya "⚙️ AI / API Anahtarı Yapılandır") butonuna tıklayarak sağlayıcı ve API anahtarınızı kaydedin.';
    } else if (it.error) {
      statusKey = 'failed';
      statusBadge = '❌ Gerçekleştirilemedi (Hata Oluştu)';
      detected = 'Test yürütülürken hata oluştu: ' + it.error;
      action = 'Hedef erişilebilirliğini, dizin yolunu veya LLM API anahtarı/kota durumunu kontrol edip tekrar deneyin.';
    } else if (it.asyncRunning) {
      statusKey = 'running_async';
      statusBadge = '🔄 Başlatıldı (Sandbox Arka Planda Çalışıyor)';
      detected = it.note || 'Derin otonom sızma testi konteyner sandbox içinde yürütülüyor.';
      action = '"⚔️ Otonom Sızma Testi (Sandbox)" sekmesinden canlı logları, alt ajanları ve üretilen PoC bulgularını takip edin.';
    } else if (it.ran) {
      const fCount = it.findings.length;
      if (fCount > 0) {
        statusKey = 'completed_findings';
        statusBadge = `⚠️ Tamamlandı (${fCount} Bulgu Tespit Edildi)`;
        const sampleTitles = it.findings.slice(0, 4).map(x => x.title).join('; ');
        detected = (it.note ? it.note + ' — ' : '') + `Tespit edilen bulgular (${fCount}): ${sampleTitles}${fCount > 4 ? ' …' : ''}`;
        const uniqueFixes = Array.from(new Set(it.findings.map(x => x.fix).filter(Boolean))).slice(0, 2);
        action = uniqueFixes.length ? uniqueFixes.join(' | ') : defaultRemediation[i];
      } else {
        statusKey = 'completed_clean';
        statusBadge = '✅ Tamamlandı (Güvenlik Açığı Bulunmadı)';
        detected = (it.note ? it.note + ' ' : '') + 'Yapılan kontrollerde bu analiz maddesi kapsamında herhangi bir güvenlik açığı tespit edilmedi.';
        action = 'Mevcut güvenli yapılandırmayı koruyun; periyodik denetimlere devam edin.';
      }
    } else {
      statusKey = 'skipped_prereq';
      statusBadge = '⏭️ Atlandı';
      detected = it.note || 'Önkoşullar sağlanmadığı için bu analiz çalıştırılmadı.';
      action = defaultRemediation[i];
    }

    reportItems.push({
      num: i,
      title: it.title,
      group: it.group,
      statusKey,
      statusBadge,
      findingCount: it.findings.length,
      detected,
      action
    });
  }

  STATE.analysisItemsReport = reportItems;

  const listEl = document.getElementById('analysis-items-report-list');
  const pillEl = document.getElementById('analysis-items-summary-pill');
  if (pillEl) {
    const ranCount = reportItems.filter(r => r.statusKey === 'completed_clean' || r.statusKey === 'completed_findings' || r.statusKey === 'running_async').length;
    const skipCount = reportItems.length - ranCount;
    pillEl.innerText = `${STATE.edition === 'lite' ? '⚡ Lite Sürüm' : '🚀 Full Sürüm'} · Çalıştırılan: ${ranCount}/${reportItems.length} · Atlanan/Seçilmeyen: ${skipCount}`;
  }
  if (!listEl) return;

  const styleMap = {
    completed_clean: { card: 'border-emerald-200 bg-white', badge: 'bg-emerald-100 text-emerald-900 border-emerald-300' },
    completed_findings: { card: 'border-amber-300 bg-amber-50/40', badge: 'bg-rose-100 text-rose-900 border-rose-300' },
    running_async: { card: 'border-sky-300 bg-sky-50/40', badge: 'bg-sky-100 text-sky-900 border-sky-300' },
    not_selected: { card: 'border-stone-200 bg-stone-50/70', badge: 'bg-stone-200 text-stone-700 border-stone-300' },
    skipped_prereq: { card: 'border-amber-200 bg-stone-50', badge: 'bg-amber-100 text-amber-900 border-amber-300' },
    failed: { card: 'border-rose-300 bg-rose-50/50', badge: 'bg-rose-600 text-white border-rose-700' }
  };

  listEl.innerHTML = reportItems.map(r => {
    const st = styleMap[r.statusKey] || styleMap.completed_clean;
    return `
      <div class="p-3.5 rounded-xl border ${st.card} space-y-1.5">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-stone-100 border border-stone-200 text-stone-700">#${r.num} (${escapeHtml(r.group)})</span>
            <h5 class="text-xs font-bold text-mistral-ink">${escapeHtml(r.title)}</h5>
          </div>
          <span class="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border ${st.badge}">${escapeHtml(r.statusBadge)}</span>
        </div>
        <div class="text-[11px] text-stone-700 leading-relaxed">
          <strong class="text-mistral-ink">🔍 Tespit Edilen Durum:</strong> ${escapeHtml(r.detected)}
        </div>
        <div class="text-[11px] text-emerald-900 bg-emerald-50/70 border border-emerald-200/80 rounded-lg px-2.5 py-1.5 leading-relaxed">
          <strong>🛠️ Yapılması Gerekenler:</strong> ${escapeHtml(r.action)}
        </div>
      </div>
    `;
  }).join('');
}

function buildAndRenderUnifiedCoverageLedger(displayTarget, rawDir, flags) {
  const ledger = [];
  const pushRow = (surface, boundary, moduleName, status, evidence, gap = '') => {
    ledger.push({
      id: 'UCOV-' + String(ledger.length + 1).padStart(3, '0'),
      surface, boundary, module: moduleName, status, evidence, gap
    });
  };

  if (displayTarget) {
    if (flags.modPassive) {
      const hCount = Object.keys(STATE.results.headers?.headers || {}).length;
      pushRow(displayTarget, 'origin_response -> browser_security_policy', 'Passive HTTP Headers', hCount ? 'covered' : 'deferred', `${hCount} güvenlik başlığı denetlendi`, STATE.mode !== 'local_api' ? 'Tarayıcı CORS sınırı (DoH fallback)' : '');
      pushRow(displayTarget, 'dns_resolver -> domain_email_auth', 'DNS & Email (DMARC/SPF/DNSSEC/CAA)', 'covered', `DMARC: ${STATE.results.dns?.dmarc?.status || '?'}, SPF: ${STATE.results.dns?.spf?.status || '?'}`, '');
    } else {
      pushRow(displayTarget, 'origin_response -> browser_security_policy', 'Passive Headers & DNS', 'out_of_scope', '-', 'Kullanıcı tarafından seçilmedi');
    }

    if (flags.modDeep) {
      if (STATE.mode === 'local_api' && STATE.results.deepScan?.success) {
        const d = STATE.results.deepScan;
        pushRow(displayTarget, 'tls_handshake_and_cookies -> client_session', 'Deep Passive (Cookies/TLS/Robots/Tech)', 'covered', `TLS: ${d.tls?.protocol || '-'}, Çerez: ${d.cookies?.count || 0}, Teknolojiler: ${(d.tech_fingerprint?.technologies || []).length}`, '');
      } else {
        pushRow(displayTarget, 'tls_handshake_and_cookies -> client_session', 'Deep Passive Scan', 'deferred', '-', STATE.mode !== 'local_api' ? 'Yerel sunucu modu gerekli' : 'Yanıt alınamadı');
      }
    }
  }

  if (rawDir) {
    const scLedger = STATE.results.sast?.security_check?.coverage_ledger || [];
    scLedger.forEach(r => {
      pushRow(r.surface, r.boundary, `SAST (${r.subsystem})`, r.status, r.evidence, r.gap || '');
    });
  }

  if (displayTarget && flags.modActive) {
    const actLedger = STATE.results.activeScan?.coverage_ledger || [];
    actLedger.forEach(r => {
      pushRow(r.surface, r.boundary, `Active DAST (${r.subsystem})`, r.status, r.evidence, r.gap || '');
    });
  }

  if (displayTarget && flags.modAi && STATE.results.aiScan) {
    const rep = STATE.results.aiScan.ai_report || {};
    pushRow(displayTarget, 'ai_strategist_probe -> analyst_verdict', 'AI Red Team Orchestration', (STATE.results.aiScan.findings || []).length ? 'candidate' : 'covered', `${rep.loops || 0} tur, ${rep.tests_executed || 0} canlı prob, ${(STATE.results.aiScan.findings || []).length} doğrulanan bulgu`, '');
  }

  STATE.unifiedCoverageLedger = ledger;
  const panel = document.getElementById('unified-coverage-panel');
  const tableEl = document.getElementById('unified-coverage-table');
  if (panel && tableEl) {
    if (!ledger.length) {
      panel.classList.add('hidden');
    } else {
      panel.classList.remove('hidden');
      tableEl.innerHTML = '<table class="w-full border-collapse text-left font-mono text-[10px]">' +
        '<thead><tr class="border-b border-stone-200 text-stone-600"><th class="p-1.5">ID</th><th class="p-1.5">Yüzey (Surface)</th><th class="p-1.5">Güven Sınırı (Boundary)</th><th class="p-1.5">Modül</th><th class="p-1.5">Durum</th><th class="p-1.5">Kanıt</th><th class="p-1.5">Kapsam Boşluğu (Gap)</th></tr></thead><tbody>' +
        ledger.map(r => '<tr class="border-b border-stone-100">' +
          '<td class="p-1.5 font-bold">' + escapeHtml(r.id) + '</td>' +
          '<td class="p-1.5">' + escapeHtml(r.surface) + '</td>' +
          '<td class="p-1.5 text-stone-500">' + escapeHtml(r.boundary) + '</td>' +
          '<td class="p-1.5 font-semibold">' + escapeHtml(r.module) + '</td>' +
          '<td class="p-1.5"><span class="px-1.5 py-0.2 rounded bg-stone-100 border border-stone-200">' + escapeHtml(r.status) + '</span></td>' +
          '<td class="p-1.5 text-stone-700">' + escapeHtml(r.evidence) + '</td>' +
          '<td class="p-1.5 text-rose-700">' + escapeHtml(r.gap || '-') + '</td>' +
        '</tr>').join('') + '</tbody></table>';
    }
  }
}

// Girdinin yerel dosya sistemi dizini olup olmadığını algılar
function isLocalDirectoryInput(val) {
  if (!val) return false;
  const s = val.trim();
  if (/^(https?:\/\/)/i.test(s)) return false;
  if (s === '.' || s === '..' || s.startsWith('/') || s.startsWith('~/') || s.startsWith('./') || s.startsWith('../') || /^[a-zA-Z]:[\\/]/.test(s)) {
    return true;
  }
  return false;
}

async function startUnifiedScan() {
  hideScanError();
  const input = document.getElementById('unified-target-input');
  const dirInput = document.getElementById('unified-dir-input');
  const btn = document.getElementById('unified-scan-btn');
  const spinner = document.getElementById('unified-scan-spinner');
  const btnText = document.getElementById('unified-scan-btn-text');

  let raw = input ? input.value.trim() : '';
  let rawDir = dirInput ? dirInput.value.trim() : '';

  if (!raw && !rawDir) {
    showToast('Lütfen taranacak bir alan adı (örn: site.com/dizin) veya yerel proje dizini girin.', 'warning');
    input?.focus();
    return;
  }

  // Ana kutuya doğrudan yerel dizin (/var/www/app, ~/proje, ./src) yazıldıysa:
  if (raw && isLocalDirectoryInput(raw) && !rawDir) {
    rawDir = raw;
    raw = '';
  }

  let cleanUrl = '';
  let cleanDomain = '';
  let displayTarget = '';

  if (raw) {
    // Otomatik شema ekleme (localhost / 127.0.0.1 ise http://, diğerlerinde https://)
    let candidate = raw;
    if (!candidate.startsWith('http://') && !candidate.startsWith('https://')) {
      const isLoopback = /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|172\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)(:\d+)?(\/|$)/i.test(candidate);
      candidate = (isLoopback ? 'http://' : 'https://') + candidate;
    }

    try {
      const u = new URL(candidate);
      cleanDomain = u.hostname;
      // Alt dizin (pathname) ve sorgu parametrelerini (search) koru!
      cleanUrl = u.origin + (u.pathname || '/') + (u.search || '');
      const pathAndQuery = ((u.pathname && u.pathname !== '/') ? u.pathname : '') + (u.search || '');
      displayTarget = u.host + pathAndQuery;
    } catch (e) {
      showScanError('Geçersiz Hedef Formatı', 'Girdiğiniz adres geçerli bir alan adı/URL veya yerel dizin yoluna uymuyor: ' + raw, [
        'Alan adı + dizin için: "ornek.com/panel" veya "https://ornek.com/api/v1"',
        'Yerel dizin (SAST) için: "/home/kullanici/proje" veya "~/proje" şeklinde girin.'
      ]);
      return;
    }
  }

  if (rawDir && STATE.mode !== 'local_api') {
    showScanError('Yerel Mod Gerekli', 'Yerel proje dizini (SAST) taraması yalnızca yerel sunucu modunda (python3 server.py) çalışır.', [
      'Terminalden "python3 server.py" komutunu çalıştırarak yerel modu aktif edin.',
      'Üstteki durum rozetinde "🟢 Yerel Mod: Aktif" ibaresini doğrulayın.'
    ]);
    return;
  }

  STATE.currentDomain = displayTarget || rawDir;
  STATE.targetUrl = cleanUrl;
  STATE.targetDir = rawDir;
  STATE.score = null;
  STATE.grade = '—';

  // Eğer hem URL hem yerel dizin girildiyse Strix ek hedeflerine otomatik bağla (beyaz-kutu)
  if (rawDir) {
    const extraEl = document.getElementById('strix-extra-targets');
    if (extraEl && !extraEl.value.includes(rawDir)) {
      extraEl.value = (extraEl.value ? extraEl.value.trim() + '\n' : '') + rawDir;
    }
  }

  syncLegacyModuleFlags();
  const chkHeaders = document.getElementById('chk-headers')?.checked ?? true;
  const chkDns = document.getElementById('chk-dns')?.checked ?? true;
  const chkDeep = document.getElementById('chk-deep')?.checked ?? true;
  const chkSast = document.getElementById('chk-sast')?.checked ?? true;
  const chkActInj = document.getElementById('chk-active-inj')?.checked ?? true;
  const chkActAcc = document.getElementById('chk-active-access')?.checked ?? true;
  const chkActCrawl = document.getElementById('chk-active-crawl')?.checked ?? true;
  const chkAiRed = document.getElementById('chk-ai-redteam')?.checked ?? false;
  const chkAiSast = document.getElementById('chk-ai-sast')?.checked ?? false;
  const chkAiPen = document.getElementById('chk-ai-pentest')?.checked ?? false;

  const modPassive = chkHeaders || chkDns;
  const modDeep = chkDeep;
  const modSast = chkSast;
  const modActive = chkActInj || chkActAcc || chkActCrawl;
  const modAi = chkAiRed || chkAiSast || chkAiPen;

  const hasWebScan = Boolean(cleanUrl) && (modPassive || modDeep || modActive || chkAiRed || chkAiPen);
  const hasDirScan = Boolean(rawDir) && (modSast || chkAiSast || !cleanUrl);

  if (!hasWebScan && !hasDirScan) {
    showToast('En az bir uygun analiz maddesi seçmelisiniz.', 'warning');
    return;
  }

  // Etik onay kontrolü (aktif veya AI web taraması varsa)
  if ((cleanUrl && (modActive || chkAiRed || chkAiPen)) || (rawDir && chkAiPen)) {
    const ethical = document.getElementById('unified-ethical-check');
    if (!ethical || !ethical.checked) {
      showScanError('Etik Onay Gerekli', 'Aktif güvenlik testi veya otonom AI analizi için etik sorumluluk beyanını onaylamanız zorunludur.', [
        'Aşağıdaki sarı kutudaki "Yasal & Etik Kullanım Beyanı" kutucuğunu işaretleyin.',
        'Sistemin sahibi olduğunuzdan veya yazılı test iznine sahip olduğunuzdan emin olun.'
      ]);
      return;
    }
  }

  // UI durumunu güncelle (Dashboard yalnızca başarılı tarama varsa açılır)
  if (btn) btn.disabled = true;
  if (spinner) spinner.classList.remove('hidden');
  if (btnText) btnText.innerText = 'Taranıyor...';

  const startTime = performance.now();
  let totalRequests = 0;
  let allFindings = [];
  let anyModuleSucceeded = false;
  STATE.unifiedRejected = [];
  STATE.unifiedVerdictFilter = 'all';

  // 10 Analiz Maddesi Durum İzleyici
  const itemTracker = {
    1: { num: 1, title: 'HTTP Güvenlik Başlıkları & Bilgi Sızıntısı Analizi', group: 'Standart', selected: chkHeaders, ran: false, findings: [], error: null, note: '' },
    2: { num: 2, title: 'DNS & E-posta Savunma Kayıtları Denetimi', group: 'Standart', selected: chkDns, ran: false, findings: [], error: null, note: '' },
    3: { num: 3, title: 'Derin Pasif Keşif, Çerez & TLS/SSL Sertifika Analizi', group: 'Standart', selected: chkDeep, ran: false, findings: [], error: null, note: '' },
    4: { num: 4, title: 'Statik Kaynak Kod & Tedarik Zinciri CVE Analizi (SAST)', group: 'Standart', selected: chkSast, ran: false, findings: [], error: null, note: '' },
    5: { num: 5, title: 'Aktif Enjeksiyon & Girdi Manipülasyonu Testleri (SQLi/NoSQLi/SSTI/XSS)', group: 'Standart', selected: chkActInj, ran: false, findings: [], error: null, note: '' },
    6: { num: 6, title: 'Aktif Oturum, CSRF, SSRF & Erişim Kontrolü Testleri', group: 'Standart', selected: chkActAcc, ran: false, findings: [], error: null, note: '' },
    7: { num: 7, title: 'Tarayıcı Simülasyonu (Crawler/JS), İş Mantığı & Altyapı Port Taraması', group: 'Standart', selected: chkActCrawl, ran: false, findings: [], error: null, note: '' },
    8: { num: 8, title: 'AI Red Team Dinamik Saldırı Orkestrasyonu', group: 'AI (API Key / Service Account)', selected: chkAiRed, ran: false, findings: [], error: null, note: '' },
    9: { num: 9, title: '4-Aşamalı AI Semantik Kaynak Kod & Mimari Denetimi', group: 'AI (API Key / Service Account)', selected: chkAiSast, ran: false, findings: [], error: null, note: '' },
    10: { num: 10, title: 'Derin Otonom Sızma Testi & Sandbox PoC Doğrulaması', group: 'AI (API Key / Service Account)', selected: chkAiPen, ran: false, findings: [], error: null, note: '', asyncRunning: false }
  };

  try {
    // -------------------------------------------------------------
    // 1. PASİF BAŞLIK & DNS TARAMASI (Madde 1 & Madde 2)
    // -------------------------------------------------------------
    if (cleanUrl && (chkHeaders || chkDns)) {
      updateProgressBar(15, `[1/6] ${displayTarget} için pasif başlık ve DNS kayıtları sorgulanıyor...`);
      
      let headerEval = { headers: {}, score: 0, maxScore: 100 };
      if (chkHeaders) {
        let headerMap = {};
        try {
          if (STATE.mode === 'local_api') {
            headerMap = await fetchLocalApiHeaders(cleanUrl);
            STATE.results.headersSource = 'local_live';
          } else {
            headerMap = await probePublicHeadersFallback(cleanDomain);
            STATE.results.headersSource = 'doh_fallback';
          }
          totalRequests++;
          headerEval = evaluateHeaders(headerMap);
          STATE.results.headers = headerEval;
          renderHeaderResults(headerEval);
          itemTracker[1].ran = true;
          Object.entries(headerEval.headers || {}).forEach(([k, item]) => {
            if (!item.pass) {
              const fObj = {
                type: 'HEADER',
                severity: item.critical ? 'YÜKSEK' : 'ORTA',
                title: `Eksik veya Zayıf Başlık: ${item.name}`,
                desc: item.note,
                fix: item.fix?.nginx || item.fix?.apache || 'Başlığı sunucunuza ekleyin.'
              };
              allFindings.push(fObj);
              itemTracker[1].findings.push(fObj);
            }
          });
          itemTracker[1].note = `6 güvenlik başlığı denetlendi (${headerEval.score || 0}/${headerEval.maxScore || 100} puan).`;
          anyModuleSucceeded = true;
        } catch (e) {
          itemTracker[1].error = 'HTTP başlıkları alınamadı: ' + e.message;
        }
      }

      let dnsReport = { domain: cleanDomain, spf: { status: 'missing' }, dmarc: { status: 'missing' }, dnssec: false, caa: { status: 'missing', records: [] }, ipv6: false, mx: [] };
      if (chkDns) {
        try {
          updateProgressBar(25, `[1/6] Cloudflare & Google DoH üzerinden DNSSEC, DMARC, SPF sorgulanıyor...`);
          dnsReport = await performDnsSecurityAudit(cleanDomain);
          totalRequests += 5;
          STATE.results.dns = dnsReport;
          renderDnsResults(dnsReport);
          itemTracker[2].ran = true;
          anyModuleSucceeded = true;

          if (dnsReport?.dmarc?.status && dnsReport.dmarc.status !== 'strong') {
            const fObj = {
              type: 'DNS',
              severity: dnsReport.dmarc.status === 'missing' ? 'YÜKSEK' : 'ORTA',
              title: 'DMARC E-posta Koruması Yetersiz',
              desc: dnsReport.dmarc.note || 'DMARC kaydı bulunamadı; phishing ve spoofing riski mevcut.',
              fix: 'TXT kaydı ekleyin: v=DMARC1; p=reject; rua=mailto:dmarc@' + cleanDomain
            };
            allFindings.push(fObj);
            itemTracker[2].findings.push(fObj);
          }
          if (dnsReport?.spf?.status && dnsReport.spf.status !== 'strong') {
            const fObj = {
              type: 'DNS',
              severity: 'ORTA',
              title: 'SPF Kaydı Zayıf veya Eksik',
              desc: dnsReport.spf.note || 'SPF kaydında katı kural (-all) kullanılmalıdır.',
              fix: 'TXT kaydı: v=spf1 mx ~all veya -all'
            };
            allFindings.push(fObj);
            itemTracker[2].findings.push(fObj);
          }
          itemTracker[2].note = `DMARC: ${dnsReport?.dmarc?.status || 'yok'}, SPF: ${dnsReport?.spf?.status || 'yok'}, DNSSEC: ${dnsReport?.dnssec ? 'Aktif' : 'Pasif'}.`;
        } catch (e) {
          itemTracker[2].error = 'DNS sorgusu başarısız: ' + e.message;
        }
      }

      const finalGrade = calculateFinalGrade(headerEval.score || 0, headerEval.maxScore || 100, dnsReport);
      STATE.score = finalGrade.score ?? finalGrade.finalScore ?? 0;
      STATE.grade = finalGrade.grade || finalGrade.letter || 'B';
    }

    // -------------------------------------------------------------
    // 2. DERİN PASİF KEŞİF (Madde 3: Cookies, TLS, Robots, Tech)
    // -------------------------------------------------------------
    if (cleanUrl && chkDeep && STATE.mode === 'local_api') {
      updateProgressBar(40, `[2/6] Derin pasif analiz (${displayTarget}): Çerez güvenliği, TLS, robots.txt ve teknoloji parmak izi...`);
      try {
        const dRes = await fetch('/api/deep-scan?url=' + encodeURIComponent(cleanUrl));
        totalRequests += 4;
        const dData = await dRes.json();
        if (dData.success) {
          anyModuleSucceeded = true;
          itemTracker[3].ran = true;
          STATE.results.deepScan = dData;
          renderDeepScanResults(dData);

          const cookieFindings = dData.cookies?.findings || (Array.isArray(dData.cookies) ? dData.cookies : []);
          cookieFindings.forEach(c => {
            if (c.issues && c.issues.length > 0) {
              const fObj = {
                type: 'COOKIE',
                severity: 'ORTA',
                title: `Güvensiz Çerez Yapılandırması: ${c.name}`,
                desc: `${c.name} çerezinde güvenlik eksikleri: ${c.issues.join(', ')}`,
                fix: 'Set-Cookie başlığına "Secure; HttpOnly; SameSite=Lax" bayraklarını ekleyin.'
              };
              allFindings.push(fObj);
              itemTracker[3].findings.push(fObj);
            }
          });
          const robotsFindings = dData.robots?.findings || [];
          if (robotsFindings.length > 0) {
            const fObj = {
              type: 'ROBOTS',
              severity: 'DÜŞÜK',
              title: 'robots.txt İçinde Hassas Dizin İfşası',
              desc: robotsFindings.map(r => r.issue).join('; '),
              evidence: robotsFindings.map(r => r.evidence).join(', '),
              fix: 'Hassas yönetim yollarını robots.txt dosyasına yazmak yerine kimlik doğrulama ile koruyun.'
            };
            allFindings.push(fObj);
            itemTracker[3].findings.push(fObj);
          }
          const tlsFindings = dData.tls?.findings || [];
          tlsFindings.forEach(tf => {
            const fObj = {
              type: 'TLS',
              severity: tf.level || 'ORTA',
              title: `TLS / Sertifika Bulgusu: ${tf.issue}`,
              desc: tf.evidence || '',
              fix: 'TLS 1.2/1.3 kullanın ve sertifikayı süresi dolmadan yenileyin.'
            };
            allFindings.push(fObj);
            itemTracker[3].findings.push(fObj);
          });
          itemTracker[3].note = `TLS: ${dData.tls?.protocol || '-'}, Çerez: ${dData.cookies?.count || 0}, Teknolojiler: ${(dData.tech_fingerprint?.technologies || []).length}.`;
        } else {
          itemTracker[3].error = dData.error || 'Derin pasif tarama yanıt döndürmedi.';
        }
      } catch (e) {
        itemTracker[3].error = 'Derin pasif tarama hatası: ' + e.message;
        console.warn('Derin tarama hatası:', e);
      }
    }

    // -------------------------------------------------------------
    // 2B. YEREL DİZİN / KAYNAK KOD ANALİZİ (Madde 4: SAST + OSV CVE)
    // -------------------------------------------------------------
    if (rawDir && chkSast && STATE.mode === 'local_api') {
      const sastProfile = document.getElementById('sast-profile')?.value || 'standard';
      const sastScope = document.getElementById('sast-scope-mode')?.value || 'full';
      const sastDiffBase = (document.getElementById('sast-diff-base')?.value || 'HEAD').trim();
      updateProgressBar(55, `[3/6] Yerel dizin kaynak kod taraması (SAST + 8 Ekosistem OSV CVE, profil: ${sastProfile}, kapsam: ${sastScope}): ${rawDir}...`);
      try {
        const sUrl = `/api/sast?path=${encodeURIComponent(rawDir)}&profile=${encodeURIComponent(sastProfile)}&scope_mode=${encodeURIComponent(sastScope)}&diff_base=${encodeURIComponent(sastDiffBase)}`;
        const sRes = await fetch(sUrl, { signal: AbortSignal.timeout(120000) });
        totalRequests++;
        const sData = await sRes.json();
        if (!sData.success) {
          const avail = Array.isArray(sData.available_dirs) && sData.available_dirs.length
            ? ['Sunucuda taranabilir mevcut proje dizinleri: ' + sData.available_dirs.join(', ')]
            : [];
          const errMsg = sData.error || ('Dizin bulunamadı veya okunamadı: ' + rawDir);
          itemTracker[4].error = errMsg;
          showToast('SAST dizin hatası: ' + errMsg, 'error');
          showScanError(
            'Yerel Dizin Bulunamadı (SAST Hatası)',
            `"${rawDir}" dizini sunucuda bulunamadı veya erişilemedi (${errMsg}).`,
            [
              'Sunucu üzerindeki tam yolu (örn: /www/wwwroot/sarjharitasi.tr) veya klasör adını (örn: sarjharitasi) kontrol edin.',
              ...avail,
              'Eğer bir web sitesini URL üzerinden taramak istiyorsanız üstteki kutuya alan adını (örn: sarjharitasi.tr) başında "/" olmadan yazın.'
            ]
          );
          if (!cleanUrl && !chkAiSast) {
            document.getElementById('scan-progress-container')?.classList.add('hidden');
            document.getElementById('scan-results-dashboard')?.classList.add('hidden');
            return;
          }
        } else {
          anyModuleSucceeded = true;
          itemTracker[4].ran = true;
          if (sData.resolved_path && dirInput) {
            dirInput.value = sData.resolved_path;
          }
          STATE.results.sast = sData;
          renderSastStats(sData);
          renderSastFindings();
          renderSastDeps(sData.dependencies);

          (sData.findings || []).forEach(f => {
            const fObj = {
              type: 'SAST',
              severity: f.severity || 'ORTA',
              title: `[${f.rule_id}] ${f.title} (${f.file}:${f.line})`,
              desc: f.description || '',
              evidence: f.match || '',
              fix: f.fix || 'Kaynak koddaki güvensiz çağrıyı parametrik/güvenli alternatifle değiştirin.'
            };
            allFindings.push(fObj);
            itemTracker[4].findings.push(fObj);
          });
          const vulnDeps = sData.dependencies?.vulnerable || [];
          vulnDeps.forEach(v => {
            const fObj = {
              type: 'CVE',
              severity: 'YÜKSEK',
              title: `Bağımlılık Zafiyeti: ${v.name}@${v.version} (${v.vuln_count} CVE)`,
              desc: (v.vulns || []).map(x => `${x.id}: ${x.summary}`).join(' | '),
              fix: `${v.name} paketini güvenli sürüme yükseltin.`
            };
            allFindings.push(fObj);
            itemTracker[4].findings.push(fObj);
          });
          itemTracker[4].note = `${sData.stats?.files_scanned || 0} dosya (${sData.stats?.total_lines || 0} satır) 98 kuralla tarandı; ${vulnDeps.length} CVE'li paket tespit edildi.`;

          if (!cleanUrl) {
            const s = sData.summary || {};
            const penalty = (s['KRİTİK'] || 0) * 18 + (s['YÜKSEK'] || 0) * 10 + (s['ORTA'] || 0) * 4 + (s['DÜŞÜK'] || 0) * 1;
            STATE.score = Math.max(0, 100 - penalty);
            STATE.grade = STATE.score >= 90 ? 'A' : STATE.score >= 75 ? 'B' : STATE.score >= 60 ? 'C' : STATE.score >= 40 ? 'D' : 'F';
          }
        }
      } catch (e) {
        itemTracker[4].error = e.message;
        console.error('SAST tarama hatası:', e);
        showToast('Yerel dizin taraması başarısız: ' + e.message, 'error');
      }
    }

    // -------------------------------------------------------------
    // 3. AKTİF ZAFİYET TARAMASI (Madde 5, 6, 7)
    // -------------------------------------------------------------
    if (cleanUrl && modActive && STATE.mode === 'local_api') {
      const selectedActiveMods = [];
      if (chkActInj) selectedActiveMods.push('sqli', 'nosqli', 'ssti', 'xss');
      if (chkActAcc) selectedActiveMods.push('csrf', 'ssrf', 'open_redirect', 'idor', 'deep_headers');
      if (chkActCrawl) selectedActiveMods.push('browser', 'logic', 'ports');

      updateProgressBar(72, `[4/6] Aktif güvenlik testleri (${displayTarget}): ${selectedActiveMods.join(', ')} taranıyor...`);
      try {
        const confirmRes = await fetch('/api/active-confirm', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: cleanUrl, confirmed: true })
        });
        const confirmData = await confirmRes.json();
        if (!confirmData.success) {
          throw new Error(confirmData.error || 'Etik onay sunucu tarafından reddedildi.');
        }

        const activeUrl = '/api/active-scan?url=' + encodeURIComponent(cleanUrl) + '&modules=' + encodeURIComponent(selectedActiveMods.join(','));
        const aRes = await fetch(activeUrl);
        const aData = await aRes.json();
        
        if (aData.success && aData.findings) {
          anyModuleSucceeded = true;
          if (chkActInj) itemTracker[5].ran = true;
          if (chkActAcc) itemTracker[6].ran = true;
          if (chkActCrawl) itemTracker[7].ran = true;

          STATE.results.activeScan = aData;
          totalRequests += (aData.requests_sent || 15);
          renderActiveResults(aData);

          aData.findings.forEach(f => {
            const fObj = {
              type: 'ACTIVE',
              severity: f.severity || 'YÜKSEK',
              verdict: f.verdict || (f.severity === 'BİLGİ' || f.severity === 'DÜŞÜK' ? 'hardening_note' : 'confirmed'),
              candidate_id: f.candidate_id,
              trust_boundary: f.trust_boundary || 'untrusted_input -> http_endpoint',
              validation_step: f.validation_step || '',
              title: f.title || f.name || 'Aktif Zafiyet',
              desc: f.desc || f.detail || f.description || '',
              evidence: f.evidence || '',
              fix: f.remediation || f.fix || 'Girdi doğrulama ve çıktı sanitizasyonu uygulayın.'
            };
            allFindings.push(fObj);
            const tName = (f.test || '').toLowerCase();
            if (tName.includes('sql') || tName.includes('ssti') || tName.includes('xss')) {
              if (fObj.verdict !== 'hardening_note') itemTracker[5].findings.push(fObj);
            } else if (tName.includes('csrf') || tName.includes('ssrf') || tName.includes('redirect') || tName.includes('idor') || tName.includes('başlık')) {
              if (fObj.verdict !== 'hardening_note') itemTracker[6].findings.push(fObj);
            } else {
              if (fObj.verdict !== 'hardening_note') itemTracker[7].findings.push(fObj);
            }
          });
          if (chkActInj) itemTracker[5].note = 'SQLi, NoSQLi, SSTI ve Reflected/DOM XSS probları tamamlandı.';
          if (chkActAcc) itemTracker[6].note = 'CSRF, SSRF, Open Redirect, IDOR ve derin CSP/CORS kontrolleri tamamlandı.';
          if (chkActCrawl) itemTracker[7].note = `Tarayıcı simülasyonu (${(aData.site_map || []).length} sayfa), iş mantığı ve 24 TCP port taraması tamamlandı.`;
        } else if (!aData.success) {
          const errStr = aData.error || aData.message || 'Aktif tarama başarısız';
          if (chkActInj) itemTracker[5].error = errStr;
          if (chkActAcc) itemTracker[6].error = errStr;
          if (chkActCrawl) itemTracker[7].error = errStr;
        }
      } catch (e) {
        if (chkActInj) itemTracker[5].error = e.message;
        if (chkActAcc) itemTracker[6].error = e.message;
        if (chkActCrawl) itemTracker[7].error = e.message;
        console.error('Aktif tarama hatası:', e);
        showToast('Aktif test uyarısı: ' + e.message, 'warning');
      }
    }

    // -------------------------------------------------------------
    // 4. AI RED TEAM & AI SAST & OTONOM SANDBOX PENTEST (Madde 8, 9, 10)
    // -------------------------------------------------------------
    const aiCredsOk = isAICredentialsConfigured();

    // Madde 8: AI Red Team Dinamik Saldırı Orkestrasyonu
    if (chkAiRed && cleanUrl && STATE.mode === 'local_api') {
      if (!aiCredsOk) {
        itemTracker[8].note = 'LLM API anahtarı / Service Account yapılandırılmadığı için atlandı.';
      } else {
        updateProgressBar(85, `[5/6] Madde 8: AI Red Team ajanları (Scout, Strategist, Analyst, Reporter) çalıştırılıyor...`);
        try {
          const aiRes = await startAIOrchestrationScan(cleanUrl, ['sqli', 'xss', 'csrf', 'ssrf']);
          if (aiRes && aiRes.success) {
            anyModuleSucceeded = true;
            itemTracker[8].ran = true;
            STATE.results.aiScan = aiRes;
            totalRequests += aiRes.requests_sent || 0;
            (aiRes.findings || []).forEach(f => {
              const fObj = {
                type: 'AI_REDTEAM',
                severity: f.severity || 'YÜKSEK',
                verdict: 'confirmed',
                trust_boundary: 'ai_probe -> verified_http_reflection_or_error',
                title: '🤖 AI Doğruladı: ' + (f.title || 'Kanıtlanmış Zafiyet'),
                desc: (f.verdict_detail && f.verdict_detail.reasoning) || f.description || 'Analyst kanıtı HTTP yanıtında doğruladı.',
                evidence: f.evidence || '',
                fix: f.fix || 'Girdi doğrulama + çıktı kodlama + parametreli sorgu uygulayın.'
              };
              allFindings.push(fObj);
              itemTracker[8].findings.push(fObj);
            });
            const execTests = aiRes.ai_report?.executed_tests || [];
            execTests.filter(t => t.verdict !== 'VULNERABLE').forEach((t, rIdx) => {
              STATE.unifiedRejected.push({
                candidate_id: 'REJ-AI-' + String(rIdx + 1).padStart(2, '0'),
                type: 'AI_PROBE',
                verdict: 'rejected',
                severity: 'BİLGİ',
                trust_boundary: 'ai_hypothesis -> disproved_by_http_response',
                title: `Elenen Hipotez (${t.verdict}): ${t.param} parametresi`,
                desc: `Hedef: ${t.url} — Analyst yanıt kanıtını inceledi ve sınır ihlali oluşmadığını doğruladı.`,
                evidence: `Payload: ${t.payload} → Verdict: ${t.verdict}`
              });
            });
            itemTracker[8].note = `${aiRes.ai_report?.loops || 0} turda ${aiRes.ai_report?.tests_executed || 0} canlı prob yürütüldü; ${(aiRes.findings || []).length} bulgu doğrulandı.`;
          } else {
            itemTracker[8].error = 'AI Red Team orkestrasyonu yanıt üretemedi (API anahtarınızı kontrol edin).';
          }
        } catch (e) {
          itemTracker[8].error = e.message;
        }
      }
    }

    // Madde 9: 4-Aşamalı AI Semantik Kaynak Kod Denetimi
    if (chkAiSast && rawDir && STATE.mode === 'local_api') {
      if (!aiCredsOk) {
        itemTracker[9].note = 'LLM API anahtarı / Service Account yapılandırılmadığı için atlandı.';
      } else {
        updateProgressBar(92, `[5/6] Madde 9: 4-Aşamalı AI Kaynak Kod Denetimi (Recon → Hunt → Verify → Report) çalıştırılıyor...`);
        try {
          const sastProfile = document.getElementById('sast-profile')?.value || 'standard';
          const sastScope = document.getElementById('sast-scope-mode')?.value || 'full';
          const sastDiffBase = (document.getElementById('sast-diff-base')?.value || 'HEAD').trim();
          const aiSastRes = await fetch('/api/sast-ai', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              path: STATE.results.sast?.resolved_path || rawDir,
              profile: sastProfile,
              scope_mode: sastScope,
              diff_base: sastDiffBase,
              ai_config: strixAIConfig()
            }),
            signal: AbortSignal.timeout(600000)
          });
          const aiSastData = await aiSastRes.json();
          if (aiSastData.success) {
            anyModuleSucceeded = true;
            itemTracker[9].ran = true;
            (aiSastData.ai_confirmed || []).forEach(c => {
              const fObj = {
                type: 'AI_SAST',
                severity: c.severity || 'YÜKSEK',
                verdict: 'confirmed',
                trust_boundary: 'source_entry -> semantic_sink',
                title: `🤖 AI Kod Denetimi: ${c.title || 'Semantik Bulgu'} (${c.file || ''}:${c.line || ''})`,
                desc: c.rationale || '',
                evidence: c.evidence || '',
                fix: c.fix || 'Yetki ve girdi doğrulama sınırını güçlendirin.'
              };
              allFindings.push(fObj);
              itemTracker[9].findings.push(fObj);
            });
            itemTracker[9].note = `4 aşama (Recon/Hunt/Verify/Report) tamamlandı; ${(aiSastData.ai_confirmed || []).length} semantik bulgu doğrulandı.`;
          } else {
            itemTracker[9].error = aiSastData.error || '4-Aşamalı AI SAST tamamlanamadı.';
          }
        } catch (e) {
          itemTracker[9].error = e.message;
        }
      }
    }

    // Madde 10: Derin Otonom Sızma Testi & Konteyner Sandbox PoC Doğrulaması
    if (chkAiPen && (cleanUrl || rawDir) && STATE.mode === 'local_api') {
      if (!aiCredsOk) {
        itemTracker[10].note = 'LLM API anahtarı / Service Account yapılandırılmadığı için atlandı.';
      } else {
        updateProgressBar(96, `[6/6] Madde 10: Derin Otonom Sızma Testi (Sandbox PoC) başlatılıyor...`);
        try {
          await startStrixScan();
          if (STRIX_ACTIVE_ID) {
            anyModuleSucceeded = true;
            itemTracker[10].ran = true;
            itemTracker[10].asyncRunning = true;
            itemTracker[10].note = `Otonom sandbox sızma testi arka planda başlatıldı (ID: ${STRIX_ACTIVE_ID}). Canlı ilerleme ve PoC bulguları "⚔️ Otonom Sızma Testi (Sandbox)" sekmesinden takip edilebilir.`;
          } else {
            itemTracker[10].error = 'Otonom sandbox sızma testi başlatılamadı.';
          }
        } catch (e) {
          itemTracker[10].error = e.message;
        }
      }
    }

    // -------------------------------------------------------------
    // SONUÇLARI GÜNCELLE VE DASHBOARD'U DOLDUR
    // -------------------------------------------------------------
    if (!anyModuleSucceeded) {
      document.getElementById('scan-progress-container')?.classList.add('hidden');
      document.getElementById('scan-results-dashboard')?.classList.add('hidden');
      return;
    }

    document.getElementById('scan-empty-state')?.classList.add('hidden');
    document.getElementById('scan-results-dashboard')?.classList.remove('hidden');
    completeProgressBar();

    const elapsedSec = ((performance.now() - startTime) / 1000).toFixed(1);
    const resolvedDirLabel = STATE.results.sast?.resolved_path || rawDir;
    const summaryLabel = (displayTarget && rawDir) ? `${displayTarget} + ${resolvedDirLabel}` : (displayTarget || resolvedDirLabel);
    buildAndRenderAnalysisItemsReport(itemTracker, { cleanUrl, rawDir: resolvedDirLabel, aiCredsOk });
    buildAndRenderUnifiedCoverageLedger(displayTarget, resolvedDirLabel, { modPassive, modDeep, modSast, modActive, modAi });
    renderUnifiedDashboard(summaryLabel, allFindings, totalRequests, elapsedSec);

    showToast(`Tarama tamamlandı! Toplam ${allFindings.length} bulgu listelendi.`, 'success');

  } catch (err) {
    console.error('Tarama genel hatası:', err);
    showScanError('Tarama Başarısız Oldu', 'İstek yürütülürken beklenmeyen bir hata ile karşılaşıldı: ' + err.message, [
      'Hedef sunucunun erişilebilir olduğundan emin olun.',
      'Hedef sitenin HTTPS protokolünü desteklediğini kontrol edin.',
      'Lokal sunucu çalışmıyorsa /api/status uç noktasını doğrulayın.'
    ]);
  } finally {
    if (btn) btn.disabled = false;
    if (spinner) spinner.classList.add('hidden');
    if (btnText) btnText.innerText = 'Taramayı Başlat';
  }
}

// DOM Hazır Olduğunda
document.addEventListener('DOMContentLoaded', () => {
  detectScannerMode();
  loadAIConfig();

  const uInput = document.getElementById('unified-target-input');
  if (uInput) {
    uInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') startUnifiedScan();
    });
  }
  const dInput = document.getElementById('unified-dir-input');
  if (dInput) {
    dInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') startUnifiedScan();
    });
    dInput.addEventListener('focus', () => updateSastDirSuggestions(dInput.value));
    dInput.addEventListener('input', () => updateSastDirSuggestions(dInput.value));
    dInput.addEventListener('blur', () => autoResolveSastDirInput(dInput));
  }

  // Modül toggle durumunu başlat
  onActiveModuleToggle();
  updateAIStatusUI();
  loadStrixCapabilities();
  loadStrixPastRuns();
});

let SAST_DIR_TIMER = null;
function updateSastDirSuggestions(q) {
  if (STATE.mode !== 'local_api') return;
  if (SAST_DIR_TIMER) clearTimeout(SAST_DIR_TIMER);
  SAST_DIR_TIMER = setTimeout(async () => {
    try {
      const res = await fetch('/api/sast-dirs?q=' + encodeURIComponent((q || '').trim()), { signal: AbortSignal.timeout(4000) });
      const d = await res.json();
      const dl = document.getElementById('sast-dir-suggestions');
      if (dl && Array.isArray(d.matches)) {
        dl.innerHTML = d.matches.map(m => `<option value="${escapeAttr(m)}"></option>`).join('');
      }
    } catch (e) {}
  }, 180);
}

async function autoResolveSastDirInput(inputEl) {
  if (!inputEl || STATE.mode !== 'local_api') return;
  const raw = (inputEl.value || '').trim();
  if (!raw || raw.startsWith('/www/') || raw.startsWith('/home/') || raw.startsWith('/opt/') || raw.startsWith('/var/')) return;
  try {
    const res = await fetch('/api/sast-dirs?q=' + encodeURIComponent(raw), { signal: AbortSignal.timeout(4000) });
    const d = await res.json();
    if (d.success && d.resolved) {
      inputEl.value = d.resolved;
      const hintEl = document.getElementById('local-dir-hint');
      if (hintEl) hintEl.innerText = '✅ Dizin bulundu ve tamamlandı: ' + d.resolved;
    }
  } catch (e) {}
}

// =============================================================
// AI RED TEAM — Nihai Rapor Kartı (v2: doğrulanmış bulgu şeması)
// =============================================================
function renderAIReportCard(data) {
  // 1) Narrative rapor (Reporter ajanı, Markdown benzeri hafif render)
  const card = document.getElementById('ai-narrative-card');
  const body = document.getElementById('ai-narrative-body');
  const meta = document.getElementById('ai-narrative-meta');
  const narrative = (data.narrative_report || data.ai_report?.narrative_report || '').trim();
  if (card && body) {
    if (narrative) {
      card.classList.remove('hidden');
      body.innerHTML = narrative.split('\n').map(line => {
        const t = line.trim();
        if (!t) return '';
        if (/^#{1,4}\s/.test(t)) return '<h5 class="font-bold text-mistral-ink mt-2">' + escapeHtml(t.replace(/^#+\s*/, '')) + '</h5>';
        if (/^\d+[.)]\s/.test(t)) return '<div class="pl-4">• ' + escapeHtml(t) + '</div>';
        if (/^[-*]\s/.test(t)) return '<div class="pl-4">• ' + escapeHtml(t.slice(2)) + '</div>';
        return '<p>' + escapeHtml(t) + '</p>';
      }).join('');
      if (meta) meta.innerText = (data.ai_report?.loops || 0) + ' tur · ' + (data.ai_report?.tests_executed || 0) + ' AI testi · ' + (data.requests_sent || 0) + ' istek';
    } else {
      card.classList.add('hidden');
    }
  }

  // 3) Deterministik motor bulguları (AI context kaynağı — şeffaflık için gösterilir)
  const bcard = document.getElementById('ai-baseline-card');
  const blist = document.getElementById('ai-baseline-list');
  const baseline = data.baseline_findings || [];
  if (bcard && blist) {
    if (baseline.length === 0) {
      bcard.classList.add('hidden');
    } else {
      bcard.classList.remove('hidden');
      const sevBadgeB = { 'KRİTİK': 'bg-rose-600 text-white', 'YÜKSEK': 'bg-orange-500 text-white', 'ORTA': 'bg-amber-500 text-white', 'DÜŞÜK': 'bg-stone-500 text-white', 'BİLGİ': 'bg-sky-600 text-white' };
      blist.innerHTML = baseline.map(f =>
        '<div class="flex items-start gap-2 p-2 rounded-xl border border-stone-200 bg-stone-50 text-[11px]">' +
        '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold font-mono shrink-0 ' + (sevBadgeB[f.severity] || 'bg-stone-400 text-white') + '">' + escapeHtml(f.severity || '?') + '</span>' +
        '<div><span class="font-bold text-mistral-ink">' + escapeHtml(f.title || '') + '</span>' +
        '<span class="text-stone-500 ml-1">[' + escapeHtml(f.test || '') + ' · ' + escapeHtml(f.cwe || '-') + ']</span>' +
        (f.evidence ? '<div class="font-mono text-[10px] text-stone-500 mt-0.5 truncate">' + escapeHtml(String(f.evidence).slice(0, 140)) + '</div>' : '') +
        '</div></div>').join('');
    }
  }

  // 2) Doğrulanmış AI bulguları
  const fcard = document.getElementById('ai-findings-card');
  const flist = document.getElementById('ai-findings-list');
  const findings = data.findings || [];
  if (fcard && flist) {
    if (findings.length === 0) {
      fcard.classList.remove('hidden');
      flist.innerHTML = '<div class="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-xs text-emerald-800">✅ AI ajanları kanıtı doğrulanmış bir zafiyet tespit etmedi (çalıştırılan test: ' + (data.ai_report?.tests_executed || 0) + ').</div>';
    } else {
      fcard.classList.remove('hidden');
      const sevBadge = { 'KRİTİK': 'bg-rose-600 text-white', 'YÜKSEK': 'bg-orange-500 text-white', 'ORTA': 'bg-amber-500 text-white', 'DÜŞÜK': 'bg-stone-500 text-white' };
      flist.innerHTML = findings.map(f =>
        '<div class="p-3 rounded-xl border border-amber-200 bg-white">' +
        '<div class="flex items-center gap-2 mb-1 flex-wrap">' +
        '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono ' + (sevBadge[f.severity] || 'bg-stone-500 text-white') + '">' + escapeHtml(f.severity || 'ORTA') + '</span>' +
        '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-stone-100 border border-stone-200">' + escapeHtml(f.cwe || '-') + '</span>' +
        (f.verdict_detail?.confidence ? '<span class="text-[10px] font-mono text-stone-500">güven: ' + escapeHtml(f.verdict_detail.confidence) + '</span>' : '') +
        '</div>' +
        '<div class="text-xs font-bold text-mistral-ink mb-1">' + escapeHtml(f.title || '') + '</div>' +
        (f.evidence ? '<div class="text-[10px] font-mono bg-stone-900 text-emerald-300 p-2 rounded-lg overflow-x-auto mb-1"><code>' + escapeHtml(f.evidence) + '</code></div>' : '') +
        (f.verdict_detail?.reasoning ? '<p class="text-[11px] text-stone-600">' + escapeHtml(f.verdict_detail.reasoning) + '</p>' : '') +
        (f.fix ? '<p class="text-[11px] text-emerald-800 bg-emerald-50 rounded-lg px-2 py-1 mt-1"><strong>Çözüm:</strong> ' + escapeHtml(f.fix) + '</p>' : '') +
        '</div>').join('');
    }
  }
}

// =============================================================
// STRIX — Gerçek Strix CLI Pentest Paneli (subprocess tabanlı)
// =============================================================
let STRIX_POLL_TIMER = null;
let STRIX_ACTIVE_ID = null;

function strixGetTargetUrl() {
  let raw = (document.getElementById('unified-target-input')?.value || '').trim();
  if (!raw) raw = STATE.targetUrl || '';
  if (raw && !raw.startsWith('http://') && !raw.startsWith('https://') && !raw.startsWith('postman://') && !raw.startsWith('./') && !raw.startsWith('../') && !raw.startsWith('/') && !raw.startsWith('~/') && !raw.startsWith('git@')) raw = 'https://' + raw;
  return raw;
}

function strixAIConfig() {
  return {
    provider: document.getElementById('ai-provider')?.value || 'openai',
    model: (document.getElementById('ai-model')?.value || '').trim(),
    base_url: (document.getElementById('ai-base-url')?.value || '').trim(),
    project_id: (document.getElementById('ai-project-id')?.value || '').trim(),
    region: (document.getElementById('ai-region')?.value || 'global').trim(),
    auth: {
      type: document.getElementById('ai-auth-type')?.value || 'api_key',
      value: (document.getElementById('ai-auth')?.value || '').trim()
    },
    api_key: (document.getElementById('ai-auth')?.value || '').trim()
  };
}

async function loadStrixCapabilities() {
  const el = document.getElementById('strix-capabilities');
  if (!el) return;
  if (STATE.mode !== 'local_api') {
    el.innerHTML = '⚠️ Strix yalnızca lokal sunucu modunda çalışır (<code>python3 server.py</code>).';
    return;
  }
  try {
    const res = await fetch('/api/strix-capabilities', { signal: AbortSignal.timeout(15000) });
    const d = await res.json();
    if (!d.installed) {
      el.innerHTML = '❌ Strix kurulu değil. Kurulum: <code>' + escapeHtml(d.install_hint || 'pip install strix-agent') + '</code> — ardından sayfayı yenileyin.';
      return;
    }
    el.innerHTML = '✅ <strong>Strix ' + escapeHtml(d.version || '') + '</strong> kurulu · Sandbox: ' +
      (d.sandbox_image ? '<code>' + escapeHtml(d.sandbox_image) + '</code>' : 'imaj bekleniyor (docker pull ghcr.io/usestrix/strix-sandbox:1.3.0)') +
      '<br>' + (d.features || []).map(f => '• ' + escapeHtml(f)).join('<br>');
  } catch (e) {
    el.innerText = 'Strix durumu alınamadı: ' + e.message;
  }
}

async function startStrixScan(options = {}) {
  if (STATE.mode !== 'local_api') { showToast('Strix yalnızca lokal sunucu modunda çalışır.', 'warning'); return; }
  const isResume = !!options.resume;
  const target = strixGetTargetUrl();
  if (!target && !isResume) { showToast('Önce üstteki hedef alanına bir URL girin.', 'warning'); return; }
  const eth = document.getElementById('unified-ethical-check');
  if (eth && !eth.checked) { showToast('Strix pentest için etik sorumluluk beyanını onaylayın.', 'warning'); return; }

  const btn = document.getElementById('strix-start-btn');
  if (btn) btn.disabled = true;
  try {
    // Etik onayı sunucuya kaydet (aktif test altyapısıyla aynı geçit)
    if (target) {
      await fetch('/api/active-confirm', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target, confirmed: true })
      });
    }

    // Gelişmiş seçenekler (tüm Strix CLI özellikleri)
    const val = (id) => (document.getElementById(id)?.value || '').trim();
    const payload = {
      url: target || undefined,
      mode: val('strix-mode') || 'standard',
      ai_config: strixAIConfig(),
      resume: isResume ? options.resume : undefined,
      max_turns: parseInt(val('strix-max-turns')) || 120,
      max_budget: parseFloat(val('strix-max-budget')) || undefined,
      fail_on: val('strix-fail-on') || undefined,
      scope_mode: val('strix-scope-mode') || undefined,
      diff_base: val('strix-diff-base') || undefined,
      instruction: val('strix-instruction') || undefined,
      extra_targets: (val('strix-extra-targets') || '').split('\n').map(s => s.trim()).filter(Boolean),
      target_list: (val('strix-target-list') || '').split('\n').map(s => s.trim()).filter(Boolean),
      mcp_servers: (val('strix-mcp-servers') || '').split(',').map(s => s.trim()).filter(Boolean),
      mcp_exclude: (val('strix-mcp-exclude') || '').split(',').map(s => s.trim()).filter(Boolean),
      strix_env_opts: {
        postman_api_key: val('strix-postman-key') || undefined,
        web_search_provider: val('strix-search-provider') || undefined,
        perplexity_api_key: val('strix-perplexity-key') || undefined,
        exa_api_key: val('strix-exa-key') || undefined,
        reasoning_effort: val('strix-reasoning-effort') || 'high',
        dedupe_model: val('strix-dedupe-model') || undefined,
        sandbox_cpus: val('strix-sandbox-cpus') || undefined,
        sandbox_mem_limit: val('strix-sandbox-mem') || undefined,
      },
    };
    // JSON alanları (geçersiz JSON'da uyar, taramayı engelleme)
    for (const [field, id] of [['mcp_config', 'strix-mcp-config'], ['workspace_files', 'strix-workspace-files'], ['config', 'strix-cli-config']]) {
      const raw = val(id);
      if (!raw) continue;
      try { payload[field] = JSON.parse(raw); }
      catch (e) { showToast('JSON alanı geçersiz (' + field + '), yok sayıldı: ' + e.message, 'warning'); }
    }

    const res = await fetch('/api/strix-scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(30000)
    });
    const d = await res.json();
    if (!d.success) {
      showToast('Strix başlatılamadı: ' + (d.message || d.error || '?'), 'error');
      if (d.capabilities && !d.capabilities.installed) loadStrixCapabilities();
      return;
    }
    STRIX_ACTIVE_ID = d.scan_id;
    showToast((isResume ? 'Strix taraması devam ettiriliyor: ' : 'Strix taraması başladı: ') + d.scan_id + (d.resumed_run ? ' (resume: ' + d.resumed_run + ')' : ''), 'success');
    document.getElementById('strix-status-card')?.classList.remove('hidden');
    document.getElementById('strix-cancel-btn')?.classList.remove('hidden');
    if (STRIX_POLL_TIMER) clearInterval(STRIX_POLL_TIMER);
    STRIX_POLL_TIMER = setInterval(pollStrixStatus, 4000);
    pollStrixStatus();
    switchDetailTab('tab-strix');
  } catch (e) {
    showToast('Strix isteği başarısız: ' + e.message, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function loadStrixPastRuns() {
  const el = document.getElementById('strix-past-runs');
  if (!el) return;
  if (STATE.mode !== 'local_api') { el.innerHTML = '<span class="text-stone-400">Yalnızca lokal sunucu modunda.</span>'; return; }
  el.innerHTML = '<span class="text-stone-400">Yükleniyor…</span>';
  try {
    const res = await fetch('/api/strix-past-runs', { signal: AbortSignal.timeout(15000) });
    const d = await res.json();
    if (!d.success || !(d.runs || []).length) {
      el.innerHTML = '<span class="text-stone-400">Henüz kayıtlı tarama yok.</span>';
      return;
    }
    const stBadge = { running: 'bg-emerald-100 text-emerald-800', completed: 'bg-sky-100 text-sky-800', interrupted: 'bg-amber-100 text-amber-800', error: 'bg-rose-100 text-rose-800' };
    el.innerHTML = d.runs.map(r =>
      '<div class="flex items-center gap-2 p-2 rounded-lg border border-stone-200 bg-stone-50">' +
      '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold font-mono shrink-0 ' + (stBadge[r.status] || 'bg-stone-200 text-stone-700') + '">' + escapeHtml(r.status || '?') + '</span>' +
      '<div class="min-w-0 flex-1"><div class="font-mono truncate" title="' + escapeAttr(r.run_name) + '">' + escapeHtml(r.run_name) + '</div>' +
      '<div class="text-[9px] text-stone-400 truncate">' + escapeHtml(r.target || '-') + ' · ' + (r.findings || 0) + ' bulgu · ' + escapeHtml(r.start_time || '') + '</div></div>' +
      '<button type="button" onclick="inspectStrixRun(' + JSON.stringify(r.run_name).replace(/"/g, '&quot;') + ')" class="px-2 py-1 rounded-lg border border-stone-300 bg-white hover:bg-stone-100 text-stone-700 text-[9px] font-bold shrink-0">🔍 İncele</button>' +
      (r.resumable
        ? '<button type="button" onclick="startStrixScan({resume: ' + JSON.stringify(r.run_name).replace(/"/g, '&quot;') + '})" class="px-2 py-1 rounded-lg bg-amber-500 hover:bg-amber-600 text-white text-[9px] font-bold shrink-0">▶ Devam</button>'
        : '<span class="text-[9px] text-stone-400 shrink-0">bitmiş</span>') +
      '</div>').join('');
  } catch (e) {
    el.innerText = 'Yüklenemedi: ' + e.message;
  }
}

async function strixUpdateCLI() {
  if (STATE.mode !== 'local_api') { showToast('Yalnızca lokal sunucu modunda.', 'warning'); return; }
  showToast('Strix güncelleme kontrol ediliyor (birkaç dk sürebilir)…', 'info');
  try {
    const res = await fetch('/api/strix-update', { method: 'POST', signal: AbortSignal.timeout(300000) });
    const d = await res.json();
    if (d.success) { showToast('Strix güncellendi/kontrol edildi.', 'success'); loadStrixCapabilities(); }
    else showToast('Güncelleme başarısız: ' + (d.error || d.output || '?'), 'error');
  } catch (e) { showToast('Güncelleme isteği başarısız: ' + e.message, 'error'); }
}

async function cancelStrixScan() {
  if (!STRIX_ACTIVE_ID) return;
  try {
    await fetch('/api/strix-cancel', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: STRIX_ACTIVE_ID })
    });
    showToast('Strix taraması durduruluyor…', 'info');
  } catch (e) { showToast('İptal başarısız: ' + e.message, 'error'); }
}

async function pollStrixStatus() {
  if (!STRIX_ACTIVE_ID) return;
  try {
    const res = await fetch('/api/strix-status?scan_id=' + encodeURIComponent(STRIX_ACTIVE_ID), { signal: AbortSignal.timeout(10000) });
    const d = await res.json();
    if (!d.success) return;

    const dot = document.getElementById('strix-status-dot');
    const txt = document.getElementById('strix-status-text');
    const el = document.getElementById('strix-elapsed');
    const sum = document.getElementById('strix-summary');
    if (el) el.innerText = d.elapsed_sec + ' sn · ' + (d.run_name || '') ;
    if (sum) {
      const s = d.severity_summary || {};
      sum.innerText = 'durum: ' + d.run_status + ' · bulgu: ' + d.finding_count +
        (Object.keys(s).length ? ' (' + Object.entries(s).map(([k, v]) => k + ':' + v).join(', ') + ')' : '') +
        (d.llm_cost_usd ? ' · maliyet: $' + Number(d.llm_cost_usd).toFixed(2) : '');
    }
    const logEl = document.getElementById('strix-log');
    if (logEl && d.log_tail) { logEl.textContent = d.log_tail; logEl.scrollTop = logEl.scrollHeight; }

    if (d.finding_count > 0 || !d.running || (d.agents && d.agents.length > 0)) {
      const rep = await (await fetch('/api/strix-report?scan_id=' + encodeURIComponent(STRIX_ACTIVE_ID), { signal: AbortSignal.timeout(15000) })).json();
      if (rep.success) {
        STATE.results.strixScan = rep;
        renderStrixFindings(rep.findings || []);
        renderStrixArtifacts(rep);
      }
    }

    if (!d.running) {
      if (STRIX_POLL_TIMER) { clearInterval(STRIX_POLL_TIMER); STRIX_POLL_TIMER = null; }
      document.getElementById('strix-cancel-btn')?.classList.add('hidden');
      if (dot) { dot.className = 'w-2.5 h-2.5 rounded-full ' + (d.exit_code === 0 ? 'bg-emerald-500' : 'bg-amber-500'); }
      if (txt) txt.innerText = d.finding_count > 0
        ? 'Tamamlandı — ' + d.finding_count + ' PoC doğrulanmış bulgu.'
        : 'Tamamlandı — doğrulanmış bulgu yok (exit ' + d.exit_code + ').';
      showToast('Strix bitti: ' + d.finding_count + ' bulgu (' + Math.round(d.elapsed_sec) + ' sn)', 'success');
    } else if (dot) {
      dot.className = 'w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse';
      if (txt) txt.innerText = 'Strix otonom pentest çalışıyor…';
    }
  } catch (e) { /* geçici ağ hatası: sonraki turda dene */ }
}

async function inspectStrixRun(runName) {
  if (!runName) return;
  try {
    const res = await fetch('/api/strix-report?run_name=' + encodeURIComponent(runName), { signal: AbortSignal.timeout(15000) });
    const rep = await res.json();
    if (!rep.success) {
      showToast('Tarama raporu yüklenemedi: ' + (rep.error || '?'), 'error');
      return;
    }
    STATE.results.strixScan = rep;
    renderStrixFindings(rep.findings || []);
    renderStrixArtifacts(rep);
    showToast('Strix tarama artefaktları yüklendi: ' + runName, 'success');
  } catch (e) {
    showToast('Rapor okuma hatası: ' + e.message, 'error');
  }
}

function downloadStrixArtifact(kind) {
  const rep = STATE.results.strixScan;
  if (!rep || !rep.artifacts) {
    showToast('Önce bir Strix taraması çalıştırın veya geçmiş taramalardan "🔍 İncele" seçin.', 'warning');
    return;
  }
  const runName = rep.scan?.run_name || 'strix-run';
  const art = rep.artifacts;
  if (kind === 'sarif') {
    if (!art.sarif) { showToast('Bu tarama için SARIF 2.1.0 çıktısı henüz oluşmamış.', 'warning'); return; }
    downloadFile(runName + '-findings.sarif', JSON.stringify(art.sarif, null, 2), 'application/sarif+json');
    showToast('SARIF 2.1.0 raporu indirildi!', 'success');
  } else if (kind === 'csv') {
    if (!art.csv_report) { showToast('Bu tarama için CSV çıktısı henüz oluşmamış.', 'warning'); return; }
    downloadFile(runName + '-vulnerabilities.csv', art.csv_report, 'text/csv');
    showToast('CSV raporu indirildi!', 'success');
  } else if (kind === 'md') {
    if (!art.markdown_report) { showToast('Bu tarama için Strix Markdown raporu henüz oluşmamış.', 'warning'); return; }
    downloadFile(runName + '-penetration_test_report.md', art.markdown_report, 'text/markdown');
    showToast('Strix yönetici Markdown raporu indirildi!', 'success');
  }
}

function renderStrixArtifacts(rep) {
  const wrap = document.getElementById('strix-artifacts-card');
  const dlBar = document.getElementById('strix-artifact-dl-bar');
  const agentsPanel = document.getElementById('strix-agents-panel');
  const agentsList = document.getElementById('strix-agents-list');
  const covPanel = document.getElementById('strix-coverage-panel');
  const covList = document.getElementById('strix-coverage-list');
  const mdPanel = document.getElementById('strix-native-md-panel');
  const mdBody = document.getElementById('strix-native-md-body');

  const art = (rep && rep.artifacts) || {};
  const agents = art.agents || [];
  const cov = art.coverage || {};
  const md = (art.markdown_report || '').trim();

  if (dlBar) {
    if (art.sarif || art.csv_report || md) dlBar.classList.remove('hidden');
    else dlBar.classList.add('hidden');
  }

  let anyVisible = false;

  // 1) Alt-ajan topolojisi
  if (agentsPanel && agentsList) {
    if (agents.length === 0) {
      agentsPanel.classList.add('hidden');
    } else {
      anyVisible = true;
      agentsPanel.classList.remove('hidden');
      const stColors = {
        completed: 'bg-emerald-100 text-emerald-800',
        running: 'bg-amber-100 text-amber-900',
        waiting: 'bg-sky-100 text-sky-800',
        stopped: 'bg-stone-200 text-stone-700',
        crashed: 'bg-rose-100 text-rose-800'
      };
      agentsList.innerHTML = agents.map(a =>
        '<div class="p-2.5 rounded-xl border border-stone-200 bg-stone-50 text-[11px]">' +
        '<div class="flex items-center justify-between gap-2 mb-1">' +
        '<span class="font-bold font-mono text-mistral-ink">🤖 ' + escapeHtml(a.name || a.id) + '</span>' +
        '<span class="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ' + (stColors[a.status] || 'bg-stone-200 text-stone-700') + '">' + escapeHtml(a.status || 'unknown') + '</span>' +
        '</div>' +
        '<div class="text-[10px] font-mono text-stone-500">ID: ' + escapeHtml(a.id) + (a.parent_id ? ' · Üst Ajan: ' + escapeHtml(a.parent_id) : ' · Kök Ajan') + (a.events_count ? ' · ' + a.events_count + ' olay' : '') + '</div>' +
        ((a.skills && a.skills.length) ? '<div class="mt-1 flex flex-wrap gap-1">' + a.skills.map(s => '<span class="px-1.5 py-0.2 rounded bg-orange-50 border border-orange-200 text-[9px] font-mono text-orange-900">' + escapeHtml(s) + '</span>').join('') + '</div>' : '') +
        (a.task ? '<div class="mt-1 text-[10px] text-stone-600 truncate" title="' + escapeAttr(a.task) + '">' + escapeHtml(a.task) + '</div>' : '') +
        (a.error ? '<div class="mt-1 text-[10px] text-rose-700 font-mono">' + escapeHtml(a.error) + '</div>' : '') +
        '</div>'
      ).join('');
    }
  }

  // 2) Kapsam defteri (coverage.json)
  if (covPanel && covList) {
    const reported = cov.agent_reported || cov.entries || [];
    const observed = cov.machine_observed || {};
    const gaps = observed.gaps || cov.gaps || [];
    if (!reported.length && !gaps.length && !Object.keys(observed).length) {
      covPanel.classList.add('hidden');
    } else {
      anyVisible = true;
      covPanel.classList.remove('hidden');
      let html = '';
      if (observed && typeof observed === 'object' && Object.keys(observed).length) {
        html += '<div class="p-2 rounded-lg bg-stone-50 border border-stone-200 font-mono text-[10px] text-stone-700">' +
          'Tamamlanma: <strong>' + (observed.complete ? '✅ Tam' : '⚠️ Kısmi') + '</strong>' +
          (observed.skills_carried ? ' · Yüklenen Beceri: ' + observed.skills_carried.length : '') +
          (gaps.length ? ' · Kapsam Boşluğu (Gaps): <span class="text-rose-700 font-bold">' + gaps.length + '</span>' : ' · Boşluk Yok') +
          '</div>';
      }
      if (Array.isArray(reported) && reported.length > 0) {
        html += '<div class="space-y-1">' + reported.slice(0, 30).map(r =>
          '<div class="p-2 rounded-lg border border-stone-200 bg-white flex items-start justify-between gap-2">' +
          '<div><span class="font-bold text-mistral-ink">' + escapeHtml(r.surface || r.target || r.area || r.skill || '-') + '</span>' +
          (r.notes || r.rationale || r.summary ? '<p class="text-[10px] text-stone-600 mt-0.5">' + escapeHtml(r.notes || r.rationale || r.summary) + '</p>' : '') + '</div>' +
          '<span class="px-1.5 py-0.5 rounded bg-stone-100 border border-stone-200 font-mono text-[9px] shrink-0">' + escapeHtml(r.outcome || r.status || 'checked') + '</span>' +
          '</div>'
        ).join('') + '</div>';
      }
      covList.innerHTML = html;
    }
  }

  // 3) Strix yerel yönetici raporu (penetration_test_report.md)
  if (mdPanel && mdBody) {
    if (!md) {
      mdPanel.classList.add('hidden');
    } else {
      anyVisible = true;
      mdPanel.classList.remove('hidden');
      mdBody.textContent = md;
    }
  }

  if (wrap) {
    if (anyVisible) wrap.classList.remove('hidden');
    else wrap.classList.add('hidden');
  }
}

function renderStrixFindings(findings) {
  const card = document.getElementById('strix-findings-card');
  const list = document.getElementById('strix-findings-list');
  if (!card || !list) return;
  if (!findings.length) {
    if (STATE.results.strixScan?.artifacts && (STATE.results.strixScan.artifacts.sarif || STATE.results.strixScan.artifacts.markdown_report)) {
      card.classList.remove('hidden');
      list.innerHTML = '<div class="p-3 rounded-xl bg-stone-50 border border-stone-200 text-xs text-mistral-slate">Bu taramada doğrulanmış zafiyet kaydı yok; üstteki butonlardan SARIF/MD artefaktlarını indirebilirsiniz.</div>';
    } else {
      card.classList.add('hidden');
    }
    return;
  }
  card.classList.remove('hidden');
  const sevBadge = { 'KRİTİK': 'bg-rose-600 text-white', 'YÜKSEK': 'bg-orange-500 text-white', 'ORTA': 'bg-amber-500 text-white', 'DÜŞÜK': 'bg-stone-500 text-white', 'BİLGİ': 'bg-sky-600 text-white' };
  list.innerHTML = findings.map(f => {
    const breakdownEntries = f.cvss_breakdown && typeof f.cvss_breakdown === 'object' ? Object.entries(f.cvss_breakdown) : [];
    const codeLocs = Array.isArray(f.code_locations) ? f.code_locations : [];
    return '<div class="p-3.5 rounded-xl border border-rose-200 bg-white space-y-1.5">' +
      '<div class="flex items-center gap-1.5 flex-wrap">' +
      '<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono ' + (sevBadge[f.severity] || 'bg-stone-500 text-white') + '">' + escapeHtml(f.severity) + '</span>' +
      (f.cvss != null ? '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-50 border border-rose-200 text-rose-700 font-bold">CVSS ' + escapeHtml(String(f.cvss)) + '</span>' : '') +
      '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-stone-100 border border-stone-200">' + escapeHtml(f.cwe || '-') + '</span>' +
      (f.cve ? '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-100 border border-amber-200 text-amber-900">' + escapeHtml(f.cve) + '</span>' : '') +
      (f.finding_class ? '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-stone-100 text-stone-700">' + escapeHtml(f.finding_class) + '</span>' : '') +
      (f.confidence ? '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-50 border border-emerald-200 text-emerald-800">güven: ' + escapeHtml(f.confidence) + '</span>' : '') +
      (f.fix_effort ? '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-sky-50 border border-sky-200 text-sky-800">efor: ' + escapeHtml(f.fix_effort) + '</span>' : '') +
      (f.agent_name ? '<span class="text-[10px] font-mono text-stone-500">🤖 ' + escapeHtml(f.agent_name) + '</span>' : '') +
      (f.endpoint ? '<span class="text-[10px] font-mono text-stone-500 truncate ml-auto">' + escapeHtml((f.method || '') + ' ' + f.endpoint) + '</span>' : '') +
      '</div>' +
      '<div class="text-xs font-bold text-mistral-ink">' + escapeHtml((f.title || '').replace(/^\[STRIX\]\s*/, '')) + '</div>' +
      (f.description ? '<p class="text-[11px] text-stone-600 leading-relaxed">' + escapeHtml(f.description) + '</p>' : '') +
      (f.impact ? '<p class="text-[11px] text-rose-800 bg-rose-50/60 rounded-lg px-2 py-1"><strong>Etki:</strong> ' + escapeHtml(f.impact) + '</p>' : '') +
      (breakdownEntries.length ? '<div class="text-[10px] font-mono text-stone-600 bg-stone-50 px-2 py-1 rounded border border-stone-200"><strong>CVSS Kırılımı:</strong> ' + breakdownEntries.map(([k, v]) => escapeHtml(k + ':' + v)).join(' · ') + '</div>' : '') +
      (f.evidence ? '<div class="text-[10px] font-mono bg-stone-900 text-emerald-300 p-2 rounded-lg overflow-x-auto max-h-32 overflow-y-auto"><code>' + escapeHtml(f.evidence) + '</code></div>' : '') +
      (f.confidence_rationale || f.assumptions || f.counterevidence || f.severity_change_conditions
        ? '<details class="text-[11px]"><summary class="text-[10px] font-bold text-stone-600 cursor-pointer">🔬 Güven Gerekçesi, Varsayımlar & Karşı-Kanıt</summary>' +
          '<div class="mt-1 p-2 rounded-lg bg-stone-50 border border-stone-200 space-y-1 text-[10px] text-stone-700">' +
          (f.confidence_rationale ? '<div><strong>Güven Gerekçesi:</strong> ' + escapeHtml(f.confidence_rationale) + '</div>' : '') +
          (f.assumptions ? '<div><strong>Varsayımlar:</strong> ' + escapeHtml(f.assumptions) + '</div>' : '') +
          (f.counterevidence ? '<div><strong>Karşı-Kanıt:</strong> ' + escapeHtml(f.counterevidence) + '</div>' : '') +
          (f.severity_change_conditions ? '<div><strong>Şiddet Değişim Koşulları:</strong> ' + escapeHtml(f.severity_change_conditions) + '</div>' : '') +
          '</div></details>'
        : '') +
      (codeLocs.length
        ? '<details class="text-[11px]"><summary class="text-[10px] font-bold text-stone-600 cursor-pointer">📍 Kaynak Kod Konumları & Önerilen Yama (' + codeLocs.length + ')</summary>' +
          '<div class="mt-1 space-y-1">' + codeLocs.map(loc =>
            '<div class="p-2 rounded bg-stone-50 border border-stone-200 font-mono text-[10px]">' +
            '<div>' + escapeHtml((loc.file || loc.path || '?') + ':' + (loc.start_line || loc.line || '')) + '</div>' +
            (loc.fix_after ? '<pre class="mt-1 p-1.5 rounded bg-stone-900 text-emerald-300 overflow-x-auto"><code>' + escapeHtml(loc.fix_after) + '</code></pre>' : '') +
            '</div>'
          ).join('') + '</div></details>'
        : '') +
      (f.poc ? '<details><summary class="text-[10px] font-bold text-mistral-orange cursor-pointer">⚡ Çalıştırılabilir PoC Scripti</summary><pre class="text-[10px] font-mono bg-stone-950 text-amber-200 p-2 rounded-lg overflow-x-auto mt-1"><code>' + escapeHtml(f.poc) + '</code></pre></details>' : '') +
      (f.fix && f.fix !== '-' ? '<p class="text-[11px] text-emerald-800 bg-emerald-50 rounded-lg px-2 py-1"><strong>Çözüm:</strong> ' + escapeHtml(f.fix) + (f.fix_verification ? '<br><strong>Doğrulama:</strong> ' + escapeHtml(f.fix_verification) : '') + '</p>' : '') +
      (f.fix_pr_body ? '<details><summary class="text-[10px] font-bold text-emerald-700 cursor-pointer">🔀 Hazır PR Açıklaması (fix_pr_body)</summary><pre class="text-[10px] font-mono bg-stone-900 text-stone-100 p-2 rounded-lg overflow-x-auto mt-1"><code>' + escapeHtml(f.fix_pr_body) + '</code></pre></details>' : '') +
      '</div>';
  }).join('');
}

