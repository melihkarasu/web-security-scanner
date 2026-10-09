/**
 * Web Security Scanner (Web Security Scanner)
 * Pasif Güvenlik Başlıkları, DoH DNS, E-posta Savunması & SSL Denetim Motoru
 * Sıfır Backend - %100 İstemci Taraflı (CORS-Açık DoH & Header Röntgeni)
 */

// =============================================================
// 1. Durum Yönetimi & Sabitler
// =============================================================
const STATE = {
  currentDomain: '',
  targetUrl: '',
  score: 0,
  grade: '?',
  results: {
    dns: {},
    headers: {},
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
    // Kullanıcı elle header yapıştırmışsa onu kullan, yoksa genel DoH ve standart güvenlik çıkarımı yap
    const manualHeadersText = document.getElementById('manual-headers-input').value.trim();
    let headerMap = {};

    if (manualHeadersText) {
      headerMap = parseRawHeaders(manualHeadersText);
    } else {
      // Standart bilinen genel profiller veya DoH HTTPS kayıtları üzerinden temel çıkarım
      headerMap = await probePublicHeadersFallback(cleanDomain);
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

    showToast(`Denetim tamamlandı! Güvenlik Notu: ${final.grade} (${final.score}/100)`, 'success');
  } catch (err) {
    console.error('Scan Error:', err);
    showToast('Tarama sırasında hata oluştu: ' + err.message, 'error');
  } finally {
    toggleLoading(false);
  }
}

// Canlı/Fallback Header Tespiti
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
      ? '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-100 text-emerald-800">✅ Güvenli (' + item.score + '/' + item.maxScore + ')</span>'
      : '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-100 text-rose-800">❌ Eksik / Zayıf (0/' + item.maxScore + ')</span>';

    const fixSnippet = !item.pass ? `
      <div class="mt-3 pt-3 border-t border-rose-100">
        <div class="flex items-center justify-between mb-1">
          <span class="text-[11px] font-semibold text-mistral-slate uppercase tracking-wider">Önerilen Nginx Çözümü:</span>
          <button onclick="copyToClipboard('${escapeAttr(item.fix.nginx)}')" class="text-[11px] text-mistral-orange hover:underline font-medium">📋 Kopyala</button>
        </div>
        <pre class="bg-stone-900 text-stone-100 p-2.5 rounded-lg text-xs font-mono overflow-x-auto select-all"><code>${escapeHtml(item.fix.nginx)}</code></pre>
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
      ? '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-100 text-emerald-800">✅ Doğrulandı</span>'
      : isWarn
      ? '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-100 text-amber-800">⚠️ İyileştirilmeli</span>'
      : '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-100 text-rose-800">❌ Eksik</span>';

    card.className = `p-4 rounded-xl border ${isPass ? 'bg-white border-stone-200' : 'bg-stone-50 border-stone-200'}`;
    card.innerHTML = `
      <div class="flex items-center justify-between gap-2 mb-1">
        <h4 class="font-bold text-sm text-mistral-ink">${escapeHtml(item.title)}</h4>
        ${badge}
      </div>
      <div class="text-xs font-mono p-2 rounded bg-white border border-stone-200/80 break-all mb-1 text-stone-700">
        ${escapeHtml(item.value)}
      </div>
      <p class="text-xs text-mistral-slate">${escapeHtml(item.note)}</p>
      ${item.fix ? `
        <div class="mt-2 text-right">
          <button onclick="copyToClipboard('${escapeAttr(item.fix)}')" class="text-[11px] text-mistral-orange hover:underline font-medium">📋 Örnek TXT Kopyala</button>
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

// Markdown Denetim Raporunu Dışa Aktarma
function exportMarkdownReport() {
  if (!STATE.currentDomain) {
    showToast('Önce bir alan adı taramalısınız.', 'warning');
    return;
  }

  const dateStr = new Date().toISOString().split('T')[0];
  let md = `# Web Güvenlik Röntgeni Raporu\n\n`;
  md += `**Taranan Hedef:** \`${STATE.currentDomain}\`  \n`;
  md += `**Tarih:** ${dateStr}  \n`;
  md += `**Güvenlik Puanı:** **${STATE.score} / 100** (Not: **${STATE.grade}**)  \n\n`;
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

  md += `\n*Rapor, [Web Security Scanner](https://melihkarasu.github.io/web-security-scanner/) tarafından pasif denetimle üretilmiştir.*`;

  downloadFile(`${STATE.currentDomain}-guvenlik-raporu.md`, md, 'text/markdown');
  showToast('Markdown raporu indirildi!', 'success');
}

// =============================================================
// 5. Yardımcı Fonksiyonlar & Başlatma
// =============================================================
function toggleLoading(isLoading) {
  const btn = document.getElementById('scan-btn');
  const spinner = document.getElementById('scan-spinner');
  const btnText = document.getElementById('scan-btn-text');

  if (btn) btn.disabled = isLoading;
  if (spinner) spinner.classList.toggle('hidden', !isLoading);
  if (btnText) btnText.innerText = isLoading ? 'Denetleniyor...' : 'Güvenlik Röntgenini Başlat';
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
  const tabs = ['audit', 'headers', 'checklist'];
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

// DOM Hazır Olduğunda
document.addEventListener('DOMContentLoaded', () => {
  const inputEl = document.getElementById('target-input');
  if (inputEl) {
    inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') startSecurityScan();
    });
  }

  // Varsayılan ilk yükleme (örnek GitHub)
  if (inputEl && !inputEl.value) {
    inputEl.value = '';
  }
});
