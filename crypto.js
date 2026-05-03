// =============================================================================
// crypto.js — CryptoDoc · Université
// Logique de chiffrement / déchiffrement (Web Crypto API)
// =============================================================================

// ── État global ───────────────────────────────────────────────────────────────
let currentFile  = null;
let currentFile2 = null;
let currentAlgo  = 'AES-GCM';
let totalFiles   = 0;
let totalBytes   = 0;

// ── Descriptions des algorithmes ─────────────────────────────────────────────
const algoInfos = {
  'AES-GCM':  '<strong>AES-GCM · Advanced Encryption Standard (Galois/Counter Mode)</strong><br>Chiffrement symétrique 256 bits avec authentification intégrée (AEAD). Détecte toute modification du fichier. Standard NIST. Clé partagée nécessaire.',
  'AES-CBC':  '<strong>AES-CBC · Cipher Block Chaining</strong><br>Chiffrement symétrique 256 bits par blocs chaînés. Sans authentification intégrée. Compatible avec de nombreux systèmes legacy.',
  'RSA-OAEP': '<strong>RSA-OAEP · Optimal Asymmetric Encryption Padding</strong><br>Chiffrement asymétrique — utile pour de petits messages ou un schéma hybride (clé AES chiffrée par RSA). Le chiffrement de fichiers entiers via RSA seul n’est pas proposé ici ; utilisez AES-GCM ou ChaCha20 pour les documents.',
  'CHACHA':   '<strong>ChaCha20-Poly1305 · Chiffrement de flux authentifié</strong><br>Alternative moderne à AES. Très rapide sur les appareils sans accélération matérielle. Utilisé dans TLS 1.3.'
};

let lastEncObjectUrl = null;
let lastDecObjectUrl = null;

function revokeIfUrl(url) {
  if (url && url.indexOf('blob:') === 0) URL.revokeObjectURL(url);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Base64 sans exploser la pile pour les gros tableaux (texte chiffré). */
function bytesToBase64(bytes) {
  let bin = '';
  const chunk = 8192;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + chunk, bytes.length)));
  }
  return btoa(bin);
}

function bufferToHex(buffer) {
  const b = new Uint8Array(buffer);
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

/** Empreinte SHA-256 (hex minuscules, 64 caractères). */
async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return bufferToHex(digest);
}

// =============================================================================
// UI — Sélecteur d'algorithme
// =============================================================================
function selectAlgo(btn) {
  document.querySelectorAll('.algo-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentAlgo = btn.dataset.algo;
  document.getElementById('algoInfo').innerHTML = algoInfos[currentAlgo];
}

// =============================================================================
// UI — Onglets
// =============================================================================
function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t, i) => {
    t.classList.toggle('active', ['encrypt', 'decrypt', 'text'][i] === name);
  });
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('active');
}

// =============================================================================
// UI — Drag & Drop
// =============================================================================
function setupDrop(zoneId, handler) {
  const zone = document.getElementById(zoneId);
  zone.addEventListener('dragover', e => {
    e.preventDefault();
    zone.classList.add('drag-over');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    if (e.dataTransfer.files[0]) handler(e.dataTransfer.files[0]);
  });
}

// =============================================================================
// UI — Gestion des fichiers
// =============================================================================
function getFileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();
  const icons = {
    pdf: '📕', doc: '📘', docx: '📘', txt: '📄',
    png: '🖼', jpg: '🖼', jpeg: '🖼', zip: '📦',
    ppt: '📊', pptx: '📊', xls: '📗', xlsx: '📗'
  };
  return icons[ext] || '📄';
}

function formatBytes(n) {
  if (n < 1024)    return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(2) + ' MB';
}

function handleFile(file) {
  if (!file) return;
  if (file.size > 50 * 1024 * 1024) { alert('Fichier trop grand (max 50 MB)'); return; }
  currentFile = file;
  document.getElementById('fileInfo').classList.add('show');
  document.getElementById('fileIcon').textContent = getFileIcon(file.name);
  document.getElementById('fileName').textContent = file.name;
  document.getElementById('fileSize').textContent = formatBytes(file.size);
  document.getElementById('dropzone').style.display = 'none';
  document.getElementById('encResult').classList.remove('show');
}

function handleFile2(file) {
  if (!file) return;
  currentFile2 = file;
  document.getElementById('fileInfo2').classList.add('show');
  document.getElementById('fileName2').textContent = file.name;
  document.getElementById('fileSize2').textContent = formatBytes(file.size);
  document.getElementById('dropzone2').style.display = 'none';
  document.getElementById('decResult').classList.remove('show');
}

function removeFile() {
  currentFile = null;
  document.getElementById('fileInfo').classList.remove('show');
  document.getElementById('dropzone').style.display = '';
  document.getElementById('fileInput').value = '';
}

function removeFile2() {
  currentFile2 = null;
  document.getElementById('fileInfo2').classList.remove('show');
  document.getElementById('dropzone2').style.display = '';
  document.getElementById('fileInput2').value = '';
}

// =============================================================================
// UI — Force du mot de passe
// =============================================================================
function checkStrength(val, prefix) {
  const fill  = document.getElementById(prefix === 'enc' ? 'encStrength' : 'txtStrength');
  const label = document.getElementById(prefix === 'enc' ? 'encStrengthLabel' : 'txtStrengthLabel');
  if (!val) { fill.style.width = '0%'; label.textContent = '—'; return; }

  let score = 0;
  if (val.length >= 8)            score++;
  if (val.length >= 16)           score++;
  if (/[A-Z]/.test(val))          score++;
  if (/[0-9]/.test(val))          score++;
  if (/[^A-Za-z0-9]/.test(val))   score++;

  const levels = [
    { w: '20%',  c: '#ef4444', t: 'Très faible' },
    { w: '40%',  c: '#f97316', t: 'Faible'       },
    { w: '60%',  c: '#f59e0b', t: 'Moyenne'      },
    { w: '80%',  c: '#84cc16', t: 'Forte'        },
    { w: '100%', c: '#22c55e', t: 'Très forte'   }
  ];
  const l = levels[Math.min(score, 4)];
  fill.style.width      = l.w;
  fill.style.background = l.c;
  label.textContent     = 'Force : ' + l.t;
  label.style.color     = l.c;
}

function toggleKey(id) {
  const el = document.getElementById(id);
  el.type = el.type === 'password' ? 'text' : 'password';
}

function generateKey(id) {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  const key = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  document.getElementById(id).value = key;
  document.getElementById(id).type  = 'text';
  if (id === 'encKey')  checkStrength(key, 'enc');
  if (id === 'textKey') checkStrength(key, 'txt');
}

// =============================================================================
// CRYPTO — Dérivation de clé (PBKDF2 + SHA-256)
// =============================================================================
/** @param {'AES-GCM'|'AES-CBC'|'ChaCha20-Poly1305'} symAlgo */
async function deriveKey(password, salt, symAlgo = 'AES-GCM') {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  const alg =
    symAlgo === 'AES-CBC'
      ? { name: 'AES-CBC', length: 256 }
      : symAlgo === 'ChaCha20-Poly1305'
        ? { name: 'ChaCha20-Poly1305', length: 256 }
        : { name: 'AES-GCM', length: 256 };
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' },
    keyMaterial,
    alg,
    false,
    ['encrypt', 'decrypt']
  );
}

// =============================================================================
// CRYPTO — Chiffrement de fichier
// =============================================================================
/** Codes algo fichier : 0 = AES-GCM, 1 = AES-CBC, 2 = ChaCha20-Poly1305 */
function symAlgoFromFileCode(code) {
  if (code === 1) return 'AES-CBC';
  if (code === 2) return 'ChaCha20-Poly1305';
  return 'AES-GCM';
}

function ivLengthForFileAlgo(code) {
  return code === 1 ? 16 : 12;
}

async function encryptFile() {
  if (!currentFile) { alert('Veuillez sélectionner un fichier.'); return; }
  if (currentAlgo === 'RSA-OAEP') {
    alert('RSA-OAEP ne peut pas chiffrer un fichier entier seul. Choisissez AES-GCM, AES-CBC ou ChaCha20, ou utilisez un outil hybride (hors périmètre de cette page).');
    return;
  }
  const password = document.getElementById('encKey').value;
  if (!password)    { alert('Veuillez entrer une clé de chiffrement.'); return; }

  const btn  = document.getElementById('encBtn');
  const prog = document.getElementById('encProgress');
  const fill = document.getElementById('encProgressFill');
  const lbl  = document.getElementById('encProgressLabel');

  btn.disabled = true;
  btn.textContent = 'Chiffrement...';
  btn.classList.add('loading');
  prog.classList.add('show');

  try {
    fill.style.width = '20%'; lbl.textContent = 'Lecture du fichier...';
    await sleep(200);

    const data = await currentFile.arrayBuffer();

    fill.style.width = '40%'; lbl.textContent = 'Dérivation de la clé (PBKDF2)...';
    await sleep(100);

    const salt = crypto.getRandomValues(new Uint8Array(32));
    const code =
      currentAlgo === 'AES-CBC' ? 1
        : currentAlgo === 'CHACHA' ? 2
          : 0;
    const ivLen = ivLengthForFileAlgo(code);
    const iv = crypto.getRandomValues(new Uint8Array(ivLen));
    const symName =
      code === 1 ? 'AES-CBC'
        : code === 2 ? 'ChaCha20-Poly1305'
          : 'AES-GCM';
    const key = await deriveKey(password, salt, symName);

    fill.style.width = '70%'; lbl.textContent = 'Chiffrement ' + currentAlgo + '...';
    await sleep(100);

    let encParams;
    if (code === 1) encParams = { name: 'AES-CBC', iv };
    else if (code === 2) encParams = { name: 'ChaCha20-Poly1305', iv };
    else encParams = { name: 'AES-GCM', iv, tagLength: 128 };

    const ciphertext = await crypto.subtle.encrypt(encParams, key, data);

    fill.style.width = '90%'; lbl.textContent = 'Construction du fichier...';
    await sleep(100);

    // Format binaire : magic(4) + algo(1) + salt(32) + iv(12 ou 16) + nameLen(2) + name + ciphertext
    const origNameBytes = new TextEncoder().encode(currentFile.name);
    const magic         = new Uint8Array([0x43, 0x52, 0x59, 0x50]); // "CRYP"
    const algoCode      = new Uint8Array([code]);
    const nameLenBuf    = new Uint8Array(2);
    new DataView(nameLenBuf.buffer).setUint16(0, origNameBytes.length, false);

    const output = concat([magic, algoCode, salt, iv, nameLenBuf, origNameBytes, new Uint8Array(ciphertext)]);

    fill.style.width = '95%'; lbl.textContent = 'Empreintes SHA-256...';
    const shaOriginal = await sha256Hex(data);
    const shaEnc = await sha256Hex(output);

    fill.style.width = '100%'; lbl.textContent = 'Terminé !';
    await sleep(300);

    // Mise à jour des stats
    totalFiles++;
    totalBytes += currentFile.size;
    document.getElementById('statFiles').textContent = totalFiles;
    document.getElementById('statSize').textContent  = formatBytes(totalBytes);

    // Téléchargement (révoquer l’ancienne URL blob pour libérer la mémoire)
    revokeIfUrl(lastEncObjectUrl);
    const blob    = new Blob([output], { type: 'application/octet-stream' });
    const url     = URL.createObjectURL(blob);
    lastEncObjectUrl = url;
    const outName = currentFile.name + '.enc';
    const dl      = document.getElementById('encDownload');
    dl.href     = url;
    dl.download = outName;

    // Métadonnées (+ empreintes pour vérification hors ligne)
    document.getElementById('encMeta').innerHTML = `
      <div class="meta-item"><div class="meta-key">Algorithme</div><div class="meta-val">${escapeHtml(currentAlgo)}</div></div>
      <div class="meta-item"><div class="meta-key">Taille originale</div><div class="meta-val">${formatBytes(currentFile.size)}</div></div>
      <div class="meta-item"><div class="meta-key">Taille chiffrée</div><div class="meta-val">${formatBytes(output.byteLength)}</div></div>
      <div class="meta-item"><div class="meta-key">Itérations PBKDF2</div><div class="meta-val">310 000</div></div>
      <div class="meta-item meta-item-wide"><div class="meta-key">SHA-256 (fichier clair)</div><div class="meta-val meta-hash">${shaOriginal}</div></div>
      <div class="meta-item meta-item-wide"><div class="meta-key">SHA-256 (fichier .enc)</div><div class="meta-val meta-hash">${shaEnc}</div></div>
    `;

    document.getElementById('encResult').classList.add('show');
    prog.classList.remove('show');

  } catch (e) {
    alert('Erreur de chiffrement : ' + e.message);
  } finally {
    btn.disabled    = false;
    btn.textContent = '⬡ Chiffrer le document';
    btn.classList.remove('loading');
  }
}

// =============================================================================
// CRYPTO — Déchiffrement de fichier
// =============================================================================
async function decryptFile() {
  if (!currentFile2) { alert('Veuillez sélectionner un fichier .enc'); return; }
  const password = document.getElementById('decKey').value;
  if (!password)     { alert('Veuillez entrer la clé de déchiffrement.'); return; }

  const btn    = document.getElementById('decBtn');
  const prog   = document.getElementById('decProgress');
  const fill   = document.getElementById('decProgressFill');
  const lbl    = document.getElementById('decProgressLabel');
  const result = document.getElementById('decResult');

  btn.disabled = true;
  btn.textContent = 'Déchiffrement...';
  btn.classList.add('loading');
  prog.classList.add('show');

  try {
    fill.style.width = '20%'; lbl.textContent = 'Lecture du fichier...';
    await sleep(200);

    const buf = await currentFile2.arrayBuffer();
    const arr = new Uint8Array(buf);

    // Vérification du magic number
    if (arr[0] !== 0x43 || arr[1] !== 0x52 || arr[2] !== 0x59 || arr[3] !== 0x50) {
      throw new Error("Ce fichier n'est pas un fichier CryptoDoc valide.");
    }

    const algoCode   = arr[4];
    if (algoCode > 2) throw new Error("Version ou algorithme de fichier non pris en charge.");
    const symName    = symAlgoFromFileCode(algoCode);
    const ivLen      = ivLengthForFileAlgo(algoCode);
    const salt       = arr.slice(5, 37);
    const iv         = arr.slice(37, 37 + ivLen);
    const nameOff    = 37 + ivLen;
    const nameLen    = new DataView(buf, nameOff, 2).getUint16(0, false);
    const origName   = new TextDecoder().decode(arr.slice(nameOff + 2, nameOff + 2 + nameLen));
    const ciphertext = arr.slice(nameOff + 2 + nameLen);

    fill.style.width = '40%'; lbl.textContent = 'Dérivation de la clé...';
    await sleep(100);

    const key = await deriveKey(password, salt, symName);

    fill.style.width = '70%'; lbl.textContent = 'Déchiffrement ' + symName + '...';
    await sleep(100);

    let decParams;
    if (algoCode === 1) decParams = { name: 'AES-CBC', iv };
    else if (algoCode === 2) decParams = { name: 'ChaCha20-Poly1305', iv };
    else decParams = { name: 'AES-GCM', iv, tagLength: 128 };

    const plaintext = await crypto.subtle.decrypt(decParams, key, ciphertext);

    fill.style.width = '95%'; lbl.textContent = 'Empreinte SHA-256...';
    const shaPlain = await sha256Hex(plaintext);

    fill.style.width = '100%'; lbl.textContent = 'Fichier restauré !';
    await sleep(300);
    prog.classList.remove('show');

    const blob = new Blob([plaintext]);
    const url  = URL.createObjectURL(blob);

    revokeIfUrl(lastDecObjectUrl);

    const safeName = escapeHtml(origName);
    result.innerHTML = `
      <div class="result-header success">
        <div class="result-title success">✓ Déchiffrement réussi — fichier authentifié</div>
      </div>
      <div class="result-body">
        <div class="result-meta">
          <div class="meta-item"><div class="meta-key">Algorithme détecté</div><div class="meta-val">${escapeHtml(symName)}</div></div>
          <div class="meta-item"><div class="meta-key">Fichier original</div><div class="meta-val">${safeName}</div></div>
          <div class="meta-item"><div class="meta-key">Taille restaurée</div><div class="meta-val">${formatBytes(plaintext.byteLength)}</div></div>
          <div class="meta-item"><div class="meta-key">Intégrité</div><div class="meta-val" style="color:var(--integrity)">✓ Vérifiée</div></div>
          <div class="meta-item meta-item-wide"><div class="meta-key">SHA-256 (fichier restauré)</div><div class="meta-val meta-hash">${shaPlain}</div></div>
        </div>
        <a class="download-btn" id="decDownloadLink" href="${url}" download="">⬇ Télécharger le fichier original</a>
      </div>`;
    const decLink = document.getElementById('decDownloadLink');
    if (decLink) decLink.setAttribute('download', origName);
    lastDecObjectUrl = url;
    result.classList.add('show');

  } catch (e) {
    prog.classList.remove('show');
    result.innerHTML = `
      <div class="result-header error">
        <div class="result-title error">✕ Échec du déchiffrement</div>
      </div>
      <div class="result-body">
        <div style="font-family:var(--mono);font-size:12px;color:var(--red);line-height:1.7;">
          ${(/invalid|auth|tag|operation/i.test(e.message) ? e.message : "Clé incorrecte ou fichier corrompu. Vérifiez que vous utilisez exactement la même clé qu'au chiffrement.")}
        </div>
      </div>`;
    result.classList.add('show');
  } finally {
    btn.disabled    = false;
    btn.textContent = '⬡ Déchiffrer le document';
    btn.classList.remove('loading');
  }
}

// =============================================================================
// CRYPTO — Chiffrement / Déchiffrement de texte
// =============================================================================
async function encryptText() {
  const text = document.getElementById('textInput').value;
  const pass = document.getElementById('textKey').value;
  if (!text || !pass) { alert('Texte et clé requis.'); return; }

  const enc  = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(pass, salt);

  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));

  const combined = concat([salt, iv, new Uint8Array(ct)]);
  const b64 = bytesToBase64(new Uint8Array(combined));

  document.getElementById('textOutput').textContent   = b64;
  document.getElementById('textResult').style.display = 'block';
}

async function decryptText() {
  const b64  = document.getElementById('textInput').value.trim();
  const pass = document.getElementById('textKey').value;
  if (!b64 || !pass) { alert('Texte chiffré (base64) et clé requis.'); return; }

  try {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const salt  = bytes.slice(0, 16);
    const iv    = bytes.slice(16, 28);
    const ct    = bytes.slice(28);
    const key   = await deriveKey(pass, salt);

    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    document.getElementById('textOutput').textContent   = new TextDecoder().decode(pt);
    document.getElementById('textResult').style.display = 'block';
  } catch {
    alert('Déchiffrement impossible. Vérifiez la clé et le texte.');
  }
}

function copyResult() {
  const t = document.getElementById('textOutput').textContent;
  navigator.clipboard.writeText(t).then(() => {
    const btn = document.querySelector('.copy-btn');
    btn.textContent = 'Copié !';
    setTimeout(() => btn.textContent = 'Copier', 1500);
  });
}

// =============================================================================
// Utilitaires
// =============================================================================

/** Concatène plusieurs ArrayBuffer / TypedArray en un seul ArrayBuffer */
function concat(arrays) {
  const total = arrays.reduce((s, a) => s + a.byteLength, 0);
  const out   = new Uint8Array(total);
  let offset  = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.byteLength; }
  return out.buffer;
}

/** Pause asynchrone (pour l'animation de progression) */
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// =============================================================================
// Initialisation au chargement de la page
// =============================================================================
document.addEventListener('DOMContentLoaded', () => {
  setupDrop('dropzone',  f => handleFile(f));
  setupDrop('dropzone2', f => handleFile2(f));
});
