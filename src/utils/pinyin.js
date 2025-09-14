const { spawn } = require('child_process');
const path = require('path');

function resolvePythonCmd() {
  // Respect environment if present
  const envPy = process.env.PYTHON || process.env.PYTHON_PATH || process.env.PY;
  const candidates = [];
  if (envPy && typeof envPy === 'string') {
    // If points to directory, append python.exe
    if (/\\$/.test(envPy) || envPy.endsWith('/') || envPy.endsWith('\\')) {
      candidates.push(path.join(envPy, process.platform === 'win32' ? 'python.exe' : 'python'));
    } else {
      candidates.push(envPy);
    }
  }
  if (process.platform === 'win32') {
    candidates.push('py', 'python', 'python3');
  } else {
    candidates.push('python3', 'python');
  }
  return candidates;
}

function runPythonPinyin(texts, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const script = path.join(__dirname, '..', '..', 'python', 'pinyin.py');
    const payload = JSON.stringify(texts || []);
    const tried = [];

    const tryNext = (cands) => {
      if (!cands.length) {
        return resolve(texts.map(t => ({ full: String(t || ''), abbr: '' })));
      }
      const cmd = cands.shift();
      tried.push(cmd);
      let proc;
      try {
        // Force UTF-8 for Python stdio on Windows to avoid mojibake
        const env = { ...process.env, PYTHONIOENCODING: 'utf-8' };
        proc = spawn(cmd, [script], { stdio: ['pipe', 'pipe', 'pipe'], env });
      } catch (e) {
        return tryNext(cands);
      }
      let out = '';
      let err = '';
      const timer = setTimeout(() => {
        try { proc.kill(); } catch(_){}
      }, timeoutMs);

      proc.stdout.on('data', b => { out += String(b); });
      proc.stderr.on('data', b => { err += String(b); });
      proc.on('error', _ => { clearTimeout(timer); tryNext(cands); });
      proc.on('close', (code) => {
        clearTimeout(timer);
        if (code === 0 && out) {
          try { return resolve(JSON.parse(out)); } catch (_) { return resolve(texts.map(t => ({ full: String(t || ''), abbr: '' }))); }
        }
        // else try next
        tryNext(cands);
      });
      try { proc.stdin.write(payload); proc.stdin.end(); } catch (_) { tryNext(cands); }
    };
    tryNext(resolvePythonCmd());
  });
}

async function attachPinyinToDocs(docs, pickers) {
  // pickers: array of { key: 'cn', outFull: 'py', outAbbr: 'py_abbr' }
  if (!Array.isArray(docs) || docs.length === 0) return docs;
  const keys = Array.isArray(pickers) ? pickers : [];
  if (!keys.length) return docs;
  if (process.env.DEBUG_PINYIN) {
    try { console.log('[pinyin] attach start, docs:', docs.length, 'keys:', keys.map(k=>k.key).join(',')); } catch(_){ }
  }
  const texts = [];
  const idxMap = [];
  docs.forEach((doc, docIdx) => {
    keys.forEach((pk, kIdx) => {
      const val = doc && pk.key ? doc[pk.key] : '';
      texts.push(val || '');
      idxMap.push([docIdx, kIdx]);
    });
  });
  const res = await runPythonPinyin(texts);
  res.forEach((r, i) => {
    const [docIdx, kIdx] = idxMap[i] || [];
    const pk = keys[kIdx];
    if (!pk) return;
    const doc = docs[docIdx];
    if (!doc) return;
    if (pk.outFull) doc[pk.outFull] = r && r.full || '';
    if (pk.outAbbr) doc[pk.outAbbr] = r && r.abbr || '';
  });
  if (process.env.DEBUG_PINYIN) {
    try { console.log('[pinyin] attach done, sample:', docs && docs[0] && { py: docs[0].py, py_abbr: docs[0].py_abbr }); } catch(_){ }
  }
  return docs;
}

module.exports = { runPythonPinyin, attachPinyinToDocs };
