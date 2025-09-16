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
  // pickers: array of { key: 'cn', outFull: 'py' }
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
  });
  if (process.env.DEBUG_PINYIN) {
    try { console.log('[pinyin] attach done, sample:', docs && docs[0] && { py: docs[0].py }); } catch(_){ }
  }
  return docs;
}

module.exports = { runPythonPinyin, attachPinyinToDocs };
/**
 * 收集一个文档内的文本，覆盖嵌套字段
 * 默认收集字段：cn/name/title/replace/content/lore/legend
 */
function collectTextsFromDoc(doc, opts = {}) {
  const limit = Number.isFinite(opts.maxDepth) ? opts.maxDepth : 6;
  const filterKeys = Array.isArray(opts.keys) && opts.keys.length ? new Set(opts.keys) : null;
  // 默认排除 _id/__v 以及英文键 en 和颜色 color
  const hideKeys = new Set(opts.hideKeys || ['_id', '__v', 'en', 'color']);
  const out = [];

  const walk = (v, depth = 0, pathStr = '', keyName = '') => {
    if (depth > limit || v == null) return;
    const t = typeof v;
    if (t === 'string') {
      if (!filterKeys) {
        // 缺省：收集所有字符串属性
        if (v.trim()) out.push(v);
      } else {
        // 如有 keys，则仅在键名或路径匹配时收集
        if ((keyName && filterKeys.has(keyName)) || (pathStr && filterKeys.has(pathStr))) {
          if (v.trim()) out.push(v);
        }
      }
      return;
    }
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) {
        const childPath = pathStr ? `${pathStr}.${i}` : String(i);
        walk(v[i], depth + 1, childPath, keyName);
      }
      return;
    }
    if (t === 'object') {
      for (const k of Object.keys(v)) {
        if (hideKeys.has(k)) continue;
        const val = v[k];
        const childPath = pathStr ? `${pathStr}.${k}` : k;
        walk(val, depth + 1, childPath, k);
      }
    }
  };
  walk(doc, 0, '', '');
  return out;
}

/**
 * 为每个文档聚合多字段拼音，生成 py 字段（原 _py 重命名为 py）
 */
async function attachAggregatePinyin(docs, opts = {}) {
  if (!Array.isArray(docs) || docs.length === 0) return docs;
  const allTexts = [];
  const idx = [];
  const perDocTexts = docs.map(d => collectTextsFromDoc(d, opts));
  perDocTexts.forEach((arr, di) => {
    (arr || []).forEach(t => { allTexts.push(t || ''); idx.push(di); });
  });
  if (allTexts.length === 0) {
    return docs;
  }
  const conv = await runPythonPinyin(allTexts);
  const agg = new Array(docs.length).fill(null).map(() => ({ fulls: [] }));
  conv.forEach((r, i) => {
    const di = idx[i];
    if (di == null || di < 0) return;
    const bucket = agg[di];
    if (!bucket) return;
    const full = r && r.full ? String(r.full) : '';
    if (full) bucket.fulls.push(full);
  });
  agg.forEach((b, di) => {
    const d = docs[di];
    if (!d || !b) return;
    d.py = b.fulls.join(' ');
  });
  if (process.env.DEBUG_PINYIN) {
    try { console.log('[pinyin] aggregate done, sample:', docs && docs[0] && { py: docs[0].py }); } catch(_){ }
  }
  return docs;
}

module.exports.attachAggregatePinyin = attachAggregatePinyin;
module.exports.collectTextsFromDoc = collectTextsFromDoc;
