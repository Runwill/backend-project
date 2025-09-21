const { spawn } = require('child_process');
const path = require('path');

function resolvePythonCmd() {
  // Respect environment if present
  const envPy = process.env.PYTHON || process.env.PYTHON_PATH || process.env.PY;
  const list = [];
  if (envPy) list.push(/\\$|\/$/.test(envPy) ? path.join(envPy, process.platform === 'win32' ? 'python.exe' : 'python') : envPy);
  list.push(...(process.platform === 'win32' ? ['py','python','python3'] : ['python3','python']));
  return list;
}

function runPythonPinyin(texts, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const script = path.join(__dirname, '..', '..', 'python', 'pinyin.py');
  const payload = JSON.stringify(texts || []);

    const tryNext = (cands) => {
      if (!cands.length) {
        return resolve(texts.map(t => ({ full: String(t || ''), abbr: '' })));
      }
      const cmd = cands.shift();
      let proc; try { proc = spawn(cmd, [script], { stdio: ['pipe','pipe','pipe'], env: { ...process.env, PYTHONIOENCODING: 'utf-8' } }); } catch { return tryNext(cands); }
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
          try { return resolve(JSON.parse(out)); } catch { return resolve(texts.map(t => ({ full: String(t || ''), abbr: '' }))); }
        }
        tryNext(cands);
      });
      try { proc.stdin.write(payload); proc.stdin.end(); } catch { tryNext(cands); }
    };
    tryNext(resolvePythonCmd());
  });
}

// 导出统一放在文件末尾，避免分散风格 & 未定义引用
/**
 * 收集一个文档内的文本，覆盖嵌套字段
 * 默认收集字段：cn/name/title/replace/content/lore/legend
 */
function collectTextsFromDoc(doc, opts = {}) {
  const limit = Number.isFinite(opts.maxDepth) ? opts.maxDepth : 6;
  const filterKeys = (Array.isArray(opts.keys) && opts.keys.length) ? new Set(opts.keys) : null;
  // 默认排除 _id/__v 以及英文键 en 和颜色 color
  const hideKeys = new Set(opts.hideKeys || ['_id', '__v', 'en', 'color']);
  const out = [];

  const walk = (v, depth = 0, pathStr = '', keyName = '') => {
    if (depth > limit || v == null) return;
    const t = typeof v;
    if (t === 'string') { if (!filterKeys ? v.trim() : ((keyName && filterKeys.has(keyName)) || (pathStr && filterKeys.has(pathStr))) && v.trim()) out.push(v); return; }
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
  docs.map(d => collectTextsFromDoc(d, opts)).forEach((arr, di) => (arr || []).forEach(t => { allTexts.push(t || ''); idx.push(di); }));
  if (allTexts.length === 0) {
    return docs;
  }
  const conv = await runPythonPinyin(allTexts);
  const agg = new Array(docs.length).fill(0).map(() => ({ fulls: [] }));
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
  if (process.env.DEBUG_PINYIN) { try { console.log('[pinyin] aggregate done, sample:', docs?.[0] && { py: docs[0].py }); } catch{} }
  return docs;
}

module.exports = {
  runPythonPinyin,
  attachAggregatePinyin,
  collectTextsFromDoc
};
