const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { User, Character, Card, TermDynamic, TermFixed, Skill, AvatarChange, TokenLog } = require('../models/index');
const { listWithPinyin } = require('../services/listWithPinyin');
const { asyncHandler } = require('../utils/asyncHandler');

// 统一的集合到模型映射（供 tokens 路由等复用）
const modelMap = {
  'term-fixed': TermFixed,
  'term-dynamic': TermDynamic,
  'card': Card,
  'character': Character,
  'skill': Skill
};

const router = express.Router();

// 统一的 brief 构造函数（用于日志与简要查询）
function pickBrief(docLike) {
  try {
    const d = docLike?.toObject?.() ?? docLike;
    if (!d) return {};
    const { en, cn, name, id } = d;
    const o = {};
    if (en) o.en = en;
    if (cn) o.cn = cn;
    if (name) o.name = name;
    if (id != null) o.id = id;
    return o;
  } catch (_) { return {}; }
}

// 统一的 Token 日志记录 + 广播（失败静默）
function logToken(type, collection, docId, payload, req) {
  try {
    const sourceId = req.header('x-client-id') || '';
    const username = req.user?.username || '';
    const base = { type, collection, docId, username, sourceId };
    TokenLog.create({ ...base, ...payload }).catch(() => {});
  } catch (_) {}
}

// 配置 multer 存储到 uploads/avatar 目录
const uploadDir = path.join(__dirname, '..', '..', 'uploads', 'avatar');
fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${Math.random().toString(36).slice(2, 8)}${path.extname(file.originalname) || '.png'}`)
});
const upload = multer({
  storage,
  fileFilter: (_req, file, cb) => {
    const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp'];
    const ok = allowed.includes(file.mimetype);
    cb(ok ? null : new Error('不支持的文件类型'), ok);
  },
  limits: { fileSize: 2 * 1024 * 1024 }
});

// 安全删除工具：仅删除 uploads/avatar 下由我们生成的文件
function getFilePathFromUrl(url) {
  try {
    const fileName = url && path.basename(url);
    return fileName ? path.join(uploadDir, fileName) : null;
  } catch (_) { return null; }
}

async function deleteAvatarFileByUrl(url) {
  const filePath = getFilePathFromUrl(url);
  if (!filePath) return;
  try {
    await fs.promises.unlink(filePath);
    console.log('已清理头像文件:', filePath);
  } catch (e) {
    if (e?.code !== 'ENOENT') console.warn('删除头像文件失败:', e?.message || e);
  }
}

// 简易鉴权：解析 JWT，附加 req.user
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ message: '未授权' });
  try { req.user = jwt.verify(token, process.env.SECRET_KEY || 'your_secret_key'); next(); }
  catch { return res.status(401).json({ message: '未授权' }); }
}

// 基于角色的通用鉴权工厂
function requireRole(allowedRoles) {
  const set = new Set(allowedRoles || []);
  return async (req, res, next) => {
    try {
      if (!req.user?.id) return res.status(401).json({ message: '未授权' });
      const u = await User.findById(req.user.id);
      if (!u) return res.status(401).json({ message: '未授权' });
      return set.has(u.role) ? next() : res.status(403).json({ message: '无权限' });
    } catch (_) { return res.status(500).json({ message: '服务器错误' }); }
  };
}

// 角色别名中间件（兼容原有命名）
const requireReviewer = requireRole(['admin', 'moderator']);
const requireAdmin = requireRole(['admin']);

// 登录方法
router.post('/login', asyncHandler(async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ message: '用户不存在' });
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ message: '密码错误' });
  if (user.username != 'admin' && !user.isActive) {
    return res.status(401).json({ message: '申请正在审核' });
  }
  const token = jwt.sign(
    { id: user._id, username: user.username },
    process.env.SECRET_KEY || 'your_secret_key',
    { expiresIn: '1h' }
  );
  res.json({
    token,
    user: { id: user._id, username: user.username, role: user.role, avatar: user.avatar || '' }
  });
}, { logLabel: 'POST /login' }));

// 注册方法
router.post('/register', asyncHandler(async (req, res) => {
  const { username, password, role, avatar } = req.body;
  const existingUser = await User.findOne({ username });
  if (existingUser) return res.status(400).json({ message: '用户' + username + '已存在' });
  const newUser = new User({ username, password, role: role || 'user', avatar: avatar || '', isActive: false });
  await newUser.save();
  const admins = await User.find({ role: 'admin' });
  admins.forEach(admin => console.log(`通知管理员 ${admin.username}: 用户 ${username} 请求注册`));
  res.status(201).json({ message: '注册请求已提交，等待管理员批准' });
}, { logLabel: 'POST /register' }));

// 修改用户名和密码方法
router.put('/update', asyncHandler(async (req, res) => {
  const { id, newUsername, newPassword, newAvatar } = req.body;
  const user = await User.findById(id);
  if (!user) return res.status(404).json({ message: '用户' + id + '不存在' });
  if (typeof newUsername === 'string') {
    const trimmed = newUsername.trim();
    if (trimmed && trimmed !== user.username) {
      const exists = await User.findOne({ username: trimmed });
      if (exists) return res.status(400).json({ message: '用户已存在' });
      user.username = trimmed;
    }
  }
  if (newPassword) user.password = newPassword; // 交由钩子加密
  if (typeof newAvatar === 'string') user.avatar = newAvatar;
  await user.save();
  res.status(200).json({ message: '用户信息更新成功' });
}, { logLabel: 'PUT /update' }));


router.get('/pending-users', auth, requireReviewer, asyncHandler(async (req, res) => {
  // 查找所有未激活的用户
  const pendingUsers = await User.find({ isActive: false });
  res.status(200).json(pendingUsers || []);
}, { logLabel: 'GET /pending-users' }));

router.post('/approve', auth, requireReviewer, asyncHandler(async (req, res) => {
  const { userId, action } = req.body; // action: 'approve' 或 'reject'
  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ message: '用户不存在' });
  if (action === 'approve') {
  user.isActive = true;
  await user.save();
  return res.status(200).json({ message: '用户已成功激活' });
  }
  if (action === 'reject') {
  if (user.avatar) await deleteAvatarFileByUrl(user.avatar);
  const changes = await AvatarChange.find({ user: userId });
  for (const c of changes) { if (c?.url) await deleteAvatarFileByUrl(c.url); }
  await AvatarChange.deleteMany({ user: userId });
  await User.findByIdAndDelete(userId);
  return res.status(200).json({ message: '用户已被退回并删除' });
  }
  return res.status(400).json({ message: '无效的操作' });
}, { logLabel: 'POST /approve' }));

// 通用列表路由注册器
function registerListRoute(pathname, Model, errorMessage, buildQuery) {
  router.get(pathname, async (req, res) => {
    try {
      const q = (typeof buildQuery === 'function' && buildQuery(req));
      const list = await listWithPinyin(Model, q && typeof q === 'object' ? { query: q } : {});
      res.status(200).json(list);
    } catch (error) {
      const status = (Number.isInteger(error?.status) && error.status >= 400 && error.status < 500) ? error.status : 500;
      res.status(status).json({ message: errorMessage, error: error?.message || String(error) });
    }
  });
}

// 注册四类 + skill 列表路由
registerListRoute('/character', Character, '获取武将失败');
registerListRoute('/card', Card, '获取基础牌失败');
registerListRoute('/term-dynamic', TermDynamic, '获取动态术语失败');
registerListRoute('/term-fixed', TermFixed, '获取静态术语失败');
// skill 需要 strength 过滤与校验
registerListRoute('/skill', Skill, '获取技能失败', (req) => {
  const { strength } = req.query || {};
  if (strength === undefined) return {};
  const n = Number(strength);
  if (![0, 1, 2].includes(n)) {
    // 与原行为保持一致：直接返回 400
    throw Object.assign(new Error('strength 参数无效，应为 0/1/2'), { status: 400 });
  }
  return { strength: n };
});

// 根据技能名获取所有强度版本（保留原逻辑）
router.get('/skill/:name', asyncHandler(async (req, res) => {
  const { name } = req.params;
  // 保持现状：不生成 py，仅按 strength 升序
  const skills = await Skill.find({ name }).sort({ strength: 1 }).lean();
  res.status(200).json(skills);
}, { logLabel: 'GET /skill/:name' }));

// 批量导入技能（保留原逻辑）
router.post('/skill/import', asyncHandler(async (req, res) => {
  const { skills, strength } = req.body;
  if (!Array.isArray(skills) || strength === undefined) {
    return res.status(400).json({ message: '请提供有效的技能数组和强度级别' });
  }
  const importResults = { success: 0, failed: 0, errors: [] };
  for (const skillData of skills) {
    try {
      const existingSkill = await Skill.findOne({ name: skillData.name, strength });
      if (existingSkill) {
        importResults.failed++;
        importResults.errors.push({ name: skillData.name, error: '技能已存在' });
        continue;
      }
      const newSkill = new Skill({ name: skillData.name, content: skillData.content, strength, role: skillData.role });
      await newSkill.save();
      importResults.success++;
    } catch (error) {
      importResults.failed++;
      importResults.errors.push({ name: skillData.name, error: error.message });
    }
  }
  res.status(200).json({ message: '批量导入完成', results: importResults });
}, { logLabel: 'POST /skill/import' }));


// 获取用户信息（用于刷新头像等）
router.get('/user/:id', asyncHandler(async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ message: '缺少用户ID' });
  const user = await User.findById(id);
  if (!user) return res.status(404).json({ message: '用户不存在' });
  return res.status(200).json({
    id: user._id,
    username: user.username,
    role: user.role,
    avatar: user.avatar || '',
    isActive: !!user.isActive,
    createdAt: user.createdAt
  });
}, { logLabel: 'GET /user/:id' }));

// 上传头像-提交审核（不直接生效）
router.post('/upload/avatar', upload.single('avatar'), async (req, res) => {
  try {
    const userId = req.body.userId;
    if (!userId) {
      return res.status(400).json({ message: '缺少用户ID' });
    }
    if (!req.file) {
      return res.status(400).json({ message: '未接收到文件' });
    }
    const relativeUrl = `/uploads/avatar/${req.file.filename}`;

    // 若已有 pending 记录，替换图片并复用该记录；否则创建新记录
    let record = await AvatarChange.findOne({ user: userId, status: 'pending' });
    if (record) {
      const oldUrl = record.url;
      record.url = relativeUrl;
      await record.save();
      // 清理上一张替换下来的待审核图片文件
      if (oldUrl && oldUrl !== relativeUrl) {
        await deleteAvatarFileByUrl(oldUrl);
      }
    } else {
      record = await AvatarChange.create({ user: userId, url: relativeUrl });
    }

    // 通知管理员（日志代替）
    const admins = await User.find({ role: 'admin' });
    admins.forEach(a => console.log(`通知管理员 ${a.username}: 用户 ${userId} 提交头像审核 ${relativeUrl}`));

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    return res.status(200).json({ message: '头像已提交审核', url: `${baseUrl}${relativeUrl}`, status: record.status });
  } catch (error) {
    console.error('上传或提交审核失败:', error);
    // 出错则尝试删除刚上传的临时文件，避免产生垃圾文件
    if (req && req.file && req.file.filename) {
      const tmpUrl = `/uploads/avatar/${req.file.filename}`;
      await deleteAvatarFileByUrl(tmpUrl);
    }
    return res.status(500).json({ message: '服务器错误' });
  }
});

// 获取待审核头像列表（管理员）
router.get('/avatar/pending', auth, requireReviewer, asyncHandler(async (_req, res) => {
  const list = await AvatarChange.find({ status: 'pending' }).populate('user', 'username role');
  res.status(200).json(list || []);
}, { logLabel: 'GET /avatar/pending' }));

// 获取当前用户的待审核头像（用于个人查看）
router.get('/avatar/pending/me', asyncHandler(async (req, res) => {
  const userId = req.query.userId;
  if (!userId) return res.status(400).json({ message: '缺少用户ID' });
  const record = await AvatarChange.findOne({ user: userId, status: 'pending' });
  return res.status(200).json(record || null);
}, { logLabel: 'GET /avatar/pending/me' }));

// 审核头像（管理员）：approve 或 reject
router.post('/avatar/approve', auth, requireReviewer, asyncHandler(async (req, res) => {
  const { recordId, action, reason } = req.body;
  if (!recordId || !['approve', 'reject'].includes(action)) return res.status(400).json({ message: '参数无效' });
  const record = await AvatarChange.findById(recordId);
  if (!record) return res.status(404).json({ message: '记录不存在' });
  if (record.status !== 'pending') return res.status(400).json({ message: '该记录已处理' });
  if (action === 'approve') {
    const user = await User.findById(record.user);
    if (!user) return res.status(404).json({ message: '用户不存在' });
    const oldAvatar = user.avatar;
    user.avatar = record.url;
    await user.save();
    if (oldAvatar && oldAvatar !== record.url) {
      const cnt = await User.countDocuments({ _id: { $ne: user._id }, avatar: oldAvatar });
      if (cnt === 0) await deleteAvatarFileByUrl(oldAvatar);
    }
    record.status = 'approved';
    record.reason = reason || '';
    record.reviewedAt = new Date();
    await record.save();
    return res.status(200).json({ message: '已通过', record });
  }
  record.status = 'rejected';
  record.reason = reason || '';
  record.reviewedAt = new Date();
  await record.save();
  if (record.url) await deleteAvatarFileByUrl(record.url);
  return res.status(200).json({ message: '已拒绝', record });
}, { logLabel: 'POST /avatar/approve' }));

// 词元内联更新（仅管理员）
router.post('/tokens/update', auth, requireAdmin, asyncHandler(async (req, res) => {
  const { collection, id, path: dotPathRaw, value, valueType } = req.body || {};
  if (!collection || !id || !dotPathRaw) return res.status(400).json({ message: '参数无效' });
  const dotPath = dotPathRaw;
  if (dotPath.startsWith('_') || dotPath.includes('.__v') || dotPath === '__v') return res.status(400).json({ message: '该字段不允许修改' });
  const Model = modelMap[collection];
  if (!Model) return res.status(400).json({ message: '未知集合' });
  let casted = value;
  if (valueType === 'number') casted = Number(value);
  if (valueType === 'boolean') casted = Boolean(value);
  const docBefore = await Model.findById(id);
  if (!docBefore) return res.status(404).json({ message: '文档不存在' });
  const parts = String(dotPath).split('.');
  let parent = docBefore;
  for (let i = 0; i < parts.length - 1; i++) {
    const k = parts[i];
    const key = /^\d+$/.test(k) ? Number(k) : k;
    parent = parent ? parent[key] : undefined;
  }
  const lastKeyRaw = parts[parts.length - 1];
  const isIndex = /^\d+$/.test(lastKeyRaw);
  const lastKey = isIndex ? Number(lastKeyRaw) : lastKeyRaw;
  let prevValue; try { prevValue = (parent && typeof parent === 'object') ? parent[lastKey] : undefined; } catch (_) { prevValue = undefined; }
  const update = { $set: { [dotPath]: casted } };
  const doc = await Model.findByIdAndUpdate(id, update, { new: true });
  if (!doc) return res.status(404).json({ message: '文档不存在' });
  logToken('update', collection, String(id), { path: dotPath, value: casted, from: prevValue, doc: pickBrief(docBefore) }, req);
  return res.status(200).json({ message: '更新成功', doc });
}, { logLabel: 'POST /tokens/update' }));

// 词元内联删除（仅管理员）：删除对象字段或数组元素
router.post('/tokens/delete', auth, requireAdmin, asyncHandler(async (req, res) => {
  const { collection, id, path: dotPathRaw } = req.body || {};
  if (!collection || !id || !dotPathRaw) return res.status(400).json({ message: '参数无效' });
  const dotPath = dotPathRaw;
  if (dotPath.startsWith('_') || dotPath.includes('.__v') || dotPath === '__v') return res.status(400).json({ message: '该字段不允许删除' });
  const Model = modelMap[collection];
  if (!Model) return res.status(400).json({ message: '未知集合' });
  const doc = await Model.findById(id);
  if (!doc) return res.status(404).json({ message: '文档不存在' });
  const parts = String(dotPath).split('.');
  const rootMark = parts[0];
  let parent = doc;
  for (let i = 0; i < parts.length - 1; i++) {
    const k = parts[i];
    const key = /^\d+$/.test(k) ? Number(k) : k;
    if (parent == null) return res.status(400).json({ message: '路径不存在' });
    parent = parent[key];
  }
  const lastKeyRaw = parts[parts.length - 1];
  const isIndex = /^\d+$/.test(lastKeyRaw);
  const lastKey = isIndex ? Number(lastKeyRaw) : lastKeyRaw;
  if (parent == null) return res.status(400).json({ message: '路径不存在' });
  let prevValue; try { prevValue = Array.isArray(parent) && isIndex ? parent[lastKey] : (typeof parent === 'object' ? parent[lastKey] : undefined); } catch (_) { prevValue = undefined; }
  if (Array.isArray(parent) && isIndex) {
    if (lastKey < 0 || lastKey >= parent.length) return res.status(400).json({ message: '数组下标越界' });
    parent.splice(lastKey, 1);
    try { doc.markModified(rootMark); } catch (_) {}
    await doc.save();
  } else if (typeof parent === 'object') {
    if (!(lastKey in parent)) return res.status(400).json({ message: '字段不存在' });
    await Model.updateOne({ _id: id }, { $unset: { [dotPath]: "" } });
  } else {
    return res.status(400).json({ message: '路径不是可删除的对象/数组' });
  }
  logToken('delete-field', collection, String(id), { path: dotPath, from: prevValue, doc: pickBrief(doc) }, req);
  return res.status(200).json({ message: '删除成功' });
}, { logLabel: 'POST /tokens/delete' }));

// 词元结构推断
router.get('/tokens/shape', auth, requireAdmin, asyncHandler(async (req, res) => {
  const collection = req.query.collection;
  if (!collection) return res.status(400).json({ message: '缺少 collection' });
  const Model = modelMap[collection];
  if (!Model) return res.status(400).json({ message: '未知集合' });
  const schema = Model.schema;
  const fields = [];
  for (const [path, desc] of Object.entries(schema.paths)) {
    if (path === '__v') continue;
    const f = { name: path, type: desc.instance || 'Mixed', required: !!(desc.options && desc.options.required) };
    if (desc.enumValues && desc.enumValues.length) f.enum = desc.enumValues;
    if (desc.options && Object.prototype.hasOwnProperty.call(desc.options, 'default')) f.default = desc.options.default;
    fields.push(f);
  }
  for (const [path, desc] of Object.entries(schema.paths)) {
    if (desc.instance === 'Array' && desc.schema && desc.schema.paths) {
      const sub = [];
      for (const [sp, sd] of Object.entries(desc.schema.paths)) {
        if (sp === '_id') continue;
        sub.push({ name: sp + '[]', type: 'Subdocument[]' });
      }
      fields.push({ name: path + '[]', type: 'Subdocument[]', fields: sub });
    }
  }
  const docs = await Model.find().limit(100).lean();
  const suggest = {};
  const addKey = (bucket, key) => { if (!bucket.includes(key)) bucket.push(key); };
  const collectKeys = (obj, base, bucket) => {
    if (!obj || typeof obj !== 'object') return;
    for (const k of Object.keys(obj)) {
      addKey(bucket, base ? base + '.' + k : k);
      const v = obj[k];
      if (v && typeof v === 'object' && !Array.isArray(v)) collectKeys(v, base ? base + '.' + k : k, bucket);
    }
  };
  const mixedCandidates = fields.filter(f => f.type === 'Mixed').map(f => f.name);
  const mixedKeys = [];
  for (const d of docs) for (const m of mixedCandidates) if (d[m]) collectKeys(d[m], m, mixedKeys);
  suggest.mixedKeys = Array.from(new Set(mixedKeys));
  if (collection === 'character') {
    const ids = (docs || []).map(x => Number(x.id)).filter(x => Number.isFinite(x));
    suggest.nextId = ids.length ? Math.max(...ids) + 1 : 1;
  }
  if (collection === 'skill') suggest.strengthEnum = [0,1,2];
  return res.status(200).json({ collection, fields, suggest });
}, { logLabel: 'GET /tokens/shape' }));

// 新增文档（仅管理员）
router.post('/tokens/create', auth, requireAdmin, asyncHandler(async (req, res) => {
  const { collection, data } = req.body || {};
  if (!collection || !data || typeof data !== 'object') return res.status(400).json({ message: '参数无效' });
  const Model = modelMap[collection];
  if (!Model) return res.status(400).json({ message: '未知集合' });

  // 服务器端兜底：剔除非持久化/内部字段
  const sanitize = (obj) => {
    try {
      if (!obj || typeof obj !== 'object') return obj;
      if (Array.isArray(obj)) return obj.map(sanitize);
      const out = {};
      for (const k of Object.keys(obj)) {
        if (k === '_id' || k === '__v' || k === '_v' || k === 'py') continue;
        out[k] = sanitize(obj[k]);
      }
      return out;
    } catch (_) { return obj; }
  };
  const payload = sanitize(data);

  try {
    const doc = new Model(payload);
    await doc.save();
    logToken('create', collection, String(doc._id), { doc: pickBrief(doc) }, req);
    return res.status(201).json({ message: '创建成功', doc });
  } catch (error) {
    // 统一为更友好的 4xx 错误信息
    if (error && error.name === 'ValidationError') {
      const details = Object.values(error.errors || {}).map(e => e.message).filter(Boolean);
      return res.status(400).json({ message: '校验失败', details });
    }
    // Mongo duplicate key error
    if (error && (error.code === 11000 || error.code === 11001)) {
      const kv = (error && error.keyValue) || {};
      const keys = Object.keys(kv);
      const msg = keys.length ? `唯一键冲突：${keys.map(k => `${k}=${kv[k]}`).join(', ')}` : '唯一键冲突';
      return res.status(409).json({ message: msg });
    }
    // 其他错误交由 asyncHandler 统一处理（返回 500）
    throw error;
  }
}, { logLabel: 'POST /tokens/create' }));

// 删除整个文档（仅管理员）
router.post('/tokens/remove', auth, requireAdmin, asyncHandler(async (req, res) => {
  const { collection, id } = req.body || {};
  if (!collection || !id) return res.status(400).json({ message: '参数无效' });
  const Model = modelMap[collection];
  if (!Model) return res.status(400).json({ message: '未知集合' });
  const doc = await Model.findByIdAndDelete(id);
  if (!doc) return res.status(404).json({ message: '文档不存在' });
  logToken('delete-doc', collection, String(id), { doc: pickBrief(doc) }, req);
  return res.status(200).json({ message: '删除成功' });
}, { logLabel: 'POST /tokens/remove' }));

// 统一存储日志：分页拉取（默认最近，按时间逆序）
router.get('/tokens/logs', auth, asyncHandler(async (req, res) => {
  const p = Math.max(1, parseInt(req.query.page, 10) || 1);
  const ps = Math.min(500, Math.max(1, parseInt(req.query.pageSize, 10) || 100));
  const q = {
    ...(req.query.collection && { collection: String(req.query.collection) }),
    ...(req.query.docId && { docId: String(req.query.docId) })
  };
  if (req.query.since || req.query.until) {
    q.createdAt = {};
    if (req.query.since) q.createdAt.$gte = new Date(req.query.since);
    if (req.query.until) q.createdAt.$lte = new Date(req.query.until);
  }
  const total = await TokenLog.countDocuments(q);
  const list = await TokenLog.find(q).sort({ createdAt: -1 }).skip((p - 1) * ps).limit(ps).lean();
  return res.status(200).json({ page: p, pageSize: ps, total, list });
}, { logLabel: 'GET /tokens/logs' }));

// 批量删除词元日志（仅管理员）：可选按筛选条件删除
router.delete('/tokens/logs', auth, requireAdmin, asyncHandler(async (req, res) => {
  const q = {
    ...(req.query.collection && { collection: String(req.query.collection) }),
    ...(req.query.docId && { docId: String(req.query.docId) })
  };
  if (req.query.since || req.query.until) {
    q.createdAt = {};
    if (req.query.since) q.createdAt.$gte = new Date(req.query.since);
    if (req.query.until) q.createdAt.$lte = new Date(req.query.until);
  }
  const r = await TokenLog.deleteMany(q);
  const deleted = (r && (r.deletedCount || r.n)) || 0;
  return res.status(200).json({ message: '已清空', deleted });
}, { logLabel: 'DELETE /tokens/logs' }));

// 删除一条词元日志（仅管理员）
router.delete('/tokens/logs/:id', auth, requireAdmin, asyncHandler(async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ message: '缺少日志ID' });
  const log = await TokenLog.findByIdAndDelete(id);
  if (!log) return res.status(404).json({ message: '日志不存在' });
  return res.status(200).json({ message: '删除成功' });
}, { logLabel: 'DELETE /tokens/logs/:id' }));

// 获取文档简要（用于日志标签兜底）：返回 { en, cn, name, id }
router.get('/tokens/brief', asyncHandler(async (req, res) => {
  const { collection, id } = req.query || {};
  if (!collection || !id) return res.status(400).json({ message: '缺少参数' });
  const Model = modelMap[collection];
  if (!Model) return res.status(400).json({ message: '未知集合' });
  const doc = await Model.findById(id).lean();
  if (!doc) return res.status(404).json({ message: '文档不存在' });
  return res.status(200).json(pickBrief(doc));
}, { logLabel: 'GET /tokens/brief' }));

module.exports = router;