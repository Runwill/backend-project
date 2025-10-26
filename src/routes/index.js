const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { User, Character, Card, TermDynamic, TermFixed, Skill, AvatarChange, UsernameChange, TokenLog, IntroChange, UserLog } = require('../models/index');
const { PERMISSIONS } = require('../config/permissions');
const { listWithPinyin } = require('../services/listWithPinyin');
const { attachAggregatePinyin } = require('../utils/pinyin');
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

// 统一：按后端基线 PERMISSIONS 的顺序对权限数组排序
function sortPerms(arr) {
  try {
    const list = Array.isArray(arr) ? arr.map(String) : [];
    const order = new Map(PERMISSIONS.map((p, i) => [String(p), i]));
    return list.slice().sort((a, b) => {
      const ia = order.has(a) ? order.get(a) : 99999;
      const ib = order.has(b) ? order.get(b) : 99999;
      if (ia !== ib) return ia - ib;
      return a.localeCompare(b);
    });
  } catch (_) { return Array.isArray(arr) ? arr : []; }
}

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

// 统一的用户行为日志记录（失败静默）
function logUser(type, userId, payload, req) {
  try {
    const sourceId = req && (req.header('x-client-id') || '');
    const actorId = req?.user?.id ? String(req.user.id) : '';
    const actorName = req?.user?.username || '';
    const base = { type, userId: String(userId || ''), actorId, actorName, sourceId };
  UserLog.create({ ...base, ...(payload || {}) }).catch(() => { });
  } catch(_) { }
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
    user: { id: user._id, username: user.username, role: user.role, avatar: user.avatar || '', intro: user.intro || '' }
  });
}, { logLabel: 'POST /login' }));

// 注册方法
router.post('/register', asyncHandler(async (req, res) => {
  const { username, password, role, avatar } = req.body || {};
  if (!username || typeof username !== 'string') return res.status(400).json({ message: '用户名无效' });
  if (!password || typeof password !== 'string') return res.status(400).json({ message: '密码无效' });
  const name = username.trim();
  if (name.length < 2) return res.status(400).json({ message: '用户名至少 2 个字符' });
  if (name.length > 12) return res.status(400).json({ message: '用户名最多 12 个字符' });
  const existingUser = await User.findOne({ username: name });
  if (existingUser) return res.status(400).json({ message: '用户' + name + '已存在' });

  const newUser = new User({
    username: name,
    password,
    role: role || 'user',
    avatar: avatar || '',
    isActive: false,
    permissions: []
  });
  await newUser.save();
  try { logUser('user-registered', String(newUser._id), { message: '用户注册，待审核', data: { applicantName: newUser.username } }, req); } catch(_){ }
  return res.status(201).json({ message: '注册成功，待审核', userId: newUser._id });
}, { logLabel: 'POST /register' }));

// 修改密码（需登录）
router.put('/change-password', auth, asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  const targetId = req.user && req.user.id;
  if (!targetId) return res.status(401).json({ message: '未授权' });
  if (!newPassword || typeof newPassword !== 'string') return res.status(400).json({ message: '新密码无效' });
  const user = await User.findById(targetId);
  if (!user) return res.status(404).json({ message: '用户不存在' });
  const ok = await bcrypt.compare(oldPassword || '', user.password);
  if (!ok) return res.status(401).json({ message: '旧密码错误' });
  user.password = newPassword; // 由模型 pre-save 钩子处理哈希
  await user.save();
  try { logUser('password-change', String(user._id), { message: '修改密码' }, req); } catch(_){ }
  return res.status(200).json({ message: '密码已更新' });
}, { logLabel: 'PUT /change-password' }));

// 修改用户名和密码方法
router.put('/update', asyncHandler(async (req, res) => {
  const { id, newUsername, newPassword, newAvatar, newIntro } = req.body;
  const user = await User.findById(id);
  if (!user) return res.status(404).json({ message: '用户' + id + '不存在' });
  // 用户名改为“需要审核”，不在此处直接修改
  if (typeof newUsername === 'string' && newUsername.trim() && newUsername.trim() !== user.username) {
    return res.status(400).json({ message: '用户名修改需提交审核，请使用 /api/username/change 接口' });
  }
  if (newPassword) user.password = newPassword; // 交由钩子加密
  if (typeof newAvatar === 'string') user.avatar = newAvatar;
  if (typeof newIntro === 'string') {
    return res.status(400).json({ message: '简介修改需提交审核，请使用 /intro/change 接口' });
  }
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
  try { logUser('user-approved', String(user._id), { message: '管理员通过注册', data: { applicantName: user.username } }, req); } catch(_){}
  return res.status(200).json({ message: '用户已成功激活' });
  }
  if (action === 'reject') {
  const applicantName = user.username;
  if (user.avatar) await deleteAvatarFileByUrl(user.avatar);
  const changes = await AvatarChange.find({ user: userId });
  for (const c of changes) { if (c?.url) await deleteAvatarFileByUrl(c.url); }
  await AvatarChange.deleteMany({ user: userId });
  await User.findByIdAndDelete(userId);
  try { logUser('user-rejected', String(userId), { message: '管理员拒绝注册', data: { applicantName } }, req); } catch(_){}
  return res.status(200).json({ message: '用户已被退回并删除' });
  }
  return res.status(400).json({ message: '无效的操作' });
}, { logLabel: 'POST /approve' }));

// 用户名修改 - 提交审核（与头像流程类似，不直接生效）
router.post('/username/change', asyncHandler(async (req, res) => {
  const { userId, newUsername } = req.body || {};
  if (!userId || typeof newUsername !== 'string') {
    return res.status(400).json({ message: '缺少用户ID或新用户名' });
  }
  const trimmed = newUsername.trim();
  if (!trimmed) return res.status(400).json({ message: '新用户名不能为空' });
  // 基本长度限制：与 userSchema 最大 12 对齐，下限 2
  if (trimmed.length < 2) return res.status(400).json({ message: '用户名至少 2 个字符' });
  if (trimmed.length > 12) return res.status(400).json({ message: '用户名最多 12 个字符' });

  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ message: '用户不存在' });
  if (trimmed === user.username) return res.status(400).json({ message: '新旧用户名相同' });

  // “仪同三司”免审核：直接修改
  const hasBypass = Array.isArray(user.permissions) && user.permissions.includes('仪同三司');
  if (hasBypass) {
    const exists = await User.findOne({ username: trimmed, _id: { $ne: user._id } });
    if (exists) return res.status(409).json({ message: '该用户名已被占用' });
    user.username = trimmed;
    await user.save();
    try { logUser('username-approved', String(user._id), { actorId: String(user._id), actorName: user.username, message: '免审核：用户名已更新', data: { username: user.username } }, req); } catch(_){ }
    return res.status(200).json({ message: '用户名已更新（免审核）', applied: true, username: user.username });
  }

  // 预检唯一性（并发情况下最终以审批步骤为准，再次校验）
  const exists = await User.findOne({ username: trimmed, _id: { $ne: user._id } });
  if (exists) return res.status(409).json({ message: '该用户名已被占用' });

  // 若已有 pending 记录，则覆盖新用户名；否则创建
  let record = await UsernameChange.findOne({ user: userId, status: 'pending' });
  if (record) {
    record.newUsername = trimmed;
    await record.save();
  } else {
    record = await UsernameChange.create({ user: userId, newUsername: trimmed });
  }

  // 通知管理员（用日志代替）
  const admins = await User.find({ role: 'admin' });
  admins.forEach(a => console.log(`通知管理员 ${a.username}: 用户 ${userId} 提交用户名修改审核 => ${trimmed}`));
  try { logUser('username-submitted', String(user._id), { actorId: String(user._id), actorName: user.username, message: '提交用户名修改审核', data: { newUsername: trimmed } }, req); } catch(_){ }
  return res.status(200).json({ message: '用户名变更已提交审核', status: record.status, newUsername: record.newUsername, recordId: record._id });
}, { logLabel: 'POST /username/change' }));

// 获取待审核的用户名变更列表（管理员/审核员）
router.get('/username/pending', auth, requireReviewer, asyncHandler(async (_req, res) => {
  const list = await UsernameChange.find({ status: 'pending' }).populate('user', 'username role');
  res.status(200).json(list || []);
}, { logLabel: 'GET /username/pending' }));

// 获取当前用户的待审核用户名变更
router.get('/username/pending/me', asyncHandler(async (req, res) => {
  const userId = req.query.userId;
  if (!userId) return res.status(400).json({ message: '缺少用户ID' });
  const record = await UsernameChange.findOne({ user: userId, status: 'pending' });
  return res.status(200).json(record || null);
}, { logLabel: 'GET /username/pending/me' }));

// 审核用户名变更
router.post('/username/approve', auth, requireReviewer, asyncHandler(async (req, res) => {
  const { recordId, action, reason } = req.body || {};
  if (!recordId || !['approve', 'reject'].includes(action)) return res.status(400).json({ message: '参数无效' });
  const record = await UsernameChange.findById(recordId);
  if (!record) return res.status(404).json({ message: '记录不存在' });
  if (record.status !== 'pending') return res.status(400).json({ message: '该记录已处理' });

  if (action === 'approve') {
    const user = await User.findById(record.user);
    if (!user) return res.status(404).json({ message: '用户不存在' });
    const target = (record.newUsername || '').trim();
    if (!target) return res.status(400).json({ message: '记录无效的新用户名' });
    if (target.length < 2) return res.status(400).json({ message: '用户名至少 2 个字符' });
    if (target.length > 12) return res.status(400).json({ message: '用户名最多 12 个字符' });
    if (target === user.username) {
      // 无需变更，直接标记通过
      record.status = 'approved';
      record.reason = reason || '';
      record.reviewedAt = new Date();
      await record.save();
    try { logUser('username-approved', String(user._id), { message: '用户名审核通过（无变更）', data: { username: user.username, applicantName: user.username } }, req); } catch(_){ }
      return res.status(200).json({ message: '已通过（用户名未变更）', record });
    }
    // 最终唯一性校验
    const exists = await User.findOne({ username: target, _id: { $ne: user._id } });
    if (exists) return res.status(409).json({ message: '该用户名已被占用' });
    user.username = target;
    await user.save();
    record.status = 'approved';
    record.reason = reason || '';
    record.reviewedAt = new Date();
    await record.save();
  try { logUser('username-approved', String(user._id), { message: '用户名审核通过', data: { username: target, applicantName: user.username } }, req); } catch(_){ }
    return res.status(200).json({ message: '已通过', record });
  }
  // reject
  record.status = 'rejected';
  record.reason = reason || '';
  record.reviewedAt = new Date();
  await record.save();
  try { const u = await User.findById(record.user).lean(); logUser('username-rejected', String(record.user), { message: '用户名修改被拒绝', data: { reason: record.reason, newUsername: record.newUsername, applicantName: (u && u.username) || '' } }, req); } catch(_){ }
  return res.status(200).json({ message: '已拒绝', record });
}, { logLabel: 'POST /username/approve' }));

// 撤回用户名变更（由用户发起）：删除自己的 pending 记录
router.post('/username/cancel', asyncHandler(async (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ message: '缺少用户ID' });
  const record = await UsernameChange.findOne({ user: userId, status: 'pending' });
  if (!record) return res.status(200).json({ message: '无待审核记录' });
  try { await UsernameChange.deleteOne({ _id: record._id }); const u = await User.findById(userId).lean(); logUser('username-cancelled', String(userId), { actorId: String(userId), actorName: (u && u.username) || '', message: '撤回用户名修改申请' }, req); } catch(_){}
  return res.status(200).json({ message: '已撤回' });
}, { logLabel: 'POST /username/cancel' }));

// 简介修改 - 提交审核（不直接生效）
router.post('/intro/change', asyncHandler(async (req, res) => {
  const { userId, newIntro } = req.body || {};
  if (!userId || typeof newIntro !== 'string') {
    return res.status(400).json({ message: '缺少用户ID或新简介' });
  }
  // 允许空字符串，但限制最大 500
  const normalized = (newIntro || '').trim().slice(0, 500);

  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ message: '用户不存在' });
  const current = (user.intro || '').trim();
  if (normalized === current) return res.status(400).json({ message: '新旧简介相同' });

  // “仪同三司”免审核：直接修改
  const hasBypass = Array.isArray(user.permissions) && user.permissions.includes('仪同三司');
  if (hasBypass) {
    user.intro = normalized;
    await user.save();
    try { logUser('intro-approved', String(user._id), { actorId: String(user._id), actorName: user.username, message: '免审核：简介已更新', data: { intro: user.intro } }, req); } catch(_){ }
    return res.status(200).json({ message: '简介已更新（免审核）', applied: true, intro: user.intro });
  }

  // 若已有 pending 记录，则覆盖；否则创建
  let record = await IntroChange.findOne({ user: userId, status: 'pending' });
  if (record) {
    record.newIntro = normalized;
    await record.save();
  } else {
    record = await IntroChange.create({ user: userId, newIntro: normalized });
  }

  // 通知管理员（日志代替）
  const admins = await User.find({ role: 'admin' });
  admins.forEach(a => console.log(`通知管理员 ${a.username}: 用户 ${userId} 提交简介修改审核`));
  try {
    const u = await User.findById(userId).lean();
    logUser('intro-submitted', String(userId), { actorId: String(userId), actorName: (u && u.username) || '', message: '提交简介修改审核', data: { newIntro: normalized } }, req);
  } catch(_){ }
  return res.status(200).json({ message: '简介变更已提交审核', status: record.status, newIntro: record.newIntro, recordId: record._id });
}, { logLabel: 'POST /intro/change' }));

// 获取待审核的简介变更列表（管理员/审核员）
router.get('/intro/pending', auth, requireReviewer, asyncHandler(async (_req, res) => {
  const list = await IntroChange.find({ status: 'pending' }).populate('user', 'username role');
  res.status(200).json(list || []);
}, { logLabel: 'GET /intro/pending' }));

// 获取当前用户的待审核简介变更
router.get('/intro/pending/me', asyncHandler(async (req, res) => {
  const userId = req.query.userId;
  if (!userId) return res.status(400).json({ message: '缺少用户ID' });
  const record = await IntroChange.findOne({ user: userId, status: 'pending' });
  return res.status(200).json(record || null);
}, { logLabel: 'GET /intro/pending/me' }));

// 审核简介变更
router.post('/intro/approve', auth, requireReviewer, asyncHandler(async (req, res) => {
  const { recordId, action, reason } = req.body || {};
  if (!recordId || !['approve', 'reject'].includes(action)) return res.status(400).json({ message: '参数无效' });
  const record = await IntroChange.findById(recordId);
  if (!record) return res.status(404).json({ message: '记录不存在' });
  if (record.status !== 'pending') return res.status(400).json({ message: '该记录已处理' });

  if (action === 'approve') {
    const user = await User.findById(record.user);
    if (!user) return res.status(404).json({ message: '用户不存在' });
    // 应用变更
    const target = (record.newIntro || '').trim().slice(0, 500);
    user.intro = target;
  await user.save();
    record.status = 'approved';
    record.reason = reason || '';
    record.reviewedAt = new Date();
    await record.save();
  try { logUser('intro-approved', String(user._id), { message: '简介审核通过', data: { intro: user.intro, applicantName: user.username } }, req); } catch(_){ }
    return res.status(200).json({ message: '已通过', record });
  }
  // reject
  record.status = 'rejected';
  record.reason = reason || '';
  record.reviewedAt = new Date();
  await record.save();
  try { const u = await User.findById(record.user).lean(); logUser('intro-rejected', String(record.user), { message: '简介审核拒绝', data: { reason: record.reason, newIntro: record.newIntro, applicantName: (u && u.username) || '' } }, req); } catch(_){ }
  return res.status(200).json({ message: '已拒绝', record });
}, { logLabel: 'POST /intro/approve' }));

// 撤回简介变更（由用户发起）：删除自己的 pending 记录
router.post('/intro/cancel', asyncHandler(async (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return res.status(400).json({ message: '缺少用户ID' });
  const record = await IntroChange.findOne({ user: userId, status: 'pending' });
  if (!record) return res.status(200).json({ message: '无待审核记录' });
  try { await IntroChange.deleteOne({ _id: record._id }); const u = await User.findById(userId).lean(); logUser('intro-cancelled', String(userId), { actorId: String(userId), actorName: (u && u.username) || '', message: '撤回简介修改申请' }, req); } catch(_){ }
  return res.status(200).json({ message: '已撤回' });
}, { logLabel: 'POST /intro/cancel' }));

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
// 注意：为避免与 /user/logs 冲突，限制 :id 为 24 位十六进制的 Mongo ObjectId
router.get('/user/:id([0-9a-fA-F]{24})', asyncHandler(async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ message: '缺少用户ID' });
  const user = await User.findById(id);
  if (!user) return res.status(404).json({ message: '用户不存在' });
  return res.status(200).json({
    id: user._id,
    username: user.username,
    role: user.role,
    avatar: user.avatar || '',
    intro: user.intro || '',
    permissions: sortPerms(user.permissions),
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

    // 若拥有“仪同三司”权限：直接替换头像，不走审核
    try {
      const user = await User.findById(userId);
      if (user && Array.isArray(user.permissions) && user.permissions.includes('仪同三司')) {
        const oldAvatar = user.avatar;
        user.avatar = relativeUrl;
        await user.save();
        if (oldAvatar && oldAvatar !== relativeUrl) {
          const cnt = await User.countDocuments({ _id: { $ne: user._id }, avatar: oldAvatar });
          if (cnt === 0) await deleteAvatarFileByUrl(oldAvatar);
        }
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  try { logUser('avatar-approved', String(user._id), { actorId: String(user._id), actorName: user.username, message: '免审核：头像已更新', data: { url: relativeUrl } }, req); } catch(_){ }
  return res.status(200).json({ message: '头像已更新（免审核）', applied: true, url: `${baseUrl}${relativeUrl}`, relativeUrl });
      }
    } catch (_) {}

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
  try { const u = await User.findById(userId).lean(); logUser('avatar-submitted', String(userId), { actorId: String(userId), actorName: (u && u.username) || '', message: '提交头像审核', data: { url: relativeUrl } }, req); } catch(_){ }
    return res.status(200).json({ message: '头像已提交审核', url: `${baseUrl}${relativeUrl}`, relativeUrl, status: record.status });
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
  try { logUser('avatar-approved', String(user._id), { message: '头像审核通过', data: { url: user.avatar, applicantName: user.username } }, req); } catch(_){}
  return res.status(200).json({ message: '已通过', record });
  }
  record.status = 'rejected';
  record.reason = reason || '';
  record.reviewedAt = new Date();
  await record.save();
  if (record.url) await deleteAvatarFileByUrl(record.url);
  try { const u = await User.findById(record.user).lean(); logUser('avatar-rejected', String(record.user), { message: '头像审核拒绝', data: { reason: record.reason, url: record.url, applicantName: (u && u.username) || '' } }, req); } catch(_){}
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
    // 在返回前计算 py，确保前端立即可用拼音搜索
    let outDoc = doc.toObject();
    try {
      const [withPy] = await attachAggregatePinyin([outDoc], { keys: ['cn','name','title','replace','content','lore','legend'] });
      if (withPy) outDoc = withPy;
    } catch (_) {}
    logToken('create', collection, String(doc._id), { doc: pickBrief(doc) }, req);
    return res.status(201).json({ message: '创建成功', doc: outDoc });
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

// === 用户日志：分页拉取 ===
router.get('/user/logs', auth, requireAdmin, asyncHandler(async (req, res) => {
  try {
    if (!UserLog || typeof UserLog.find !== 'function') {
      return res.status(200).json({ page: 1, pageSize: 0, total: 0, list: [] });
    }
    const p = Math.max(1, parseInt(req.query.page, 10) || 1);
    const ps = Math.min(500, Math.max(1, parseInt(req.query.pageSize, 10) || 100));
    const q = {};
    if (req.query.userId) q.userId = String(req.query.userId);
    const total = await UserLog.countDocuments(q);
    const list = await UserLog.find(q).sort({ createdAt: -1 }).skip((p - 1) * ps).limit(ps).lean();
    return res.status(200).json({ page: p, pageSize: ps, total, list });
  } catch (e) {
    console.error('GET /user/logs failed:', e && e.message);
    return res.status(500).json({ message: '服务器错误' });
  }
}, { logLabel: 'GET /user/logs' }));

// 删除用户日志（仅管理员）：可选按 userId 删除
router.delete('/user/logs', auth, requireAdmin, asyncHandler(async (req, res) => {
  try {
    if (!UserLog || typeof UserLog.deleteMany !== 'function') {
      return res.status(200).json({ message: '已清空', deleted: 0 });
    }
    const q = {};
    if (req.query.userId) q.userId = String(req.query.userId);
    const r = await UserLog.deleteMany(q);
    const deleted = (r && (r.deletedCount || r.n)) || 0;
    return res.status(200).json({ message: '已清空', deleted });
  } catch (e) {
    console.error('DELETE /user/logs failed:', e && e.message);
    return res.status(500).json({ message: '服务器错误' });
  }
}, { logLabel: 'DELETE /user/logs' }));

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
 
// ======= 权限管理（仅管理员） =======
// 列出统一权限清单（前端据此渲染可分配列表）
router.get('/permissions', asyncHandler(async (_req, res) => {
  res.status(200).json(PERMISSIONS || []);
}, { logLabel: 'GET /permissions' }));

// 查询用户（用于权限管理列表）
router.get('/users/permissions', auth, requireAdmin, asyncHandler(async (req, res) => {
  const q = (req.query.search || '').trim();
  const cond = q ? { username: { $regex: q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } } : {};
  const list = await User.find(cond).select('username role permissions createdAt isActive').sort({ createdAt: -1 }).limit(500).lean();
  const ordered = (list || []).map(u => ({ ...u, permissions: sortPerms(u.permissions) }));
  res.status(200).json(ordered);
}, { logLabel: 'GET /users/permissions' }));

// 更新指定用户的权限集合（覆盖或增删）
router.post('/user/permissions/update', auth, requireAdmin, asyncHandler(async (req, res) => {
  const { userId, action, permission, permissions } = req.body || {};
  if (!userId) return res.status(400).json({ message: '缺少用户ID' });
  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ message: '用户不存在' });
  const prev = Array.isArray(user.permissions) ? user.permissions.slice() : [];
  let changed = null;
  if (Array.isArray(permissions)) {
    // 校验整包权限是否均在后端清单中
    const all = permissions.map(String);
    const invalid = all.find(p => !PERMISSIONS.includes(p));
    if (invalid) return res.status(400).json({ message: '无效的权限', permission: invalid });
    user.permissions = all;
    changed = { type: 'replaced', to: all };
  } else if (permission && (action === 'grant' || action === 'revoke')) {
    const p = String(permission);
    // 仅在新增授予时做清单校验；撤销允许（即使权限不在清单，以便清理历史遗留）
    if (action === 'grant' && !PERMISSIONS.includes(p)) {
      return res.status(400).json({ message: '无效的权限', permission: p });
    }
    const arr = prev.slice();
    const has = arr.includes(p);
    if (action === 'grant' && !has) { arr.push(p); changed = { type: 'grant', p }; }
    if (action === 'revoke' && has) { arr.splice(arr.indexOf(p), 1); changed = { type: 'revoke', p }; }
    user.permissions = arr;
  } else {
    return res.status(400).json({ message: '参数无效' });
  }
  await user.save();
  try {
    if (changed) {
      if (changed.type === 'replaced') logUser('permissions-replaced', String(user._id), { data: { from: prev, to: changed.to } }, req);
      if (changed.type === 'grant') logUser('permissions-granted', String(user._id), { data: { perm: changed.p } }, req);
      if (changed.type === 'revoke') logUser('permissions-revoked', String(user._id), { data: { perm: changed.p } }, req);
    }
  } catch(_){}
  res.status(200).json({ message: '已更新', user: { id: user._id, username: user.username, role: user.role, permissions: sortPerms(user.permissions) } });
}, { logLabel: 'POST /user/permissions/update' }));