const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { User, Character, Card, TermDynamic, TermFixed, Skill, AvatarChange, TokenLog } = require('../models/index'); // 正确引入所有模型

const router = express.Router();

// Realtime SSE removed; keep a no-op broadcaster for compatibility
function sseBroadcast(_) { /* no-op */ }

// 配置 multer 存储到 uploads/avatar 目录
const uploadDir = path.join(__dirname, '..', '..', 'uploads', 'avatar');
fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname) || '.png';
        const safeName = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`;
        cb(null, safeName);
    }
});
const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        // 仅允许常见图片类型
        const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp'];
        if (allowed.includes(file.mimetype)) cb(null, true);
        else cb(new Error('不支持的文件类型'));
    },
    limits: { fileSize: 2 * 1024 * 1024 } // 2MB
});

// 安全删除工具：仅删除 uploads/avatar 下由我们生成的文件
function getFilePathFromUrl(url) {
    try {
        if (!url) return null;
        // 仅使用文件名，避免路径穿越
        const fileName = path.basename(url);
        if (!fileName) return null;
        return path.join(uploadDir, fileName);
    } catch (e) {
        return null;
    }
}

async function deleteAvatarFileByUrl(url) {
    const filePath = getFilePathFromUrl(url);
    if (!filePath) return;
    try {
        await fs.promises.unlink(filePath);
        console.log('已清理头像文件:', filePath);
    } catch (e) {
        if (e && e.code === 'ENOENT') return; // 文件不存在则忽略
        console.warn('删除头像文件失败:', e && e.message ? e.message : e);
    }
}

// 简易鉴权：解析 JWT，附加 req.user
function auth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: '未授权' });
    try {
        const payload = jwt.verify(token, process.env.SECRET_KEY || 'your_secret_key');
        req.user = payload; // { id, username }
        next();
    } catch (e) {
        return res.status(401).json({ message: '未授权' });
    }
}

// 读取数据库中的用户并校验角色（moderator 或 admin 可审核）
async function requireReviewer(req, res, next) {
    try {
        if (!req.user?.id) return res.status(401).json({ message: '未授权' });
        const u = await User.findById(req.user.id);
        if (!u) return res.status(401).json({ message: '未授权' });
        if (u.role === 'admin' || u.role === 'moderator') return next();
        return res.status(403).json({ message: '无权限' });
    } catch (e) {
        return res.status(500).json({ message: '服务器错误' });
    }
}

// 仅管理员
async function requireAdmin(req, res, next) {
    try {
        if (!req.user?.id) return res.status(401).json({ message: '未授权' });
        const u = await User.findById(req.user.id);
        if (!u) return res.status(401).json({ message: '未授权' });
        if (u.role === 'admin') return next();
        return res.status(403).json({ message: '无权限' });
    } catch (e) {
        return res.status(500).json({ message: '服务器错误' });
    }
}

// 登录方法
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // 查找用户
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: '用户不存在' });
        }

        // 验证密码
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: '密码错误' });
        }

        // 验证是否通过
        if (user.username != 'admin' && !user.isActive) {
            return res.status(401).json({ message: '申请正在审核' });
        }

        // 生成 JWT
        const token = jwt.sign(
            { id: user._id, username: user.username },
            process.env.SECRET_KEY || 'your_secret_key',
            { expiresIn: '1h' }
        );

        res.json({
            token,
            user: {
                id: user._id,
                username: user.username,
                role: user.role,
                avatar: user.avatar || ''
            }
        });
    } catch (error) {
        console.error('登录失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 注册方法
router.post('/register', async (req, res) => {
    const { username, password, role, avatar } = req.body;

    try {
        // 检查用户名是否已存在
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: '用户' + username + '已存在' });
        }

        // 创建新用户（未激活）
        const newUser = new User({ 
            username, 
            password, 
            role: role || 'user', 
            avatar: avatar || '',
            isActive: false // 默认未激活
        });
        await newUser.save();

        // 模拟向管理员发送通知
        const admins = await User.find({ role: 'admin' });
        admins.forEach(admin => {
            console.log(`通知管理员 ${admin.username}: 用户 ${username} 请求注册`);
            // 在实际应用中，这里可以通过电子邮件或其他方式通知管理员
        });

        res.status(201).json({ message: '注册请求已提交，等待管理员批准' });
    } catch (error) {
        console.error('注册失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 修改用户名和密码方法
router.put('/update', async (req, res) => {
    const { id, newUsername, newPassword, newAvatar } = req.body;

    try {
        // 查找用户
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ message: '用户' + id + '不存在' });
        }

        // 更新用户名和密码
        if (typeof newUsername === 'string') {
            const trimmed = newUsername.trim();
            if (trimmed && trimmed !== user.username) {
                // 若修改了用户名，先检查是否已存在
                const exists = await User.findOne({ username: trimmed });
                if (exists) {
                    return res.status(400).json({ message: '用户已存在' });
                }
                user.username = trimmed;
            }
        }
        if (newPassword) {
            // 直接赋值明文，交由 userSchema.pre('save') 统一加密，避免二次哈希
            user.password = newPassword;
        }

        // 更新头像
        if (typeof newAvatar === 'string') {
            user.avatar = newAvatar;
        }

        await user.save();

        res.status(200).json({ message: '用户信息更新成功' });
    } catch (error) {
        console.error('更新失败:', error);
        // 兜底处理唯一索引冲突
        if (error && error.code === 11000) {
            return res.status(400).json({ message: '用户已存在' });
        }
        res.status(500).json({ message: '服务器错误' });
    }
});


router.get('/pending-users', auth, requireReviewer, async (req, res) => {
    try {
        // 查找所有未激活的用户
        const pendingUsers = await User.find({ isActive: false });
        res.status(200).json(pendingUsers || []);
    } catch (error) {
        console.error('获取未激活用户失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

router.post('/approve', auth, requireReviewer, async (req, res) => {
    const { userId, action } = req.body; // action: 'approve' 或 'reject'

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: '用户不存在' });
        }

        if (action === 'approve') {
            // 激活用户
            user.isActive = true;
            await user.save();
            res.status(200).json({ message: '用户已成功激活' });
        } else if (action === 'reject') {
            // 拒绝注册：删除用户以及其相关头像文件与待审核记录
            // 1) 删除该用户当前头像文件（如果有）
            if (user.avatar) {
                await deleteAvatarFileByUrl(user.avatar);
            }
            // 2) 删除所有该用户的头像审核记录文件（pending/approved/rejected），然后删除记录
            const changes = await AvatarChange.find({ user: userId });
            for (const c of changes) {
                if (c && c.url) await deleteAvatarFileByUrl(c.url);
            }
            await AvatarChange.deleteMany({ user: userId });
            // 3) 删除用户
            await User.findByIdAndDelete(userId);
            res.status(200).json({ message: '用户已被退回并删除' });
        } else {
            res.status(400).json({ message: '无效的操作' });
        }
    } catch (error) {
        console.error('操作失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

router.get('/character', async (req, res) => {
    try {
        const characters = await Character.find();
        res.status(200).json(characters);
    } catch (error) {
        res.status(500).json({ message: '获取武将失败', error });
    }
});

// 获取所有基础牌
router.get('/card', async (req, res) => {
    try {
        const cards = await Card.find();
        res.status(200).json(cards);
    } catch (error) {
        res.status(500).json({ message: '获取基础牌失败', error });
    }
});


// 获取所有动态术语
router.get('/term-dynamic', async (req, res) => {
    try {
        const terms = await TermDynamic.find();
        res.status(200).json(terms);
    } catch (error) {
        res.status(500).json({ message: '获取动态术语失败', error });
    }
});

// 获取所有静态术语
router.get('/term-fixed', async (req, res) => {
    try {
        const terms = await TermFixed.find();
        res.status(200).json(terms);
    } catch (error) {
        res.status(500).json({ message: '获取静态术语失败', error });
    }
});

// 获取强度0的技能
router.get('/skill0', async (req, res) => {
    try {
        const skills = await Skill.find({ strength: 0 });
        res.status(200).json(skills);
    } catch (error) {
        res.status(500).json({ message: '获取强度0技能失败', error });
    }
});

// 获取强度1的技能
router.get('/skill1', async (req, res) => {
    try {
        const skills = await Skill.find({ strength: 1 });
        res.status(200).json(skills);
    } catch (error) {
        res.status(500).json({ message: '获取强度1技能失败', error });
    }
});

// 获取强度2的技能
router.get('/skill2', async (req, res) => {
    try {
        const skills = await Skill.find({ strength: 2 });
        res.status(200).json(skills);
    } catch (error) {
        res.status(500).json({ message: '获取强度2技能失败', error });
    }
});

// 根据技能名获取所有强度版本
router.get('/skill/:name', async (req, res) => {
    try {
        const { name } = req.params;
        const skills = await Skill.find({ name }).sort({ strength: 1 });
        res.status(200).json(skills);
    } catch (error) {
        res.status(500).json({ message: '获取技能失败', error });
    }
});


// 批量导入技能数据（用于从 JSON 文件导入）
router.post('/skill/import', async (req, res) => {
    try {
        const { skills, strength } = req.body; // skills 是技能数组，strength 是强度级别
        
        if (!Array.isArray(skills) || strength === undefined) {
            return res.status(400).json({ 
                message: '请提供有效的技能数组和强度级别' 
            });
        }
        
        const importResults = {
            success: 0,
            failed: 0,
            errors: []
        };
        
        for (const skillData of skills) {
            try {
                // 检查是否已存在
                const existingSkill = await Skill.findOne({ 
                    name: skillData.name, 
                    strength 
                });
                
                if (existingSkill) {
                    importResults.failed++;
                    importResults.errors.push({
                        name: skillData.name,
                        error: '技能已存在'
                    });
                    continue;
                }
                
                const newSkill = new Skill({
                    name: skillData.name,
                    content: skillData.content,
                    strength,
                    role: skillData.role
                });
                
                await newSkill.save();
                importResults.success++;
            } catch (error) {
                importResults.failed++;
                importResults.errors.push({
                    name: skillData.name,
                    error: error.message
                });
            }
        }
        
        res.status(200).json({
            message: '批量导入完成',
            results: importResults
        });
    } catch (error) {
        console.error('批量导入失败:', error);
        res.status(500).json({ message: '批量导入失败', error });
    }
});


module.exports = router;

// 获取用户信息（用于刷新头像等）
router.get('/user/:id', async (req, res) => {
    try {
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
    } catch (error) {
        console.error('获取用户信息失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

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
router.get('/avatar/pending', auth, requireReviewer, async (req, res) => {
    try {
        const list = await AvatarChange.find({ status: 'pending' }).populate('user', 'username role');
        res.status(200).json(list || []);
    } catch (error) {
        console.error('获取待审核头像失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 获取当前用户的待审核头像（用于个人查看）
router.get('/avatar/pending/me', async (req, res) => {
    try {
        const userId = req.query.userId;
        if (!userId) return res.status(400).json({ message: '缺少用户ID' });
        const record = await AvatarChange.findOne({ user: userId, status: 'pending' });
        return res.status(200).json(record || null);
    } catch (error) {
        console.error('获取个人待审核头像失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 审核头像（管理员）：approve 或 reject
router.post('/avatar/approve', auth, requireReviewer, async (req, res) => {
    try {
        const { recordId, action, reason } = req.body;
        if (!recordId || !['approve', 'reject'].includes(action)) {
            return res.status(400).json({ message: '参数无效' });
        }
        const record = await AvatarChange.findById(recordId);
        if (!record) return res.status(404).json({ message: '记录不存在' });
        if (record.status !== 'pending') return res.status(400).json({ message: '该记录已处理' });

        if (action === 'approve') {
            // 审核通过：把用户 avatar 更新为该 url
            const user = await User.findById(record.user);
            if (!user) return res.status(404).json({ message: '用户不存在' });
            const oldAvatar = user.avatar;
            user.avatar = record.url;
            await user.save();
            // 清理旧头像文件（如果没有被其他用户引用且与新头像不同）
            if (oldAvatar && oldAvatar !== record.url) {
                const cnt = await User.countDocuments({ _id: { $ne: user._id }, avatar: oldAvatar });
                if (cnt === 0) {
                    await deleteAvatarFileByUrl(oldAvatar);
                }
            }
            record.status = 'approved';
            record.reason = reason || '';
            record.reviewedAt = new Date();
            await record.save();
            return res.status(200).json({ message: '已通过', record });
        } else {
            // 拒绝：仅更新状态与备注
            record.status = 'rejected';
            record.reason = reason || '';
            record.reviewedAt = new Date();
            await record.save();
            // 清理被拒绝的头像文件
            if (record.url) {
                await deleteAvatarFileByUrl(record.url);
            }
            return res.status(200).json({ message: '已拒绝', record });
        }
    } catch (error) {
        console.error('审核失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 词元内联更新（仅管理员）
router.post('/tokens/update', auth, requireAdmin, async (req, res) => {
    try {
    const { collection, id, path: dotPath, value, valueType } = req.body || {};
        if (!collection || !id || !dotPath) {
            return res.status(400).json({ message: '参数无效' });
        }
        // 禁止更新危险字段
        if (dotPath.startsWith('_') || dotPath.includes('.__v') || dotPath === '__v') {
            return res.status(400).json({ message: '该字段不允许修改' });
        }
        // 映射集合到模型
        const modelMap = {
            'term-fixed': TermFixed,
            'term-dynamic': TermDynamic,
            'card': Card,
            'character': Character,
            'skill': Skill
        };
        const Model = modelMap[collection];
        if (!Model) return res.status(400).json({ message: '未知集合' });

        // 类型转换（与前端一致）
        let casted = value;
        if (valueType === 'number') casted = Number(value);
        if (valueType === 'boolean') casted = Boolean(value);

        // 执行更新
        const update = { $set: { [dotPath]: casted } };
        const doc = await Model.findByIdAndUpdate(id, update, { new: true });
        if (!doc) return res.status(404).json({ message: '文档不存在' });
        // Persist log + broadcast realtime event
        try {
            const sourceId = req.header('x-client-id') || '';
            const username = (req.user && req.user.username) || '';
            // Save to DB
            await TokenLog.create({ type: 'update', collection, docId: String(id), path: dotPath, value: casted, username, sourceId });
            // SSE
            sseBroadcast({ type: 'update', collection, id, path: dotPath, value: casted, sourceId });
        } catch (_) { }
        return res.status(200).json({ message: '更新成功', doc });
    } catch (e) {
        console.error('tokens/update 失败:', e);
        // 可能是路径错误或类型校验失败
        return res.status(500).json({ message: '服务器错误' });
    }
});

// 词元内联删除（仅管理员）：删除对象字段或数组元素
router.post('/tokens/delete', auth, requireAdmin, async (req, res) => {
    try {
        const { collection, id, path: dotPath } = req.body || {};
        if (!collection || !id || !dotPath) {
            return res.status(400).json({ message: '参数无效' });
        }
        // 禁止删除危险字段
        if (dotPath.startsWith('_') || dotPath.includes('.__v') || dotPath === '__v') {
            return res.status(400).json({ message: '该字段不允许删除' });
        }
        const modelMap = {
            'term-fixed': TermFixed,
            'term-dynamic': TermDynamic,
            'card': Card,
            'character': Character,
            'skill': Skill
        };
        const Model = modelMap[collection];
        if (!Model) return res.status(400).json({ message: '未知集合' });

        const doc = await Model.findById(id);
        if (!doc) return res.status(404).json({ message: '文档不存在' });

        const parts = String(dotPath).split('.');
        const rootMark = parts[0];
        let parent = doc;
        // 走到倒数第二段
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

        // Snapshot previous value
        let prevValue;
        try { prevValue = Array.isArray(parent) && isIndex ? parent[lastKey] : (typeof parent === 'object' ? parent[lastKey] : undefined); } catch (_) { prevValue = undefined; }

        if (Array.isArray(parent) && isIndex) {
            if (lastKey < 0 || lastKey >= parent.length) {
                return res.status(400).json({ message: '数组下标越界' });
            }
            parent.splice(lastKey, 1);
        } else if (typeof parent === 'object') {
            if (!(lastKey in parent)) return res.status(400).json({ message: '字段不存在' });
            delete parent[lastKey];
        } else {
            return res.status(400).json({ message: '路径不是可删除的对象/数组' });
        }

        try { doc.markModified(rootMark); } catch (_) {}
        await doc.save();
        // Persist log + broadcast realtime event
        try {
            const sourceId = req.header('x-client-id') || '';
            const username = (req.user && req.user.username) || '';
            await TokenLog.create({ type: 'delete-field', collection, docId: String(id), path: dotPath, from: prevValue, username, sourceId });
            sseBroadcast({ type: 'delete-field', collection, id, path: dotPath, from: prevValue, sourceId });
        } catch (_) { }
        return res.status(200).json({ message: '删除成功' });
    } catch (e) {
        console.error('tokens/delete 失败:', e);
        return res.status(500).json({ message: '服务器错误' });
    }
});

// 推断集合字段结构（用于前端生成新增模板）
router.get('/tokens/shape', auth, requireAdmin, async (req, res) => {
    try {
        const collection = req.query.collection;
        if (!collection) return res.status(400).json({ message: '缺少 collection' });
        const modelMap = {
            'term-fixed': TermFixed,
            'term-dynamic': TermDynamic,
            'card': Card,
            'character': Character,
            'skill': Skill
        };
        const Model = modelMap[collection];
        if (!Model) return res.status(400).json({ message: '未知集合' });

        const schema = Model.schema;
        const fields = [];
        const seen = new Set();
        // 从 schema 提取字段
        for (const [path, desc] of Object.entries(schema.paths)) {
            if (path === '__v') continue;
            const f = {
                name: path,
                type: desc.instance || 'Mixed',
                required: !!(desc.options && desc.options.required),
            };
            if (desc.enumValues && desc.enumValues.length) f.enum = desc.enumValues;
            if (desc.options && Object.prototype.hasOwnProperty.call(desc.options, 'default')) f.default = desc.options.default;
            fields.push(f);
            seen.add(path);
        }
        // 对数组子文档（如 skill.role）提供子结构提示
        for (const [path, desc] of Object.entries(schema.paths)) {
            if (desc.instance === 'Array' && desc.schema && desc.schema.paths) {
                const sub = [];
                for (const [sp, sd] of Object.entries(desc.schema.paths)) {
                    if (sp === '_id') continue; // 子文档默认 _id
                    sub.push({ name: sp, type: sd.instance || 'Mixed', required: !!(sd.options && sd.options.required) });
                }
                fields.push({ name: path + '[]', type: 'Subdocument[]', fields: sub });
            }
        }

        // 从样本文档中收集 Mixed/对象的可能键（最多 100 条）
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
        for (const d of docs) {
            for (const m of mixedCandidates) {
                if (d[m]) collectKeys(d[m], m, mixedKeys);
            }
        }
        suggest.mixedKeys = Array.from(new Set(mixedKeys));

        // 一些集合的“下一 ID”等便民建议
        if (collection === 'character') {
            const ids = (docs || []).map(x => Number(x.id)).filter(x => Number.isFinite(x));
            const nextId = ids.length ? Math.max(...ids) + 1 : 1;
            suggest.nextId = nextId;
        }
        if (collection === 'skill') {
            suggest.strengthEnum = [0,1,2];
        }

        return res.status(200).json({ collection, fields, suggest });
    } catch (e) {
        console.error('tokens/shape 失败:', e);
        return res.status(500).json({ message: '服务器错误' });
    }
});

// 新增文档（仅管理员）
router.post('/tokens/create', auth, requireAdmin, async (req, res) => {
    try {
        const { collection, data } = req.body || {};
        if (!collection || !data || typeof data !== 'object') {
            return res.status(400).json({ message: '参数无效' });
        }
        const modelMap = {
            'term-fixed': TermFixed,
            'term-dynamic': TermDynamic,
            'card': Card,
            'character': Character,
            'skill': Skill
        };
        const Model = modelMap[collection];
        if (!Model) return res.status(400).json({ message: '未知集合' });
        const doc = new Model(data);
        await doc.save();
        // Persist log + broadcast realtime event
        try {
            const sourceId = req.header('x-client-id') || '';
            const username = (req.user && req.user.username) || '';
            // Pick brief
            const brief = (()=>{ try{ const d = doc.toObject ? doc.toObject() : doc; const o={}; if(d.en) o.en=d.en; if(d.cn) o.cn=d.cn; if(d.name) o.name=d.name; if(d.id!=null) o.id=d.id; return o; }catch(_){ return {}; }})();
            await TokenLog.create({ type: 'create', collection, docId: String(doc._id), doc: brief, username, sourceId });
            sseBroadcast({ type: 'create', collection, id: doc._id, doc: brief, sourceId });
        } catch (_) { }
        return res.status(201).json({ message: '创建成功', doc });
    } catch (e) {
        console.error('tokens/create 失败:', e);
        if (e && e.code === 11000) {
            return res.status(400).json({ message: '唯一索引冲突（例如重复的唯一字段）' });
        }
        // mongoose 验证错误
        if (e && e.name === 'ValidationError') {
            return res.status(400).json({ message: e.message });
        }
        return res.status(500).json({ message: '服务器错误' });
    }
});

// 删除整个文档（仅管理员）
router.post('/tokens/remove', auth, requireAdmin, async (req, res) => {
    try {
        const { collection, id } = req.body || {};
        if (!collection || !id) return res.status(400).json({ message: '参数无效' });
        const modelMap = {
            'term-fixed': TermFixed,
            'term-dynamic': TermDynamic,
            'card': Card,
            'character': Character,
            'skill': Skill
        };
        const Model = modelMap[collection];
        if (!Model) return res.status(400).json({ message: '未知集合' });
        const doc = await Model.findByIdAndDelete(id);
        if (!doc) return res.status(404).json({ message: '文档不存在' });
        // Persist log + broadcast realtime event
        try {
            const sourceId = req.header('x-client-id') || '';
            const username = (req.user && req.user.username) || '';
            await TokenLog.create({ type: 'delete-doc', collection, docId: String(id), username, sourceId });
            sseBroadcast({ type: 'delete-doc', collection, id, sourceId });
        } catch (_) { }
        return res.status(200).json({ message: '删除成功' });
    } catch (e) {
        console.error('tokens/remove 失败:', e);
        return res.status(500).json({ message: '服务器错误' });
    }
});

// 统一存储日志：分页拉取（默认最近，按时间逆序）
router.get('/tokens/logs', auth, async (req, res) => {
    try {
        const { page = 1, pageSize = 100, since, until, collection, docId } = req.query;
        const p = Math.max(1, parseInt(page, 10) || 1);
        const ps = Math.min(500, Math.max(1, parseInt(pageSize, 10) || 100));
        const q = {};
        if (since || until) {
            q.createdAt = {};
            if (since) q.createdAt.$gte = new Date(since);
            if (until) q.createdAt.$lte = new Date(until);
        }
        if (collection) q.collection = String(collection);
        if (docId) q.docId = String(docId);
        const total = await TokenLog.countDocuments(q);
        const list = await TokenLog.find(q).sort({ createdAt: -1 }).skip((p - 1) * ps).limit(ps).lean();
        return res.status(200).json({ page: p, pageSize: ps, total, list });
    } catch (e) {
        console.error('tokens/logs 失败:', e);
        return res.status(500).json({ message: '服务器错误' });
    }
});