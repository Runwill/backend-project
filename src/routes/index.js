const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { User, Character, Card, TermDynamic, TermFixed, Skill } = require('../models/index'); // 正确引入所有模型

const router = express.Router();

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
                role: user.role
            }
        });
    } catch (error) {
        console.error('登录失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 注册方法
router.post('/register', async (req, res) => {
    const { username, password, role } = req.body;

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
    const { id, newUsername, newPassword } = req.body;

    try {
        // 查找用户
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ message: '用户' + id + '不存在' });
        }

        // 更新用户名和密码
        if (newUsername) {
            user.username = newUsername;
        }
        if (newPassword) {
            user.password = await bcrypt.hash(newPassword, 10);
        }

        await user.save();

        res.status(200).json({ message: '用户信息更新成功' });
    } catch (error) {
        console.error('更新失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});


router.get('/pending-users', async (req, res) => {
    try {
        // 查找所有未激活的用户
        const pendingUsers = await User.find({ isActive: false });
        res.status(200).json(pendingUsers || []);
    } catch (error) {
        console.error('获取未激活用户失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

router.post('/approve', async (req, res) => {
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
            // 删除用户
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