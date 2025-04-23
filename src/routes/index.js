const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { User } = require('../models/index'); // 引入用户模型

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

        // 生成 JWT
        const token = jwt.sign(
            { id: user._id, username: user.username },
            process.env.SECRET_KEY || 'your_secret_key',
            { expiresIn: '1h' }
        );

        res.json({ token });
    } catch (error) {
        console.error('登录失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

// 注册方法
router.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        // 检查用户名是否已存在
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: '用户'+ username + '已存在' });
        }

        // 创建新用户
        const newUser = new User({ username, password });
        await newUser.save();

        res.status(201).json({ message: '注册成功' });
    } catch (error) {
        console.error('注册失败:', error);
        res.status(500).json({ message: '服务器错误' });
    }
});

module.exports = router;