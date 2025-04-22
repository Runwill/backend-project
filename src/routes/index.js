const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const router = express.Router();

// 模拟用户数据（实际项目中应使用数据库）
const users = [
    { id: 1, username: 'admin', password: '$2b$10$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36Zf4z5lZ9E2y1Z1ZQF3K1W' } // 密码为 "password"
];

// 登录方法
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // 查找用户
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).json({ message: '用户名错误' });
    }

    // 验证密码
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(401).json({ message: '密码错误' });
    }

    // 生成 JWT
    const token = jwt.sign({ id: user.id, username: user.username }, 'your_secret_key', { expiresIn: '1h' });

    res.json({ token });
});

module.exports = router;