require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors'); // 引入 CORS 模块
const mongoose = require('mongoose');
const routes = require('./routes/index');

const app = express();

// 启用 CORS
app.use(cors({
    origin: (origin, callback) => {
        const allowed = [
            'http://127.0.0.1:5500',
            'http://localhost:5500',
            'http://127.0.0.1:3000',
            'http://localhost:3000'
        ];
        // 允许无 Origin 的请求（如本地工具、curl）
        if (!origin || allowed.includes(origin)) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // 允许的 HTTP 方法
    credentials: true // 如果需要发送 Cookie 或认证信息
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 静态资源服务：用于访问上传的头像
app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads')));

// Routes
app.use('/api', routes);

// Error handling（保持在路由之后）
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// 数据库连接成功后再启动服务
const PORT = process.env.PORT || 3000;
const DB_URL = process.env.DB_URL || 'mongodb://localhost:27017/backend-project';

mongoose.connect(DB_URL)
    .then(() => {
        console.log('数据库连接成功');
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    })
    .catch(err => {
        console.error('数据库连接失败:', err);
        process.exit(1);
    });