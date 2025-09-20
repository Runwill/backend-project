require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors'); // 引入 CORS 模块
const mongoose = require('mongoose');
const routes = require('./routes/index');
const serverConfig = require('./config/serverConfig');

const app = express();

// 启用 CORS（允许来源可通过环境变量 CORS_ORIGINS 配置，逗号分隔；为空则允许同源/无 Origin）
const CORS_ORIGINS = serverConfig.corsOrigins;
app.use(cors({
    origin: (origin, callback) => {
        // 允许无 Origin 的请求（如本地工具、curl）
        if (!origin) return callback(null, true);
        if (CORS_ORIGINS.includes(origin)) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
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
const PORT = serverConfig.port;
const DB_URL = serverConfig.dbUrl;

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