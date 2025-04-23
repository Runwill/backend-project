const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); // 引入 CORS 模块
const routes = require('./routes/index');

const app = express();

// 启用 CORS
app.use(cors({
    origin: 'http://127.0.0.1:5500', // 允许的前端地址
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // 允许的 HTTP 方法
    credentials: true // 如果需要发送 Cookie 或认证信息
}));

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Routes
app.use('/api', routes);

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

const mongoose = require('mongoose');

// 数据库连接
mongoose.connect(process.env.DB_URL || 'mongodb://localhost:27017/backend-project')
    .then(() => {
        console.log('数据库连接成功');
    })
    .catch(err => {
        console.error('数据库连接失败:', err);
    });