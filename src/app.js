require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const mongoose = require('mongoose');
const routes = require('./routes/index');
const serverConfig = require('./config/serverConfig');

const app = express();

// CORS
const ORIGINS = serverConfig.corsOrigins;
app.use(cors({
    origin: (origin, cb) => (!origin || ORIGINS.includes(origin)) ? cb(null, true) : cb(new Error('Not allowed by CORS')),
    methods: ['GET','POST','PUT','DELETE'],
    credentials: true
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static
app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads')));

// Routes
app.use('/api', routes);

// Errors
app.use((err, _req, res, _next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start after DB
const { port: PORT, dbUrl: DB_URL } = serverConfig;
mongoose.connect(DB_URL)
    .then(() => {
        console.log('数据库连接成功');
        app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
    })
    .catch(err => { console.error('数据库连接失败:', err); process.exit(1); });