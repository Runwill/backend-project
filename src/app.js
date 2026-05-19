require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const cors = require('cors');
const mongoose = require('mongoose');
const { Server: SocketIO } = require('socket.io');
const routes = require('./routes/index');
const serverConfig = require('./config/serverConfig');
const gameRoomService = require('./services/gameRoom');

const app = express();
const server = http.createServer(app);

// CORS
const ORIGINS = serverConfig.corsOrigins;
const corsOptions = {
    origin: (origin, cb) => (!origin || ORIGINS.includes(origin)) ? cb(null, true) : cb(new Error('Not allowed by CORS')),
    methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
    allowedHeaders: ['Content-Type','Authorization','x-requested-with','x-client-id'],
    credentials: true,
};
app.use(cors(corsOptions));
// 显式处理所有路径的预检请求
app.options('*', cors(corsOptions));

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

// ===== Socket.IO =====
const io = new SocketIO(server, {
    cors: {
        origin: (origin, cb) => (!origin || ORIGINS.includes(origin)) ? cb(null, true) : cb(new Error('Not allowed by CORS')),
        methods: ['GET', 'POST'],
        credentials: true
    }
});

io.on('connection', (socket) => {
    console.log(`[Socket.IO] 客户端已连接: ${socket.id}`);

    // 创建房间
    socket.on('room:create', (data, callback) => {
        const { roomId, userInfo } = data;

        // 如果已在其他房间，先自动离开（清理 socket room）
        const oldMapping = gameRoomService.socketToUser.get(socket.id);
        if (oldMapping) {
            socket.leave(oldMapping.roomId);
            const leaveResult = gameRoomService.leaveRoom(socket.id);
            if (leaveResult) {
                const oldRoomInfo = gameRoomService.getRoom(leaveResult.roomId);
                socket.to(leaveResult.roomId).emit('room:user-left', {
                    userId: leaveResult.userId,
                    username: leaveResult.username,
                    room: oldRoomInfo
                });
            }
        }

        const result = gameRoomService.createRoom(roomId, userInfo);
        if (result.success) {
            // 创建者自动加入
            gameRoomService.joinRoom(roomId, socket.id, userInfo);
            socket.join(roomId);
            // 设置默认视角
            const perspResult = gameRoomService.setPerspective(socket.id, 0);
            // 返回包含最新 perspectives 的房间数据
            const freshRoom = gameRoomService.getRoom(roomId);
            callback({ success: true, room: freshRoom });
        } else {
            callback(result);
        }
    });

    // 加入房间
    socket.on('room:join', (data, callback) => {
        const { roomId, userInfo } = data;

        // 如果已在其他房间，先自动离开并通知旧房间成员
        const oldMapping = gameRoomService.socketToUser.get(socket.id);
        if (oldMapping && oldMapping.roomId !== roomId) {
            socket.leave(oldMapping.roomId);
            const leaveResult = gameRoomService.leaveRoom(socket.id);
            if (leaveResult) {
                const oldRoomInfo = gameRoomService.getRoom(leaveResult.roomId);
                socket.to(leaveResult.roomId).emit('room:user-left', {
                    userId: leaveResult.userId,
                    username: leaveResult.username,
                    room: oldRoomInfo
                });
            }
        }

        const result = gameRoomService.joinRoom(roomId, socket.id, userInfo);
        if (result.success) {
            socket.join(roomId);
            // 设置默认视角
            const perspResult = gameRoomService.setPerspective(socket.id, 0);
            // 获取最新房间数据（包含 perspectives）
            const freshRoom = gameRoomService.getRoom(roomId);
            // 通知房间内其他人（含最新 perspectives）
            socket.to(roomId).emit('room:user-joined', {
                userId: userInfo.userId,
                username: userInfo.username,
                room: freshRoom
            });
            // 广播视角更新给所有人（包括自己）
            if (perspResult) {
                io.to(roomId).emit('room:perspectives-updated', {
                    perspectives: perspResult.perspectives
                });
            }
            callback({ success: true, room: freshRoom, gameState: result.gameState, gameConfig: result.gameConfig });
        } else {
            callback(result);
        }
    });

    // 离开房间
    socket.on('room:leave', (callback) => {
        const result = gameRoomService.leaveRoom(socket.id);
        if (result) {
            socket.leave(result.roomId);
            // 通知房间内其他人
            const roomInfo = gameRoomService.getRoom(result.roomId);
            socket.to(result.roomId).emit('room:user-left', {
                userId: result.userId,
                username: result.username,
                room: roomInfo
            });
        }
        if (typeof callback === 'function') callback({ success: true });
    });

    // 获取房间列表
    socket.on('room:list', (callback) => {
        callback(gameRoomService.listRooms());
    });

    // 解散房间（房主专用）
    socket.on('room:dissolve', (data, callback) => {
        const { roomId } = data;
        const mapping = gameRoomService.socketToUser.get(socket.id);
        if (!mapping) {
            if (typeof callback === 'function') callback({ success: false, error: '未在任何房间中' });
            return;
        }

        const result = gameRoomService.dissolveRoom(roomId, mapping.userId);
        if (result.success) {
            // 通知房间内所有人房间已解散
            io.to(roomId).emit('room:dissolved', { roomId });
            // 让所有成员的 socket 离开房间
            result.memberSocketIds.forEach(sid => {
                const s = io.sockets.sockets.get(sid);
                if (s) s.leave(roomId);
            });
            console.log(`[Room] 房间 ${roomId} 已被房主解散`);
        }
        if (typeof callback === 'function') callback(result);
    });

    // 更新房间选项（如允许旁观）
    socket.on('room:update-option', (data) => {
        const mapping = gameRoomService.socketToUser.get(socket.id);
        if (!mapping) return;
        const result = gameRoomService.updateRoomOption(mapping.roomId, data.key, data.value);
        if (result) {
            // 广播给房间所有人（包括自己）
            io.to(mapping.roomId).emit('room:option-updated', { key: data.key, value: result.value });
        }
    });

    // 切换视角
    socket.on('room:set-perspective', (data) => {
        const { perspectiveIndex } = data;
        const result = gameRoomService.setPerspective(socket.id, perspectiveIndex);
        if (result) {
            // 广播视角变化给房间所有人
            io.to(result.roomId).emit('room:perspectives-updated', {
                perspectives: result.perspectives
            });
        }
    });

    // 更新游戏配置（房主操作）
    socket.on('room:update-config', (data) => {
        const { roomId, config } = data;
        const result = gameRoomService.updateGameConfig(roomId, config);
        if (result) {
            socket.to(roomId).emit('room:config-updated', { config });
        }
    });

    // 开始游戏（房主操作）
    socket.on('room:start-game', (data) => {
        const { roomId, gameConfig, gameState } = data;
        gameRoomService.startGame(roomId, gameState);
        if (gameConfig) gameRoomService.updateGameConfig(roomId, gameConfig);
        // 广播给房间所有人
        io.to(roomId).emit('room:game-started', { gameConfig, gameState });
    });

    // 游戏动作同步（任何用户操作游戏后广播）
    socket.on('game:action', (data) => {
        const mapping = gameRoomService.socketToUser.get(socket.id);
        if (!mapping) return;
        const { roomId } = mapping;
        // 广播给房间其他人
        socket.to(roomId).emit('game:action', {
            ...data,
            from: { userId: mapping.userId, username: mapping.username }
        });
    });

    // 游戏状态全量同步
    socket.on('game:sync-state', (data) => {
        const mapping = gameRoomService.socketToUser.get(socket.id);
        if (!mapping) return;
        const { roomId } = mapping;
        gameRoomService.syncGameState(roomId, data.gameState);
        // 广播给房间其他人
        socket.to(roomId).emit('game:state-updated', {
            gameState: data.gameState,
            from: { userId: mapping.userId, username: mapping.username }
        });
    });

    // 断开连接
    socket.on('disconnect', () => {
        console.log(`[Socket.IO] 客户端已断开: ${socket.id}`);
        const result = gameRoomService.leaveRoom(socket.id);
        if (result) {
            const roomInfo = gameRoomService.getRoom(result.roomId);
            io.to(result.roomId).emit('room:user-left', {
                userId: result.userId,
                username: result.username,
                room: roomInfo
            });
        }
    });
});

mongoose.connect(DB_URL)
    .then(() => {
        console.log('数据库连接成功');
        server.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
    })
    .catch(err => { console.error('数据库连接失败:', err); process.exit(1); });