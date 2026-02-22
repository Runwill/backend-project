/**
 * Game Room Service
 * 管理在线房间的创建、加入、离开和状态同步
 */

class GameRoomService {
    constructor() {
        // roomId -> RoomData
        this.rooms = new Map();
        // socketId -> { roomId, username, userId }
        this.socketToUser = new Map();
    }

    /**
     * 创建新房间
     */
    createRoom(roomId, hostInfo) {
        if (this.rooms.has(roomId)) {
            return { success: false, error: '房间已存在' };
        }

        const room = {
            id: roomId,
            host: hostInfo.userId,
            createdAt: Date.now(),
            // 游戏配置（从设置面板确认后同步）
            gameConfig: null,
            // 游戏是否已开始
            gameStarted: false,
            // 序列化的游戏状态（由客户端同步）
            gameState: null,
            // 房间内的用户列表: userId -> { username, socketId, perspectiveIndex }
            users: new Map(),
            // 视角映射: perspectiveIndex -> [{ userId, username }]
            perspectives: {}
        };

        this.rooms.set(roomId, room);
        return { success: true, room: this.serializeRoom(room) };
    }

    /**
     * 加入房间
     */
    joinRoom(roomId, socketId, userInfo) {
        const room = this.rooms.get(roomId);
        if (!room) {
            return { success: false, error: '房间不存在' };
        }

        // 记录映射
        this.socketToUser.set(socketId, {
            roomId,
            username: userInfo.username,
            userId: userInfo.userId
        });

        // 添加到房间用户列表
        room.users.set(userInfo.userId, {
            username: userInfo.username,
            socketId: socketId,
            perspectiveIndex: 0 // 默认视角
        });

        return {
            success: true,
            room: this.serializeRoom(room),
            gameState: room.gameState,
            gameConfig: room.gameConfig
        };
    }

    /**
     * 离开房间
     */
    leaveRoom(socketId) {
        const mapping = this.socketToUser.get(socketId);
        if (!mapping) return null;

        const { roomId, userId } = mapping;
        const room = this.rooms.get(roomId);

        if (room) {
            // 从视角映射中移除
            const user = room.users.get(userId);
            if (user && room.perspectives[user.perspectiveIndex]) {
                room.perspectives[user.perspectiveIndex] = 
                    room.perspectives[user.perspectiveIndex].filter(u => u.userId !== userId);
                if (room.perspectives[user.perspectiveIndex].length === 0) {
                    delete room.perspectives[user.perspectiveIndex];
                }
            }

            room.users.delete(userId);

            // 房间空了就删除
            if (room.users.size === 0) {
                this.rooms.delete(roomId);
            }
        }

        this.socketToUser.delete(socketId);

        return { roomId, userId, username: mapping.username };
    }

    /**
     * 设置用户视角
     */
    setPerspective(socketId, perspectiveIndex) {
        const mapping = this.socketToUser.get(socketId);
        if (!mapping) return null;

        const room = this.rooms.get(mapping.roomId);
        if (!room) return null;

        const user = room.users.get(mapping.userId);
        if (!user) return null;

        // 从旧视角移除
        const oldIdx = user.perspectiveIndex;
        if (room.perspectives[oldIdx]) {
            room.perspectives[oldIdx] = room.perspectives[oldIdx].filter(
                u => u.userId !== mapping.userId
            );
            if (room.perspectives[oldIdx].length === 0) {
                delete room.perspectives[oldIdx];
            }
        }

        // 设置新视角
        user.perspectiveIndex = perspectiveIndex;
        if (!room.perspectives[perspectiveIndex]) {
            room.perspectives[perspectiveIndex] = [];
        }
        room.perspectives[perspectiveIndex].push({
            userId: mapping.userId,
            username: mapping.username
        });

        return {
            roomId: mapping.roomId,
            perspectives: room.perspectives
        };
    }

    /**
     * 更新游戏配置
     */
    updateGameConfig(roomId, config) {
        const room = this.rooms.get(roomId);
        if (!room) return null;
        room.gameConfig = config;
        return { roomId, config };
    }

    /**
     * 标记游戏开始
     */
    startGame(roomId, gameState) {
        const room = this.rooms.get(roomId);
        if (!room) return null;
        room.gameStarted = true;
        room.gameState = gameState;
        return { roomId, gameState };
    }

    /**
     * 同步游戏状态
     */
    syncGameState(roomId, gameState) {
        const room = this.rooms.get(roomId);
        if (!room) return null;
        room.gameState = gameState;
        return true;
    }

    /**
     * 获取房间列表
     */
    listRooms() {
        const list = [];
        for (const [id, room] of this.rooms) {
            list.push({
                id,
                host: room.host,
                userCount: room.users.size,
                gameStarted: room.gameStarted,
                createdAt: room.createdAt
            });
        }
        return list;
    }

    /**
     * 获取房间信息
     */
    getRoom(roomId) {
        const room = this.rooms.get(roomId);
        if (!room) return null;
        return this.serializeRoom(room);
    }

    /**
     * 序列化房间（Map -> 普通对象）
     */
    serializeRoom(room) {
        const users = {};
        for (const [userId, data] of room.users) {
            users[userId] = {
                username: data.username,
                perspectiveIndex: data.perspectiveIndex
            };
        }
        return {
            id: room.id,
            host: room.host,
            createdAt: room.createdAt,
            gameStarted: room.gameStarted,
            gameConfig: room.gameConfig,
            users,
            perspectives: room.perspectives
        };
    }
}

module.exports = new GameRoomService();
