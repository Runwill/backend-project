const jwt = require('jsonwebtoken');
const { User } = require('../models/index');
const bcrypt = require('bcrypt');

class Controller {
    async getResource(req, res) {
        // Logic to get a resource
        res.send("Get resource");
    }

    async createResource(req, res) {
        // Logic to create a resource
        res.send("Create resource");
    }

    async updateResource(req, res) {
        // Logic to update a resource
        res.send("Update resource");
    }

    async deleteResource(req, res) {
        // Logic to delete a resource
        res.send("Delete resource");
    }

    async login(req, res) {
        const { username, password } = req.body;

        try {
            // 查找用户
            const user = await User.findOne({ email: username });
            if (!user) {
                return res.status(401).json({ message: '用户不存在' });
            }

            // 验证密码
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ message: '密码错误' });
            }

            // 生成 JWT
            const token = jwt.sign({ id: user._id, email: user.email }, process.env.SECRET_KEY, {
                expiresIn: '1h',
            });

            res.json({ token });
        } catch (error) {
            console.error('登录失败:', error);
            res.status(500).json({ message: '服务器错误' });
        }
    }
}

module.exports = new Controller();