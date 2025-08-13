const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['user', 'admin'], // 定义权限等级
        default: 'user' // 默认权限为普通用户
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    isActive: {
        type: Boolean,
        default: false // 默认未激活
    }
});

// 在保存用户之前加密密码
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

const characterSchema = new mongoose.Schema({
    id: {
        type: Number,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true,
        maxlength: 50
    },
    title: {
        type: String,
        maxlength: 50
    },
    health: {
        type: Number,
        required: true
    },
    dominator: {
        type: Number,
        required: true
    },
    position: {
        type: String,
        maxlength: 20
    }
});

const cardSchema = new mongoose.Schema({
    en: {
        type: String,
        required: true,
        unique: true,
        maxlength: 50
    },
    cn: {
        type: String,
        required: true,
        maxlength: 50
    },
    type: {
        type: String,
        maxlength: 20
    }
});

const termDynamicSchema = new mongoose.Schema({
    en: {
        type: String,
        required: true,
        maxlength: 50
    },
    part: {
        type: mongoose.Schema.Types.Mixed, // 用于存储任意 JSON
        required: true
    }
});

const termFixedSchema = new mongoose.Schema({
    en: {
        type: String,
        required: true,
        unique: true,
        maxlength: 50
    },
    cn: {
        type: String,
        required: true,
        maxlength: 100
    },
    color: {
        type: String,
        maxlength: 20
    },
    replace_text: {
        type: String,
        maxlength: 100
    },
    part: {
        type: mongoose.Schema.Types.Mixed // 存储任意 JSON
    },
    epithet: {
        type: mongoose.Schema.Types.Mixed // 存储任意 JSON
    }
});

const skillSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        maxlength: 50
    },
    content: {
        type: String,
        required: true
    },
    strength: {
        type: Number,
        required: true,
        enum: [0, 1, 2] // 限制只能是 0、1、2
    },
    role: [{
        id: {
            type: Number,
            required: true
        },
        skill_order: {
            type: Number,
            required: true
        },
        dominator: {
            type: Boolean,
            default: false
        },
        lore: {
            type: String,
            maxlength: 200
        },
        legend: {
            type: String,
            maxlength: 200
        }
    }]
});

// 创建复合唯一索引：strength + name 的组合必须唯一
skillSchema.index({ strength: 1, name: 1 }, { unique: true });

const User = mongoose.model('User', userSchema);
const Character = mongoose.model('Character', characterSchema);
const Card = mongoose.model('Card', cardSchema);
const TermDynamic = mongoose.model('TermDynamic', termDynamicSchema);
const TermFixed = mongoose.model('TermFixed', termFixedSchema);
const Skill = mongoose.model('Skill', skillSchema);

module.exports = {
    User,
    Character,
    Card,
    TermDynamic,
    TermFixed,
    Skill
};