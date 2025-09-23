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
    role: { type: String, enum: ['user','moderator','admin'], default: 'user' },
    // 用户头像（可选）：存储为 URL 或相对路径
    avatar: { type: String, trim: true, default: '' },
    createdAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: false }
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
    title: { type: String, maxlength: 50 },
    health: {
        type: Number,
        required: true
    },
    dominator: {
        type: Number,
        required: true
    },
    position: { type: String, maxlength: 20 }
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
    type: { type: String, maxlength: 20 }
});

const termDynamicSchema = new mongoose.Schema({
    en: {
        type: String,
        required: true,
        maxlength: 50
    },
    part: { type: mongoose.Schema.Types.Mixed, required: true }
});

const termFixedSchema = new mongoose.Schema({
    en: {
        type: String,
        required: true,
        unique: true,
        maxlength: 50
    },
    // 顶层 cn 改为可选，允许仅使用 epithet/part 等组合
    cn: {
        type: String,
        required: false,
        maxlength: 100
    },
    color: { type: String, maxlength: 20 },
    replace: { type: String, maxlength: 100 },
    part: { type: mongoose.Schema.Types.Mixed },
    epithet: { type: mongoose.Schema.Types.Mixed }
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
    strength: { type: Number, required: true, enum: [0,1,2] },
    role: [{
        id: {
            type: Number,
            required: true
        },
        skill_order: {
            type: Number,
            required: true
        },
        dominator: { type: Boolean, default: false },
        lore: { type: String, maxlength: 200 },
        legend: { type: String, maxlength: 200 }
    }]
});

// 创建复合唯一索引：strength + name 的组合必须唯一
skillSchema.index({ strength: 1, name: 1 }, { unique: true });

// 头像审核记录（待审核/已通过/已拒绝）
const avatarChangeSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    url: { type: String, required: true }, // 相对路径，如 /uploads/avatar/xxxx.png
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    reason: { type: String, default: '' }, // 审核备注
    createdAt: { type: Date, default: Date.now },
    reviewedAt: { type: Date }
});

// 限制同一用户仅存在1条待审核记录
avatarChangeSchema.index({ user: 1 }, { unique: true, partialFilterExpression: { status: 'pending' } });

const User = mongoose.model('User', userSchema);
const Character = mongoose.model('Character', characterSchema);
const Card = mongoose.model('Card', cardSchema);
const TermDynamic = mongoose.model('TermDynamic', termDynamicSchema);
const TermFixed = mongoose.model('TermFixed', termFixedSchema);
const Skill = mongoose.model('Skill', skillSchema);
const AvatarChange = mongoose.model('AvatarChange', avatarChangeSchema);

// 词元变更日志（统一存储，供客户端拉取）
const tokenLogSchema = new mongoose.Schema({
    type: { type: String, enum: ['create','update','delete-field','delete-doc','save-edits'], required: true },
    collection: { type: String, required: true },
    docId: { type: String, required: true },
    path: { type: String },
    value: { type: mongoose.Schema.Types.Mixed },
    from: { type: mongoose.Schema.Types.Mixed },
    doc: { type: mongoose.Schema.Types.Mixed }, // create 时的简要对象（只含 en/cn/name/id 等）
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    username: { type: String },
    sourceId: { type: String },
    createdAt: { type: Date, default: Date.now }
});
tokenLogSchema.index({ createdAt: 1 });
tokenLogSchema.index({ collection: 1, docId: 1, createdAt: 1 });

const TokenLog = mongoose.model('TokenLog', tokenLogSchema);

module.exports = { User, Character, Card, TermDynamic, TermFixed, Skill, AvatarChange, TokenLog };