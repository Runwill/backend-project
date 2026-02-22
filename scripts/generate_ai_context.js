const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

// 尝试加载配置，兼容性处理
let config;
try {
    config = require('../config/default.json');
} catch (e) {
    console.error('Error loading config/default.json. Please ensure the file exists.');
    process.exit(1);
}

// 引入模型
const { TermFixed, TermDynamic, Skill, Character, Card } = require('../src/models');

// 输出文件位置：放在 backend-project 根目录下，方便查看
const OUTPUT_FILE = path.join(__dirname, '../AI_DATA_CONTEXT.md');

async function generate() {
    try {
        console.log('正在连接 MongoDB...');
        // 确保使用正确的连接字符串
        const dbUrl = config.database.url || 'mongodb://localhost:27017/backend-project'; 
        await mongoose.connect(dbUrl, config.database.options);
        console.log('MongoDB 连接成功。正在抽取数据...');

        let mdContent = '# AI 项目数据上下文 (AI Data Context)\n\n';
        mdContent += '> 本文件由 `scripts/generate_ai_context.js` 自动生成。\n';
        mdContent += '> **给 AI 的说明**: 本文件包含 HTML 自定义标签的中文含义以及核心游戏数据。当阅读前端 HTML 源码时，请参考此表将 `<tag>` 映射为实际文本。\n\n';

        // --- 1. 术语表 (解决 HTML 阅读问题) ---
        mdContent += '## 1. 术语与 HTML 标签映射 (Terms Mapping)\n\n';
        mdContent += '前端 HTML 中的自定义标签（如 `<procedure>`）对应的实际中文含义：\n\n';
        mdContent += '| HTML 标签 (en) | 中文含义 (cn) | 替换内容 (replace) | 备注 |\n';
        mdContent += '| --- | --- | --- | --- |\n';
        
        const fixedTerms = await TermFixed.find({}).sort({ en: 1 });
        const dynTerms = await TermDynamic.find({}).sort({ en: 1 });

        for (const t of fixedTerms) {
            let cn = t.cn || '(复合/分段)';
            let replace = t.replace ? `\`${t.replace}\`` : '-';
            let note = '';
            
            // 简单的处理分段逻辑的显示，帮助 AI 理解结构
            if (t.part && Array.isArray(t.part)) {
                const parts = t.part.map(p => `<${p.en}>:${p.cn}`).join(', ');
                note = `分段: ${parts}`;
            }

            mdContent += `| \`<${t.en}>\` | ${cn} | ${replace} | ${note} |\n`;
        }
        
        // 动态术语也列出，虽然结构复杂，但至少知道标签存在
        for (const t of dynTerms) {
             mdContent += `| \`<${t.en}>\` | (动态术语) | - | 见 Dynamic Terms 详情 |\n`;
        }
        mdContent += '\n';

        // --- 2. 技能库 (解决逻辑判断问题) ---
        mdContent += '## 2. 技能库 (Skills)\n\n';
        mdContent += '用于辅助判断代码中涉及技能逻辑的部分：\n\n';
        
        const skills = await Skill.find({}).sort({ strength: 1, name: 1 });
        for (const s of skills) {
             mdContent += `### [${s.strength === 2 ? '君主' : s.strength === 1 ? '普通' : '衍生物'}] ${s.name}\n`;
             mdContent += `> **内容**: ${s.content}\n`;
             if (s.role && s.role.length > 0) {
                 mdContent += `> **关联角色ID**: ${s.role.map(r => r.id).join(', ')}\n`;
             }
             mdContent += '\n';
        }

        // --- 3. 角色列表 ---
        mdContent += '## 3. 角色列表 (Characters)\n\n';
        const chars = await Character.find({}).sort({ id: 1 });
        mdContent += '| ID | 姓名 | 称号 | 体力 | 势力 |\n';
        mdContent += '| --- | --- | --- | --- | --- |\n';
        for (const c of chars) {
            mdContent += `| ${c.id} | ${c.name} | ${c.title || '-'} | ${c.health} | ${c.position || '-'} |\n`;
        }
        mdContent += '\n';

        fs.writeFileSync(OUTPUT_FILE, mdContent, 'utf8');
        console.log(`\n[完成] 数据上下文已生成至: ${OUTPUT_FILE}`);
        console.log('现在您可以要求 AI 读取此文件来理解您的项目数据了。');

    } catch (err) {
        console.error('发生错误:', err);
    } finally {
        await mongoose.disconnect();
    }
}

generate();
