const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const { Skill } = require('./src/models/index');

// 数据库连接
async function connectDB() {
    try {
        await mongoose.connect(process.env.DB_URL || 'mongodb://localhost:27017/backend-project');
        console.log('数据库连接成功');
    } catch (error) {
        console.error('数据库连接失败:', error);
        process.exit(1);
    }
}

// 导入技能数据
async function importSkills() {
    try {
        // 读取三个 JSON 文件
        const strengthFiles = [
            { file: 'strength0.json', strength: 0 },
            { file: 'strength1.json', strength: 1 },
            { file: 'strength2.json', strength: 2 }
        ];

        let totalImported = 0;
        let totalSkipped = 0;

        for (const { file, strength } of strengthFiles) {
            console.log(`\n正在导入 ${file}...`);
            
            const filePath = path.join(__dirname, file);
            if (!fs.existsSync(filePath)) {
                console.log(`文件 ${file} 不存在，跳过`);
                continue;
            }

            const fileContent = fs.readFileSync(filePath, 'utf8');
            const skillsData = JSON.parse(fileContent);

            for (const skillData of skillsData) {
                try {
                    // 检查是否已存在
                    const existingSkill = await Skill.findOne({
                        name: skillData.name,
                        strength: strength
                    });

                    if (existingSkill) {
                        console.log(`技能 "${skillData.name}" (强度${strength}) 已存在，跳过`);
                        totalSkipped++;
                        continue;
                    }

                    // 创建新技能
                    const newSkill = new Skill({
                        name: skillData.name,
                        content: skillData.content,
                        strength: strength,
                        role: skillData.role
                    });

                    await newSkill.save();
                    console.log(`成功导入技能: ${skillData.name} (强度${strength})`);
                    totalImported++;
                } catch (error) {
                    console.error(`导入技能 "${skillData.name}" 失败:`, error.message);
                }
            }
        }

        console.log(`\n导入完成！`);
        console.log(`成功导入: ${totalImported} 个技能`);
        console.log(`跳过已存在: ${totalSkipped} 个技能`);
        
    } catch (error) {
        console.error('导入过程出错:', error);
    }
}

// 主函数
async function main() {
    await connectDB();
    await importSkills();
    await mongoose.connection.close();
    console.log('数据库连接已关闭');
}

// 如果直接运行此脚本
if (require.main === module) {
    main().catch(console.error);
}

module.exports = { importSkills };
