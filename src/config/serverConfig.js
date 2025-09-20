// 后端单点配置：端口、数据库地址、CORS 白名单
// 使用方法：直接修改下方常量或通过环境变量覆盖。

const DEFAULT_PORT = Number(process.env.PORT) || 3000;
const DEFAULT_DB_URL = process.env.DB_URL || 'mongodb://localhost:27017/backend-project';
const DEFAULT_CORS = [
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  // 如需允许本机 3000 前端调试，可取消下一行的注释
  // 'http://localhost:3000'
];

function parseOrigins(val) {
  if (!val) return null;
  return String(val)
    .split(',')
    .map(s => s && s.trim())
    .filter(Boolean);
}

module.exports = {
  port: DEFAULT_PORT,
  dbUrl: DEFAULT_DB_URL,
  corsOrigins: parseOrigins(process.env.CORS_ORIGINS) || DEFAULT_CORS,
};
