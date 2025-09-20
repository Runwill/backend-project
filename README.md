# Backend Project

## 项目简介
这是一个基于 Express 的后端项目，旨在提供一个 RESTful API 接口。该项目包含多个模块，包括控制器、模型、路由和服务层，便于管理和扩展。

## 文件结构
```
backend-project
├── src
│   ├── controllers        # 控制器，处理请求
│   ├── models             # 数据模型，定义与数据库的交互
│   ├── routes             # 路由，定义 API 端点
│   ├── services           # 服务层，处理业务逻辑
│   └── app.js             # 应用程序入口点
├── config                 # 配置文件
│   └── default.json       # 默认配置
├── package.json           # npm 配置文件
├── .env                   # 环境变量
└── README.md              # 项目文档
```

## 安装
1. 克隆项目到本地：
   ```
   git clone <repository-url>
   ```
2. 进入项目目录：
   ```
   cd backend-project
   ```
3. 安装依赖：
   ```
   npm install
   ```

## 运行
1. 确保已配置 `.env` 文件，包含必要的环境变量。
2. 启动应用程序：
   ```
   npm start
   ```

## 配置与常见修改

后端的“端口、数据库地址、CORS 白名单”集中在 `src/config/serverConfig.js`，并可被环境变量覆盖（app.js 顶部有 `require('dotenv').config()`，会自动读取项目根目录的 `.env`）。你可以按以下三种方式二选一（或三选一）修改：

1) 直接改文件（最直观）

- 文件：`src/config/serverConfig.js`
- 可改动项：
   - `DEFAULT_PORT`（默认 3000）
   - `DEFAULT_DB_URL`（MongoDB 连接串）
   - `DEFAULT_CORS`（允许的前端来源列表）

2) 用 .env（推荐，方便不同环境）

- 在项目根目录新建或编辑 `.env`：

```
# 端口（例如改成 3001）
PORT=3001

# 数据库连接串
DB_URL=mongodb://localhost:27017/backend-project

# 允许的前端来源（逗号分隔，勿带空格）
# 示例：本机 Live Server、以及你的内网 IP:5500
CORS_ORIGINS=http://127.0.0.1:5500,http://localhost:5500,http://192.168.1.5:5500
```

3) 临时只改本次运行（PowerShell）

在 Windows PowerShell 下，你可以临时设置环境变量并启动：

```powershell
$env:PORT=3001; $env:DB_URL="mongodb://localhost:27017/backend-project"; $env:CORS_ORIGINS="http://127.0.0.1:5500,http://localhost:5500"; node src/app.js
```

说明与注意：
- CORS：当你的前端地址（协议+域名/IP+端口）变化时，把它加入 `CORS_ORIGINS` 列表即可，例如 `http://192.168.1.5:8080`。
- 允许无 Origin 请求：后端已允许无 Origin（如 Postman、本地脚本）通过。
- 端口与前端联动：如果你把后端端口从 3000 改到 3001，记得在前端 `card-html/function/api/endpoints.js` 把 `DEFAULT_BASE` 改成 `http://<你的主机>:3001`。
- 任务启动：在 VS Code 可使用任务 “Start backend server (node)” 启动（项目根目录为 `backend-project`）。

## 使用
- API 端点将根据定义的路由提供服务。请参考 `src/routes/index.js` 以获取详细的路由信息。

## 贡献
欢迎任何形式的贡献！请提交问题或拉取请求。

## 许可证
本项目遵循 MIT 许可证。