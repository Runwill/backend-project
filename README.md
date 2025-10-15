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

## 公网映射变更速查：需要修改哪些地方？

若你的公网映射地址（或端口）发生变化，请在后端做如下调整（并参考前端仓库的 README 同步修改前端部分）。

1) CORS 白名单（最重要）
- 文件：`src/config/serverConfig.js`
- 字段：`DEFAULT_CORS`（或使用环境变量 `CORS_ORIGINS` 覆盖）
- 操作：将新的前端来源（例如 `http://ewdu7894156.vicp.fun` 或 `http://your.domain.com:5500`）加入允许列表。多个地址用英文逗号分隔。
- 环境变量示例：
   ```powershell
   $env:CORS_ORIGINS="http://ewdu7894156.vicp.fun,http://localhost:5500"; node src/app.js
   ```

2) 服务端口（如果改变映射到的服务端口）
- 文件：`src/config/serverConfig.js`
- 字段：`DEFAULT_PORT`（或环境变量 `PORT`）
- 操作：改成新端口，例如 3001；同时通知前端同步把后端基址中的端口改为 3001。

3) 数据库地址（如部署拓扑调整）
- 文件：`src/config/serverConfig.js`
- 字段：`DEFAULT_DB_URL`（或环境变量 `DB_URL`）

4) 其他与代理/内网穿透相关的注意
- 反向代理需要允许并透传 `OPTIONS` 预检请求，不能拦截或丢弃。
- 反向代理不要覆盖服务端返回的 CORS 头（除非你十分确认需求），以免与服务端配置冲突。
- 若前端改为 HTTPS，而后端为 HTTP，浏览器仍允许跨域，但 Cookie/凭证相关需正确设置（SameSite=None; Secure）。

5) 与前端的联动修改（提醒）
- 前端仓库 `card-html/login.html`：
   - 修改 `PUBLIC_URL` 为新的后端对外地址；
   - `isPublic()` 里替换为你的新域名/IP；
   - 如本地端口变化，更新 `LOCAL_URL`。
- 前端仓库 `card-html/function/api/endpoints.js`：
   - 如需改变默认后端基址，把内置默认值从 `http://localhost:3000` 改成新地址（也可在运行时通过“切换后端”按钮写入 localStorage 覆盖）。

## 使用
- API 端点将根据定义的路由提供服务。请参考 `src/routes/index.js` 以获取详细的路由信息。

## 贡献
欢迎任何形式的贡献！请提交问题或拉取请求。

## 许可证
本项目遵循 MIT 许可证。