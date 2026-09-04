# 手机端开发/部署建议

你目前如果只有 iPhone，不能直接在“文件”App里运行 Node.js 后端。

建议：
1. 把整个项目上传到一个支持 Node.js 的云端开发/部署平台。
2. 设置环境变量：
   - PORT（平台通常自动提供）
   - JWT_SECRET
3. 启动命令：`npm start`
4. 浏览器打开平台分配的 HTTPS 地址。
5. 后续再绑定自己的域名。

如果使用云端 PostgreSQL，需要把 SQLite 数据层迁移到 PostgreSQL；V4 已经把业务表结构和 API 分层好，下一版可以直接做。


## V8 手机部署
你可以继续用手机浏览器连接云端 Node.js 环境部署。iPhone“文件”App 本身不能直接运行 Node.js 后端。
推荐流程：
1. 把 ZIP 上传到支持 Node.js 的云 IDE / 云服务器。
2. `npm install`
3. 复制 `.env.example` 为 `.env` 并设置 JWT_SECRET。
4. `npm start`
5. 打开部署后的 `/` 登录，进入 `/dashboard`。
6. 在“支付通道”页面配置官方/授权服务商参数。
