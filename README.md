# PayHub V4 — 订单 + 钱包 + API Key

这一版是在 V3 登录/注册基础上继续开发，加入了真正的数据库业务模型和 API：

- 商户注册 / 登录 / JWT
- 商户编号、账户余额
- 订单创建、订单列表、订单详情
- 订单状态：pending / paid
- 开发环境测试支付接口 `/api/orders/:orderNo/mock-pay`
- 钱包流水 ledger
- API Key 创建 / 列表 / 撤销
- Webhook 签名示例
- Dashboard 统计 API
- SQLite 开箱即用

## 启动

```bash
npm install
cp .env.example .env
npm start
```

然后打开 `http://localhost:3000`。

## 测试流程

1. 注册商户
2. 登录
3. POST `/api/orders` 创建订单
4. POST `/api/orders/:orderNo/mock-pay` 模拟支付
5. 查看 `/api/dashboard/stats`
6. 查看 `/api/wallet/transactions`

## 重要

`mock-pay` 只是开发测试，不是真实支付。

真正接入微信支付、支付宝、银行卡、TRC20 USDT 时，应使用对应官方/授权支付服务商的商户资质、密钥、回调验签和风控规则。不要把测试接口当作真实收款通道。

生产环境建议：
- HTTPS
- PostgreSQL
- Redis
- 密钥放 Secret Manager
- 管理员后台 + RBAC
- webhook 重试 / 幂等
- 订单超时关闭
- 退款与对账
- KYC/AML、商户审核和风控


## V5 收银台

订单创建后可打开 `/checkout.html?order=订单号`。
目前 Mock 测试支付可以完整走：订单 → 支付成功 → 商户钱包入账。
微信、支付宝、银行卡、TRC20 USDT 为真实通道接入预留入口，生产环境必须使用官方/授权服务商接口和异步回调验签。


## V7 登录与注册 UI

- 全新 PayHub 登录页
- 商户注册页
- 密码确认
- 服务条款勾选
- 登录错误提示
- 注册成功自动进入商户后台
- 移动端 / 桌面端自适应
- 原 V6 商户后台保存在 `/dashboard`


## V8 支付通道与 Webhook

新增：
- 微信支付、支付宝、银行卡、USDT TRC20、Mock 五类通道配置 UI
- 通道启用/停用
- 商户支付参数保存（敏感字段前端掩码展示）
- Webhook URL / Callback Secret 配置
- HMAC-SHA256 签名预览
- Webhook 日志查询
- 真实支付通道仍为“待接入官方/授权服务商 API”的架构，不会伪造真实支付成功

### 重要
真实微信/支付宝/银行卡/USDT 支付必须使用官方或合规授权服务商的接口、商户资质、密钥、证书和回调协议。当前 V8 不绕过任何支付机构的风控、签名或审核流程。

## V9
商户 API Key/Secret、凭证轮换、HMAC-SHA256 请求签名、创建订单 API、查询订单 API、开发者 API 页面。

## V10 完整支付订单链路
- Mock 收银台支付完成后自动更新订单为 paid
- 钱包自动入账
- Demo 平台手续费 2%（生产环境应改为商户独立费率配置）
- 幂等钱包流水，避免同一订单重复入账
- Webhook 事件进入发送队列
- Webhook 重试接口
- 商户交易明细 API
- 订单生命周期查询 API
- 保留 V9 商户 API、V8 支付通道配置
- 真实支付通道仍需官方/授权服务商适配器，不伪造支付成功

## V11
- 退款 / 部分退款
- 待支付订单关闭
- 支付、退款、结算手续费率配置
- 商户结算/提现申请与取消
- 结算及退款记录
- 真实支付和真实银行出款仍需接入官方/授权服务商；当前结算仅做开发版余额扣减与状态流转


## V12.1 修复
- 修复 SQLite `orders` 兼容字段迁移：payment_method / checkout_token / return_url / notify_url。
- 修复公开收银台 GET/POST 接口。
- 修复 V10 Mock 支付与钱包字段映射。
- 修复支付通道/ Webhook 商户 ID 查询。
- 修复退款/结算与商户 `balance_cents` 的一致性。
- 修复前端 catch-all 路由顺序，避免 API GET 被首页路由拦截。

管理员入口：`/admin`
开发管理员：`admin@payhub.local` / `Admin123!`（生产必须通过环境变量覆盖）
