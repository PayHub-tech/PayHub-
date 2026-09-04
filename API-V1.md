# PayHub Merchant API V1

### 创建订单
POST `/api/v1/orders`

```json
{"amount":99.00,"subject":"测试商品","channel":"mock","returnUrl":"https://merchant.example/success","notifyUrl":"https://merchant.example/payhub/webhook"}
```

### 查询订单
GET `/api/v1/orders/:orderNo`

### 签名
`HMAC-SHA256(API_SECRET, timestamp + "." + nonce + "." + raw_json_body)`

请求头：`X-PayHub-Key`、`X-PayHub-Timestamp`、`X-PayHub-Nonce`、`X-PayHub-Secret`、`X-PayHub-Signature`

生产环境必须使用 HTTPS。真实微信/支付宝/银行卡/USDT TRC20 仍需官方或合规授权服务商的真实 API、商户资质、证书/密钥和回调协议。

## V11 endpoints
- POST /api/orders/:orderNo/refund
- GET /api/refunds
- POST /api/orders/:orderNo/close
- GET/PUT /api/merchant/fee-config
- POST /api/settlements
- GET /api/settlements
- POST /api/settlements/:settlementNo/cancel
