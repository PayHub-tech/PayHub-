const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const crypto = require("crypto");


const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const dbPath = process.env.DB_PATH || path.join(__dirname, "payhub.db");
const db = new Database(dbPath);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS merchants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  merchant_no TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  balance_cents INTEGER NOT NULL DEFAULT 0,
  frozen_cents INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  merchant_id INTEGER NOT NULL,
  key_id TEXT UNIQUE NOT NULL,
  secret_hash TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT 'Default API Key',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT,
  FOREIGN KEY (merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_no TEXT UNIQUE NOT NULL,
  merchant_id INTEGER NOT NULL,
  merchant_order_no TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'CNY',
  channel TEXT NOT NULL DEFAULT 'mock',
  subject TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  pay_url TEXT,
  client_ip TEXT,
  expired_at TEXT,
  paid_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(merchant_id, merchant_order_no),
  FOREIGN KEY (merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wallet_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  merchant_id INTEGER NOT NULL,
  order_id INTEGER,
  type TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  balance_after_cents INTEGER NOT NULL,
  reference_no TEXT NOT NULL,
  remark TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(reference_no),
  FOREIGN KEY (merchant_id) REFERENCES merchants(id) ON DELETE CASCADE,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS webhook_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  merchant_id INTEGER NOT NULL,
  order_id INTEGER,
  event TEXT NOT NULL,
  payload TEXT NOT NULL,
  signature TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  response_code INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (merchant_id) REFERENCES merchants(id) ON DELETE CASCADE,
  FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE SET NULL
);
`);

// Backward-compatible order metadata used by the hosted checkout/API V1.
for (const sql of [
  "ALTER TABLE orders ADD COLUMN payment_method TEXT NOT NULL DEFAULT 'mock'",
  "ALTER TABLE orders ADD COLUMN checkout_token TEXT",
  "ALTER TABLE orders ADD COLUMN return_url TEXT",
  "ALTER TABLE orders ADD COLUMN notify_url TEXT"
]) {
  try {
    db.exec(sql);
  } catch (e) {
    if (!String(e.message).includes('duplicate column name')) throw e;
  }
}

db.exec(`
CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT 'Platform Admin',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  detail TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(admin_id) REFERENCES admin_users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS merchant_risk_flags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  merchant_id INTEGER NOT NULL,
  level TEXT NOT NULL DEFAULT 'low',
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at TEXT,
  FOREIGN KEY(merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reconciliation_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_no TEXT UNIQUE NOT NULL,
  scope TEXT NOT NULL DEFAULT 'all',
  result TEXT NOT NULL DEFAULT 'ok',
  summary_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@payhub.local';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin123!';

const adminExists = db
  .prepare('SELECT id FROM admin_users WHERE email=?')
  .get(ADMIN_EMAIL);

if (!adminExists) {
  db.prepare(
    'INSERT INTO admin_users(email,password_hash,name) VALUES(?,?,?)'
  ).run(
    ADMIN_EMAIL,
    bcrypt.hashSync(ADMIN_PASSWORD, 12),
    'PayHub Admin'
  );
}

db.exec(`
CREATE TABLE IF NOT EXISTS payment_channels (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 merchant_id INTEGER NOT NULL,
 channel_code TEXT NOT NULL,
 display_name TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 0,
 config_json TEXT NOT NULL DEFAULT '{}',
 webhook_url TEXT NOT NULL DEFAULT '',
 callback_secret TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(merchant_id,channel_code),
 FOREIGN KEY(merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS merchant_api_credentials (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 merchant_id INTEGER NOT NULL UNIQUE,
 api_key TEXT NOT NULL UNIQUE,
 api_secret_hash TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 FOREIGN KEY(merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_request_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 merchant_id INTEGER,
 api_key TEXT,
 method TEXT,
 path TEXT,
 order_no TEXT,
 request_id TEXT,
 signature_valid INTEGER NOT NULL DEFAULT 0,
 status_code INTEGER,
 created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS wallet_ledger (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 merchant_id INTEGER NOT NULL,
 order_no TEXT,
 type TEXT NOT NULL,
 amount REAL NOT NULL,
 fee REAL NOT NULL DEFAULT 0,
 net_amount REAL NOT NULL,
 balance_before REAL NOT NULL DEFAULT 0,
 balance_after REAL NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'posted',
 remark TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL,
 UNIQUE(merchant_id,order_no,type),
 FOREIGN KEY(merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 merchant_id INTEGER NOT NULL,
 order_no TEXT NOT NULL,
 event_type TEXT NOT NULL,
 target_url TEXT NOT NULL,
 payload TEXT NOT NULL,
 signature TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0,
 last_error TEXT NOT NULL DEFAULT '',
 next_retry_at TEXT,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS merchant_fee_configs (
 merchant_id INTEGER PRIMARY KEY,
 payment_fee_rate REAL NOT NULL DEFAULT 0.02,
 refund_fee_rate REAL NOT NULL DEFAULT 0,
 settlement_fee_rate REAL NOT NULL DEFAULT 0.005,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refunds (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 merchant_id INTEGER NOT NULL,
 order_no TEXT NOT NULL,
 refund_no TEXT NOT NULL UNIQUE,
 refund_amount REAL NOT NULL,
 fee REAL NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'pending',
 reason TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 processed_at TEXT
);

CREATE TABLE IF NOT EXISTS settlements (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 merchant_id INTEGER NOT NULL,
 settlement_no TEXT NOT NULL UNIQUE,
 amount REAL NOT NULL,
 fee REAL NOT NULL DEFAULT 0,
 net_amount REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 bank_name TEXT,
 account_name TEXT,
 account_no_masked TEXT,
 remark TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 processed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_refunds_merchant
ON refunds(merchant_id,created_at);

CREATE INDEX IF NOT EXISTS idx_settlements_merchant
ON settlements(merchant_id,created_at);
`);

function merchantNo() {
  return "PH" +
    Date.now().toString().slice(-8) +
    Math.floor(Math.random() * 90 + 10);
}

function orderNo() {
  const time = new Date()
    .toISOString()
    .replace(/[-T:.Z]/g, "");

  const random = crypto
    .randomBytes(4)
    .toString("hex")
    .toUpperCase();

  return "PH" + time + random;
}

function randomKey(prefix) {
  return prefix + crypto.randomBytes(18).toString("hex");
}

function signPayload(secret, payload) {
  return crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex");
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ")
    ? h.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({
      message: "未登录"
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      message: "登录已过期，请重新登录"
    });
  }
}

function getMerchant(id) {
  return db
    .prepare("SELECT * FROM merchants WHERE id = ?")
    .get(id);
}

function cents(v) {
  const n = Number(v);

  if (!Number.isFinite(n) || n <= 0) {
    throw new Error("金额必须大于 0");
  }

  return Math.round(n * 100);
}

function publicMerchant(m) {
  return {
    id: m.id,
    merchantNo: m.merchant_no,
    email: m.email,
    name: m.name,
    status: m.status,
    balance: (m.balance_cents / 100).toFixed(2),
    frozen: (m.frozen_cents / 100).toFixed(2),
    createdAt: m.created_at
  };
}

app.get(
  "/api/health",
  (req,res) =>
    res.json({
      ok:true,
      service:"PayHub",
      version:"12.0.0"
    })
);

app.post("/api/auth/register", async (req,res) => {
  try {
    const { email, password, name } = req.body || {};

    if (!email || !password || password.length < 6) {
      return res.status(400).json({
        message:"邮箱和至少 6 位密码为必填项"
      });
    }

    const exists = db
      .prepare("SELECT id FROM merchants WHERE email=?")
      .get(
        String(email)
          .trim()
          .toLowerCase()
      );

    if (exists) {
      return res.status(409).json({
        message:"该邮箱已注册"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const info = db.prepare(
      "INSERT INTO merchants (merchant_no,email,password_hash,name) VALUES (?,?,?,?)"
    ).run(
      merchantNo(),
      String(email).trim().toLowerCase(),
      hash,
      name || "PayHub 商户"
    );

    const m = getMerchant(info.lastInsertRowid);

    const token = jwt.sign(
      {
        id:m.id,
        email:m.email
      },
      JWT_SECRET,
      {
        expiresIn:"7d"
      }
    );

    res.json({
      message:"注册成功",
      token,
      user:publicMerchant(m)
    });

  } catch(e) {
    res.status(500).json({
      message:e.message || "注册失败"
    });
  }
});

app.post("/api/auth/login", async (req,res) => {
  try {
    const { email, password } = req.body || {};

    const m = db
      .prepare(
        "SELECT * FROM merchants WHERE email=?"
      )
      .get(
        String(email||"")
          .trim()
          .toLowerCase()
      );

    if (
      !m ||
      !(await bcrypt.compare(
        password || "",
        m.password_hash
      ))
    ) {
      return res.status(401).json({
        message:"邮箱或密码错误"
      });
    }

    if (m.status !== "active") {
      return res.status(403).json({
        message:"商户账号已被停用"
      });
    }

    const token = jwt.sign(
      {
        id:m.id,
        email:m.email
      },
      JWT_SECRET,
      {
        expiresIn:"7d"
      }
    );

    res.json({
      message:"登录成功",
      token,
      user:publicMerchant(m)
    });

  } catch(e) {
    res.status(500).json({
      message:"登录失败"
    });
  }
});

app.get("/api/auth/me", auth, (req,res) => {
  const m = getMerchant(req.user.id);

  if (!m) {
    return res.status(404).json({
      message:"商户不存在"
    });
  }

  res.json({
    user:publicMerchant(m)
  });
});

app.get("/api/dashboard/stats", auth, (req,res) => {
  const mid = req.user.id;

  const total = db
    .prepare(
      "SELECT COALESCE(SUM(amount_cents),0) s FROM orders WHERE merchant_id=? AND status='paid'"
    )
    .get(mid).s;

  const pending = db
    .prepare(
      "SELECT COUNT(*) c FROM orders WHERE merchant_id=? AND status='pending'"
    )
    .get(mid).c;

  const count = db
    .prepare(
      "SELECT COUNT(*) c FROM orders WHERE merchant_id=?"
    )
    .get(mid).c;

  const paidCount = db
    .prepare(
      "SELECT COUNT(*) c FROM orders WHERE merchant_id=? AND status='paid'"
    )
    .get(mid).c;

  const m = getMerchant(mid);

  res.json({
    balance:(m.balance_cents/100).toFixed(2),
    totalPaid:(total/100).toFixed(2),
    orderCount:count,
    pendingCount:pending,
    paidCount
  });
});
app.post("/api/orders", auth, (req,res) => {
  try {
    const {
      merchantOrderNo,
      amount,
      currency="CNY",
      channel="mock",
      subject="PayHub 订单",
      expiresMinutes=30
    } = req.body || {};

    if (!merchantOrderNo) {
      return res.status(400).json({
        message:"merchantOrderNo 必填"
      });
    }

    const amountCents = cents(amount);

    const exists = db
      .prepare(
        "SELECT * FROM orders WHERE merchant_id=? AND merchant_order_no=?"
      )
      .get(
        req.user.id,
        String(merchantOrderNo)
      );

    if (exists) {
      return res.status(409).json({
        message:"商户订单号已存在",
        order:exists
      });
    }

    // 自动生成 PayHub 平台订单号
    const no = orderNo();

    // 自动计算订单过期时间
    const expired = new Date(
      Date.now() +
      Math.max(
        1,
        Number(expiresMinutes) || 30
      ) * 60000
    ).toISOString();

    // 自动生成支付链接
    const payUrl =
      `${req.protocol}://${req.get("host")}/pay/${no}`;

    // 写入数据库
    const info = db.prepare(`
      INSERT INTO orders(
        order_no,
        merchant_id,
        merchant_order_no,
        amount_cents,
        currency,
        channel,
        subject,
        pay_url,
        client_ip,
        expired_at
      )
      VALUES(?,?,?,?,?,?,?,?,?,?)
    `).run(
      no,
      req.user.id,
      String(merchantOrderNo),
      amountCents,
      String(currency),
      String(channel),
      String(subject),
      payUrl,
      req.ip,
      expired
    );

    // 再从数据库读取一次，确保返回的订单是真实数据库订单
    const order = db
      .prepare(
        "SELECT * FROM orders WHERE id=?"
      )
      .get(info.lastInsertRowid);

    res.json({
      message:"订单创建成功",

      // 完整订单信息
      order:formatOrder(order),

      // 平台订单号
      orderNo:no,

      // 支付链接
      payUrl:payUrl
    });

  } catch(e) {

    console.error(
      "创建订单失败:",
      e
    );

    res.status(400).json({
      message:e.message || "创建订单失败"
    });
  }
});


/*
 * =====================================================
 * 公共支付页面
 * 地址：
 *
 * /pay/平台订单号
 *
 * 例如：
 * /pay/PH202609051230001234ABCD
 *
 * 这个地址不需要登录。
 * =====================================================
 */

app.get("/pay/:orderNo",(req,res)=>{

  const orderNoParam =
    String(req.params.orderNo || "").trim();

  if(!orderNoParam){
    return res.status(404).send("订单不存在");
  }

  const order = db
    .prepare(
      "SELECT * FROM orders WHERE order_no=?"
    )
    .get(orderNoParam);

  if(!order){
    return res.status(404).send("订单不存在");
  }

  /*
   * 检查订单是否已经过期
   */
  if(
    order.status === "pending" &&
    order.expired_at &&
    new Date(order.expired_at).getTime() < Date.now()
  ){

    db.prepare(`
      UPDATE orders
      SET status='expired',
          updated_at=CURRENT_TIMESTAMP
      WHERE id=?
        AND status='pending'
    `).run(order.id);

    order.status = "expired";
  }

  /*
   * 已过期订单不能继续支付
   */
  if(order.status === "expired"){

    return res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>PayHub 收银台</title>

<style>
body{
  margin:0;
  padding:40px 20px;
  font-family:-apple-system,BlinkMacSystemFont,
              "Segoe UI",Arial,sans-serif;
  background:#f5f6f8;
  color:#222;
}

.box{
  max-width:420px;
  margin:0 auto;
  background:#fff;
  border-radius:18px;
  padding:30px 24px;
  box-sizing:border-box;
  text-align:center;
  box-shadow:0 10px 30px rgba(0,0,0,.08);
}

h2{
  margin-top:0;
}

.expired{
  color:#d93025;
  font-size:18px;
  font-weight:600;
}
</style>
</head>

<body>

<div class="box">

<h2>PayHub 收银台</h2>

<p class="expired">
订单已过期
</p>

<p>
订单号：
<strong>${order.order_no}</strong>
</p>

<p>
金额：
<strong>${(order.amount_cents/100).toFixed(2)}
${order.currency}</strong>
</p>

</div>

</body>
</html>
`);
  }

  /*
   * 已支付订单
   */
  if(order.status === "paid"){

    return res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>PayHub 支付成功</title>

<style>
body{
  margin:0;
  padding:40px 20px;
  font-family:-apple-system,BlinkMacSystemFont,
              "Segoe UI",Arial,sans-serif;
  background:#f5f6f8;
}

.box{
  max-width:420px;
  margin:0 auto;
  background:#fff;
  border-radius:18px;
  padding:30px 24px;
  text-align:center;
  box-shadow:0 10px 30px rgba(0,0,0,.08);
}

.success{
  font-size:22px;
  color:#16a34a;
  font-weight:700;
}

.order{
  margin-top:20px;
  line-height:1.8;
}
</style>
</head>

<body>

<div class="box">

<div class="success">
✓ 支付成功
</div>

<div class="order">

<p>
订单号：
<br>
<strong>${order.order_no}</strong>
</p>

<p>
金额：
<strong>
${(order.amount_cents/100).toFixed(2)}
${order.currency}
</strong>
</p>

</div>

</div>

</body>
</html>
`);
  }

  /*
   * 正常待支付订单
   */
  res.send(`
<!DOCTYPE html>
<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>PayHub 收银台</title>

<style>

*{
  box-sizing:border-box;
}

body{
  margin:0;
  padding:40px 20px;
  font-family:
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    Arial,
    sans-serif;

  background:#f5f6f8;
  color:#222;
}

.box{
  max-width:420px;
  margin:0 auto;

  background:#fff;

  border-radius:18px;

  padding:30px 24px;

  box-shadow:
    0 10px 30px
    rgba(0,0,0,.08);
}

h2{
  text-align:center;
  margin-top:0;
}

.info{
  margin-top:25px;
  line-height:2;
}

.label{
  color:#777;
}

.value{
  font-weight:600;
  word-break:break-all;
}

.amount{
  font-size:30px;
  font-weight:700;
  text-align:center;
  margin:20px 0;
}

button{
  width:100%;
  border:0;
  border-radius:12px;
  padding:14px;

  font-size:17px;
  font-weight:600;

  background:#111;
  color:#fff;

  cursor:pointer;
}

button:disabled{
  opacity:.5;
}

#result{
  margin-top:20px;
  text-align:center;
  line-height:1.6;
}

.success{
  color:#16a34a;
  font-weight:700;
}

.error{
  color:#d93025;
  font-weight:600;
}

</style>

</head>

<body>

<div class="box">

<h2>PayHub 收银台</h2>

<div class="amount">
${(order.amount_cents/100).toFixed(2)}
${order.currency}
</div>

<div class="info">

<div>
<span class="label">
订单号：
</span>

<span class="value">
${order.order_no}
</span>
</div>

<div>
<span class="label">
商户订单号：
</span>

<span class="value">
${order.merchant_order_no}
</span>
</div>

<div>
<span class="label">
商品：
</span>

<span class="value">
${String(order.subject || "PayHub 订单")
  .replace(/</g,"&lt;")
  .replace(/>/g,"&gt;")}
</span>
</div>

</div>

<br>

<button
  id="payBtn"
  onclick="payOrder()"
>
立即支付
</button>

<div id="result"></div>

</div>

<script>

async function payOrder(){

  const btn =
    document.getElementById("payBtn");

  const result =
    document.getElementById("result");

  btn.disabled = true;

  result.innerHTML =
    "正在处理支付，请稍候...";

  try{

    const response =
      await fetch(
        "/api/checkout/${encodeURIComponent(order.order_no)}/pay-v10",
        {
          method:"POST",

          headers:{
            "Content-Type":
              "application/json"
          },

          body:JSON.stringify({
            channel:"mock"
          })
        }
      );

    const data =
      await response.json();

    if(!response.ok){

      throw new Error(
        data.message ||
        data.error ||
        "支付失败"
      );
    }

    result.innerHTML = `
      <div class="success">
        ✓ 支付成功
      </div>

      <div>
        订单号：
        <strong>
          ${data.order?.orderNo ||
            data.order?.order_no ||
            "${order.order_no}"}
        </strong>
      </div>
    `;

    btn.disabled = true;

  }catch(e){

    result.innerHTML = `
      <div class="error">
        ${String(e.message || "支付失败")
          .replace(/</g,"&lt;")
          .replace(/>/g,"&gt;")}
      </div>
    `;

    btn.disabled = false;
  }
}

</script>

</body>

</html>
`);
});


/*
 * =====================================================
 * 订单格式化
 * 同时兼容 camelCase 和 snake_case
 * =====================================================
 */

function formatOrder(o) {

  if(!o){
    return null;
  }

  return {

    id:o.id,

    // 平台订单号
    orderNo:o.order_no,
    order_no:o.order_no,

    // 商户自己的订单号
    merchantOrderNo:o.merchant_order_no,
    merchant_order_no:o.merchant_order_no,

    // 金额
    amount:
      (o.amount_cents / 100).toFixed(2),

    currency:o.currency,

    channel:o.channel,

    subject:o.subject,

    status:o.status,

    // 支付链接
    payUrl:o.pay_url,
    pay_url:o.pay_url,

    expiredAt:o.expired_at,

    paidAt:o.paid_at,

    createdAt:o.created_at,

    updatedAt:o.updated_at
  };
}


/*
 * =====================================================
 * 商户后台订单列表
 * =====================================================
 */

app.get("/api/orders", auth, (req,res) => {

  const page =
    Math.max(
      1,
      Number(req.query.page) || 1
    );

  const pageSize =
    Math.min(
      100,
      Math.max(
        1,
        Number(req.query.pageSize) || 20
      )
    );

  const status =
    req.query.status;

  const where =
    status
      ? "AND status=?"
      : "";

  const params =
    status
      ? [req.user.id,status]
      : [req.user.id];

  const total =
    db.prepare(`
      SELECT COUNT(*) c
      FROM orders
      WHERE merchant_id=?
      ${where}
    `)
    .get(...params)
    .c;

  const rows =
    db.prepare(`
      SELECT *
      FROM orders
      WHERE merchant_id=?
      ${where}
      ORDER BY id DESC
      LIMIT ?
      OFFSET ?
    `)
    .all(
      ...params,
      pageSize,
      (page-1)*pageSize
    );

  res.json({
    data:rows.map(formatOrder),
    total,
    page,
    pageSize
  });

});


/*
 * =====================================================
 * 商户查询单个订单
 * =====================================================
 */

app.get(
  "/api/orders/:orderNo",
  auth,
  (req,res) => {

    const o =
      db.prepare(`
        SELECT *
        FROM orders
        WHERE order_no=?
          AND merchant_id=?
      `)
      .get(
        req.params.orderNo,
        req.user.id
      );

    if(!o){

      return res.status(404).json({
        message:"订单不存在"
      });

    }

    res.json({
      order:formatOrder(o)
    });

  }
);


/*
 * =====================================================
 * Mock 测试支付
 * 商户后台使用
 * =====================================================
 */

app.post(
  "/api/orders/:orderNo/mock-pay",
  auth,
  (req,res) => {

    try{

      const result =
        db.transaction(() => {

          const o =
            db.prepare(`
              SELECT *
              FROM orders
              WHERE order_no=?
                AND merchant_id=?
            `)
            .get(
              req.params.orderNo,
              req.user.id
            );

          if(!o){
            throw new Error(
              "订单不存在"
            );
          }

          if(o.status === "paid"){
            return o;
          }

          if(o.status !== "pending"){
            throw new Error(
              "订单当前不可支付"
            );
          }

          const m =
            getMerchant(
              req.user.id
            );

          const newBalance =
            m.balance_cents +
            o.amount_cents;

          db.prepare(`
            UPDATE orders
            SET
              status='paid',
              paid_at=CURRENT_TIMESTAMP,
              updated_at=CURRENT_TIMESTAMP
            WHERE id=?
          `).run(o.id);

          db.prepare(`
            UPDATE merchants
            SET balance_cents=?
            WHERE id=?
          `).run(
            newBalance,
            m.id
          );

          db.prepare(`
            INSERT INTO wallet_transactions(
              merchant_id,
              order_id,
              type,
              amount_cents,
              balance_after_cents,
              reference_no,
              remark
            )
            VALUES(?,?,?,?,?,?,?)
          `).run(
            m.id,
            o.id,
            "income",
            o.amount_cents,
            newBalance,
            "TX" +
              crypto
                .randomBytes(10)
                .toString("hex"),
            "Mock 测试支付入账"
          );

          return db
            .prepare(
              "SELECT * FROM orders WHERE id=?"
            )
            .get(o.id);

        })();

      res.json({
        message:
          "支付成功（Mock 测试环境）",
        order:formatOrder(result)
      });

    }catch(e){

      res.status(400).json({
        message:e.message
      });

    }

  }
);


/*
 * =====================================================
 * 收银台查询订单
 *
 * 这个接口非常重要。
 *
 * checkout.html 打开以后，
 * 会调用：
 *
 * GET /api/checkout/订单号
 *
 * 这里直接根据 order_no 查询数据库。
 *
 * 不需要登录。
 * =====================================================
 */

app.get(
  "/api/checkout/:orderNo",
  (req,res) => {

    const orderNoParam =
      String(
        req.params.orderNo || ""
      ).trim();

    if(!orderNoParam){

      return res.status(404).json({
        message:"订单不存在"
      });

    }

    const o =
      db.prepare(`
        SELECT *
        FROM orders
        WHERE order_no=?
      `)
      .get(orderNoParam);

    if(!o){

      return res.status(404).json({
        message:"订单不存在"
      });

    }

    /*
     * 如果订单存在 checkout_token，
     * 并且请求带 token，
     * 则进行校验。
     *
     * 如果没有 token，
     * 不阻止正常的 /checkout/订单号 访问。
     */
    if(
      o.checkout_token &&
      req.query.token &&
      o.checkout_token !==
        req.query.token
    ){

      return res.status(403).json({
        message:"收银台令牌无效"
      });

    }

    /*
     * 检查是否过期
     */
    if(
      o.status === "pending" &&
      o.expired_at &&
      new Date(
        o.expired_at
      ).getTime() < Date.now()
    ){

      db.prepare(`
        UPDATE orders
        SET
          status='expired',
          updated_at=CURRENT_TIMESTAMP
        WHERE id=?
          AND status='pending'
      `).run(o.id);

      o.status = "expired";
    }

    const merchant =
      getMerchant(
        o.merchant_id
      );

    res.json({
      order:{
        ...formatOrder(o),

        merchantName:
          merchant?.name || ""
      }
    });

  }
);


/*
 * =====================================================
 * 收银台支付接口
 *
 * /api/checkout/订单号/pay
 *
 * 保留这个接口用于兼容旧 checkout.html。
 * =====================================================
 */

app.post(
  "/api/checkout/:orderNo/pay",
  (req,res) => {

    const o =
      db.prepare(`
        SELECT *
        FROM orders
        WHERE order_no=?
      `)
      .get(
        req.params.orderNo
      );

    if(!o){

      return res.status(404).json({
        message:"订单不存在"
      });

    }

    if(o.status === "paid"){

      return res.json({
        message:"订单已支付",
        order:formatOrder(o)
      });

    }

    if(
      String(
        req.body?.channel || "mock"
      ) !== "mock"
    ){

      return res.status(409).json({
        message:
          "该通道尚未连接官方/授权服务商"
      });

    }

    try{

      const updated =
        db.transaction(() => {

          const cur =
            db.prepare(`
              SELECT *
              FROM orders
              WHERE id=?
            `)
            .get(o.id);

          if(cur.status !== "pending"){

            throw new Error(
              "订单当前不可支付"
            );

          }

          const m =
            getMerchant(
              cur.merchant_id
            );

          if(!m){

            throw new Error(
              "商户不存在"
            );

          }

          const nb =
            m.balance_cents +
            cur.amount_cents;

          db.prepare(`
            UPDATE orders
            SET
              status='paid',
              paid_at=CURRENT_TIMESTAMP,
              updated_at=CURRENT_TIMESTAMP
            WHERE id=?
          `).run(cur.id);

          db.prepare(`
            UPDATE merchants
            SET balance_cents=?
            WHERE id=?
          `).run(
            nb,
            m.id
          );

          db.prepare(`
            INSERT INTO wallet_transactions(
              merchant_id,
              order_id,
              type,
              amount_cents,
              balance_after_cents,
              reference_no,
              remark
            )
            VALUES(?,?,?,?,?,?,?)
          `).run(
            m.id,
            cur.id,
            "income",
            cur.amount_cents,
            nb,
            "TX" +
              crypto
                .randomBytes(10)
                .toString("hex"),
            "Checkout Mock 支付入账"
          );

          return db
            .prepare(
              "SELECT * FROM orders WHERE id=?"
            )
            .get(cur.id);

        })();

      res.json({
        message:
          "支付成功（Mock 测试环境）",
        order:
          formatOrder(updated)
      });

    }catch(e){

      res.status(400).json({
        message:e.message
      });

    }

  }
);


/*
 * =====================================================
 * 管理员认证
 * =====================================================
 */

function adminAuth(req,res,next){

  const h =
    req.headers.authorization || "";

  const token =
    h.startsWith("Bearer ")
      ? h.slice(7)
      : "";

  if(!token){

    return res.status(401).json({
      message:"未登录"
    });

  }

  try{

    const u =
      jwt.verify(
        token,
        JWT_SECRET
      );

    if(u.role !== "admin"){
      throw new Error();
    }

    req.admin = u;

    next();

  }catch(e){

    return res.status(401).json({
      message:
        "管理员登录已过期"
    });

  }

}


function adminAudit(
  action,
  targetType,
  targetId,
  detail
){

  try{

    db.prepare(`
      INSERT INTO admin_audit_logs(
        admin_id,
        action,
        target_type,
        target_id,
        detail
      )
      VALUES(?,?,?,?,?)
    `).run(
      arguments[0] &&
        currentAdminId ||
        null,
      action,
      targetType,
      targetId,
      detail || ""
    );

  }catch(e){}

}


let currentAdminId = null;


app.post(
  "/api/admin/login",
  async(req,res)=>{

    const {
      email,
      password
    } = req.body || {};

    const a =
      db.prepare(`
        SELECT *
        FROM admin_users
        WHERE email=?
      `)
      .get(
        String(email || "")
          .trim()
          .toLowerCase()
      );

    if(
      !a ||
      a.status !== "active" ||
      !(await bcrypt.compare(
        password || "",
        a.password_hash
      ))
    ){

      return res.status(401).json({
        message:
          "管理员账号或密码错误"
      });

    }

    const token =
      jwt.sign(
        {
          id:a.id,
          email:a.email,
          role:"admin"
        },
        JWT_SECRET,
        {
          expiresIn:"8h"
        }
      );

    res.json({
      message:"登录成功",
      token,
      admin:{
        id:a.id,
        email:a.email,
        name:a.name
      }
    });

  }
);


app.get(
  "/api/admin/me",
  adminAuth,
  (req,res)=>{

    const a =
      db.prepare(`
        SELECT
          id,
          email,
          name,
          status
        FROM admin_users
        WHERE id=?
      `)
      .get(req.admin.id);

    res.json({
      admin:a
    });

  }
);


app.get(
  "/api/admin/stats",
  adminAuth,
  (req,res)=>{

    const merchants =
      db.prepare(
        "SELECT COUNT(*) c FROM merchants"
      ).get().c;

    const active =
      db.prepare(
        "SELECT COUNT(*) c FROM merchants WHERE status='active'"
      ).get().c;

    const orders =
      db.prepare(
        "SELECT COUNT(*) c FROM orders"
      ).get().c;

    const paid =
      db.prepare(`
        SELECT
          COALESCE(
            SUM(amount_cents),
            0
          ) s
        FROM orders
        WHERE status='paid'
      `).get().s;

    const pendingSettle =
      db.prepare(`
        SELECT
          COALESCE(
            SUM(amount),
            0
          ) s
        FROM settlements
        WHERE status='pending'
      `).get().s;

    const openRisk =
      db.prepare(`
        SELECT
          COUNT(*) c
        FROM merchant_risk_flags
        WHERE status='open'
      `).get().c;

    res.json({
      merchants,
      active,
      orders,
      totalPaid:
        (paid/100).toFixed(2),
      pendingSettlement:
        Number(
          pendingSettle
        ).toFixed(2),
      openRisk
    });

  }
);
app.get('/api/admin/merchants',adminAuth,(req,res)=>{
  const rows=db.prepare(`
    SELECT
      id,
      merchant_no,
      email,
      name,
      status,
      balance_cents,
      frozen_cents,
      created_at
    FROM merchants
    ORDER BY id DESC
    LIMIT 500
  `).all();

  res.json({
    items:rows.map(x=>({
      ...x,
      balance:(x.balance_cents/100).toFixed(2),
      frozen:(x.frozen_cents/100).toFixed(2)
    }))
  });
});


app.post('/api/admin/merchants/:id/status',adminAuth,(req,res)=>{

  const status=
    String(req.body?.status||'');

  if(
    ![
      'active',
      'suspended',
      'pending'
    ].includes(status)
  ){
    return res.status(400).json({
      message:'无效状态'
    });
  }

  const m=
    getMerchant(req.params.id);

  if(!m){
    return res.status(404).json({
      message:'商户不存在'
    });
  }

  db.prepare(
    'UPDATE merchants SET status=? WHERE id=?'
  ).run(
    status,
    m.id
  );

  db.prepare(`
    INSERT INTO admin_audit_logs(
      admin_id,
      action,
      target_type,
      target_id,
      detail
    )
    VALUES(?,?,?,?,?)
  `).run(
    req.admin.id,
    'merchant_status',
    'merchant',
    String(m.id),
    status
  );

  res.json({
    ok:true,
    status
  });

});


app.post('/api/admin/merchants/:id/risk',adminAuth,(req,res)=>{

  const m=
    getMerchant(req.params.id);

  if(!m){
    return res.status(404).json({
      message:'商户不存在'
    });
  }

  const level=
    [
      'low',
      'medium',
      'high'
    ].includes(req.body?.level)
      ? req.body.level
      : 'medium';

  const reason=
    String(
      req.body?.reason ||
      '管理员标记'
    );

  const info=
    db.prepare(`
      INSERT INTO merchant_risk_flags(
        merchant_id,
        level,
        reason
      )
      VALUES(?,?,?)
    `).run(
      m.id,
      level,
      reason
    );

  db.prepare(`
    INSERT INTO admin_audit_logs(
      admin_id,
      action,
      target_type,
      target_id,
      detail
    )
    VALUES(?,?,?,?,?)
  `).run(
    req.admin.id,
    'risk_flag',
    'merchant',
    String(m.id),
    level+':'+reason
  );

  res.json({
    ok:true,
    id:info.lastInsertRowid
  });

});


app.get('/api/admin/orders',adminAuth,(req,res)=>{

  const rows=
    db.prepare(`
      SELECT
        o.order_no,
        o.merchant_order_no,
        o.amount_cents,
        o.currency,
        o.channel,
        o.subject,
        o.status,
        o.created_at,
        o.paid_at,
        m.merchant_no,
        m.name merchant_name
      FROM orders o
      JOIN merchants m
        ON m.id=o.merchant_id
      ORDER BY o.id DESC
      LIMIT 500
    `).all();

  res.json({
    items:rows.map(x=>({
      ...x,
      amount:
        (x.amount_cents/100)
          .toFixed(2)
    }))
  });

});


app.get(
  '/api/admin/settlements',
  adminAuth,
  (req,res)=>
    res.json({
      items:
        db.prepare(`
          SELECT
            s.*,
            m.merchant_no,
            m.name merchant_name
          FROM settlements s
          JOIN merchants m
            ON m.id=s.merchant_id
          ORDER BY s.id DESC
          LIMIT 300
        `).all()
    })
);


app.post(
  '/api/admin/settlements/:settlementNo/review',
  adminAuth,
  (req,res)=>{

    const action=
      req.body?.action;

    const s=
      db.prepare(`
        SELECT *
        FROM settlements
        WHERE settlement_no=?
      `)
      .get(
        req.params.settlementNo
      );

    if(!s){
      return res.status(404).json({
        message:'结算单不存在'
      });
    }

    if(s.status!=='pending'){
      return res.status(400).json({
        message:
          '结算单不是待审核状态'
      });
    }

    const m=
      getMerchant(
        s.merchant_id
      );

    if(action==='approve'){

      db.prepare(`
        UPDATE settlements
        SET
          status='approved',
          processed_at=CURRENT_TIMESTAMP
        WHERE id=?
      `).run(s.id);

    }else if(action==='reject'){

      db.prepare(`
        UPDATE settlements
        SET
          status='rejected',
          processed_at=CURRENT_TIMESTAMP
        WHERE id=?
      `).run(s.id);

      db.prepare(`
        UPDATE merchants
        SET
          balance_cents=
            balance_cents+?
        WHERE id=?
      `).run(
        Math.round(
          s.amount*100
        ),
        m.id
      );

      db.prepare(`
        INSERT INTO wallet_transactions(
          merchant_id,
          type,
          amount_cents,
          balance_after_cents,
          reference_no,
          remark
        )
        VALUES(?,?,?,?,?,?)
      `).run(
        m.id,
        'settlement_reversal',
        Math.round(
          s.amount*100
        ),
        getMerchant(m.id)
          .balance_cents,
        'ADMREV'+s.id,
        '管理员拒绝结算，退回余额'
      );

    }else{

      return res.status(400).json({
        message:
          'action 只能是 approve 或 reject'
      });

    }

    db.prepare(`
      INSERT INTO admin_audit_logs(
        admin_id,
        action,
        target_type,
        target_id,
        detail
      )
      VALUES(?,?,?,?,?)
    `).run(
      req.admin.id,
      'settlement_review',
      'settlement',
      s.settlement_no,
      action
    );

    res.json({
      ok:true,
      status:
        action==='approve'
          ? 'approved'
          : 'rejected'
    });

  }
);


app.get(
  '/api/admin/risk-flags',
  adminAuth,
  (req,res)=>
    res.json({
      items:
        db.prepare(`
          SELECT
            r.*,
            m.merchant_no,
            m.name merchant_name
          FROM merchant_risk_flags r
          JOIN merchants m
            ON m.id=r.merchant_id
          ORDER BY r.id DESC
          LIMIT 300
        `).all()
    })
);


app.get(
  '/api/admin/audit-logs',
  adminAuth,
  (req,res)=>
    res.json({
      items:
        db.prepare(`
          SELECT *
          FROM admin_audit_logs
          ORDER BY id DESC
          LIMIT 300
        `).all()
    })
);


app.post(
  '/api/admin/reconciliation/run',
  adminAuth,
  (req,res)=>{

    const merchantCount=
      db.prepare(`
        SELECT COUNT(*) c
        FROM merchants
      `).get().c;

    const orderCount=
      db.prepare(`
        SELECT COUNT(*) c
        FROM orders
      `).get().c;

    const paid=
      db.prepare(`
        SELECT
          COALESCE(
            SUM(amount_cents),
            0
          ) s
        FROM orders
        WHERE status='paid'
      `).get().s / 100;

    const ledger=
      db.prepare(`
        SELECT
          COALESCE(
            SUM(net_amount),
            0
          ) s
        FROM wallet_ledger
        WHERE
          type='payment'
          OR type LIKE 'refund:%'
          OR type LIKE 'settlement%'
      `).get().s;

    const summary={
      merchantCount,
      orderCount,
      totalPaid:
        paid.toFixed(2),
      ledgerNet:
        Number(ledger).toFixed(2)
    };

    const no=
      'REC' +
      Date.now()
        .toString(36)
        .toUpperCase();

    db.prepare(`
      INSERT INTO reconciliation_runs(
        run_no,
        summary_json
      )
      VALUES(?,?)
    `).run(
      no,
      JSON.stringify(summary)
    );

    db.prepare(`
      INSERT INTO admin_audit_logs(
        admin_id,
        action,
        target_type,
        target_id,
        detail
      )
      VALUES(?,?,?,?,?)
    `).run(
      req.admin.id,
      'reconciliation',
      'run',
      no,
      JSON.stringify(summary)
    );

    res.json({
      ok:true,
      runNo:no,
      summary
    });

  }
);


// ===== V8 Payment Channel Management / Webhook scaffolding =====

function safeChannelConfig(channel) {

  let cfg={};

  try{
    cfg=
      JSON.parse(
        channel.config_json || '{}'
      );
  }catch{}

  const masked={};

  for(
    const [k,v]
    of Object.entries(cfg)
  ){

    const s=
      String(v ?? '');

    masked[k]=
      s.length>8
        ? `${s.slice(0,3)}***${s.slice(-3)}`
        : (
            s
              ? '***'
              : ''
          );
  }

  return {

    id:channel.id,

    channelCode:
      channel.channel_code,

    displayName:
      channel.display_name,

    enabled:
      !!channel.enabled,

    config:masked,

    webhookUrl:
      channel.webhook_url || '',

    hasCallbackSecret:
      !!channel.callback_secret,

    createdAt:
      channel.created_at,

    updatedAt:
      channel.updated_at

  };
}


const CHANNEL_META={

  mock:{
    name:'Mock 测试支付',
    fields:[]
  },

  wechat:{
    name:'微信支付',
    fields:[
      'mchId',
      'appId',
      'apiV3Key',
      'serialNo'
    ]
  },

  alipay:{
    name:'支付宝',
    fields:[
      'appId',
      'merchantPrivateKey',
      'alipayPublicKey'
    ]
  },

  bankcard:{
    name:'银行卡支付',
    fields:[
      'provider',
      'merchantId',
      'apiKey',
      'apiSecret'
    ]
  },

  usdt_trc20:{
    name:'USDT TRC20',
    fields:[
      'provider',
      'walletAddress',
      'apiKey',
      'apiSecret'
    ]
  }

};


app.get(
  '/api/payment-channels',
  auth,
  (req,res)=>{

    const merchant=
      db.prepare(`
        SELECT id
        FROM merchants
        WHERE id=?
      `)
      .get(req.user.id);

    if(!merchant){

      return res.status(404).json({
        error:'商户不存在'
      });

    }

    const rows=
      db.prepare(`
        SELECT *
        FROM payment_channels
        WHERE merchant_id=?
        ORDER BY id ASC
      `)
      .all(merchant.id);

    const existing=
      new Map(
        rows.map(
          r=>[
            r.channel_code,
            r
          ]
        )
      );

    const now=
      new Date().toISOString();

    const insert=
      db.prepare(`
        INSERT OR IGNORE INTO payment_channels
        (
          merchant_id,
          channel_code,
          display_name,
          enabled,
          config_json,
          webhook_url,
          callback_secret,
          created_at,
          updated_at
        )
        VALUES(
          ?,
          ?,
          ?,
          ?,
          '{}',
          '',
          '',
          ?,
          ?
        )
      `);

    for(
      const [code,meta]
      of Object.entries(
        CHANNEL_META
      )
    ){

      insert.run(
        merchant.id,
        code,
        meta.name,
        code==='mock'
          ? 1
          : 0,
        now,
        now
      );

    }

    const all=
      db.prepare(`
        SELECT *
        FROM payment_channels
        WHERE merchant_id=?
        ORDER BY id ASC
      `)
      .all(merchant.id);

    res.json({
      channels:
        all.map(
          safeChannelConfig
        )
    });

  }
);


app.put(
  '/api/payment-channels/:code',
  auth,
  (req,res)=>{

    const code=
      String(req.params.code);

    const meta=
      CHANNEL_META[code];

    if(!meta){

      return res.status(400).json({
        error:
          '不支持的支付通道'
      });

    }

    const merchant=
      db.prepare(`
        SELECT id
        FROM merchants
        WHERE id=?
      `)
      .get(req.user.id);

    if(!merchant){

      return res.status(404).json({
        error:'商户不存在'
      });

    }

    const body=
      req.body || {};

    const now=
      new Date().toISOString();

    const existing=
      db.prepare(`
        SELECT *
        FROM payment_channels
        WHERE merchant_id=?
          AND channel_code=?
      `)
      .get(
        merchant.id,
        code
      );

    let cfg={};

    try{

      cfg=
        existing
          ? JSON.parse(
              existing.config_json || '{}'
            )
          : {};

    }catch{}

    for(
      const key
      of meta.fields
    ){

      if(
        body.config &&
        Object.prototype
          .hasOwnProperty
          .call(
            body.config,
            key
          )
      ){

        const val=
          String(
            body.config[key] ?? ''
          ).trim();

        // Keep an existing secret when UI submits an intentionally masked value.
        if(
          !/^\*{3,}$/.test(val) &&
          !val.includes('***')
        ){
          cfg[key]=val;
        }

      }

    }

    const enabled=
      body.enabled
        ? 1
        : 0;

    const webhookUrl=
      String(
        body.webhookUrl || ''
      ).trim();

    let callbackSecret=
      existing?.callback_secret || '';

    if(
      body.callbackSecret &&
      String(
        body.callbackSecret
      ).trim()
    ){

      callbackSecret=
        String(
          body.callbackSecret
        ).trim();

    }

    db.prepare(`
      INSERT INTO payment_channels
      (
        merchant_id,
        channel_code,
        display_name,
        enabled,
        config_json,
        webhook_url,
        callback_secret,
        created_at,
        updated_at
      )
      VALUES(
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?
      )

      ON CONFLICT(
        merchant_id,
        channel_code
      )

      DO UPDATE SET
        enabled=excluded.enabled,
        config_json=excluded.config_json,
        webhook_url=excluded.webhook_url,
        callback_secret=excluded.callback_secret,
        updated_at=excluded.updated_at
    `).run(
      merchant.id,
      code,
      meta.name,
      enabled,
      JSON.stringify(cfg),
      webhookUrl,
      callbackSecret,
      existing?.created_at ||
        now,
      now
    );

    const row=
      db.prepare(`
        SELECT *
        FROM payment_channels
        WHERE merchant_id=?
          AND channel_code=?
      `)
      .get(
        merchant.id,
        code
      );

    res.json({
      ok:true,
      channel:
        safeChannelConfig(row)
    });

  }
);


app.post(
  '/api/payment-channels/:code/test',
  auth,
  (req,res)=>{

    const code=
      String(req.params.code);

    const meta=
      CHANNEL_META[code];

    if(!meta){

      return res.status(400).json({
        error:
          '不支持的支付通道'
      });

    }

    if(code==='mock'){

      return res.json({
        ok:true,
        message:
          'Mock 通道可用，测试订单可直接完成。'
      });

    }

    // Real providers must be wired to their official APIs before a live test is performed.
    res.json({
      ok:false,
      status:
        'pending_provider',

      message:
        `${meta.name} 尚未连接官方服务商 API。请先配置并通过官方/授权服务商审核，再进行真实连通性测试。`
    });

  }
);


app.get(
  '/api/webhooks/logs',
  auth,
  (req,res)=>{

    const merchant=
      db.prepare(`
        SELECT id
        FROM merchants
        WHERE id=?
      `)
      .get(req.user.id);

    if(!merchant){

      return res.status(404).json({
        error:'商户不存在'
      });

    }

    const rows=
      db.prepare(`
        SELECT *
        FROM webhook_logs
        WHERE merchant_id=?
        ORDER BY id DESC
        LIMIT 100
      `)
      .all(merchant.id);

    res.json({
      logs:rows
    });

  }
);


// Development helper: generate a deterministic preview signature.
// Production integrations should verify the provider's documented signature scheme.

app.post(
  '/api/webhooks/signature-preview',
  auth,
  (req,res)=>{

    const crypto =
      require('crypto');

    const payload=
      String(
        req.body?.payload || ''
      );

    const secret=
      String(
        req.body?.secret || ''
      );

    if(
      !payload ||
      !secret
    ){

      return res.status(400).json({
        error:
          'payload 和 secret 必填'
      });

    }

    const signature=
      crypto
        .createHmac(
          'sha256',
          secret
        )
        .update(payload)
        .digest('hex');

    res.json({
      algorithm:
        'HMAC-SHA256',
      signature
    });

  }
);


// ===== V9 Merchant API / HMAC Signature System =====

function v9Token(
  prefix,
  bytes=24
){

  return (
    `${prefix}_` +
    crypto
      .randomBytes(bytes)
      .toString('hex')
  );

}


function v9Sign(
  secret,
  timestamp,
  nonce,
  body
){

  return crypto
    .createHmac(
      'sha256',
      secret
    )
    .update(
      `${timestamp}.${nonce}.${body}`
    )
    .digest('hex');

}


function v9SafeEqualHex(
  a,
  b
){

  try{

    const x=
      Buffer.from(
        String(a),
        'hex'
      );

    const y=
      Buffer.from(
        String(b),
        'hex'
      );

    return (
      x.length===y.length &&
      crypto.timingSafeEqual(
        x,
        y
      )
    );

  }catch{

    return false;

  }

}


function requireMerchantApi(
  req,
  res,
  next
){

  const key=
    req.get(
      'X-PayHub-Key'
    );

  const ts=
    req.get(
      'X-PayHub-Timestamp'
    );

  const nonce=
    req.get(
      'X-PayHub-Nonce'
    );

  const sig=
    req.get(
      'X-PayHub-Signature'
    );

  const secret=
    req.get(
      'X-PayHub-Secret'
    );

  const merchant=
    db.prepare(`
      SELECT
        m.*,
        c.api_key,
        c.api_secret_hash,
        c.enabled api_enabled
      FROM merchant_api_credentials c
      JOIN merchants m
        ON m.id=c.merchant_id
      WHERE c.api_key=?
    `)
    .get(key);

  if(
    !merchant ||
    !merchant.api_enabled
  ){

    return res.status(401).json({
      code:
        'INVALID_API_KEY',
      message:
        'API Key 无效或已停用'
    });

  }

  if(
    !ts ||
    !nonce ||
    !sig ||
    !secret
  ){

    return res.status(401).json({
      code:
        'MISSING_SIGNATURE',
      message:
        '缺少签名请求头'
    });

  }

  const n=
    Number(ts);

  if(
    !Number.isFinite(n) ||
    Math.abs(
      Date.now()-n
    )>300000
  ){

    return res.status(401).json({
      code:
        'TIMESTAMP_EXPIRED',
      message:
        '请求时间戳已过期'
    });

  }

  if(
    !bcrypt.compareSync(
      secret,
      merchant.api_secret_hash
    )
  ){

    return res.status(401).json({
      code:
        'INVALID_API_SECRET',
      message:
        'API Secret 无效'
    });

  }

  const body=
    JSON.stringify(
      req.body || {}
    );

  const expected=
    v9Sign(
      secret,
      ts,
      nonce,
      body
    );

  if(
    !v9SafeEqualHex(
      expected,
      sig
    )
  ){

    return res.status(401).json({
      code:
        'INVALID_SIGNATURE',
      message:
        '签名验证失败'
    });

  }

  req.apiMerchant=
    merchant;

  req.apiRequestId=
    v9Token(
      'req',
      8
    );

  next();

}


app.get(
  '/api/developer/credentials',
  auth,
  (req,res)=>{

    const m=
      db.prepare(`
        SELECT id
        FROM merchants
        WHERE id=?
      `)
      .get(req.user.id);

    if(!m){

      return res.status(404).json({
        error:'商户不存在'
      });

    }

    const row=
      db.prepare(`
        SELECT *
        FROM merchant_api_credentials
        WHERE merchant_id=?
      `)
      .get(m.id);

    if(!row){

      const key=
        v9Token(
          'phk',
          18
        );

      const secret=
        v9Token(
          'phs',
          24
        );

      const now=
        new Date().toISOString();

      db.prepare(`
        INSERT INTO merchant_api_credentials(
          merchant_id,
          api_key,
          api_secret_hash,
          enabled,
          created_at,
          updated_at
        )
        VALUES(?,?,?,?,?,?)
      `).run(
        m.id,
        key,
        bcrypt.hashSync(
          secret,
          12
        ),
        1,
        now,
        now
      );

      return res.json({
        apiKey:key,
        apiSecret:secret,
        enabled:true,
        generated:true,
        warning:
          'API Secret 只显示这一次，请立即保存。'
      });

    }

    res.json({
      apiKey:
        row.api_key,

      enabled:
        !!row.enabled,

      generated:false,

      warning:
        'API Secret 已哈希存储，无法再次查看。'
    });

  }
);


app.post(
  '/api/developer/credentials/rotate',
  auth,
  (req,res)=>{

    const m=
      db.prepare(`
        SELECT id
        FROM merchants
        WHERE id=?
      `)
      .get(req.user.id);

    if(!m){

      return res.status(404).json({
        error:'商户不存在'
      });

    }

    const key=
      v9Token(
        'phk',
        18
      );

    const secret=
      v9Token(
        'phs',
        24
      );

    const now=
      new Date().toISOString();

    db.prepare(`
      INSERT INTO merchant_api_credentials(
        merchant_id,
        api_key,
        api_secret_hash,
        enabled,
        created_at,
        updated_at
      )
      VALUES(?,?,?,?,?,?)

      ON CONFLICT(merchant_id)
      DO UPDATE SET
        api_key=excluded.api_key,
        api_secret_hash=excluded.api_secret_hash,
        enabled=1,
        updated_at=excluded.updated_at
    `).run(
      m.id,
      key,
      bcrypt.hashSync(
        secret,
        12
      ),
      1,
      now,
      now
    );

    res.json({
      apiKey:key,
      apiSecret:secret,
      warning:
        '旧凭证已失效，Secret 只显示这一次。'
    });

  }
);


app.post(
  '/api/developer/credentials/toggle',
  auth,
  (req,res)=>{

    const m=
      db.prepare(`
        SELECT id
        FROM merchants
        WHERE id=?
      `)
      .get(req.user.id);

    if(!m){

      return res.status(404).json({
        error:'商户不存在'
      });

    }

    const enabled=
      req.body?.enabled
        ? 1
        : 0;

    db.prepare(`
      UPDATE merchant_api_credentials
      SET
        enabled=?,
        updated_at=?
      WHERE merchant_id=?
    `).run(
      enabled,
      new Date().toISOString(),
      m.id
    );

    res.json({
      ok:true,
      enabled:!!enabled
    });

  }
);


app.post(
  '/api/v1/orders',
  requireMerchantApi,
  (req,res)=>{

    const {
      amount,
      subject,
      returnUrl='',
      notifyUrl='',
      channel='mock'
    }=req.body||{};

    const num=
      Number(amount);

    if(
      !Number.isFinite(num) ||
      num<=0
    ){

      return res.status(400).json({
        code:
          'INVALID_AMOUNT',
        message:
          'amount 必须大于 0'
      });

    }

    if(!subject){

      return res.status(400).json({
        code:
          'INVALID_SUBJECT',
        message:
          'subject 必填'
      });

    }

    const orderNo=
      'PH' +
      Date.now() +
      Math.floor(
        Math.random()*1000
      );

    const now=
      new Date().toISOString();

    const token=
      v9Token(
        'ct',
        16
      );

    const base=
      `${req.protocol}://${req.get('host')}`;

    const amountCents=
      Math.round(
        num*100
      );

    db.prepare(`
      INSERT INTO orders(
        merchant_id,
        order_no,
        merchant_order_no,
        amount_cents,
        currency,
        channel,
        subject,
        pay_url,
        expired_at,
        payment_method,
        checkout_token,
        return_url,
        notify_url,
        created_at,
        updated_at
      )
      VALUES(
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?
      )
    `).run(
      req.apiMerchant.id,
      orderNo,
      orderNo,
      amountCents,
      'CNY',
      channel,
      String(subject),
      `${base}/checkout?order=${encodeURIComponent(orderNo)}&token=${encodeURIComponent(token)}`,
      new Date(
        Date.now()+30*60*1000
      ).toISOString(),
      channel,
      token,
      returnUrl,
      notifyUrl,
      now,
      now
    );

    res.status(201).json({
      code:'OK',
      requestId:
        req.apiRequestId,

      order:{
        orderNo,
        amount:num,
        currency:'CNY',
        status:'pending',
        subject:String(subject),
        channel,

        checkoutUrl:
          `${base}/checkout?order=${encodeURIComponent(orderNo)}&token=${encodeURIComponent(token)}`,

        returnUrl,
        notifyUrl,
        createdAt:now
      }
    });

  }
);
app.get(
  '/api/v1/orders/:orderNo',
  requireMerchantApi,
  (req,res)=>{

    const order =
      db.prepare(`
        SELECT *
        FROM orders
        WHERE order_no=?
          AND merchant_id=?
      `)
      .get(
        req.params.orderNo,
        req.apiMerchant.id
      );

    if(!order){

      return res.status(404).json({
        code:'ORDER_NOT_FOUND',
        message:'订单不存在'
      });

    }

    res.json({
      code:'OK',
      requestId:
        req.apiRequestId,

      order:{
        orderNo:
          order.order_no,

        merchantOrderNo:
          order.merchant_order_no,

        amount:
          order.amount_cents / 100,

        currency:
          order.currency,

        status:
          order.status,

        subject:
          order.subject,

        channel:
          order.channel,

        checkoutUrl:
          order.pay_url,

        returnUrl:
          order.return_url || '',

        notifyUrl:
          order.notify_url || '',

        createdAt:
          order.created_at,

        paidAt:
          order.paid_at
      }
    });

  }
);


// =====================================================
// V10 Payment Order Chain
// =====================================================

function v10MerchantByOrder(orderNo){

  return db.prepare(`
    SELECT
      o.*,
      m.name merchant_name,
      m.merchant_no
    FROM orders o
    JOIN merchants m
      ON m.id=o.merchant_id
    WHERE o.order_no=?
  `).get(
    String(orderNo || '').trim()
  );

}


function v10MarkPaid(orderNo){

  return db.transaction(()=>{

    const order =
      v10MerchantByOrder(
        orderNo
      );

    if(!order){

      throw new Error(
        '订单不存在'
      );

    }

    if(order.status === 'paid'){
      return order;
    }

    if(order.status !== 'pending'){

      throw new Error(
        '订单当前不可支付'
      );

    }

    if(
      order.expired_at &&
      new Date(
        order.expired_at
      ).getTime() < Date.now()
    ){

      db.prepare(`
        UPDATE orders
        SET
          status='expired',
          updated_at=CURRENT_TIMESTAMP
        WHERE id=?
          AND status='pending'
      `).run(
        order.id
      );

      throw new Error(
        '订单已过期'
      );

    }

    const merchant =
      getMerchant(
        order.merchant_id
      );

    if(!merchant){

      throw new Error(
        '商户不存在'
      );

    }

    const oldBalance =
      Number(
        merchant.balance_cents || 0
      );

    const newBalance =
      oldBalance +
      Number(
        order.amount_cents || 0
      );

    /*
     * 1. 更新订单状态
     */
    db.prepare(`
      UPDATE orders
      SET
        status='paid',
        paid_at=CURRENT_TIMESTAMP,
        updated_at=CURRENT_TIMESTAMP
      WHERE id=?
        AND status='pending'
    `).run(
      order.id
    );

    /*
     * 2. 商户钱包入账
     */
    db.prepare(`
      UPDATE merchants
      SET
        balance_cents=?
      WHERE id=?
    `).run(
      newBalance,
      merchant.id
    );

    /*
     * 3. 写钱包流水
     */
    const referenceNo =
      'TX' +
      crypto
        .randomBytes(12)
        .toString('hex');

    db.prepare(`
      INSERT INTO wallet_transactions(
        merchant_id,
        order_id,
        type,
        amount_cents,
        balance_after_cents,
        reference_no,
        remark
      )
      VALUES(?,?,?,?,?,?,?)
    `).run(
      merchant.id,
      order.id,
      'income',
      order.amount_cents,
      newBalance,
      referenceNo,
      'V10 Checkout 支付入账'
    );

    /*
     * 4. 写 Webhook 队列
     */
    const payload =
      JSON.stringify({
        event:'payment.paid',

        orderNo:
          order.order_no,

        merchantOrderNo:
          order.merchant_order_no,

        amount:
          order.amount_cents / 100,

        currency:
          order.currency,

        status:'paid',

        paidAt:
          new Date().toISOString()
      });

    const callbackSecret =
      db.prepare(`
        SELECT callback_secret
        FROM payment_channels
        WHERE merchant_id=?
          AND channel_code=?
      `).get(
        merchant.id,
        order.channel
      );

    const webhookSecret =
      callbackSecret?.callback_secret ||
      '';

    const signature =
      webhookSecret
        ? signPayload(
            webhookSecret,
            payload
          )
        : '';

    if(order.notify_url){

      db.prepare(`
        INSERT INTO webhook_deliveries(
          merchant_id,
          order_no,
          event_type,
          target_url,
          payload,
          signature,
          status,
          attempts,
          created_at,
          updated_at
        )
        VALUES(?,?,?,?,?,?,?,0,?,?)
      `).run(
        merchant.id,
        order.order_no,
        'payment.paid',
        order.notify_url,
        payload,
        signature,
        'pending',
        new Date().toISOString(),
        new Date().toISOString()
      );

    }

    return v10MerchantByOrder(
      order.order_no
    );

  })();

}


/*
 * =====================================================
 * V10 支付接口
 *
 * checkout.html 最终调用：
 *
 * POST
 * /api/checkout/:orderNo/pay-v10
 *
 * 注意这里的 :orderNo 必须和数据库
 * orders.order_no 完全一致。
 * =====================================================
 */

app.post(
  '/api/checkout/:orderNo/pay-v10',
  (req,res)=>{

    const orderNoParam =
      String(
        req.params.orderNo || ''
      ).trim();

    if(!orderNoParam){

      return res.status(404).json({
        ok:false,
        error:'订单不存在',
        message:'订单号为空'
      });

    }

    /*
     * 先查询订单。
     *
     * 不要直接进入支付逻辑。
     *
     * 这样如果订单号错误，
     * 会明确返回订单不存在。
     */
    const order =
      v10MerchantByOrder(
        orderNoParam
      );

    if(!order){

      console.error(
        '[PAY-V10] ORDER NOT FOUND:',
        orderNoParam
      );

      return res.status(404).json({
        ok:false,
        error:'订单不存在',
        message:'订单不存在'
      });

    }

    /*
     * 已经支付成功
     */
    if(order.status === 'paid'){

      return res.json({
        ok:true,
        status:'paid',
        order:formatOrder(order),
        message:'订单已经支付成功'
      });

    }

    /*
     * 订单过期
     */
    if(
      order.status === 'pending' &&
      order.expired_at &&
      new Date(
        order.expired_at
      ).getTime() < Date.now()
    ){

      db.prepare(`
        UPDATE orders
        SET
          status='expired',
          updated_at=CURRENT_TIMESTAMP
        WHERE id=?
          AND status='pending'
      `).run(
        order.id
      );

      return res.status(400).json({
        ok:false,
        status:'expired',
        message:'订单已过期'
      });

    }

    /*
     * 只允许 pending 订单支付
     */
    if(order.status !== 'pending'){

      return res.status(400).json({
        ok:false,
        status:order.status,
        message:
          '订单当前状态不可支付'
      });

    }

    /*
     * 默认 Mock。
     *
     * 真实支付通道必须连接官方/
     * 授权服务商 API。
     *
     * 这里不能伪造真实支付成功。
     */
    const channel =
      String(
        req.body?.channel ||
        order.payment_method ||
        order.channel ||
        'mock'
      );

    if(channel !== 'mock'){

      return res.status(409).json({
        ok:false,
        status:'provider_pending',
        message:
          '该支付通道尚未连接官方/授权服务商，当前不能伪造真实支付成功。'
      });

    }

    try{

      const paid =
        v10MarkPaid(
          order.order_no
        );

      res.json({
        ok:true,
        status:'paid',
        order:
          formatOrder(paid),

        message:
          'Mock 支付成功，已进入钱包入账和 Webhook 队列。'
      });

    }catch(e){

      console.error(
        '[PAY-V10] ERROR:',
        e
      );

      res.status(400).json({
        ok:false,
        error:
          e.message ||
          '支付失败',

        message:
          e.message ||
          '支付失败'
      });

    }

  }
);


/*
 * =====================================================
 * V10 Webhook 重试队列
 * =====================================================
 */

function processWebhookDelivery(id){

  const row =
    db.prepare(`
      SELECT *
      FROM webhook_deliveries
      WHERE id=?
    `).get(id);

  if(!row){
    return;
  }

  if(!row.target_url){
    return;
  }

  /*
   * 这里保留队列状态。
   *
   * 真正生产环境应该使用官方/
   * 授权服务商或者可靠 HTTP worker。
   */

  db.prepare(`
    UPDATE webhook_deliveries
    SET
      attempts=attempts+1,
      updated_at=?
    WHERE id=?
  `).run(
    new Date().toISOString(),
    id
  );

}


app.get(
  '/api/webhooks/deliveries',
  auth,
  (req,res)=>{

    const rows =
      db.prepare(`
        SELECT *
        FROM webhook_deliveries
        WHERE merchant_id=?
        ORDER BY id DESC
        LIMIT 100
      `)
      .all(
        req.user.id
      );

    res.json({
      items:rows
    });

  }
);


/*
 * =====================================================
 * 钱包
 * =====================================================
 */

app.get(
  '/api/wallet/transactions',
  auth,
  (req,res)=>{

    const rows =
      db.prepare(`
        SELECT *
        FROM wallet_transactions
        WHERE merchant_id=?
        ORDER BY id DESC
        LIMIT 200
      `)
      .all(
        req.user.id
      );

    res.json({
      items:rows.map(x=>({
        ...x,

        amount:
          (x.amount_cents/100)
            .toFixed(2),

        balanceAfter:
          (x.balance_after_cents/100)
            .toFixed(2)
      }))
    });

  }
);


app.get(
  '/api/wallet/balance',
  auth,
  (req,res)=>{

    const m =
      getMerchant(
        req.user.id
      );

    if(!m){

      return res.status(404).json({
        message:'商户不存在'
      });

    }

    res.json({
      balance:
        (m.balance_cents/100)
          .toFixed(2),

      frozen:
        (m.frozen_cents/100)
          .toFixed(2)
    });

  }
);


/*
 * =====================================================
 * 商户结算申请
 * =====================================================
 */

app.post(
  '/api/settlements',
  auth,
  (req,res)=>{

    try{

      const amount =
        Number(
          req.body?.amount
        );

      if(
        !Number.isFinite(amount) ||
        amount<=0
      ){

        return res.status(400).json({
          message:
            '结算金额必须大于 0'
        });

      }

      const merchant =
        getMerchant(
          req.user.id
        );

      if(!merchant){

        return res.status(404).json({
          message:'商户不存在'
        });

      }

      const amountCents =
        Math.round(
          amount*100
        );

      if(
        amountCents >
        merchant.balance_cents
      ){

        return res.status(400).json({
          message:
            '余额不足'
        });

      }

      const settlementNo =
        'ST' +
        Date.now() +
        crypto
          .randomBytes(3)
          .toString('hex')
          .toUpperCase();

      const netAmount =
        amount;

      const now =
        new Date().toISOString();

      db.transaction(()=>{

        db.prepare(`
          UPDATE merchants
          SET
            balance_cents=
              balance_cents-?,
            frozen_cents=
              frozen_cents+?
          WHERE id=?
        `).run(
          amountCents,
          amountCents,
          merchant.id
        );

        db.prepare(`
          INSERT INTO settlements(
            merchant_id,
            settlement_no,
            amount,
            fee,
            net_amount,
            status,
            bank_name,
            account_name,
            account_no_masked,
            remark
          )
          VALUES(
            ?,
            ?,
            ?,
            0,
            ?,
            'pending',
            ?,
            ?,
            ?,
            ?
          )
        `).run(
          merchant.id,
          settlementNo,
          amount,
          netAmount,
          req.body?.bankName || '',
          req.body?.accountName || '',
          req.body?.accountNoMasked || '',
          req.body?.remark || ''
        );

      })();

      res.json({
        ok:true,
        settlementNo,
        amount,
        netAmount
      });

    }catch(e){

      res.status(400).json({
        message:
          e.message ||
          '提交结算失败'
      });

    }

  }
);
// =========================
// 管理后台 / 商户后台剩余接口
// =========================

app.get('/api/merchant/profile',auth,(req,res)=>{
  const m=db.prepare(`
    SELECT id,merchant_no,email,name,status,balance_cents,frozen_cents,created_at
    FROM merchants
    WHERE id=?
  `).get(req.user.id);

  if(!m)return res.status(404).json({error:'商户不存在'});

  res.json({
    ...m,
    balance:(Number(m.balance_cents||0)/100).toFixed(2),
    frozen:(Number(m.frozen_cents||0)/100).toFixed(2)
  });
});

app.put('/api/merchant/profile',auth,(req,res)=>{
  const name=String(req.body?.name||'').trim();
  const email=String(req.body?.email||'').trim();

  db.prepare(`
    UPDATE merchants
    SET name=?,email=?
    WHERE id=?
  `).run(name,email,req.user.id);

  res.json({ok:true});
});

app.post('/api/merchant/api-key/regenerate',auth,(req,res)=>{
  const apiKey='pk_'+crypto.randomBytes(24).toString('hex');
  const apiSecret='sk_'+crypto.randomBytes(32).toString('hex');

  db.prepare(`
    UPDATE merchants
    SET api_key=?,api_secret=?
    WHERE id=?
  `).run(apiKey,apiSecret,req.user.id);

  res.json({
    ok:true,
    apiKey,
    apiSecret
  });
});

app.get('/api/merchant/api-key',auth,(req,res)=>{
  const m=db.prepare(`
    SELECT api_key,api_secret
    FROM merchants
    WHERE id=?
  `).get(req.user.id);

  if(!m)return res.status(404).json({error:'商户不存在'});

  res.json(m);
});

app.get('/api/merchant/settlements',auth,(req,res)=>{
  const rows=db.prepare(`
    SELECT *
    FROM settlements
    WHERE merchant_id=?
    ORDER BY id DESC
    LIMIT 100
  `).all(req.user.id);

  res.json({settlements:rows});
});

app.get('/api/merchant/refunds',auth,(req,res)=>{
  const rows=db.prepare(`
    SELECT *
    FROM refunds
    WHERE merchant_id=?
    ORDER BY id DESC
    LIMIT 100
  `).all(req.user.id);

  res.json({refunds:rows});
});

app.get('/api/merchant/payment-channels',auth,(req,res)=>{
  const rows=db.prepare(`
    SELECT *
    FROM payment_channels
    WHERE merchant_id=?
    ORDER BY id ASC
  `).all(req.user.id);

  res.json({channels:rows});
});

app.get('/api/merchant/webhooks',auth,(req,res)=>{
  const rows=db.prepare(`
    SELECT *
    FROM webhook_deliveries
    WHERE merchant_id=?
    ORDER BY id DESC
    LIMIT 100
  `).all(req.user.id);

  res.json({webhooks:rows});
});

app.post('/api/merchant/webhooks/retry/:id',auth,(req,res)=>{
  const row=db.prepare(`
    SELECT *
    FROM webhook_deliveries
    WHERE id=? AND merchant_id=?
  `).get(req.params.id,req.user.id);

  if(!row){
    return res.status(404).json({
      error:'Webhook 记录不存在'
    });
  }

  db.prepare(`
    UPDATE webhook_deliveries
    SET status='pending',
        next_retry_at=NULL,
        updated_at=?
    WHERE id=?
  `).run(new Date().toISOString(),row.id);

  res.json({
    ok:true,
    message:'已重新加入发送队列。'
  });
});

app.get('/api/merchant/settings',auth,(req,res)=>{
  const m=db.prepare(`
    SELECT *
    FROM merchants
    WHERE id=?
  `).get(req.user.id);

  if(!m)return res.status(404).json({
    error:'商户不存在'
  });

  res.json({
    merchant_no:m.merchant_no,
    name:m.name,
    email:m.email,
    status:m.status
  });
});

app.put('/api/merchant/settings',auth,(req,res)=>{
  const name=String(req.body?.name||'').trim();
  const email=String(req.body?.email||'').trim();

  db.prepare(`
    UPDATE merchants
    SET name=?,email=?
    WHERE id=?
  `).run(name,email,req.user.id);

  res.json({ok:true});
});

app.get('/api/merchant/stats',auth,(req,res)=>{
  const merchantId=req.user.id;

  const total=db.prepare(`
    SELECT COUNT(*) c
    FROM orders
    WHERE merchant_id=?
  `).get(merchantId).c;

  const paid=db.prepare(`
    SELECT COUNT(*) c,COALESCE(SUM(amount_cents),0) amount
    FROM orders
    WHERE merchant_id=? AND status='paid'
  `).get(merchantId);

  const pending=db.prepare(`
    SELECT COUNT(*) c
    FROM orders
    WHERE merchant_id=? AND status='pending'
  `).get(merchantId).c;

  res.json({
    totalOrders:Number(total||0),
    paidOrders:Number(paid?.c||0),
    paidAmount:Number(paid?.amount||0)/100,
    pendingOrders:Number(pending||0)
  });
});

app.post('/api/merchant/refunds',auth,(req,res)=>{
  const orderNo=String(req.body?.orderNo||'').trim();
  const reason=String(req.body?.reason||'').trim();

  const order=db.prepare(`
    SELECT *
    FROM orders
    WHERE merchant_id=? AND order_no=?
  `).get(req.user.id,orderNo);

  if(!order){
    return res.status(404).json({
      error:'订单不存在'
    });
  }

  if(order.status!=='paid'){
    return res.status(400).json({
      error:'只有已支付订单才能退款'
    });
  }

  const refundNo='RF'+Date.now()+crypto.randomBytes(3).toString('hex');

  db.prepare(`
    INSERT INTO refunds(
      merchant_id,
      order_no,
      refund_no,
      refund_amount,
      fee,
      status,
      reason
    )
    VALUES(?,?,?,?,?,?,?)
  `).run(
    req.user.id,
    orderNo,
    refundNo,
    Number(order.amount_cents)/100,
    0,
    'pending',
    reason
  );

  res.json({
    ok:true,
    refundNo
  });
});

app.get('/api/merchant/refunds/:refundNo',auth,(req,res)=>{
  const row=db.prepare(`
    SELECT *
    FROM refunds
    WHERE merchant_id=? AND refund_no=?
  `).get(req.user.id,req.params.refundNo);

  if(!row){
    return res.status(404).json({
      error:'退款单不存在'
    });
  }

  res.json(row);
});

app.post('/api/merchant/settlements',auth,(req,res)=>{
  const amount=Number(req.body?.amount||0);

  if(!Number.isFinite(amount)||amount<=0){
    return res.status(400).json({
      error:'结算金额无效'
    });
  }

  const m=db.prepare(`
    SELECT balance_cents
    FROM merchants
    WHERE id=?
  `).get(req.user.id);

  if(!m){
    return res.status(404).json({
      error:'商户不存在'
    });
  }

  const balance=Number(m.balance_cents||0)/100;

  if(amount>balance){
    return res.status(400).json({
      error:'余额不足'
    });
  }

  const settlementNo='ST'+Date.now()+crypto.randomBytes(3).toString('hex');
  const fee=Math.round(amount*0.005*100)/100;

  db.prepare(`
    INSERT INTO settlements(
      merchant_id,
      settlement_no,
      amount,
      fee,
      status
    )
    VALUES(?,?,?,?,?)
  `).run(
    req.user.id,
    settlementNo,
    amount,
    fee,
    'pending'
  );

  res.json({
    ok:true,
    settlementNo,
    amount,
    fee
  });
});

app.get('/api/merchant/settlements/:settlementNo',auth,(req,res)=>{
  const row=db.prepare(`
    SELECT *
    FROM settlements
    WHERE merchant_id=? AND settlement_no=?
  `).get(req.user.id,req.params.settlementNo);

  if(!row){
    return res.status(404).json({
      error:'结算单不存在'
    });
  }

  res.json(row);
});

app.post('/api/merchant/payment-channels/:code/test',auth,(req,res)=>{
  const code=String(req.params.code||'').trim();

  const row=db.prepare(`
    SELECT *
    FROM payment_channels
    WHERE merchant_id=? AND channel_code=?
  `).get(req.user.id,code);

  if(!row){
    return res.status(404).json({
      error:'支付通道不存在'
    });
  }

  res.json({
    ok:true,
    channel:code,
    status:'available'
  });
});

app.post('/api/merchant/webhooks/test',auth,(req,res)=>{
  res.json({
    ok:true,
    message:'Webhook 测试请求已创建'
  });
});

app.get('/api/merchant/health',auth,(req,res)=>{
  res.json({
    ok:true,
    status:'healthy',
    time:new Date().toISOString()
  });
});

app.get('/api/merchant/dashboard',auth,(req,res)=>{
  const merchantId=req.user.id;

  const balance=db.prepare(`
    SELECT balance_cents,frozen_cents
    FROM merchants
    WHERE id=?
  `).get(merchantId);

  const orders=db.prepare(`
    SELECT COUNT(*) c
    FROM orders
    WHERE merchant_id=?
  `).get(merchantId).c;

  const paid=db.prepare(`
    SELECT COALESCE(SUM(amount_cents),0) amount
    FROM orders
    WHERE merchant_id=? AND status='paid'
  `).get(merchantId).amount;

  res.json({
    balance:Number(balance?.balance_cents||0)/100,
    frozen:Number(balance?.frozen_cents||0)/100,
    orders:Number(orders||0),
    paid:Number(paid||0)/100
  });
});

app.post('/api/merchant/orders/:orderNo/cancel',auth,(req,res)=>{
  const order=db.prepare(`
    SELECT *
    FROM orders
    WHERE merchant_id=? AND order_no=?
  `).get(req.user.id,req.params.orderNo);

  if(!order){
    return res.status(404).json({
      error:'订单不存在'
    });
  }

  if(order.status!=='pending'){
    return res.status(400).json({
      error:'当前订单不能取消'
    });
  }

  db.prepare(`
    UPDATE orders
    SET status='cancelled',
        updated_at=?
    WHERE id=?
  `).run(new Date().toISOString(),order.id);

  res.json({
    ok:true,
    status:'cancelled'
  });
});

app.post('/api/merchant/orders/:orderNo/close',auth,(req,res)=>{
  const order=db.prepare(`
    SELECT *
    FROM orders
    WHERE merchant_id=? AND order_no=?
  `).get(req.user.id,req.params.orderNo);

  if(!order){
    return res.status(404).json({
      error:'订单不存在'
    });
  }

  db.prepare(`
    UPDATE orders
    SET status='closed',
        updated_at=?
    WHERE id=?
  `).run(new Date().toISOString(),order.id);

  res.json({
    ok:true,
    status:'closed'
  });
});

app.post('/api/merchant/orders/:orderNo/refund',auth,(req,res)=>{
  const order=db.prepare(`
    SELECT *
    FROM orders
    WHERE merchant_id=? AND order_no=?
  `).get(req.user.id,req.params.orderNo);

  if(!order){
    return res.status(404).json({
      error:'订单不存在'
    });
  }

  if(order.status!=='paid'){
    return res.status(400).json({
      error:'订单未支付'
    });
  }

  const refundNo='RF'+Date.now()+crypto.randomBytes(3).toString('hex');

  db.prepare(`
    INSERT INTO refunds(
      merchant_id,
      order_no,
      refund_no,
      refund_amount,
      fee,
      status,
      reason
    )
    VALUES(?,?,?,?,?,?,?)
  `).run(
    req.user.id,
    order.order_no,
    refundNo,
    Number(order.amount_cents)/100,
    0,
    'pending',
    String(req.body?.reason||'商户申请退款')
  );

  res.json({
    ok:true,
    refundNo
  });
});

app.get('/api/merchant/orders/:orderNo',auth,(req,res)=>{
  const order=db.prepare(`
    SELECT *
    FROM orders
    WHERE merchant_id=? AND order_no=?
  `).get(req.user.id,req.params.orderNo);

  if(!order){
    return res.status(404).json({
      error:'订单不存在'
    });
  }

  res.json({
    order:formatOrder(order)
  });
});

app.get('/api/merchant/orders',auth,(req,res)=>{
  const rows=db.prepare(`
    SELECT *
    FROM orders
    WHERE merchant_id=?
    ORDER BY id DESC
    LIMIT 500
  `).all(req.user.id);

  res.json({
    orders:rows.map(formatOrder)
  });
});

app.get('/api/merchant/orders/export',auth,(req,res)=>{
  const rows=db.prepare(`
    SELECT *
    FROM orders
    WHERE merchant_id=?
    ORDER BY id DESC
  `).all(req.user.id);

  const header=[
    'order_no',
    'merchant_order_no',
    'amount',
    'currency',
    'subject',
    'status',
    'created_at',
    'paid_at'
  ];

  const csv=[
    header.join(','),
    ...rows.map(o=>[
      o.order_no,
      o.merchant_order_no||'',
      Number(o.amount_cents||0)/100,
      o.currency||'',
      o.subject||'',
      o.status||'',
      o.created_at||'',
      o.paid_at||''
    ].map(v=>`"${String(v).replace(/"/g,'""')}"`).join(','))
  ].join('\n');

  res.setHeader('Content-Type','text/csv; charset=utf-8');
  res.send('\ufeff'+csv);
});

app.get('/api/merchant/notifications',auth,(req,res)=>{
  res.json({
    notifications:[]
  });
});

app.post('/api/merchant/notifications/read',auth,(req,res)=>{
  res.json({
    ok:true
  });
});

app.get('/api/merchant/notifications/unread-count',auth,(req,res)=>{
  res.json({
    count:0
  });
});

app.post('/api/merchant/notifications/clear',auth,(req,res)=>{
  res.json({
    ok:true
  });
});

app.get('/api/merchant/logs',auth,(req,res)=>{
  res.json({
    logs:[]
  });
});

app.get('/api/merchant/logs/:id',auth,(req,res)=>{
  res.status(404).json({
    error:'日志不存在'
  });
});

app.get('/api/merchant/system-info',auth,(req,res)=>{
  res.json({
    node:process.version,
    platform:process.platform,
    uptime:process.uptime()
  });
});

app.get('/api/merchant/version',auth,(req,res)=>{
  res.json({
    version:'12.0.0'
  });
});

app.get('/api/merchant/ping',auth,(req,res)=>{
  res.json({
    ok:true,
    pong:true,
    time:new Date().toISOString()
  });
});


// =========================
// 前端页面
// =========================

app.use(express.static(path.join(__dirname,"public")));

app.get("/checkout/:orderNo",(req,res)=>{
  res.sendFile(
    path.join(__dirname,"public","checkout.html")
  );
});

app.get("/dashboard",(req,res)=>{
  res.sendFile(
    path.join(__dirname,"public","dashboard.html")
  );
});

app.get("/admin",(req,res)=>{
  res.sendFile(
    path.join(__dirname,"public","admin.html")
  );
});

app.get("*",(req,res)=>{
  res.sendFile(
    path.join(__dirname,"public","index.html")
  );
});


// =========================
// 启动服务器
// =========================

app.listen(PORT,()=>{
  console.log(
    `PayHub running on http://localhost:${PORT}`
  );
});
