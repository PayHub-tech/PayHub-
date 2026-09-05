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
]) { try { db.exec(sql); } catch (e) { if (!String(e.message).includes('duplicate column name')) throw e; } }

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
const adminExists = db.prepare('SELECT id FROM admin_users WHERE email=?').get(ADMIN_EMAIL);
if (!adminExists) {
  db.prepare('INSERT INTO admin_users(email,password_hash,name) VALUES(?,?,?)')
    .run(ADMIN_EMAIL, bcrypt.hashSync(ADMIN_PASSWORD, 12), 'PayHub Admin');
}


db.exec(`
CREATE TABLE IF NOT EXISTS payment_channels (
 id INTEGER PRIMARY KEY AUTOINCREMENT, merchant_id INTEGER NOT NULL, channel_code TEXT NOT NULL,
 display_name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0, config_json TEXT NOT NULL DEFAULT '{}',
 webhook_url TEXT NOT NULL DEFAULT '', callback_secret TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(merchant_id,channel_code),
 FOREIGN KEY(merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS merchant_api_credentials (
 id INTEGER PRIMARY KEY AUTOINCREMENT, merchant_id INTEGER NOT NULL UNIQUE, api_key TEXT NOT NULL UNIQUE,
 api_secret_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 FOREIGN KEY(merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS api_request_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, merchant_id INTEGER, api_key TEXT, method TEXT, path TEXT,
 order_no TEXT, request_id TEXT, signature_valid INTEGER NOT NULL DEFAULT 0, status_code INTEGER, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wallet_ledger (
 id INTEGER PRIMARY KEY AUTOINCREMENT, merchant_id INTEGER NOT NULL, order_no TEXT, type TEXT NOT NULL,
 amount REAL NOT NULL, fee REAL NOT NULL DEFAULT 0, net_amount REAL NOT NULL,
 balance_before REAL NOT NULL DEFAULT 0, balance_after REAL NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'posted', remark TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
 UNIQUE(merchant_id,order_no,type), FOREIGN KEY(merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
 id INTEGER PRIMARY KEY AUTOINCREMENT, merchant_id INTEGER NOT NULL, order_no TEXT NOT NULL, event_type TEXT NOT NULL,
 target_url TEXT NOT NULL, payload TEXT NOT NULL, signature TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', next_retry_at TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS merchant_fee_configs (
 merchant_id INTEGER PRIMARY KEY, payment_fee_rate REAL NOT NULL DEFAULT 0.02,
 refund_fee_rate REAL NOT NULL DEFAULT 0, settlement_fee_rate REAL NOT NULL DEFAULT 0.005,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS refunds (
 id INTEGER PRIMARY KEY AUTOINCREMENT, merchant_id INTEGER NOT NULL, order_no TEXT NOT NULL,
 refund_no TEXT NOT NULL UNIQUE, refund_amount REAL NOT NULL, fee REAL NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'pending', reason TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, processed_at TEXT
);
CREATE TABLE IF NOT EXISTS settlements (
 id INTEGER PRIMARY KEY AUTOINCREMENT, merchant_id INTEGER NOT NULL, settlement_no TEXT NOT NULL UNIQUE,
 amount REAL NOT NULL, fee REAL NOT NULL DEFAULT 0, net_amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 bank_name TEXT, account_name TEXT, account_no_masked TEXT, remark TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, processed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_refunds_merchant ON refunds(merchant_id,created_at);
CREATE INDEX IF NOT EXISTS idx_settlements_merchant ON settlements(merchant_id,created_at);
`);


function merchantNo() {
  return "PH" + Date.now().toString().slice(-8) + Math.floor(Math.random() * 90 + 10);
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
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return res.status(401).json({ message: "未登录" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "登录已过期，请重新登录" });
  }
}
function getMerchant(id) {
  return db.prepare("SELECT * FROM merchants WHERE id = ?").get(id);
}
function cents(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) throw new Error("金额必须大于 0");
  return Math.round(n * 100);
}
function publicMerchant(m) {
  return {
    id: m.id, merchantNo: m.merchant_no, email: m.email, name: m.name,
    status: m.status, balance: (m.balance_cents / 100).toFixed(2),
    frozen: (m.frozen_cents / 100).toFixed(2), createdAt: m.created_at
  };
}

app.get("/api/health", (req,res) => res.json({ ok:true, service:"PayHub", version:"12.0.0" }));

app.post("/api/auth/register", async (req,res) => {
  try {
    const { email, password, name } = req.body || {};
    if (!email || !password || password.length < 6)
      return res.status(400).json({ message:"邮箱和至少 6 位密码为必填项" });
    const exists = db.prepare("SELECT id FROM merchants WHERE email=?").get(String(email).trim().toLowerCase());
    if (exists) return res.status(409).json({ message:"该邮箱已注册" });
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare(
      "INSERT INTO merchants (merchant_no,email,password_hash,name) VALUES (?,?,?,?)"
    ).run(merchantNo(), String(email).trim().toLowerCase(), hash, name || "PayHub 商户");
    const m = getMerchant(info.lastInsertRowid);
    const token = jwt.sign({ id:m.id, email:m.email }, JWT_SECRET, { expiresIn:"7d" });
    res.json({ message:"注册成功", token, user:publicMerchant(m) });
  } catch(e) {
    res.status(500).json({ message:e.message || "注册失败" });
  }
});

app.post("/api/auth/login", async (req,res) => {
  try {
    const { email, password } = req.body || {};
    const m = db.prepare("SELECT * FROM merchants WHERE email=?").get(String(email||"").trim().toLowerCase());
    if (!m || !(await bcrypt.compare(password || "", m.password_hash)))
      return res.status(401).json({ message:"邮箱或密码错误" });
    if (m.status !== "active") return res.status(403).json({ message:"商户账号已被停用" });
    const token = jwt.sign({ id:m.id, email:m.email }, JWT_SECRET, { expiresIn:"7d" });
    res.json({ message:"登录成功", token, user:publicMerchant(m) });
  } catch(e) { res.status(500).json({ message:"登录失败" }); }
});

app.get("/api/auth/me", auth, (req,res) => {
  const m = getMerchant(req.user.id);
  if (!m) return res.status(404).json({ message:"商户不存在" });
  res.json({ user:publicMerchant(m) });
});

app.get("/api/dashboard/stats", auth, (req,res) => {
  const mid = req.user.id;
  const total = db.prepare("SELECT COALESCE(SUM(amount_cents),0) s FROM orders WHERE merchant_id=? AND status='paid'").get(mid).s;
  const pending = db.prepare("SELECT COUNT(*) c FROM orders WHERE merchant_id=? AND status='pending'").get(mid).c;
  const count = db.prepare("SELECT COUNT(*) c FROM orders WHERE merchant_id=?").get(mid).c;
  const paidCount = db.prepare("SELECT COUNT(*) c FROM orders WHERE merchant_id=? AND status='paid'").get(mid).c;
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
    const { merchantOrderNo, amount, currency="CNY", channel="mock", subject="PayHub 订单", expiresMinutes=30 } = req.body || {};
    if (!merchantOrderNo) return res.status(400).json({message:"merchantOrderNo 必填"});
    const amountCents = cents(amount);
    const exists = db.prepare("SELECT * FROM orders WHERE merchant_id=? AND merchant_order_no=?")
      .get(req.user.id, String(merchantOrderNo));
    if (exists) return res.status(409).json({message:"商户订单号已存在", order:exists});
    const no = orderNo();
    const expired = new Date(Date.now() + Math.max(1, Number(expiresMinutes)||30)*60000).toISOString();
    const payUrl = `${req.protocol}://${req.get("host")}/pay/${no}`;
    
 if(!order){
   return res.status(404).send("订单不存在");
 }

 res.send(`
 <html>
 <body style="text-align:center;margin-top:50px">

 <h2>PayHub 收银台</h2>

 <p>订单号：${order.order_no}</p>

 <p>金额：${order.amount_cents/100} ${order.currency}</p>

 <button onclick="
 fetch('/api/checkout/${order.order_no}/pay-v10',{
 method:'POST',
 headers:{
 'Content-Type':'application/json'
 },
 body:JSON.stringify({
 channel:'mock'
 })
 })
 .then(r=>r.json())
 .then(x=>alert(JSON.stringify(x)))
 ">
 立即支付
 </button>

 </body>
 </html>
 `);

});
    const info = db.prepare(`
      INSERT INTO orders(order_no,merchant_id,merchant_order_no,amount_cents,currency,channel,subject,pay_url,client_ip,expired_at)
      VALUES(?,?,?,?,?,?,?,?,?,?)
    `).run(no,req.user.id,String(merchantOrderNo),amountCents,String(currency),String(channel),String(subject),payUrl,req.ip,expired);
    const order = db.prepare("SELECT * FROM orders WHERE id=?").get(info.lastInsertRowid);

res.json({
  message:"订单创建成功",
  order:formatOrder(order),
  orderNo:no,
  payUrl:payUrl
});
  } catch(e) { res.status(400).json({message:e.message || "创建订单失败"}); }
});
});



app.get("/pay/:orderNo",(req,res)=>{

  const order=db.prepare(
    "SELECT * FROM orders WHERE order_no=?"
  ).get(req.params.orderNo);


  if(!order){
    return res.status(404).send("订单不存在");
  }


  res.send(`
  <html>
  <body style="text-align:center;margin-top:50px">

  <h2>PayHub 收银台</h2>

  <p>订单号：${order.order_no}</p>

  <p>金额：${order.amount_cents/100} ${order.currency}</p>


  <button onclick="
  fetch('/api/checkout/${order.order_no}/pay-v10',{
    method:'POST',
    headers:{
      'Content-Type':'application/json'
    },
    body:JSON.stringify({
      channel:'mock'
    })
  })
  .then(r=>r.json())
  .then(x=>alert(JSON.stringify(x)))
  ">
  立即支付
  </button>


  </body>
  </html>
  `);

});






function formatOrder(o) {
  return {
    id: o.id,

    // 同时兼容前端两种写法
    orderNo: o.order_no,
    order_no: o.order_no,

    merchantOrderNo: o.merchant_order_no,
    merchant_order_no: o.merchant_order_no,

    amount: (o.amount_cents / 100).toFixed(2),
    currency: o.currency,

    channel: o.channel,
    subject: o.subject,

    status: o.status,

    payUrl: o.pay_url,
    pay_url: o.pay_url,

    expiredAt: o.expired_at,
    paidAt: o.paid_at,

    createdAt: o.created_at,
    updatedAt: o.updated_at
  };
}

app.get("/api/orders", auth, (req,res) => {
  const page = Math.max(1, Number(req.query.page)||1);
  const pageSize = Math.min(100, Math.max(1, Number(req.query.pageSize)||20));
  const status = req.query.status;
  const where = status ? "AND status=?" : "";
  const params = status ? [req.user.id,status] : [req.user.id];
  const total = db.prepare(`SELECT COUNT(*) c FROM orders WHERE merchant_id=? ${where}`).get(...params).c;
  const rows = db.prepare(`
    SELECT * FROM orders WHERE merchant_id=? ${where}
    ORDER BY id DESC LIMIT ? OFFSET ?
  `).all(...params,pageSize,(page-1)*pageSize);
  res.json({ data:rows.map(formatOrder), total, page, pageSize });
});

app.get("/api/orders/:orderNo", auth, (req,res) => {
  const o = db.prepare("SELECT * FROM orders WHERE order_no=? AND merchant_id=?").get(req.params.orderNo,req.user.id);
  if (!o) return res.status(404).json({message:"订单不存在"});
  res.json({order:formatOrder(o)});
});

/*
 * DEMO / TEST PAYMENT:
 * This endpoint is deliberately separated from real provider integrations.
 * In production, only an authorized provider callback should mark an order paid.
 */
app.post("/api/orders/:orderNo/mock-pay", auth, (req,res) => {
  try {
    const result = db.transaction(() => {
      const o = db.prepare("SELECT * FROM orders WHERE order_no=? AND merchant_id=?").get(req.params.orderNo, req.user.id);
      if (!o) throw new Error("订单不存在");
      if (o.status === "paid") return o;
      if (o.status !== "pending") throw new Error("订单当前不可支付");
      const m = getMerchant(req.user.id);
      const newBalance = m.balance_cents + o.amount_cents;
      db.prepare("UPDATE orders SET status='paid', paid_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?").run(o.id);
      db.prepare("UPDATE merchants SET balance_cents=? WHERE id=?").run(newBalance, m.id);
      db.prepare(`INSERT INTO wallet_transactions(merchant_id,order_id,type,amount_cents,balance_after_cents,reference_no,remark) VALUES(?,?,?,?,?,?,?)`)
        .run(m.id,o.id,"income",o.amount_cents,newBalance,"TX"+crypto.randomBytes(10).toString("hex"),"Mock 测试支付入账");
      return db.prepare("SELECT * FROM orders WHERE id=?").get(o.id);
    })();
    res.json({message:"支付成功（Mock 测试环境）",order:formatOrder(result)});
  } catch(e) { res.status(400).json({message:e.message}); }
});

app.get('/api/checkout/:orderNo',(req,res)=>{
  const o=db.prepare("SELECT * FROM orders WHERE order_no=?").get(req.params.orderNo);
  if(!o) return res.status(404).json({message:'订单不存在'});
  if(o.checkout_token && req.query.token && o.checkout_token!==req.query.token) return res.status(403).json({message:'收银台令牌无效'});
  res.json({order:{...formatOrder(o),merchantName:getMerchant(o.merchant_id)?.name||''}});
});
app.post('/api/checkout/:orderNo/pay',(req,res)=>{
  const o=db.prepare("SELECT * FROM orders WHERE order_no=?").get(req.params.orderNo);
  if(!o) return res.status(404).json({message:'订单不存在'});
  if(o.status==='paid') return res.json({message:'订单已支付',order:formatOrder(o)});
  if(String(req.body?.channel||'mock')!=='mock') return res.status(409).json({message:'该通道尚未连接官方/授权服务商'});
  try {
    const updated=db.transaction(()=>{
      const cur=db.prepare("SELECT * FROM orders WHERE id=?").get(o.id);
      if(cur.status!=='pending') throw new Error('订单当前不可支付');
      const m=getMerchant(cur.merchant_id);
      const nb=m.balance_cents+cur.amount_cents;
      db.prepare("UPDATE orders SET status='paid',paid_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(cur.id);
      db.prepare("UPDATE merchants SET balance_cents=? WHERE id=?").run(nb,m.id);
      db.prepare("INSERT INTO wallet_transactions(merchant_id,order_id,type,amount_cents,balance_after_cents,reference_no,remark) VALUES(?,?,?,?,?,?,?)").run(m.id,cur.id,'income',cur.amount_cents,nb,'TX'+crypto.randomBytes(10).toString('hex'),'Checkout Mock 支付入账');
      return db.prepare("SELECT * FROM orders WHERE id=?").get(cur.id);
    })();
    res.json({message:'支付成功（Mock 测试环境）',order:formatOrder(updated)});
  } catch(e) { res.status(400).json({message:e.message}); }
});

function adminAuth(req,res,next){
  const h=req.headers.authorization||""; const token=h.startsWith("Bearer ")?h.slice(7):"";
  if(!token) return res.status(401).json({message:"未登录"});
  try{ const u=jwt.verify(token,JWT_SECRET); if(u.role!=="admin") throw new Error(); req.admin=u; next(); }
  catch(e){ return res.status(401).json({message:"管理员登录已过期"}); }
}
function adminAudit(action,targetType,targetId,detail){
  try{ db.prepare('INSERT INTO admin_audit_logs(admin_id,action,target_type,target_id,detail) VALUES(?,?,?,?,?)').run(arguments[0] && currentAdminId || null,action,targetType,targetId,detail||''); }catch(e){}
}
let currentAdminId=null;
app.post('/api/admin/login',async(req,res)=>{
  const {email,password}=req.body||{}; const a=db.prepare('SELECT * FROM admin_users WHERE email=?').get(String(email||'').trim().toLowerCase());
  if(!a || a.status!=='active' || !(await bcrypt.compare(password||'',a.password_hash))) return res.status(401).json({message:'管理员账号或密码错误'});
  const token=jwt.sign({id:a.id,email:a.email,role:'admin'},JWT_SECRET,{expiresIn:'8h'});
  res.json({message:'登录成功',token,admin:{id:a.id,email:a.email,name:a.name}});
});
app.get('/api/admin/me',adminAuth,(req,res)=>{const a=db.prepare('SELECT id,email,name,status FROM admin_users WHERE id=?').get(req.admin.id);res.json({admin:a});});
app.get('/api/admin/stats',adminAuth,(req,res)=>{
 const merchants=db.prepare('SELECT COUNT(*) c FROM merchants').get().c;
 const active=db.prepare("SELECT COUNT(*) c FROM merchants WHERE status='active'").get().c;
 const orders=db.prepare('SELECT COUNT(*) c FROM orders').get().c;
 const paid=db.prepare("SELECT COALESCE(SUM(amount_cents),0) s FROM orders WHERE status='paid'").get().s;
 const pendingSettle=db.prepare("SELECT COALESCE(SUM(amount),0) s FROM settlements WHERE status='pending'").get().s;
 const openRisk=db.prepare("SELECT COUNT(*) c FROM merchant_risk_flags WHERE status='open'").get().c;
 res.json({merchants,active,orders,totalPaid:(paid/100).toFixed(2),pendingSettlement:Number(pendingSettle).toFixed(2),openRisk});
});
app.get('/api/admin/merchants',adminAuth,(req,res)=>{
 const rows=db.prepare(`SELECT id,merchant_no,email,name,status,balance_cents,frozen_cents,created_at FROM merchants ORDER BY id DESC LIMIT 500`).all();
 res.json({items:rows.map(x=>({...x,balance:(x.balance_cents/100).toFixed(2),frozen:(x.frozen_cents/100).toFixed(2)}))});
});
app.post('/api/admin/merchants/:id/status',adminAuth,(req,res)=>{
 const status=String(req.body?.status||''); if(!['active','suspended','pending'].includes(status)) return res.status(400).json({message:'无效状态'});
 const m=getMerchant(req.params.id); if(!m)return res.status(404).json({message:'商户不存在'});
 db.prepare('UPDATE merchants SET status=? WHERE id=?').run(status,m.id);
 db.prepare('INSERT INTO admin_audit_logs(admin_id,action,target_type,target_id,detail) VALUES(?,?,?,?,?)').run(req.admin.id,'merchant_status','merchant',String(m.id),status);
 res.json({ok:true,status});
});
app.post('/api/admin/merchants/:id/risk',adminAuth,(req,res)=>{
 const m=getMerchant(req.params.id); if(!m)return res.status(404).json({message:'商户不存在'});
 const level=['low','medium','high'].includes(req.body?.level)?req.body.level:'medium'; const reason=String(req.body?.reason||'管理员标记');
 const info=db.prepare('INSERT INTO merchant_risk_flags(merchant_id,level,reason) VALUES(?,?,?)').run(m.id,level,reason);
 db.prepare('INSERT INTO admin_audit_logs(admin_id,action,target_type,target_id,detail) VALUES(?,?,?,?,?)').run(req.admin.id,'risk_flag','merchant',String(m.id),level+':'+reason);
 res.json({ok:true,id:info.lastInsertRowid});
});
app.get('/api/admin/orders',adminAuth,(req,res)=>{
 const rows=db.prepare(`SELECT o.order_no,o.merchant_order_no,o.amount_cents,o.currency,o.channel,o.subject,o.status,o.created_at,o.paid_at,m.merchant_no,m.name merchant_name FROM orders o JOIN merchants m ON m.id=o.merchant_id ORDER BY o.id DESC LIMIT 500`).all();
 res.json({items:rows.map(x=>({...x,amount:(x.amount_cents/100).toFixed(2)}))});
});
app.get('/api/admin/settlements',adminAuth,(req,res)=>res.json({items:db.prepare(`SELECT s.*,m.merchant_no,m.name merchant_name FROM settlements s JOIN merchants m ON m.id=s.merchant_id ORDER BY s.id DESC LIMIT 300`).all()}));
app.post('/api/admin/settlements/:settlementNo/review',adminAuth,(req,res)=>{
 const action=req.body?.action; const s=db.prepare('SELECT * FROM settlements WHERE settlement_no=?').get(req.params.settlementNo);
 if(!s)return res.status(404).json({message:'结算单不存在'}); if(s.status!=='pending')return res.status(400).json({message:'结算单不是待审核状态'});
 const m=getMerchant(s.merchant_id); if(action==='approve'){
   db.prepare("UPDATE settlements SET status='approved',processed_at=CURRENT_TIMESTAMP WHERE id=?").run(s.id);
 } else if(action==='reject'){
   db.prepare("UPDATE settlements SET status='rejected',processed_at=CURRENT_TIMESTAMP WHERE id=?").run(s.id);
   db.prepare('UPDATE merchants SET balance_cents=balance_cents+? WHERE id=?').run(Math.round(s.amount*100),m.id);
   db.prepare('INSERT INTO wallet_transactions(merchant_id,type,amount_cents,balance_after_cents,reference_no,remark) VALUES(?,?,?,?,?,?)').run(m.id,'settlement_reversal',Math.round(s.amount*100),getMerchant(m.id).balance_cents,'ADMREV'+s.id,'管理员拒绝结算，退回余额');
 } else return res.status(400).json({message:'action 只能是 approve 或 reject'});
 db.prepare('INSERT INTO admin_audit_logs(admin_id,action,target_type,target_id,detail) VALUES(?,?,?,?,?)').run(req.admin.id,'settlement_review','settlement',s.settlement_no,action);
 res.json({ok:true,status:action==='approve'?'approved':'rejected'});
});
app.get('/api/admin/risk-flags',adminAuth,(req,res)=>res.json({items:db.prepare(`SELECT r.*,m.merchant_no,m.name merchant_name FROM merchant_risk_flags r JOIN merchants m ON m.id=r.merchant_id ORDER BY r.id DESC LIMIT 300`).all()}));
app.get('/api/admin/audit-logs',adminAuth,(req,res)=>res.json({items:db.prepare('SELECT * FROM admin_audit_logs ORDER BY id DESC LIMIT 300').all()}));
app.post('/api/admin/reconciliation/run',adminAuth,(req,res)=>{
 const merchantCount=db.prepare('SELECT COUNT(*) c FROM merchants').get().c;
 const orderCount=db.prepare('SELECT COUNT(*) c FROM orders').get().c;
 const paid=db.prepare("SELECT COALESCE(SUM(amount_cents),0) s FROM orders WHERE status='paid'").get().s/100;
 const ledger=db.prepare("SELECT COALESCE(SUM(net_amount),0) s FROM wallet_ledger WHERE type='payment' OR type LIKE 'refund:%' OR type LIKE 'settlement%'").get().s;
 const summary={merchantCount,orderCount,totalPaid:paid.toFixed(2),ledgerNet:Number(ledger).toFixed(2)};
 const no='REC'+Date.now().toString(36).toUpperCase(); db.prepare('INSERT INTO reconciliation_runs(run_no,summary_json) VALUES(?,?)').run(no,JSON.stringify(summary));
 db.prepare('INSERT INTO admin_audit_logs(admin_id,action,target_type,target_id,detail) VALUES(?,?,?,?,?)').run(req.admin.id,'reconciliation','run',no,JSON.stringify(summary));
 res.json({ok:true,runNo:no,summary});
});

// ===== V8 Payment Channel Management / Webhook scaffolding =====
function safeChannelConfig(channel) {
  let cfg = {};
  try { cfg = JSON.parse(channel.config_json || '{}'); } catch {}
  const masked = {};
  for (const [k, v] of Object.entries(cfg)) {
    const s = String(v ?? '');
    masked[k] = s.length > 8 ? `${s.slice(0, 3)}***${s.slice(-3)}` : (s ? '***' : '');
  }
  return {
    id: channel.id,
    channelCode: channel.channel_code,
    displayName: channel.display_name,
    enabled: !!channel.enabled,
    config: masked,
    webhookUrl: channel.webhook_url || '',
    hasCallbackSecret: !!channel.callback_secret,
    createdAt: channel.created_at,
    updatedAt: channel.updated_at
  };
}

const CHANNEL_META = {
  mock: { name: 'Mock 测试支付', fields: [] },
  wechat: { name: '微信支付', fields: ['mchId', 'appId', 'apiV3Key', 'serialNo'] },
  alipay: { name: '支付宝', fields: ['appId', 'merchantPrivateKey', 'alipayPublicKey'] },
  bankcard: { name: '银行卡支付', fields: ['provider', 'merchantId', 'apiKey', 'apiSecret'] },
  usdt_trc20: { name: 'USDT TRC20', fields: ['provider', 'walletAddress', 'apiKey', 'apiSecret'] }
};

app.get('/api/payment-channels', auth, (req, res) => {
  const merchant = db.prepare('SELECT id FROM merchants WHERE id = ?').get(req.user.id);
  if (!merchant) return res.status(404).json({ error: '商户不存在' });

  const rows = db.prepare('SELECT * FROM payment_channels WHERE merchant_id = ? ORDER BY id ASC').all(merchant.id);
  const existing = new Map(rows.map(r => [r.channel_code, r]));
  const now = new Date().toISOString();

  const insert = db.prepare(`
    INSERT OR IGNORE INTO payment_channels
    (merchant_id, channel_code, display_name, enabled, config_json, webhook_url, callback_secret, created_at, updated_at)
    VALUES (?, ?, ?, ?, '{}', '', '', ?, ?)
  `);
  for (const [code, meta] of Object.entries(CHANNEL_META)) {
    insert.run(merchant.id, code, meta.name, code === 'mock' ? 1 : 0, now, now);
  }

  const all = db.prepare('SELECT * FROM payment_channels WHERE merchant_id = ? ORDER BY id ASC').all(merchant.id);
  res.json({ channels: all.map(safeChannelConfig) });
});

app.put('/api/payment-channels/:code', auth, (req, res) => {
  const code = String(req.params.code);
  const meta = CHANNEL_META[code];
  if (!meta) return res.status(400).json({ error: '不支持的支付通道' });

  const merchant = db.prepare('SELECT id FROM merchants WHERE id = ?').get(req.user.id);
  if (!merchant) return res.status(404).json({ error: '商户不存在' });

  const body = req.body || {};
  const now = new Date().toISOString();
  const existing = db.prepare('SELECT * FROM payment_channels WHERE merchant_id = ? AND channel_code = ?')
    .get(merchant.id, code);

  let cfg = {};
  try { cfg = existing ? JSON.parse(existing.config_json || '{}') : {}; } catch {}

  for (const key of meta.fields) {
    if (body.config && Object.prototype.hasOwnProperty.call(body.config, key)) {
      const val = String(body.config[key] ?? '').trim();
      // Keep an existing secret when UI submits an intentionally masked value.
      if (!/^\*{3,}$/.test(val) && !val.includes('***')) cfg[key] = val;
    }
  }

  const enabled = body.enabled ? 1 : 0;
  const webhookUrl = String(body.webhookUrl || '').trim();
  let callbackSecret = existing?.callback_secret || '';
  if (body.callbackSecret && String(body.callbackSecret).trim()) {
    callbackSecret = String(body.callbackSecret).trim();
  }

  db.prepare(`
    INSERT INTO payment_channels
      (merchant_id, channel_code, display_name, enabled, config_json, webhook_url, callback_secret, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(merchant_id, channel_code) DO UPDATE SET
      enabled=excluded.enabled,
      config_json=excluded.config_json,
      webhook_url=excluded.webhook_url,
      callback_secret=excluded.callback_secret,
      updated_at=excluded.updated_at
  `).run(
    merchant.id, code, meta.name, enabled, JSON.stringify(cfg),
    webhookUrl, callbackSecret, existing?.created_at || now, now
  );

  const row = db.prepare('SELECT * FROM payment_channels WHERE merchant_id = ? AND channel_code = ?')
    .get(merchant.id, code);
  res.json({ ok: true, channel: safeChannelConfig(row) });
});

app.post('/api/payment-channels/:code/test', auth, (req, res) => {
  const code = String(req.params.code);
  const meta = CHANNEL_META[code];
  if (!meta) return res.status(400).json({ error: '不支持的支付通道' });
  if (code === 'mock') return res.json({ ok: true, message: 'Mock 通道可用，测试订单可直接完成。' });

  // Real providers must be wired to their official APIs before a live test is performed.
  res.json({
    ok: false,
    status: 'pending_provider',
    message: `${meta.name} 尚未连接官方服务商 API。请先配置并通过官方/授权服务商审核，再进行真实连通性测试。`
  });
});

app.get('/api/webhooks/logs', auth, (req, res) => {
  const merchant = db.prepare('SELECT id FROM merchants WHERE id = ?').get(req.user.id);
  if (!merchant) return res.status(404).json({ error: '商户不存在' });
  const rows = db.prepare(`
    SELECT * FROM webhook_logs
    WHERE merchant_id = ?
    ORDER BY id DESC LIMIT 100
  `).all(merchant.id);
  res.json({ logs: rows });
});

// Development helper: generate a deterministic preview signature.
// Production integrations should verify the provider's documented signature scheme.
app.post('/api/webhooks/signature-preview', auth, (req, res) => {
  const crypto = require('crypto');
  const payload = String(req.body?.payload || '');
  const secret = String(req.body?.secret || '');
  if (!payload || !secret) return res.status(400).json({ error: 'payload 和 secret 必填' });
  const signature = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  res.json({ algorithm: 'HMAC-SHA256', signature });
});


// ===== V9 Merchant API / HMAC Signature System =====
function v9Token(prefix, bytes=24){ return `${prefix}_${crypto.randomBytes(bytes).toString('hex')}`; }
function v9Sign(secret,timestamp,nonce,body){
  return crypto.createHmac('sha256',secret).update(`${timestamp}.${nonce}.${body}`).digest('hex');
}
function v9SafeEqualHex(a,b){
  try{const x=Buffer.from(String(a),'hex'),y=Buffer.from(String(b),'hex');return x.length===y.length&&crypto.timingSafeEqual(x,y)}catch{return false}
}
function requireMerchantApi(req,res,next){
  const key=req.get('X-PayHub-Key'), ts=req.get('X-PayHub-Timestamp'), nonce=req.get('X-PayHub-Nonce'), sig=req.get('X-PayHub-Signature'), secret=req.get('X-PayHub-Secret');
  const merchant=db.prepare(`SELECT m.*,c.api_key,c.api_secret_hash,c.enabled api_enabled FROM merchant_api_credentials c JOIN merchants m ON m.id=c.merchant_id WHERE c.api_key=?`).get(key);
  if(!merchant||!merchant.api_enabled) return res.status(401).json({code:'INVALID_API_KEY',message:'API Key 无效或已停用'});
  if(!ts||!nonce||!sig||!secret) return res.status(401).json({code:'MISSING_SIGNATURE',message:'缺少签名请求头'});
  const n=Number(ts);
  if(!Number.isFinite(n)||Math.abs(Date.now()-n)>300000) return res.status(401).json({code:'TIMESTAMP_EXPIRED',message:'请求时间戳已过期'});
  if(!bcrypt.compareSync(secret,merchant.api_secret_hash)) return res.status(401).json({code:'INVALID_API_SECRET',message:'API Secret 无效'});
  const body=JSON.stringify(req.body||{}), expected=v9Sign(secret,ts,nonce,body);
  if(!v9SafeEqualHex(expected,sig)) return res.status(401).json({code:'INVALID_SIGNATURE',message:'签名验证失败'});
  req.apiMerchant=merchant; req.apiRequestId=v9Token('req',8); next();
}

app.get('/api/developer/credentials',auth,(req,res)=>{
  const m=db.prepare('SELECT id FROM merchants WHERE id=?').get(req.user.id);
  if(!m)return res.status(404).json({error:'商户不存在'});
  const row=db.prepare('SELECT * FROM merchant_api_credentials WHERE merchant_id=?').get(m.id);
  if(!row){
    const key=v9Token('phk',18),secret=v9Token('phs',24),now=new Date().toISOString();
    db.prepare('INSERT INTO merchant_api_credentials(merchant_id,api_key,api_secret_hash,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)')
      .run(m.id,key,bcrypt.hashSync(secret,12),1,now,now);
    return res.json({apiKey:key,apiSecret:secret,enabled:true,generated:true,warning:'API Secret 只显示这一次，请立即保存。'});
  }
  res.json({apiKey:row.api_key,enabled:!!row.enabled,generated:false,warning:'API Secret 已哈希存储，无法再次查看。'});
});

app.post('/api/developer/credentials/rotate',auth,(req,res)=>{
  const m=db.prepare('SELECT id FROM merchants WHERE id=?').get(req.user.id);
  if(!m)return res.status(404).json({error:'商户不存在'});
  const key=v9Token('phk',18),secret=v9Token('phs',24),now=new Date().toISOString();
  db.prepare(`INSERT INTO merchant_api_credentials(merchant_id,api_key,api_secret_hash,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)
    ON CONFLICT(merchant_id) DO UPDATE SET api_key=excluded.api_key,api_secret_hash=excluded.api_secret_hash,enabled=1,updated_at=excluded.updated_at`)
    .run(m.id,key,bcrypt.hashSync(secret,12),1,now,now);
  res.json({apiKey:key,apiSecret:secret,warning:'旧凭证已失效，Secret 只显示这一次。'});
});

app.post('/api/developer/credentials/toggle',auth,(req,res)=>{
  const m=db.prepare('SELECT id FROM merchants WHERE id=?').get(req.user.id);
  if(!m)return res.status(404).json({error:'商户不存在'});
  const enabled=req.body?.enabled?1:0;
  db.prepare('UPDATE merchant_api_credentials SET enabled=?,updated_at=? WHERE merchant_id=?').run(enabled,new Date().toISOString(),m.id);
  res.json({ok:true,enabled:!!enabled});
});

app.post('/api/v1/orders',requireMerchantApi,(req,res)=>{
  const {amount,subject,returnUrl='',notifyUrl='',channel='mock'}=req.body||{}, num=Number(amount);
  if(!Number.isFinite(num)||num<=0)return res.status(400).json({code:'INVALID_AMOUNT',message:'amount 必须大于 0'});
  if(!subject)return res.status(400).json({code:'INVALID_SUBJECT',message:'subject 必填'});
  const orderNo='PH'+Date.now()+Math.floor(Math.random()*1000),now=new Date().toISOString(),token=v9Token('ct',16);
  const base=`${req.protocol}://${req.get('host')}`;
  const amountCents=Math.round(num*100);
  db.prepare(`INSERT INTO orders(merchant_id,order_no,merchant_order_no,amount_cents,currency,channel,subject,pay_url,expired_at,payment_method,checkout_token,return_url,notify_url,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(req.apiMerchant.id,orderNo,orderNo,amountCents,'CNY',channel,String(subject),`${base}/checkout?order=${encodeURIComponent(orderNo)}&token=${encodeURIComponent(token)}`,new Date(Date.now()+30*60*1000).toISOString(),channel,token,returnUrl,notifyUrl,now,now);
  res.status(201).json({code:'OK',requestId:req.apiRequestId,order:{orderNo,amount:num,currency:'CNY',status:'pending',subject:String(subject),channel,checkoutUrl:`${base}/checkout?order=${encodeURIComponent(orderNo)}&token=${encodeURIComponent(token)}`,returnUrl,notifyUrl,createdAt:now}});
});

app.get('/api/v1/orders/:orderNo',requireMerchantApi,(req,res)=>{
  const row=db.prepare('SELECT * FROM orders WHERE merchant_id=? AND order_no=?').get(req.apiMerchant.id,req.params.orderNo);
  if(!row)return res.status(404).json({code:'ORDER_NOT_FOUND',message:'订单不存在'});
  res.json({code:'OK',requestId:req.apiRequestId,order:row});
});

app.get('/api/v1/docs',(req,res)=>res.json({
  name:'PayHub Merchant API V1',version:'1.0',
  authentication:{headers:['X-PayHub-Key','X-PayHub-Timestamp','X-PayHub-Nonce','X-PayHub-Secret','X-PayHub-Signature'],algorithm:'HMAC-SHA256',canonical:'timestamp.nonce.raw_json_body'},
  endpoints:[{method:'POST',path:'/api/v1/orders',description:'创建支付订单'},{method:'GET',path:'/api/v1/orders/:orderNo',description:'查询订单'}],
  note:'生产环境必须使用 HTTPS；真实支付通道需官方/授权服务商接入。'
}));


// ===== V10 Complete Payment Order Chain =====
function v10MerchantByOrder(orderNo){
  return db.prepare(`SELECT o.*,m.name merchant_name,m.id merchant_id FROM orders o JOIN merchants m ON m.id=o.merchant_id WHERE o.order_no=?`).get(orderNo);
}
function v10Channel(order){
  return db.prepare(`SELECT * FROM payment_channels WHERE merchant_id=? AND channel_code=?`).get(order.merchant_id,order.payment_method||'mock');
}
function v10Webhook(order,eventType){
  const ch=v10Channel(order);
  const url=(order.notify_url||ch?.webhook_url||'').trim();
  if(!url) return null;
  let secret=ch?.callback_secret||'';
  let payload=JSON.stringify({event:eventType,order:{orderNo:order.order_no,subject:order.subject,amount:Number(order.amount_cents)/100,currency:order.currency,status:order.status,paidAt:order.paid_at||null}});
  const sig=secret?crypto.createHmac('sha256',secret).update(payload).digest('hex'):'';
  const now=new Date().toISOString();
  const r=db.prepare(`INSERT INTO webhook_deliveries(merchant_id,order_no,event_type,target_url,payload,signature,status,attempts,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`)
    .run(order.merchant_id,order.order_no,eventType,url,payload,sig,'pending',0,now,now);
  return r.lastInsertRowid;
}
function v10PostWallet(order){
  const fee=Math.round(Number(order.amount_cents)/100*0.02*100)/100; // demo platform fee 2%
  const net=Math.round((Number(order.amount_cents)/100-fee)*100)/100;
  const merchant=db.prepare('SELECT balance_cents FROM merchants WHERE id=?').get(order.merchant_id);
  const before=Number(merchant?.balance_cents||0), after=Math.round((before+net)*100)/100, now=new Date().toISOString();
  const exists=db.prepare(`SELECT id FROM wallet_ledger WHERE merchant_id=? AND order_no=? AND type='payment'`).get(order.merchant_id,order.order_no);
  if(exists) return;
  db.prepare('UPDATE merchants SET balance_cents=? WHERE id=?').run(after,order.merchant_id);
  db.prepare(`INSERT INTO wallet_ledger(merchant_id,order_no,type,amount,fee,net_amount,balance_before,balance_after,status,remark,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
    .run(order.merchant_id,order.order_no,'payment',Number(order.amount_cents)/100,fee,net,before,after,'posted','订单支付入账',now);
}
function v10MarkPaid(orderNo){
  const order=v10MerchantByOrder(orderNo);
  if(!order) return null;
  if(order.status==='paid') return order;
  const now=new Date().toISOString();
  db.prepare(`UPDATE orders SET status='paid',paid_at=?,updated_at=? WHERE order_no=? AND status='pending'`).run(now,now,orderNo);
  const updated=v10MerchantByOrder(orderNo);
  v10PostWallet(updated);
  v10Webhook(updated,'payment.succeeded');
  return updated;
}

// Public checkout payment endpoint upgraded: only Mock completes automatically.
// Other channels remain explicit placeholders until an official provider adapter is installed.
app.post('/api/checkout/:orderNo/pay-v10',(req,res)=>{
  const order=v10MerchantByOrder(req.params.orderNo);
  if(!order) return res.status(404).json({error:'订单不存在'});
  if(order.status==='paid') return res.json({ok:true,status:'paid',order});
  const channel=String(req.body?.channel||order.payment_method||'mock');
  if(channel!=='mock'){
    return res.status(409).json({ok:false,status:'provider_pending',message:'该支付通道尚未连接官方/授权服务商，当前不能伪造真实支付成功。'});
  }
  const paid=v10MarkPaid(order.order_no);
  res.json({ok:true,status:'paid',order:paid,message:'Mock 支付成功，已进入钱包入账和 Webhook 队列。'});
});

app.get('/api/merchant/transactions',auth,(req,res)=>{
  const m=db.prepare('SELECT id FROM merchants WHERE id=?').get(req.user.id);
  if(!m)return res.status(404).json({error:'商户不存在'});
  const rows=db.prepare('SELECT * FROM wallet_ledger WHERE merchant_id=? ORDER BY id DESC LIMIT 100').all(m.id);
  res.json({transactions:rows});
});

app.get('/api/merchant/balance',auth,(req,res)=>{
  const m=db.prepare('SELECT id,balance_cents FROM merchants WHERE id=?').get(req.user.id);
  if(!m)return res.status(404).json({error:'商户不存在'});
  res.json({balance:Number(m.balance_cents||0)});
});

app.get('/api/webhooks/deliveries',auth,(req,res)=>{
  const m=db.prepare('SELECT id FROM merchants WHERE id=?').get(req.user.id);
  if(!m)return res.status(404).json({error:'商户不存在'});
  const rows=db.prepare('SELECT id,order_no,event_type,target_url,status,attempts,last_error,next_retry_at,created_at,updated_at FROM webhook_deliveries WHERE merchant_id=? ORDER BY id DESC LIMIT 100').all(m.id);
  res.json({deliveries:rows});
});

app.post('/api/webhooks/deliveries/:id/retry',auth,(req,res)=>{
  const m=db.prepare('SELECT id FROM merchants WHERE id=?').get(req.user.id);
  if(!m)return res.status(404).json({error:'商户不存在'});
  const row=db.prepare('SELECT * FROM webhook_deliveries WHERE id=? AND merchant_id=?').get(req.params.id,m.id);
  if(!row)return res.status(404).json({error:'Webhook 记录不存在'});
  db.prepare(`UPDATE webhook_deliveries SET status='pending',next_retry_at=NULL,updated_at=? WHERE id=?`).run(new Date().toISOString(),row.id);
  res.json({ok:true,message:'已重新加入发送队列。当前 V10 默认不主动请求外部商户 URL，待生产 Webhook worker/队列接入。'});
});

// Internal development view of the order lifecycle.
app.get('/api/orders/:orderNo/lifecycle',auth,(req,res)=>{
  const m=db.prepare('SELECT id FROM merchants WHERE id=?').get(req.user.id);
  if(!m)return res.status(404).json({error:'商户不存在'});
  const order=db.prepare('SELECT * FROM orders WHERE merchant_id=? AND order_no=?').get(m.id,req.params.orderNo);
  if(!order)return res.status(404).json({error:'订单不存在'});
  const ledger=db.prepare('SELECT * FROM wallet_ledger WHERE merchant_id=? AND order_no=? ORDER BY id ASC').all(m.id,order.order_no);
  const hooks=db.prepare('SELECT * FROM webhook_deliveries WHERE merchant_id=? AND order_no=? ORDER BY id ASC').all(m.id,order.order_no);
  res.json({order,ledger,webhooks:hooks});
});


// V11 schema: refunds, fee configuration, settlements
try {
  db.exec(`
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
  CREATE INDEX IF NOT EXISTS idx_refunds_merchant ON refunds(merchant_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_settlements_merchant ON settlements(merchant_id, created_at);
  `);
} catch (e) { console.error('V11 schema init failed', e); }

function v11Money(n) { return Math.round(Number(n) * 100) / 100; }
function v11EnsureFees(merchantId) {
  let row = db.prepare('SELECT * FROM merchant_fee_configs WHERE merchant_id=?').get(merchantId);
  if (!row) {
    db.prepare('INSERT INTO merchant_fee_configs (merchant_id) VALUES (?)').run(merchantId);
    row = db.prepare('SELECT * FROM merchant_fee_configs WHERE merchant_id=?').get(merchantId);
  }
  return row;
}
function v11No(prefix) { return prefix + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2, 7).toUpperCase(); }
function v11Mask(v) { const x=String(v||''); return x.length<=4 ? (x?'****':'') : '*'.repeat(x.length-4)+x.slice(-4); }

app.get('/api/merchant/fee-config', auth, (req,res)=>{
  const x=v11EnsureFees(req.user.id);
  res.json({paymentFeeRate:x.payment_fee_rate, refundFeeRate:x.refund_fee_rate, settlementFeeRate:x.settlement_fee_rate});
});
app.put('/api/merchant/fee-config', auth, (req,res)=>{
  const p=Number(req.body?.paymentFeeRate), r=Number(req.body?.refundFeeRate), st=Number(req.body?.settlementFeeRate);
  if (![p,r,st].every(Number.isFinite) || [p,r,st].some(x=>x<0 || x>0.2)) return res.status(400).json({error:'invalid_fee_rate'});
  v11EnsureFees(req.user.id);
  db.prepare('UPDATE merchant_fee_configs SET payment_fee_rate=?, refund_fee_rate=?, settlement_fee_rate=?, updated_at=CURRENT_TIMESTAMP WHERE merchant_id=?').run(p,r,st,req.user.id);
  res.json({ok:true,paymentFeeRate:p,refundFeeRate:r,settlementFeeRate:st});
});

app.post('/api/orders/:orderNo/close', auth, (req,res)=>{
  const o=db.prepare('SELECT * FROM orders WHERE order_no=? AND merchant_id=?').get(req.params.orderNo,req.user.id);
  if(!o) return res.status(404).json({error:'order_not_found'});
  if(o.status!=='pending') return res.status(400).json({error:'order_not_closable'});
  db.prepare("UPDATE orders SET status='closed' WHERE order_no=? AND merchant_id=?").run(o.order_no,req.user.id);
  res.json({ok:true,orderNo:o.order_no,status:'closed'});
});

app.post('/api/orders/:orderNo/refund', auth, (req,res)=>{
  const o=db.prepare('SELECT * FROM orders WHERE order_no=? AND merchant_id=?').get(req.params.orderNo,req.user.id);
  if(!o) return res.status(404).json({error:'order_not_found'});
  if(!['paid','partially_refunded'].includes(o.status)) return res.status(400).json({error:'order_not_refundable'});
  const used=db.prepare("SELECT COALESCE(SUM(refund_amount),0) total FROM refunds WHERE merchant_id=? AND order_no=? AND status='processed'").get(req.user.id,o.order_no).total;
  const amount=v11Money(req.body?.amount==null?o.amount_cents/100:req.body.amount);
  const refundable=v11Money(o.amount_cents/100-Number(used||0));
  if(amount<=0 || amount>refundable) return res.status(400).json({error:'invalid_refund_amount',refundable});
  const cfg=v11EnsureFees(req.user.id);
  const fee=v11Money(amount*Number(cfg.refund_fee_rate||0));
  const m=db.prepare('SELECT balance_cents FROM merchants WHERE id=?').get(req.user.id);
  const before=v11Money(m.balance_cents), debit=v11Money(amount+fee), after=v11Money(before-debit);
  if(after<0) return res.status(400).json({error:'insufficient_balance_for_refund',balance:before});
  const refundNo=v11No('RF');
  const now=new Date().toISOString();
  const tx=db.transaction(()=>{
    db.prepare('UPDATE merchants SET balance_cents=? WHERE id=?').run(after,req.user.id);
    db.prepare(`INSERT INTO refunds (merchant_id,order_no,refund_no,refund_amount,fee,status,reason,created_at,processed_at) VALUES (?,?,?,?,?,'processed',?,?,?)`).run(req.user.id,o.order_no,refundNo,amount,fee,String(req.body?.reason||'merchant_refund'),now,now);
    db.prepare(`INSERT INTO wallet_ledger (merchant_id,order_no,type,amount,fee,net_amount,balance_before,balance_after,status,remark) VALUES (?,?,?,?,?,?,?,?, 'posted',?)`).run(req.user.id,o.order_no,'refund:'+refundNo,-amount,fee,-debit,before,after,'refund '+refundNo);
    const remaining=v11Money(refundable-amount);
    db.prepare("UPDATE orders SET status=? WHERE order_no=? AND merchant_id=?").run(remaining<=0?'refunded':'partially_refunded',o.order_no,req.user.id);
  });
  tx();
  res.json({ok:true,refund:{refundNo,orderNo:o.order_no,amount,fee,status:'processed',remainingRefundable:v11Money(refundable-amount)},balance:after});
});
app.get('/api/refunds',auth,(req,res)=>res.json({items:db.prepare('SELECT * FROM refunds WHERE merchant_id=? ORDER BY id DESC LIMIT 200').all(req.user.id)}));

app.post('/api/settlements',auth,(req,res)=>{
  const amount=v11Money(req.body?.amount);
  if(amount<=0) return res.status(400).json({error:'invalid_amount'});
  const m=db.prepare('SELECT balance_cents FROM merchants WHERE id=?').get(req.user.id), before=v11Money(m.balance_cents);
  if(amount>before) return res.status(400).json({error:'insufficient_balance',balance:before});
  const cfg=v11EnsureFees(req.user.id), fee=v11Money(amount*Number(cfg.settlement_fee_rate||0.005)), net=v11Money(amount-fee), no=v11No('ST'), after=v11Money(before-amount);
  const now=new Date().toISOString();
  const tx=db.transaction(()=>{
    db.prepare('UPDATE merchants SET balance_cents=? WHERE id=?').run(after,req.user.id);
    db.prepare(`INSERT INTO settlements (merchant_id,settlement_no,amount,fee,net_amount,status,bank_name,account_name,account_no_masked,remark,created_at) VALUES (?,?,?,?,?,'pending',?,?,?,?,?)`).run(req.user.id,no,amount,fee,net,String(req.body?.bankName||''),String(req.body?.accountName||''),v11Mask(req.body?.accountNo||''),String(req.body?.remark||''),now);
    db.prepare(`INSERT INTO wallet_ledger (merchant_id,order_no,type,amount,fee,net_amount,balance_before,balance_after,status,remark) VALUES (?,?,?,?,?,?,?,?, 'posted',?)`).run(req.user.id,no,'settlement:'+no,-amount,fee,-amount,before,after,'settlement requested '+no);
  }); tx();
  res.json({ok:true,settlement:{settlementNo:no,amount,fee,netAmount:net,status:'pending'},balance:after});
});
app.get('/api/settlements',auth,(req,res)=>res.json({items:db.prepare('SELECT * FROM settlements WHERE merchant_id=? ORDER BY id DESC LIMIT 200').all(req.user.id)}));
app.post('/api/settlements/:settlementNo/cancel',auth,(req,res)=>{
  const x=db.prepare('SELECT * FROM settlements WHERE settlement_no=? AND merchant_id=?').get(req.params.settlementNo,req.user.id);
  if(!x) return res.status(404).json({error:'settlement_not_found'});
  if(x.status!=='pending') return res.status(400).json({error:'settlement_not_cancellable'});
  const m=db.prepare('SELECT balance_cents FROM merchants WHERE id=?').get(req.user.id), before=v11Money(m.balance_cents), after=v11Money(before+x.amount);
  const tx=db.transaction(()=>{
    db.prepare('UPDATE merchants SET balance_cents=? WHERE id=?').run(after,req.user.id);
    db.prepare("UPDATE settlements SET status='cancelled',processed_at=CURRENT_TIMESTAMP WHERE id=?").run(x.id);
    db.prepare(`INSERT INTO wallet_ledger (merchant_id,order_no,type,amount,fee,net_amount,balance_before,balance_after,status,remark) VALUES (?,?,?,?,?,?,?,?, 'posted',?)`).run(req.user.id,x.settlement_no,'settlement_cancel:'+x.settlement_no,x.amount,0,x.amount,before,after,'settlement cancelled '+x.settlement_no);
  }); tx(); res.json({ok:true,balance:after});
});



// ===== V13 Merchant/KYC/Risk/Settlement controls =====
for (const sql of [
 "ALTER TABLE merchants ADD COLUMN merchant_type TEXT NOT NULL DEFAULT 'company'",
 "ALTER TABLE merchants ADD COLUMN legal_name TEXT NOT NULL DEFAULT ''",
 "ALTER TABLE merchants ADD COLUMN contact_name TEXT NOT NULL DEFAULT ''",
 "ALTER TABLE merchants ADD COLUMN contact_phone TEXT NOT NULL DEFAULT ''",
 "ALTER TABLE merchants ADD COLUMN kyc_status TEXT NOT NULL DEFAULT 'pending'",
 "ALTER TABLE merchants ADD COLUMN kyc_note TEXT NOT NULL DEFAULT ''",
 "ALTER TABLE merchants ADD COLUMN daily_limit_cents INTEGER NOT NULL DEFAULT 100000000",
 "ALTER TABLE merchants ADD COLUMN single_limit_cents INTEGER NOT NULL DEFAULT 10000000",
 "ALTER TABLE merchants ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'normal'"
]) { try { db.exec(sql); } catch(e) { if(!String(e.message).includes('duplicate column name')) throw e; } }
db.exec(`
CREATE TABLE IF NOT EXISTS risk_rules (
 id INTEGER PRIMARY KEY AUTOINCREMENT, rule_code TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1, config_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS merchant_risk_profiles (
 merchant_id INTEGER PRIMARY KEY, daily_limit_cents INTEGER NOT NULL DEFAULT 100000000,
 single_limit_cents INTEGER NOT NULL DEFAULT 10000000, velocity_count INTEGER NOT NULL DEFAULT 20,
 velocity_window_minutes INTEGER NOT NULL DEFAULT 10, blacklist INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS kyc_reviews (
 id INTEGER PRIMARY KEY AUTOINCREMENT, merchant_id INTEGER NOT NULL, action TEXT NOT NULL,
 note TEXT NOT NULL DEFAULT '', admin_id INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);
`);
const defaultRules=[
 ['single_limit','单笔交易限额',1,JSON.stringify({maxCents:10000000})],
 ['daily_limit','单日交易限额',1,JSON.stringify({maxCents:100000000})],
 ['velocity','短时频繁交易',1,JSON.stringify({count:20,windowMinutes:10})],
 ['risk_merchant','风险商户拦截',1,JSON.stringify({levels:['high']})]
];
const insRule=db.prepare('INSERT OR IGNORE INTO risk_rules(rule_code,name,enabled,config_json) VALUES(?,?,?,?)');
for(const r of defaultRules) insRule.run(...r);

function v13EnsureRisk(merchantId){
 let x=db.prepare('SELECT * FROM merchant_risk_profiles WHERE merchant_id=?').get(merchantId);
 if(!x){ const m=getMerchant(merchantId); db.prepare('INSERT INTO merchant_risk_profiles(merchant_id,daily_limit_cents,single_limit_cents) VALUES(?,?,?)').run(merchantId,m?.daily_limit_cents||100000000,m?.single_limit_cents||10000000); x=db.prepare('SELECT * FROM merchant_risk_profiles WHERE merchant_id=?').get(merchantId); }
 return x;
}
function v13RiskDecision(merchantId,amountCents){
 const m=getMerchant(merchantId), r=v13EnsureRisk(merchantId); if(!m) return {ok:false,reason:'merchant_not_found'};
 if(m.status!=='active') return {ok:false,reason:'merchant_not_active'};
 if(m.risk_level==='high' || r.blacklist) return {ok:false,reason:'merchant_risk_blocked'};
 if(amountCents>r.single_limit_cents) return {ok:false,reason:'single_limit_exceeded',limit:r.single_limit_cents};
 const today=new Date().toISOString().slice(0,10);
 const daily=db.prepare("SELECT COALESCE(SUM(amount_cents),0) s FROM orders WHERE merchant_id=? AND status IN ('paid','pending','partially_refunded','refunded') AND substr(created_at,1,10)=?").get(merchantId,today).s;
 if(Number(daily)+amountCents>r.daily_limit_cents) return {ok:false,reason:'daily_limit_exceeded',limit:r.daily_limit_cents};
 const recent=db.prepare("SELECT COUNT(*) c FROM orders WHERE merchant_id=? AND created_at>=datetime('now',?)").get(merchantId,`-${r.velocity_window_minutes} minutes`).c;
 if(Number(recent)>=r.velocity_count) return {ok:false,reason:'velocity_limit_exceeded'};
 return {ok:true};
}

app.get('/api/admin/kyc/pending',adminAuth,(req,res)=>{
 const rows=db.prepare("SELECT id,merchant_no,name,email,merchant_type,legal_name,contact_name,contact_phone,kyc_status,kyc_note,created_at FROM merchants WHERE kyc_status='pending' ORDER BY id DESC LIMIT 300").all(); res.json({items:rows});
});
app.get('/api/admin/merchants/:id/detail',adminAuth,(req,res)=>{
 const m=db.prepare('SELECT id,merchant_no,email,name,status,balance_cents,frozen_cents,merchant_type,legal_name,contact_name,contact_phone,kyc_status,kyc_note,daily_limit_cents,single_limit_cents,risk_level,created_at FROM merchants WHERE id=?').get(req.params.id); if(!m)return res.status(404).json({message:'商户不存在'});
 res.json({...m,balance:m.balance_cents/100,frozen:m.frozen_cents/100,dailyLimit:m.daily_limit_cents/100,singleLimit:m.single_limit_cents/100,risk:v13EnsureRisk(m.id)});
});
app.post('/api/admin/merchants/:id/kyc-review',adminAuth,(req,res)=>{
 const m=getMerchant(req.params.id); if(!m)return res.status(404).json({message:'商户不存在'}); const action=String(req.body?.action||''); if(!['approve','reject','pending'].includes(action))return res.status(400).json({message:'无效审核动作'});
 const status=action==='approve'?'approved':action==='reject'?'rejected':'pending', note=String(req.body?.note||'');
 db.prepare('UPDATE merchants SET kyc_status=?,kyc_note=? WHERE id=?').run(status,note,m.id); db.prepare('INSERT INTO kyc_reviews(merchant_id,action,note,admin_id) VALUES(?,?,?,?)').run(m.id,action,note,req.admin.id); db.prepare('INSERT INTO admin_audit_logs(admin_id,action,target_type,target_id,detail) VALUES(?,?,?,?,?)').run(req.admin.id,'kyc_review','merchant',String(m.id),action+':'+note); res.json({ok:true,kycStatus:status});
});
app.put('/api/admin/merchants/:id/risk-profile',adminAuth,(req,res)=>{
 const m=getMerchant(req.params.id); if(!m)return res.status(404).json({message:'商户不存在'}); const daily=Math.round(Number(req.body?.dailyLimit||0)*100), single=Math.round(Number(req.body?.singleLimit||0)*100), count=Math.max(1,Math.floor(Number(req.body?.velocityCount||20))), win=Math.max(1,Math.floor(Number(req.body?.velocityWindowMinutes||10))), blacklist=req.body?.blacklist?1:0;
 if(daily<=0||single<=0)return res.status(400).json({message:'限额必须大于0'}); v13EnsureRisk(m.id); db.prepare('UPDATE merchant_risk_profiles SET daily_limit_cents=?,single_limit_cents=?,velocity_count=?,velocity_window_minutes=?,blacklist=?,updated_at=CURRENT_TIMESTAMP WHERE merchant_id=?').run(daily,single,count,win,blacklist,m.id); db.prepare('UPDATE merchants SET daily_limit_cents=?,single_limit_cents=?,risk_level=? WHERE id=?').run(daily,single,blacklist?'high':(m.risk_level||'normal'),m.id); db.prepare('INSERT INTO admin_audit_logs(admin_id,action,target_type,target_id,detail) VALUES(?,?,?,?,?)').run(req.admin.id,'risk_profile','merchant',String(m.id),JSON.stringify({daily,single,count,win,blacklist})); res.json({ok:true});
});
app.get('/api/admin/risk-rules',adminAuth,(req,res)=>res.json({items:db.prepare('SELECT * FROM risk_rules ORDER BY id').all()}));
app.put('/api/admin/risk-rules/:code',adminAuth,(req,res)=>{ const r=db.prepare('SELECT * FROM risk_rules WHERE rule_code=?').get(req.params.code); if(!r)return res.status(404).json({message:'规则不存在'}); const enabled=req.body?.enabled?1:0, cfg=req.body?.config||{}; db.prepare('UPDATE risk_rules SET enabled=?,config_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(enabled,JSON.stringify(cfg),r.id); db.prepare('INSERT INTO admin_audit_logs(admin_id,action,target_type,target_id,detail) VALUES(?,?,?,?,?)').run(req.admin.id,'risk_rule','rule',r.rule_code,JSON.stringify({enabled,cfg})); res.json({ok:true}); });
app.get('/api/admin/financial-summary',adminAuth,(req,res)=>{ const x=db.prepare(`SELECT COALESCE(SUM(CASE WHEN status='paid' THEN amount_cents ELSE 0 END),0) paid,COALESCE(SUM(CASE WHEN status='refunded' OR status='partially_refunded' THEN amount_cents ELSE 0 END),0) refundBase FROM orders`).get(); const bal=db.prepare('SELECT COALESCE(SUM(balance_cents),0) s FROM merchants').get().s; const frozen=db.prepare('SELECT COALESCE(SUM(frozen_cents),0) s FROM merchants').get().s; const fees=db.prepare("SELECT COALESCE(SUM(fee),0) s FROM wallet_ledger WHERE fee>0").get().s; const settle=db.prepare("SELECT COALESCE(SUM(amount),0) s FROM settlements WHERE status IN ('pending','approved','processing')").get().s; res.json({paid:x.paid/100,refundBase:x.refundBase/100,merchantBalances:bal/100,frozen:frozen/100,fees:Number(fees),pendingSettlements:Number(settle)}); });

// Apply risk controls to new merchant order creation without changing the existing public API shape.

app.use(express.static(path.join(__dirname,"public")));
app.get("/dashboard",(req,res)=>res.sendFile(path.join(__dirname,"public","dashboard.html")));
app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT,()=>console.log(`PayHub V12 running on http://localhost:${PORT}`));
