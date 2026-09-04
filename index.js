/* PayHub V14 — Cloudflare Workers + D1
 * Test/development payment platform. Real payment channels remain provider placeholders.
 */

const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', ...extra }
});
const text = (data, status = 200) => new Response(data, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } });

const enc = new TextEncoder();
const b64u = (bytes) => {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};
const unb64u = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const hex = (bytes) => [...bytes].map(x => x.toString(16).padStart(2, '0')).join('');
const bytesHex = (s) => { const a = new Uint8Array(s.length / 2); for (let i=0;i<a.length;i++) a[i]=parseInt(s.slice(i*2,i*2+2),16); return a; };

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign','verify']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
}
async function sha256Hex(s) { return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)))); }
async function passwordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 120000;
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name:'PBKDF2', salt, iterations, hash:'SHA-256' }, key, 256));
  return `pbkdf2$${iterations}$${hex(salt)}$${hex(bits)}`;
}
async function passwordCompare(password, stored) {
  try {
    const [kind, it, saltHex, hashHex] = String(stored).split('$');
    if (kind !== 'pbkdf2') return false;
    const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name:'PBKDF2', salt:bytesHex(saltHex), iterations:Number(it), hash:'SHA-256' }, key, 256));
    const a = bytesHex(hashHex); if (a.length !== bits.length) return false;
    let d=0; for(let i=0;i<a.length;i++) d |= a[i]^bits[i]; return d===0;
  } catch { return false; }
}

async function jwtSign(payload, secret, ttlSeconds = 604800) {
  const now = Math.floor(Date.now()/1000);
  const p = { ...payload, iat: now, exp: now + ttlSeconds };
  const h = b64u(enc.encode(JSON.stringify({ alg:'HS256', typ:'JWT' })));
  const b = b64u(enc.encode(JSON.stringify(p)));
  const sig = b64u(await hmac(secret, `${h}.${b}`));
  return `${h}.${b}.${sig}`;
}
async function jwtVerify(token, secret) {
  const [h,b,s] = String(token||'').split('.');
  if (!h || !b || !s) throw new Error('invalid token');
  const expected = b64u(await hmac(secret, `${h}.${b}`));
  if (expected !== s) throw new Error('invalid signature');
  const p = JSON.parse(new TextDecoder().decode(unb64u(b)));
  if (!p.exp || p.exp < Math.floor(Date.now()/1000)) throw new Error('expired');
  return p;
}

async function bodyJson(req) { try { return await req.json(); } catch { return {}; } }
async function dbAll(db, sql, params=[]) { return (await db.prepare(sql).bind(...params).all()).results || []; }
async function dbFirst(db, sql, params=[]) { return (await db.prepare(sql).bind(...params).first()) || null; }
async function dbRun(db, sql, params=[]) { return await db.prepare(sql).bind(...params).run(); }
async function dbBatch(db, statements) { return await db.batch(statements); }
function cents(v) { const n=Number(v); if(!Number.isFinite(n)||n<=0) throw new Error('金额必须大于 0'); return Math.round(n*100); }
function money(v) { return Math.round(Number(v)*100)/100; }
function merchantNo(){ return 'PH'+Date.now().toString().slice(-8)+Math.floor(Math.random()*90+10); }
function orderNo(){ return 'PHO'+Date.now().toString()+Math.floor(Math.random()*900+100); }
function randomToken(prefix){ return `${prefix}_${crypto.randomUUID().replaceAll('-','')}`; }
function mask(v){ const x=String(v||''); return x.length<=4?(x?'****':''):'*'.repeat(x.length-4)+x.slice(-4); }

const CHANNEL_META = {
  mock:{name:'Mock 测试支付',fields:[]},
  wechat:{name:'微信支付',fields:['mchId','appId','apiV3Key','serialNo']},
  alipay:{name:'支付宝',fields:['appId','merchantPrivateKey','alipayPublicKey']},
  bankcard:{name:'银行卡支付',fields:['provider','merchantId','apiKey','apiSecret']},
  usdt_trc20:{name:'USDT TRC20',fields:['provider','walletAddress','apiKey','apiSecret']}
};

function publicMerchant(m){ return {
  id:m.id, merchantNo:m.merchant_no, email:m.email, name:m.name, status:m.status,
  balance:(Number(m.balance_cents||0)/100).toFixed(2), frozen:(Number(m.frozen_cents||0)/100).toFixed(2), createdAt:m.created_at,
  kycStatus:m.kyc_status, riskLevel:m.risk_level
}; }
function formatOrder(o){ return {id:o.id,orderNo:o.order_no,merchantOrderNo:o.merchant_order_no,amount:(Number(o.amount_cents)/100).toFixed(2),currency:o.currency,channel:o.channel,subject:o.subject,status:o.status,payUrl:o.pay_url,expiredAt:o.expired_at,paidAt:o.paid_at,createdAt:o.created_at,updatedAt:o.updated_at}; }

async function ensureBootstrap(db, env) {
  // Seed admin once. Password can be changed later by replacing ADMIN_* configuration.
  const email = (env.ADMIN_EMAIL || 'admin@payhub.local').toLowerCase();
  const exists = await dbFirst(db, 'SELECT id FROM admin_users WHERE email=?', [email]);
  if (!exists) {
    const hash = await passwordHash(env.ADMIN_PASSWORD || 'Admin123!');
    await dbRun(db, 'INSERT OR IGNORE INTO admin_users(email,password_hash,name,status) VALUES(?,?,?,?)', [email,hash,'PayHub Admin','active']);
  }
}

async function merchantAuth(req, env, db) {
  const h=req.headers.get('authorization')||''; if(!h.startsWith('Bearer ')) return null;
  try { const p=await jwtVerify(h.slice(7),env.JWT_SECRET||'change-this-secret'); if(p.role==='admin') return null; const m=await dbFirst(db,'SELECT * FROM merchants WHERE id=?',[p.id]); return m||null; } catch { return null; }
}
async function adminAuth(req, env, db) {
  const h=req.headers.get('authorization')||''; if(!h.startsWith('Bearer ')) return null;
  try { const p=await jwtVerify(h.slice(7),env.JWT_SECRET||'change-this-secret'); if(p.role!=='admin') return null; return await dbFirst(db,'SELECT id,email,name,status FROM admin_users WHERE id=?',[p.id]); } catch { return null; }
}
async function requireMerchantApi(req, env, db) {
  const key=req.headers.get('x-payhub-key')||''; const ts=req.headers.get('x-payhub-timestamp')||''; const nonce=req.headers.get('x-payhub-nonce')||''; const sig=req.headers.get('x-payhub-signature')||'';
  if(!key||!ts||!nonce||!sig) return null;
  const c=await dbFirst(db,'SELECT * FROM merchant_api_credentials WHERE api_key=? AND enabled=1',[key]); if(!c) return null;
  const now=Math.floor(Date.now()/1000); if(Math.abs(now-Number(ts))>300) return null;
  const body=await req.clone().text(); const expected=b64u(await hmac(c.api_secret_hash,`${ts}.${nonce}.${body}`));
  if(expected!==sig) return null;
  const m=await dbFirst(db,'SELECT * FROM merchants WHERE id=?',[c.merchant_id]); return m?{merchant:m,credential:c}:null;
}

async function riskDecision(db, merchantId, amountCents) {
  const m=await dbFirst(db,'SELECT * FROM merchants WHERE id=?',[merchantId]);
  if(!m) return {ok:false,reason:'merchant_not_found'};
  if(m.status!=='active') return {ok:false,reason:'merchant_not_active'};
  const r=await dbFirst(db,'SELECT * FROM merchant_risk_profiles WHERE merchant_id=?',[merchantId]);
  const profile=r || {daily_limit_cents:m.daily_limit_cents||100000000,single_limit_cents:m.single_limit_cents||10000000,velocity_count:20,velocity_window_minutes:10,blacklist:0};
  if(Number(m.risk_level)==='high' || m.risk_level==='high' || Number(profile.blacklist)===1) return {ok:false,reason:'merchant_risk_blocked'};
  const rule=await dbFirst(db,'SELECT * FROM risk_rules WHERE rule_code=?',['single_limit']); if(!rule || rule.enabled){ if(amountCents>Number(profile.single_limit_cents)) return {ok:false,reason:'single_limit_exceeded',limit:Number(profile.single_limit_cents)}; }
  const today=new Date().toISOString().slice(0,10);
  const daily=await dbFirst(db,"SELECT COALESCE(SUM(amount_cents),0) s FROM orders WHERE merchant_id=? AND status IN ('paid','pending','partially_refunded','refunded') AND substr(created_at,1,10)=?",[merchantId,today]);
  if(Number(daily?.s||0)+amountCents>Number(profile.daily_limit_cents)) return {ok:false,reason:'daily_limit_exceeded',limit:Number(profile.daily_limit_cents)};
  const recent=await dbFirst(db,"SELECT COUNT(*) c FROM orders WHERE merchant_id=? AND created_at>=datetime('now',?)",[merchantId,`-${Number(profile.velocity_window_minutes)} minutes`]);
  if(Number(recent?.c||0)>=Number(profile.velocity_count)) return {ok:false,reason:'velocity_limit_exceeded'};
  return {ok:true};
}

async function handleApi(req, env, db, url) {
  const path=url.pathname, method=req.method.toUpperCase();
  await ensureBootstrap(db,env);

  if(path==='/api/health' && method==='GET') return json({ok:true,service:'PayHub',version:'14.0.0',runtime:'Cloudflare Workers + D1'});

  if(path==='/api/auth/register' && method==='POST') {
    const b=await bodyJson(req); const email=String(b.email||'').trim().toLowerCase(), password=String(b.password||''), name=String(b.name||'PayHub 商户').trim()||'PayHub 商户';
    if(!email||password.length<6) return json({message:'邮箱和至少 6 位密码为必填项'},400);
    if(await dbFirst(db,'SELECT id FROM merchants WHERE email=?',[email])) return json({message:'该邮箱已注册'},409);
    const hash=await passwordHash(password), no=merchantNo();
    const r=await dbRun(db,'INSERT INTO merchants(merchant_no,email,password_hash,name) VALUES(?,?,?,?)',[no,email,hash,name]);
    const m=await dbFirst(db,'SELECT * FROM merchants WHERE id=?',[r.meta.last_row_id]);
    const token=await jwtSign({id:m.id,email:m.email},env.JWT_SECRET||'change-this-secret');
    return json({message:'注册成功',token,user:publicMerchant(m)});
  }
  if(path==='/api/auth/login' && method==='POST') {
    const b=await bodyJson(req), email=String(b.email||'').trim().toLowerCase(); const m=await dbFirst(db,'SELECT * FROM merchants WHERE email=?',[email]);
    if(!m||!(await passwordCompare(String(b.password||''),m.password_hash))) return json({message:'邮箱或密码错误'},401);
    if(m.status!=='active') return json({message:'商户账号已被停用'},403);
    const token=await jwtSign({id:m.id,email:m.email},env.JWT_SECRET||'change-this-secret'); return json({message:'登录成功',token,user:publicMerchant(m)});
  }
  if(path==='/api/auth/me' && method==='GET') { const m=await merchantAuth(req,env,db); if(!m)return json({message:'登录已过期，请重新登录'},401); return json({user:publicMerchant(m)}); }

  const m=await merchantAuth(req,env,db);
  if(path==='/api/dashboard/stats' && method==='GET') {
    if(!m)return json({message:'未登录'},401); const total=await dbFirst(db,"SELECT COALESCE(SUM(amount_cents),0) s FROM orders WHERE merchant_id=? AND status='paid'",[m.id]); const pending=await dbFirst(db,"SELECT COUNT(*) c FROM orders WHERE merchant_id=? AND status='pending'",[m.id]); const count=await dbFirst(db,'SELECT COUNT(*) c FROM orders WHERE merchant_id=?',[m.id]); const paid=await dbFirst(db,"SELECT COUNT(*) c FROM orders WHERE merchant_id=? AND status='paid'",[m.id]); const fresh=await dbFirst(db,'SELECT * FROM merchants WHERE id=?',[m.id]);
    return json({balance:(fresh.balance_cents/100).toFixed(2),totalPaid:(Number(total.s)/100).toFixed(2),orderCount:Number(count.c),pendingCount:Number(pending.c),paidCount:Number(paid.c)});
  }
  if(path==='/api/orders' && method==='POST') {
    if(!m)return json({message:'未登录'},401); const b=await bodyJson(req); if(!b.merchantOrderNo)return json({message:'merchantOrderNo 必填'},400); let amount; try{amount=cents(b.amount)}catch(e){return json({message:e.message},400)};
    if(await dbFirst(db,'SELECT * FROM orders WHERE merchant_id=? AND merchant_order_no=?',[m.id,String(b.merchantOrderNo)])) return json({message:'商户订单号已存在'},409);
    const risk=await riskDecision(db,m.id,amount); if(!risk.ok)return json({message:`风控拦截: ${risk.reason}`,risk},403);
    const no=orderNo(), expired=new Date(Date.now()+Math.max(1,Number(b.expiresMinutes)||30)*60000).toISOString(), payUrl=`/checkout/${no}`;
    const r=await dbRun(db,`INSERT INTO orders(order_no,merchant_id,merchant_order_no,amount_cents,currency,channel,subject,pay_url,expired_at,payment_method,return_url,notify_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,[no,m.id,String(b.merchantOrderNo),amount,String(b.currency||'CNY'),String(b.channel||'mock'),String(b.subject||'PayHub 订单'),payUrl,expired,String(b.channel||'mock'),String(b.returnUrl||''),String(b.notifyUrl||'')]);
    const o=await dbFirst(db,'SELECT * FROM orders WHERE id=?',[r.meta.last_row_id]); return json({message:'订单创建成功',order:formatOrder(o)});
  }
  if(path==='/api/orders' && method==='GET') {
    if(!m)return json({message:'未登录'},401); const page=Math.max(1,Number(url.searchParams.get('page')||1)), pageSize=Math.min(100,Math.max(1,Number(url.searchParams.get('pageSize')||20))), status=url.searchParams.get('status');
    const where=status?' AND status=?':''; const p=status?[m.id,status]:[m.id]; const total=await dbFirst(db,`SELECT COUNT(*) c FROM orders WHERE merchant_id=?${where}`,p); const rows=await dbAll(db,`SELECT * FROM orders WHERE merchant_id=?${where} ORDER BY id DESC LIMIT ? OFFSET ?`,[...p,pageSize,(page-1)*pageSize]); return json({data:rows.map(formatOrder),total:Number(total.c),page,pageSize});
  }
  const om=path.match(/^\/api\/orders\/([^/]+)$/); if(om && method==='GET'){ if(!m)return json({message:'未登录'},401); const o=await dbFirst(db,'SELECT * FROM orders WHERE order_no=? AND merchant_id=?',[om[1],m.id]); if(!o)return json({message:'订单不存在'},404); return json({order:formatOrder(o)}); }
  const mock=path.match(/^\/api\/orders\/([^/]+)\/mock-pay$/); if(mock&&method==='POST'){ if(!m)return json({message:'未登录'},401); return await markPaid(db,m.id,mock[1],'Mock 测试支付'); }

  const co=path.match(/^\/api\/checkout\/([^/]+)$/); if(co&&method==='GET'){ const o=await dbFirst(db,'SELECT * FROM orders WHERE order_no=?',[co[1]]); if(!o)return json({message:'订单不存在'},404); return json({order:{...formatOrder(o),merchantName:(await dbFirst(db,'SELECT name FROM merchants WHERE id=?',[o.merchant_id]))?.name||''}}); }
  if(co&&method==='POST'){ const b=await bodyJson(req); const o=await dbFirst(db,'SELECT * FROM orders WHERE order_no=?',[co[1]]); if(!o)return json({message:'订单不存在'},404); if(o.status==='paid')return json({message:'订单已支付',order:formatOrder(o)}); if(String(b.channel||'mock')!=='mock')return json({message:'该通道尚未连接官方/授权服务商'},409); return await markPaid(db,o.merchant_id,o.order_no,'Checkout Mock 支付入账'); }

  if(path==='/api/wallet/transactions'&&method==='GET'){ if(!m)return json({message:'未登录'},401); const rows=await dbAll(db,'SELECT * FROM wallet_transactions WHERE merchant_id=? ORDER BY id DESC LIMIT 300',[m.id]); return json({items:rows}); }
  if(path==='/api/merchant/transactions'&&method==='GET'){ if(!m)return json({message:'未登录'},401); const rows=await dbAll(db,'SELECT * FROM wallet_ledger WHERE merchant_id=? ORDER BY id DESC LIMIT 300',[m.id]); return json({items:rows}); }
  if(path==='/api/merchant/balance'&&method==='GET'){ if(!m)return json({message:'未登录'},401); const x=await dbFirst(db,'SELECT balance_cents,frozen_cents FROM merchants WHERE id=?',[m.id]); return json({balance:Number(x.balance_cents)/100,frozen:Number(x.frozen_cents)/100}); }

  if(path==='/api/api-keys'&&method==='GET'){ if(!m)return json({message:'未登录'},401); const rows=await dbAll(db,'SELECT id,key_id,name,status,created_at,last_used_at FROM api_keys WHERE merchant_id=? ORDER BY id DESC',[m.id]); return json({items:rows}); }
  if(path==='/api/api-keys'&&method==='POST'){ if(!m)return json({message:'未登录'},401); const b=await bodyJson(req), key=randomToken('phk'), secret=randomToken('phs'); const hash=await sha256Hex(secret); const r=await dbRun(db,'INSERT INTO api_keys(merchant_id,key_id,secret_hash,name) VALUES(?,?,?,?)',[m.id,key,hash,String(b.name||'Default API Key')]); return json({id:r.meta.last_row_id,keyId:key,secret,warning:'Secret 仅显示一次，请立即保存'}); }

  if(path==='/api/developer/credentials'&&method==='GET'){ if(!m)return json({message:'未登录'},401); let c=await dbFirst(db,'SELECT * FROM merchant_api_credentials WHERE merchant_id=?',[m.id]); if(!c){ const apiKey=randomToken('phk'), secret=randomToken('phs'); const sh=await sha256Hex(secret); await dbRun(db,'INSERT INTO merchant_api_credentials(merchant_id,api_key,api_secret_hash) VALUES(?,?,?)',[m.id,apiKey,sh]); c=await dbFirst(db,'SELECT * FROM merchant_api_credentials WHERE merchant_id=?',[m.id]); return json({apiKey:c.api_key,apiSecret:secret,enabled:Boolean(c.enabled),newSecret:true}); } return json({apiKey:c.api_key,enabled:Boolean(c.enabled),apiSecretMasked:'********'}); }
  if(path==='/api/developer/credentials/rotate'&&method==='POST'){ if(!m)return json({message:'未登录'},401); const apiKey=randomToken('phk'), secret=randomToken('phs'), sh=await sha256Hex(secret); await dbRun(db,'INSERT INTO merchant_api_credentials(merchant_id,api_key,api_secret_hash,enabled,created_at,updated_at) VALUES(?,?,?,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT(merchant_id) DO UPDATE SET api_key=excluded.api_key,api_secret_hash=excluded.api_secret_hash,enabled=1,updated_at=CURRENT_TIMESTAMP',[m.id,apiKey,sh]); return json({ok:true,apiKey,apiSecret:secret}); }
  if(path==='/api/developer/credentials/toggle'&&method==='POST'){ if(!m)return json({message:'未登录'},401); const b=await bodyJson(req); await dbRun(db,'UPDATE merchant_api_credentials SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE merchant_id=?',[b.enabled?1:0,m.id]); return json({ok:true,enabled:Boolean(b.enabled)}); }

  if(path==='/api/payment-channels'&&method==='GET'){ if(!m)return json({message:'未登录'},401); const rows=await dbAll(db,'SELECT * FROM payment_channels WHERE merchant_id=? ORDER BY id',[m.id]); const map=new Map(rows.map(x=>[x.channel_code,x])); return json({items:Object.entries(CHANNEL_META).map(([code,meta])=>{const x=map.get(code); return {code,name:meta.name,fields:meta.fields,enabled:Boolean(x?.enabled),config:x?JSON.parse(x.config_json||'{}'): {},webhookUrl:x?.webhook_url||''};})}); }
  const pc=path.match(/^\/api\/payment-channels\/([^/]+)$/); if(pc&&method==='PUT'){ if(!m)return json({message:'未登录'},401); const code=pc[1]; if(!CHANNEL_META[code])return json({message:'通道不存在'},404); const b=await bodyJson(req); const config=JSON.stringify(b.config||{}); await dbRun(db,`INSERT INTO payment_channels(merchant_id,channel_code,display_name,enabled,config_json,webhook_url,callback_secret) VALUES(?,?,?,?,?,?,?) ON CONFLICT(merchant_id,channel_code) DO UPDATE SET enabled=excluded.enabled,config_json=excluded.config_json,webhook_url=excluded.webhook_url,callback_secret=excluded.callback_secret,updated_at=CURRENT_TIMESTAMP`,[m.id,code,CHANNEL_META[code].name,b.enabled?1:0,config,String(b.webhookUrl||''),String(b.callbackSecret||'')]); return json({ok:true}); }
  const pct=path.match(/^\/api\/payment-channels\/([^/]+)\/test$/); if(pct&&method==='POST'){ if(!m)return json({message:'未登录'},401); const code=pct[1]; if(code==='mock')return json({ok:true,message:'Mock 通道可用'}); return json({ok:false,message:'该通道仅完成配置框架，尚未连接官方/授权服务商'},409); }

  if(path==='/api/webhooks/logs'&&method==='GET'){ if(!m)return json({message:'未登录'},401); return json({items:await dbAll(db,'SELECT * FROM webhook_logs WHERE merchant_id=? ORDER BY id DESC LIMIT 300',[m.id])}); }
  if(path==='/api/webhooks/deliveries'&&method==='GET'){ if(!m)return json({message:'未登录'},401); return json({items:await dbAll(db,'SELECT * FROM webhook_deliveries WHERE merchant_id=? ORDER BY id DESC LIMIT 300',[m.id])}); }
  const wr=path.match(/^\/api\/webhooks\/deliveries\/(\d+)\/retry$/); if(wr&&method==='POST'){ if(!m)return json({message:'未登录'},401); const d=await dbFirst(db,'SELECT * FROM webhook_deliveries WHERE id=? AND merchant_id=?',[wr[1],m.id]); if(!d)return json({message:'记录不存在'},404); await dbRun(db,"UPDATE webhook_deliveries SET status='pending',attempts=attempts+1,next_retry_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?",[d.id]); return json({ok:true,status:'pending'}); }
  if(path==='/api/webhooks/signature-preview'&&method==='POST'){ if(!m)return json({message:'未登录'},401); const b=await bodyJson(req), secret=String(b.secret||'demo-secret'), payload=String(b.payload||'{}'); return json({signature:hex(await hmac(secret,payload)),algorithm:'HMAC-SHA256'}); }

  if(path==='/api/merchant/fee-config'&&method==='GET'){ if(!m)return json({message:'未登录'},401); let x=await dbFirst(db,'SELECT * FROM merchant_fee_configs WHERE merchant_id=?',[m.id]); if(!x){await dbRun(db,'INSERT OR IGNORE INTO merchant_fee_configs(merchant_id) VALUES(?)',[m.id]);x=await dbFirst(db,'SELECT * FROM merchant_fee_configs WHERE merchant_id=?',[m.id]);} return json({paymentFeeRate:x.payment_fee_rate,refundFeeRate:x.refund_fee_rate,settlementFeeRate:x.settlement_fee_rate}); }
  if(path==='/api/merchant/fee-config'&&method==='PUT'){ if(!m)return json({message:'未登录'},401); const b=await bodyJson(req), p=Number(b.paymentFeeRate),r=Number(b.refundFeeRate),s=Number(b.settlementFeeRate); if([p,r,s].some(x=>!Number.isFinite(x)||x<0||x>0.2))return json({error:'invalid_fee_rate'},400); await dbRun(db,'INSERT INTO merchant_fee_configs(merchant_id,payment_fee_rate,refund_fee_rate,settlement_fee_rate) VALUES(?,?,?,?) ON CONFLICT(merchant_id) DO UPDATE SET payment_fee_rate=excluded.payment_fee_rate,refund_fee_rate=excluded.refund_fee_rate,settlement_fee_rate=excluded.settlement_fee_rate,updated_at=CURRENT_TIMESTAMP',[m.id,p,r,s]); return json({ok:true,paymentFeeRate:p,refundFeeRate:r,settlementFeeRate:s}); }

  const close=path.match(/^\/api\/orders\/([^/]+)\/close$/); if(close&&method==='POST'){ if(!m)return json({message:'未登录'},401); const o=await dbFirst(db,'SELECT * FROM orders WHERE order_no=? AND merchant_id=?',[close[1],m.id]); if(!o)return json({error:'order_not_found'},404); if(o.status!=='pending')return json({error:'order_not_closable'},400); await dbRun(db,"UPDATE orders SET status='closed',updated_at=CURRENT_TIMESTAMP WHERE id=?",[o.id]); return json({ok:true,orderNo:o.order_no,status:'closed'}); }
  const refund=path.match(/^\/api\/orders\/([^/]+)\/refund$/); if(refund&&method==='POST'){ if(!m)return json({message:'未登录'},401); return await doRefund(db,m,refund[1],await bodyJson(req)); }
  if(path==='/api/refunds'&&method==='GET'){ if(!m)return json({message:'未登录'},401); return json({items:await dbAll(db,'SELECT * FROM refunds WHERE merchant_id=? ORDER BY id DESC LIMIT 200',[m.id])}); }
  if(path==='/api/settlements'&&method==='POST'){ if(!m)return json({message:'未登录'},401); return await createSettlement(db,m,await bodyJson(req)); }
  if(path==='/api/settlements'&&method==='GET'){ if(!m)return json({message:'未登录'},401); return json({items:await dbAll(db,'SELECT * FROM settlements WHERE merchant_id=? ORDER BY id DESC LIMIT 200',[m.id])}); }
  const sc=path.match(/^\/api\/settlements\/([^/]+)\/cancel$/); if(sc&&method==='POST'){ if(!m)return json({message:'未登录'},401); return await cancelSettlement(db,m,sc[1]); }

  if(path==='/api/v1/docs'&&method==='GET') return json({name:'PayHub Merchant API V1',version:'14.0.0',signature:'X-PayHub-Key/Timestamp/Nonce/Signature',endpoints:['POST /api/v1/orders','GET /api/v1/orders/:orderNo']});
  if(path==='/api/v1/orders'&&method==='POST'){ const a=await requireMerchantApi(req,env,db); if(!a)return json({error:'invalid_signature'},401); const b=await bodyJson(req); if(!b.merchantOrderNo)return json({error:'merchantOrderNo_required'},400); let amount; try{amount=cents(b.amount)}catch(e){return json({error:e.message},400)}; const risk=await riskDecision(db,a.merchant.id,amount); if(!risk.ok)return json({error:'risk_blocked',risk},403); if(await dbFirst(db,'SELECT id FROM orders WHERE merchant_id=? AND merchant_order_no=?',[a.merchant.id,String(b.merchantOrderNo)]))return json({error:'duplicate_merchant_order_no'},409); const no=orderNo(), expired=new Date(Date.now()+30*60000).toISOString(); const r=await dbRun(db,'INSERT INTO orders(order_no,merchant_id,merchant_order_no,amount_cents,currency,channel,subject,pay_url,expired_at,payment_method,notify_url,return_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',[no,a.merchant.id,String(b.merchantOrderNo),amount,String(b.currency||'CNY'),String(b.channel||'mock'),String(b.subject||'PayHub API Order'),`/checkout/${no}`,expired,String(b.channel||'mock'),String(b.notifyUrl||''),String(b.returnUrl||'')]); const o=await dbFirst(db,'SELECT * FROM orders WHERE id=?',[r.meta.last_row_id]); return json({order:formatOrder(o)}); }
  const v1=path.match(/^\/api\/v1\/orders\/([^/]+)$/); if(v1&&method==='GET'){ const a=await requireMerchantApi(req,env,db); if(!a)return json({error:'invalid_signature'},401); const o=await dbFirst(db,'SELECT * FROM orders WHERE order_no=? AND merchant_id=?',[v1[1],a.merchant.id]); if(!o)return json({error:'order_not_found'},404); return json({order:formatOrder(o)}); }

  // Admin
  if(path==='/api/admin/login'&&method==='POST'){ const b=await bodyJson(req), email=String(b.email||'').trim().toLowerCase(), a=await dbFirst(db,'SELECT * FROM admin_users WHERE email=?',[email]); if(!a||a.status!=='active'||!(await passwordCompare(String(b.password||''),a.password_hash)))return json({message:'管理员账号或密码错误'},401); const token=await jwtSign({id:a.id,email:a.email,role:'admin'},env.JWT_SECRET||'change-this-secret',28800); return json({message:'登录成功',token,admin:{id:a.id,email:a.email,name:a.name}}); }
  const admin=await adminAuth(req,env,db);
  if(path.startsWith('/api/admin/')){
    if(!admin)return json({message:'未登录或管理员登录已过期'},401);
    if(path==='/api/admin/me'&&method==='GET')return json({admin});
    if(path==='/api/admin/stats'&&method==='GET'){ const merchants=await dbFirst(db,'SELECT COUNT(*) c FROM merchants'),active=await dbFirst(db,"SELECT COUNT(*) c FROM merchants WHERE status='active'"),orders=await dbFirst(db,'SELECT COUNT(*) c FROM orders'),paid=await dbFirst(db,"SELECT COALESCE(SUM(amount_cents),0) s FROM orders WHERE status='paid'"),ps=await dbFirst(db,"SELECT COALESCE(SUM(amount),0) s FROM settlements WHERE status='pending'"),risk=await dbFirst(db,"SELECT COUNT(*) c FROM merchant_risk_flags WHERE status='open'"); return json({merchants:Number(merchants.c),active:Number(active.c),orders:Number(orders.c),totalPaid:(Number(paid.s)/100).toFixed(2),pendingSettlement:Number(ps.s).toFixed(2),openRisk:Number(risk.c)}); }
    if(path==='/api/admin/merchants'&&method==='GET'){ const rows=await dbAll(db,'SELECT id,merchant_no,email,name,status,balance_cents,frozen_cents,kyc_status,risk_level,created_at FROM merchants ORDER BY id DESC LIMIT 500'); return json({items:rows.map(x=>({...x,balance:(x.balance_cents/100).toFixed(2),frozen:(x.frozen_cents/100).toFixed(2)}))}); }
    const ms=path.match(/^\/api\/admin\/merchants\/(\d+)\/status$/); if(ms&&method==='POST'){ const b=await bodyJson(req); if(!['active','suspended','pending'].includes(String(b.status)))return json({message:'无效状态'},400); const x=await dbFirst(db,'SELECT * FROM merchants WHERE id=?',[ms[1]]); if(!x)return json({message:'商户不存在'},404); await dbRun(db,'UPDATE merchants SET status=? WHERE id=?',[b.status,x.id]); await audit(db,admin.id,'merchant_status','merchant',x.id,String(b.status)); return json({ok:true,status:b.status}); }
    const mr=path.match(/^\/api\/admin\/merchants\/(\d+)\/risk$/); if(mr&&method==='POST'){ const b=await bodyJson(req),x=await dbFirst(db,'SELECT id FROM merchants WHERE id=?',[mr[1]]); if(!x)return json({message:'商户不存在'},404); const level=['low','medium','high'].includes(b.level)?b.level:'medium'; const r=await dbRun(db,'INSERT INTO merchant_risk_flags(merchant_id,level,reason) VALUES(?,?,?)',[x.id,level,String(b.reason||'管理员标记')]); await audit(db,admin.id,'risk_flag','merchant',x.id,`${level}:${b.reason||''}`); return json({ok:true,id:r.meta.last_row_id}); }
    if(path==='/api/admin/orders'&&method==='GET'){ const rows=await dbAll(db,`SELECT o.order_no,o.merchant_order_no,o.amount_cents,o.currency,o.channel,o.subject,o.status,o.created_at,o.paid_at,m.merchant_no,m.name merchant_name FROM orders o JOIN merchants m ON m.id=o.merchant_id ORDER BY o.id DESC LIMIT 500`); return json({items:rows.map(x=>({...x,amount:(x.amount_cents/100).toFixed(2)}))}); }
    if(path==='/api/admin/settlements'&&method==='GET')return json({items:await dbAll(db,`SELECT s.*,m.merchant_no,m.name merchant_name FROM settlements s JOIN merchants m ON m.id=s.merchant_id ORDER BY s.id DESC LIMIT 300`)});
    const sr=path.match(/^\/api\/admin\/settlements\/([^/]+)\/review$/); if(sr&&method==='POST'){ const b=await bodyJson(req),s=await dbFirst(db,'SELECT * FROM settlements WHERE settlement_no=?',[sr[1]]); if(!s)return json({message:'结算单不存在'},404); if(s.status!=='pending')return json({message:'结算单不是待审核状态'},400); if(b.action==='approve')await dbRun(db,"UPDATE settlements SET status='approved',processed_at=CURRENT_TIMESTAMP WHERE id=?",[s.id]); else if(b.action==='reject'){const mm=await dbFirst(db,'SELECT * FROM merchants WHERE id=?',[s.merchant_id]); const after=Number(mm.balance_cents)+Math.round(Number(s.amount)*100); await dbBatch(db,[db.prepare("UPDATE settlements SET status='rejected',processed_at=CURRENT_TIMESTAMP WHERE id=?").bind(s.id),db.prepare('UPDATE merchants SET balance_cents=? WHERE id=?').bind(after,mm.id),db.prepare('INSERT INTO wallet_transactions(merchant_id,type,amount_cents,balance_after_cents,reference_no,remark) VALUES(?,?,?,?,?,?)').bind(mm.id,'settlement_reversal',Math.round(Number(s.amount)*100),after,'ADMREV'+s.id,'管理员拒绝结算，退回余额')]);} else return json({message:'action 只能是 approve 或 reject'},400); await audit(db,admin.id,'settlement_review','settlement',s.settlement_no,String(b.action)); return json({ok:true,status:b.action==='approve'?'approved':'rejected'}); }
    if(path==='/api/admin/risk-flags'&&method==='GET')return json({items:await dbAll(db,`SELECT r.*,m.merchant_no,m.name merchant_name FROM merchant_risk_flags r JOIN merchants m ON m.id=r.merchant_id ORDER BY r.id DESC LIMIT 300`)});
    if(path==='/api/admin/audit-logs'&&method==='GET')return json({items:await dbAll(db,'SELECT * FROM admin_audit_logs ORDER BY id DESC LIMIT 300')});
    if(path==='/api/admin/reconciliation/run'&&method==='POST'){ const runNo=randomToken('REC'), summary={orders:await dbFirst(db,'SELECT COUNT(*) c FROM orders'),merchants:await dbFirst(db,'SELECT COUNT(*) c FROM merchants')}; await dbRun(db,'INSERT INTO reconciliation_runs(run_no,scope,result,summary_json) VALUES(?,?,?,?)',[runNo,'all','ok',JSON.stringify(summary)]); await audit(db,admin.id,'reconciliation','run',runNo,'manual'); return json({ok:true,runNo,summary}); }
    if(path==='/api/admin/kyc/pending'&&method==='GET')return json({items:await dbAll(db,"SELECT id,merchant_no,name,email,merchant_type,legal_name,contact_name,contact_phone,kyc_status,kyc_note,created_at FROM merchants WHERE kyc_status='pending' ORDER BY id DESC LIMIT 300")});
    const kd=path.match(/^\/api\/admin\/merchants\/(\d+)\/detail$/); if(kd&&method==='GET'){ const x=await dbFirst(db,'SELECT * FROM merchants WHERE id=?',[kd[1]]); if(!x)return json({message:'商户不存在'},404); const r=await dbFirst(db,'SELECT * FROM merchant_risk_profiles WHERE merchant_id=?',[x.id]); return json({...x,balance:x.balance_cents/100,frozen:x.frozen_cents/100,dailyLimit:x.daily_limit_cents/100,singleLimit:x.single_limit_cents/100,risk:r}); }
    const kr=path.match(/^\/api\/admin\/merchants\/(\d+)\/kyc-review$/); if(kr&&method==='POST'){ const b=await bodyJson(req),x=await dbFirst(db,'SELECT id FROM merchants WHERE id=?',[kr[1]]); if(!x)return json({message:'商户不存在'},404); if(!['approve','reject','pending'].includes(String(b.action)))return json({message:'无效审核动作'},400); const st=b.action==='approve'?'approved':b.action==='reject'?'rejected':'pending'; await dbBatch(db,[db.prepare('UPDATE merchants SET kyc_status=?,kyc_note=? WHERE id=?').bind(st,String(b.note||''),x.id),db.prepare('INSERT INTO kyc_reviews(merchant_id,action,note,admin_id) VALUES(?,?,?,?)').bind(x.id,b.action,String(b.note||''),admin.id),db.prepare('INSERT INTO admin_audit_logs(admin_id,action,target_type,target_id,detail) VALUES(?,?,?,?,?)').bind(admin.id,'kyc_review','merchant',String(x.id),`${b.action}:${b.note||''}`)]); return json({ok:true,kycStatus:st}); }
    const rp=path.match(/^\/api\/admin\/merchants\/(\d+)\/risk-profile$/); if(rp&&method==='PUT'){ const b=await bodyJson(req),x=await dbFirst(db,'SELECT * FROM merchants WHERE id=?',[rp[1]]); if(!x)return json({message:'商户不存在'},404); const daily=Math.round(Number(b.dailyLimit||0)*100),single=Math.round(Number(b.singleLimit||0)*100),count=Math.max(1,Math.floor(Number(b.velocityCount||20))),win=Math.max(1,Math.floor(Number(b.velocityWindowMinutes||10))),blacklist=b.blacklist?1:0; if(daily<=0||single<=0)return json({message:'限额必须大于0'},400); await dbRun(db,'INSERT INTO merchant_risk_profiles(merchant_id,daily_limit_cents,single_limit_cents,velocity_count,velocity_window_minutes,blacklist) VALUES(?,?,?,?,?,?) ON CONFLICT(merchant_id) DO UPDATE SET daily_limit_cents=excluded.daily_limit_cents,single_limit_cents=excluded.single_limit_cents,velocity_count=excluded.velocity_count,velocity_window_minutes=excluded.velocity_window_minutes,blacklist=excluded.blacklist,updated_at=CURRENT_TIMESTAMP',[x.id,daily,single,count,win,blacklist]); await dbRun(db,'UPDATE merchants SET daily_limit_cents=?,single_limit_cents=? WHERE id=?',[daily,single,x.id]); await audit(db,admin.id,'risk_profile','merchant',x.id,JSON.stringify({daily,single,count,win,blacklist})); return json({ok:true}); }
    if(path==='/api/admin/risk-rules'&&method==='GET')return json({items:await dbAll(db,'SELECT * FROM risk_rules ORDER BY id')});
    const rr=path.match(/^\/api\/admin\/risk-rules\/([^/]+)$/); if(rr&&method==='PUT'){ const b=await bodyJson(req),x=await dbFirst(db,'SELECT * FROM risk_rules WHERE rule_code=?',[rr[1]]); if(!x)return json({message:'规则不存在'},404); await dbRun(db,'UPDATE risk_rules SET enabled=?,config_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',[b.enabled?1:0,JSON.stringify(b.config||{}),x.id]); await audit(db,admin.id,'risk_rule','rule',x.rule_code,JSON.stringify(b)); return json({ok:true}); }
    if(path==='/api/admin/financial-summary'&&method==='GET'){ const x=await dbFirst(db,"SELECT COALESCE(SUM(CASE WHEN status='paid' THEN amount_cents ELSE 0 END),0) paid,COALESCE(SUM(CASE WHEN status IN ('refunded','partially_refunded') THEN amount_cents ELSE 0 END),0) refundBase FROM orders"),bal=await dbFirst(db,'SELECT COALESCE(SUM(balance_cents),0) s FROM merchants'),frozen=await dbFirst(db,'SELECT COALESCE(SUM(frozen_cents),0) s FROM merchants'),fees=await dbFirst(db,'SELECT COALESCE(SUM(fee),0) s FROM wallet_ledger WHERE fee>0'),settle=await dbFirst(db,"SELECT COALESCE(SUM(amount),0) s FROM settlements WHERE status IN ('pending','approved','processing')"); return json({paid:x.paid/100,refundBase:x.refundBase/100,merchantBalances:bal.s/100,frozen:frozen.s/100,fees:Number(fees.s),pendingSettlements:Number(settle.s)}); }
  }
  return null;
}

async function audit(db,adminId,action,targetType,targetId,detail){ await dbRun(db,'INSERT INTO admin_audit_logs(admin_id,action,target_type,target_id,detail) VALUES(?,?,?,?,?)',[adminId,action,targetType,String(targetId),detail||'']); }
async function markPaid(db,merchantId,orderNoValue,remark){
  const o=await dbFirst(db,'SELECT * FROM orders WHERE order_no=? AND merchant_id=?',[orderNoValue,merchantId]); if(!o)return json({message:'订单不存在'},404); if(o.status==='paid')return json({message:'订单已支付',order:formatOrder(o)}); if(o.status!=='pending')return json({message:'订单当前不可支付'},400);
  const m=await dbFirst(db,'SELECT * FROM merchants WHERE id=?',[merchantId]); const nb=Number(m.balance_cents)+Number(o.amount_cents), ref='TX'+crypto.randomUUID().replaceAll('-','').slice(0,20);
  const payload=JSON.stringify({event:'order.paid',orderNo:o.order_no,amount:Number(o.amount_cents)/100,status:'paid'});
  const channel=await dbFirst(db,'SELECT * FROM payment_channels WHERE merchant_id=? AND channel_code=?',[merchantId,o.channel]); const webhookUrl=channel?.webhook_url||''; const callbackSecret=channel?.callback_secret||''; const signature=hex(await hmac(callbackSecret||'demo-secret',payload));
  const stmts=[db.prepare("UPDATE orders SET status='paid',paid_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").bind(o.id),db.prepare('UPDATE merchants SET balance_cents=? WHERE id=?').bind(nb,merchantId),db.prepare('INSERT INTO wallet_transactions(merchant_id,order_id,type,amount_cents,balance_after_cents,reference_no,remark) VALUES(?,?,?,?,?,?,?)').bind(merchantId,o.id,'income',o.amount_cents,nb,ref,remark),db.prepare('INSERT INTO wallet_ledger(merchant_id,order_no,type,amount,fee,net_amount,balance_before,balance_after,status,remark) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(merchantId,o.order_no,'income',Number(o.amount_cents)/100,0,Number(o.amount_cents)/100,Number(m.balance_cents)/100,nb/100,'posted',remark)];
  if(webhookUrl) stmts.push(db.prepare('INSERT INTO webhook_deliveries(merchant_id,order_no,event_type,target_url,payload,signature,status) VALUES(?,?,?,?,?,?,?)').bind(merchantId,o.order_no,'order.paid',webhookUrl,payload,signature,'pending'));
  await dbBatch(db,stmts); const updated=await dbFirst(db,'SELECT * FROM orders WHERE id=?',[o.id]); return json({message:'支付成功（Mock 测试环境）',order:formatOrder(updated)});
}
async function doRefund(db,m,orderNoValue,b){
  const o=await dbFirst(db,'SELECT * FROM orders WHERE order_no=? AND merchant_id=?',[orderNoValue,m.id]); if(!o)return json({error:'order_not_found'},404); if(!['paid','partially_refunded'].includes(o.status))return json({error:'order_not_refundable'},400);
  const used=await dbFirst(db,"SELECT COALESCE(SUM(refund_amount),0) total FROM refunds WHERE merchant_id=? AND order_no=? AND status='processed'",[m.id,o.order_no]); const amount=money(b.amount==null?o.amount_cents/100:b.amount), refundable=money(o.amount_cents/100-Number(used.total||0)); if(amount<=0||amount>refundable)return json({error:'invalid_refund_amount',refundable},400);
  const cfg=await dbFirst(db,'SELECT * FROM merchant_fee_configs WHERE merchant_id=?',[m.id]); const fee=money(amount*Number(cfg?.refund_fee_rate||0)), before=Number(m.balance_cents)/100, after=money(before-amount-fee); if(after<0)return json({error:'insufficient_balance_for_refund',balance:before},400); const no=randomToken('RF'), now=new Date().toISOString(); const remain=money(refundable-amount);
  await dbBatch(db,[db.prepare('UPDATE merchants SET balance_cents=? WHERE id=?').bind(Math.round(after*100),m.id),db.prepare("INSERT INTO refunds(merchant_id,order_no,refund_no,refund_amount,fee,status,reason,created_at,processed_at) VALUES(?,?,?,?,?,'processed',?,?,?)").bind(m.id,o.order_no,no,amount,fee,String(b.reason||'merchant_refund'),now,now),db.prepare("INSERT INTO wallet_ledger(merchant_id,order_no,type,amount,fee,net_amount,balance_before,balance_after,status,remark) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(m.id,o.order_no,'refund:'+no,-amount,fee,-amount-fee,before,after,'posted','refund '+no),db.prepare("UPDATE orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(remain<=0?'refunded':'partially_refunded',o.id)]); return json({ok:true,refund:{refundNo:no,orderNo:o.order_no,amount,fee,status:'processed',remainingRefundable:remain},balance:after});
}
async function createSettlement(db,m,b){ const amount=money(b.amount); if(amount<=0)return json({error:'invalid_amount'},400); const before=Number(m.balance_cents)/100; if(amount>before)return json({error:'insufficient_balance',balance:before},400); const cfg=await dbFirst(db,'SELECT * FROM merchant_fee_configs WHERE merchant_id=?',[m.id]); const fee=money(amount*Number(cfg?.settlement_fee_rate||0.005)), net=money(amount-fee), no=randomToken('ST'), after=money(before-amount), now=new Date().toISOString(); await dbBatch(db,[db.prepare('UPDATE merchants SET balance_cents=? WHERE id=?').bind(Math.round(after*100),m.id),db.prepare("INSERT INTO settlements(merchant_id,settlement_no,amount,fee,net_amount,status,bank_name,account_name,account_no_masked,remark,created_at) VALUES(?,?,?,?,?,'pending',?,?,?,?,?)").bind(m.id,no,amount,fee,net,String(b.bankName||''),String(b.accountName||''),mask(b.accountNo||''),String(b.remark||''),now),db.prepare("INSERT INTO wallet_ledger(merchant_id,order_no,type,amount,fee,net_amount,balance_before,balance_after,status,remark) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(m.id,no,'settlement:'+no,-amount,fee,-amount,before,after,'posted','settlement requested '+no)]); return json({ok:true,settlement:{settlementNo:no,amount,fee,netAmount:net,status:'pending'},balance:after}); }
async function cancelSettlement(db,m,no){ const x=await dbFirst(db,'SELECT * FROM settlements WHERE settlement_no=? AND merchant_id=?',[no,m.id]); if(!x)return json({error:'settlement_not_found'},404); if(x.status!=='pending')return json({error:'settlement_not_cancellable'},400); const before=Number(m.balance_cents)/100, after=money(before+Number(x.amount)); await dbBatch(db,[db.prepare('UPDATE merchants SET balance_cents=? WHERE id=?').bind(Math.round(after*100),m.id),db.prepare("UPDATE settlements SET status='cancelled',processed_at=CURRENT_TIMESTAMP WHERE id=?").bind(x.id),db.prepare("INSERT INTO wallet_ledger(merchant_id,order_no,type,amount,fee,net_amount,balance_before,balance_after,status,remark) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(m.id,x.settlement_no,'settlement_cancel:'+x.settlement_no,x.amount,0,x.amount,before,after,'posted','settlement cancelled '+x.settlement_no)]); return json({ok:true,balance:after}); }

export default {
  async fetch(req, env) {
    const url=new URL(req.url); const db=env.DB;
    try {
      if(url.pathname.startsWith('/api/')) { const r=await handleApi(req,env,db,url); if(r)return r; return json({message:'接口不存在'},404); }
      // Serve the existing PayHub UI through Cloudflare Workers Static Assets.
      if(!env.ASSETS) return text('PayHub V14: ASSETS binding is not configured.',500);
      if(url.pathname==='/dashboard' || url.pathname==='/dashboard/') return env.ASSETS.fetch(new Request(new URL('/dashboard.html',url),req));
      if(url.pathname==='/admin' || url.pathname==='/admin/') return env.ASSETS.fetch(new Request(new URL('/admin.html',url),req));
      if(url.pathname.startsWith('/checkout/')) return env.ASSETS.fetch(new Request(new URL('/checkout.html',url),req));
      return env.ASSETS.fetch(req);
    } catch(e) { console.error(e); return json({message:e?.message||'服务器错误'},500); }
  }
};
