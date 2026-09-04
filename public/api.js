window.PayHubAPI = {
  token(){ return localStorage.getItem('payhub_token') || ''; },
  async request(url, options={}){
    const headers = Object.assign({'Content-Type':'application/json'}, options.headers||{});
    const t = this.token();
    if(t) headers.Authorization = 'Bearer ' + t;
    const r = await fetch(url, Object.assign({}, options, {headers}));
    const data = await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(data.message || '请求失败');
    return data;
  },
  stats(){ return this.request('/api/dashboard/stats'); },
  orders(params=''){ return this.request('/api/orders' + params); },
  createOrder(body){ return this.request('/api/orders',{method:'POST',body:JSON.stringify(body)}); },
  wallet(){ return this.request('/api/wallet/transactions'); },
  apiKeys(){ return this.request('/api/api-keys'); },
  createApiKey(name){ return this.request('/api/api-keys',{method:'POST',body:JSON.stringify({name})}); }
};
