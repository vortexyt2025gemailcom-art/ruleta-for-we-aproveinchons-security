import{getStore}from'@netlify/blobs';
import{randomBytes,scryptSync,timingSafeEqual,createHash}from'node:crypto';

const PRICE={"r0":0,"r1":500,"r2":800,"r3":1000,"r4":1200,"r5":1500,"r6":1800,"r7":2000,"r8":2300,"r9":2500,"r10":3000,"r11":3500,"r12":4000,"r13":4500,"r14":5000,"r15":6000,"r16":7000,"r17":8000,"r18":9000,"r19":6500,"r20":1500,"r21":2000,"r22":3000,"r23":3500,"r24":4000,"r25":5500,"r26":7500,"r27":10000,"rf":50000,"b0":0,"b1":300,"b2":500,"b3":700,"b4":900,"b5":1100,"b6":1300,"b7":1500,"b8":1800,"b9":2000,"b10":2300,"b11":2600,"b12":3000,"b13":3400,"b14":3800,"b15":4200,"b16":4600,"b17":5000,"b18":5500,"b19":6000,"b20":800,"b21":1200,"b22":1800,"b23":2200,"b24":2600,"b25":3200,"b26":4000,"b27":4500,"b28":5200,"b29":6000,"b30":7000,"b31":2400,"b32":2800,"b33":3200,"b34":3600,"b35":4000,"b36":4400,"bv":50000,"drb":20000,"dfi":12000,"dne":12000,"dor":15000,"dic":12000,"dto":12000,"dco":12000,"dga":25000,"dpl":14000,"dso":14000,"dbn":16000,"dec":20000,"dpa":22000,"dho":18000,"dau":26000,"dla":28000,"dl1":9000,"dl2":9000,"dl3":13000,"dl4":13000,"dl5":13000,"dl6":15000,"dl7":16000,"dl8":17000,"dl9":18000,"dl10":19000,"dl11":21000,"dl12":24000,"pc0":0,"hc0":0,"pc1":300,"hc1":300,"pc2":400,"hc2":400,"pc3":500,"hc3":500,"pc4":600,"hc4":600,"pc5":700,"hc5":700,"pc6":800,"hc6":800,"pc7":900,"hc7":900,"pc8":1000,"hc8":1000,"pc9":1100,"hc9":1100,"pc10":1200,"hc10":1200,"pc11":1300,"hc11":1300,"pc12":1400,"hc12":1400,"pc13":1500,"hc13":1500,"pc14":1600,"hc14":1600,"pc15":1700,"hc15":1700,"pc16":1800,"hc16":1800,"pc17":1900,"hc17":1900,"pc18":2000,"hc18":2000,"pc19":2100,"hc19":2100,"pd0":800,"pd1":1200,"pd2":1600,"pd3":2000,"pd4":2400,"pd5":2800,"pd6":3200,"pd7":3600,"pd8":4000,"pd9":4400,"pd10":4800,"pd11":5200,"pd12":5600,"pd13":6000,"pd14":6400,"pd15":6800,"pd16":7200,"pd17":7600,"pd18":8000,"pd19":8400,"hd0":800,"hd1":1200,"hd2":1600,"hd3":2000,"hd4":2400,"hd5":2800,"hd6":3200,"hd7":3600,"hd8":4000,"hd9":4400,"hd10":4800,"hd11":5200,"hd12":5600,"hd13":6000,"hd14":6400,"hd15":6800,"hd16":7200,"hd17":7600,"hd18":8000,"hd19":8400};
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json'}}),
E=(m,s=400)=>J({e:m},s),
nk=n=>'u/'+String(n).toLowerCase(),
th=t=>createHash('sha256').update(String(t)).digest('hex'),
hp=(p,s)=>scryptSync(p,s,32).toString('hex'),
eq=(a,b)=>{a=Buffer.from(String(a));b=Buffer.from(String(b));return a.length===b.length&&timingSafeEqual(a,b)},
isOwner=k=>!!process.env.OWNER_KEY&&typeof k==='string'&&eq(k,process.env.OWNER_KEY),
okp=p=>typeof p==='string'&&p.length<30000&&/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]*$/.test(p),
cl=d=>{if(!d||typeof d!=='object'||JSON.stringify(d).length>3e6)return{};delete d.coins;delete d.own;return d},
pv=u=>({...u.d,coins:u.c|0,own:u.o||{}}),
AB='ABCDEFGHJKLMNPQRSTUVWXYZ23456789',
gen=()=>[...randomBytes(24)].map(x=>AB[x%32]).join('');

/* leer-modificar-escribir con reintento (no pisa cambios simultáneos) */
const upd=async(s,key,fn)=>{
  for(let i=0;i<6;i++){
    const r=await s.getWithMetadata(key,{type:'json'});
    if(!r)return{err:'Sesión inválida'};
    const out=await fn(r.data);
    if(out&&out.err)return out;
    const w=await s.setJSON(key,r.data,{onlyIfMatch:r.etag});
    if(!w||w.modified!==false)return out||{};
  }
  return{err:'Intenta de nuevo'};
};

export default async req=>{
  if(req.method!=='POST')return E('Método no permitido',405);
  let b;try{b=await req.json()}catch{return E('Datos inválidos')}
  if(!b||typeof b!=='object')return E('Datos inválidos');
  const s=getStore({name:'ruleta',consistency:'strong'}),a=b.a,
    bad=u=>!Array.isArray(u.tk)||!u.tk.includes(th(b.k))?'Sesión inválida':u.ban?'Cuenta bloqueada por intentar modificar las monedas':'',
    res=r=>E(r.err,/^(Sesión|Cuenta)/.test(r.err)?401:400);

  /* crear cuenta (nombre real = privado; nombre de perfil + foto = público) */
  if(a==='reg'){
    if(!/^\w{3,16}$/.test(b.n||'')||typeof b.pw!=='string'||b.pw.length<6||typeof b.r!=='string'||!b.r.trim()||b.r.length>30)return E('Datos incompletos o inválidos');
    if(await s.get(nk(b.n)))return E('Ese nombre ya está en uso');
    const k=randomBytes(24).toString('hex'),sl=randomBytes(16).toString('hex'),
      u={n:b.n,r:b.r.trim(),s:sl,h:hp(b.pw,sl),p:okp(b.p)?b.p:'',d:cl(b.d),c:500,o:{},t:0,tk:[th(k)]};
    const w=await s.setJSON(nk(b.n),u,{onlyIfNew:true});
    if(w&&w.modified===false)return E('Ese nombre ya está en uso');
    return J({n:u.n,k,p:u.p,r:u.r,d:pv(u)});
  }

  /* entrar desde cualquier celular: devuelve todo lo guardado */
  if(a==='login'){
    const u=await s.get(nk(b.n||''),{type:'json'});
    if(!u||typeof b.pw!=='string'||!eq(hp(b.pw,u.s),u.h))return E('Nombre o contraseña incorrectos',401);
    if(u.ban)return E('Cuenta bloqueada por intentar modificar las monedas',401);const k=randomBytes(24).toString('hex');let d;
    const r=await upd(s,nk(u.n),x=>{x.tk=[...x.tk.slice(-7),th(k)];d=pv(x);return{n:x.n,r:x.r,p:x.p}});
    return r.err?res(r):J({...r,k,d});
  }

  /* guardar en la nube / recuperar al abrir */
  if(a==='save'||a==='me'){
    let o;
    const r=await upd(s,nk(b.n||''),x=>{
      {const m=bad(x);if(m)return{err:m}}
      if(a==='save'){if(b.d&&+b.d.coins>(x.c|0)+150000){x.ban=1;return{ban:1}}x.d=cl(b.d);if(okp(b.p))x.p=b.p;o={c:x.c|0}}
      else o={d:pv(x),p:x.p};
    });
    return r.err?res(r):r.ban?E('Cuenta bloqueada por intentar modificar las monedas',401):J(o);
  }

  /* buscar: solo nombre y foto son públicos */
  if(a==='find'){
    const q=String(b.q||'').toLowerCase().replace(/\W/g,'').slice(0,16),{blobs}=await s.list({prefix:'u/'+q});
    const u=(await Promise.all(blobs.slice(0,30).map(x=>s.get(x.key,{type:'json'})))).filter(Boolean).map(x=>({n:x.n,p:x.p}));
    return J({u});
  }

  /* regalar: se descuenta en el servidor; si no alcanza, no pasa */
  if(a==='gift'){
    const amt=Math.floor(+b.amt),to=String(b.to||'');
    if(!(amt>=1)||amt>1e9)return E('Cantidad inválida');
    if(to.toLowerCase()===String(b.n||'').toLowerCase())return E('No puedes regalarte a ti mismo');
    if(!await s.get(nk(to)))return E('Esa persona no existe');
    const r=await upd(s,nk(b.n||''),x=>{
      {const m=bad(x);if(m)return{err:m}}
      const c=x.c|0;
      if(c<amt)return{err:'No te alcanzan las monedas'};
      x.c=c-amt;return{c:x.c};
    });
    if(r.err)return res(r);
    const t=await upd(s,nk(to),x=>{x.c=(x.c|0)+amt});
    if(t.err){await upd(s,nk(b.n),x=>{x.c=(x.c|0)+amt});return E('No se pudo enviar, intenta de nuevo')}
    return J({c:r.c});
  }

  /* 50 monedas por minuto, calculado por el servidor */
  if(a==='earn'){
    const r=await upd(s,nk(b.n||''),x=>{
      {const m=bad(x);if(m)return{err:m}}
      const n=Date.now(),v=n-(x.t|0)>=55000?50:0;if(v){x.t=n;x.c=(x.c|0)+v}
      return{c:x.c|0,v};
    });
    return r.err?res(r):J(r);
  }

  /* comprar: el servidor revisa precio y saldo */
  if(a==='buy'){
    if(!Object.hasOwn(PRICE,String(b.key)))return E('Ese artículo no existe');
    const p=PRICE[b.key];
    const r=await upd(s,nk(b.n||''),x=>{
      {const m=bad(x);if(m)return{err:m}}
      x.o=x.o||{};
      if(x.o[b.key]||p===0)return{c:x.c|0,o:x.o};
      if((x.c|0)<p)return{err:'No te alcanzan las monedas'};
      x.c=(x.c|0)-p;x.o[b.key]=1;return{c:x.c,o:x.o};
    });
    return r.err?res(r):J(r);
  }

  /* dueño: agarrar monedas gratis */
  if(a==='grant'){
    if(!isOwner(b.key))return E('No autorizado',403);
    const v=Math.floor(+b.v);if(!(v>=1)||v>1e8)return E('Cantidad inválida');
    const r=await upd(s,nk(b.n||''),x=>{
      {const m=bad(x);if(m)return{err:m}}
      x.c=(x.c|0)+v;return{c:x.c};
    });
    return r.err?res(r):J(r);
  }

  /* dueño: el código secreto vive en la variable OWNER_KEY de Netlify */
  if(a==='own')return isOwner(b.key)?J({ok:1}):E('Código incorrecto',403);

  if(a==='mk'){
    if(!isOwner(b.key))return E('No autorizado',403);
    const v=Math.floor(+b.v);if(!(v>=1)||v>1e8)return E('Cantidad inválida');
    const c=gen();await s.setJSON('c/'+c,{v,t:Date.now()});
    return J({code:c.match(/.{4}/g).join('-')});
  }

  /* canjear: un solo uso, a la primera persona que lo use */
  if(a==='use'){
    const u=await s.get(nk(b.n||''),{type:'json'});
    {const m=u?bad(u):'Sesión inválida';if(m)return E(m,401)}
    const c=String(b.code||'').toUpperCase().replace(/[^A-Z0-9]/g,'');
    if(c.length!==24)return E('Código inválido');
    const g=await s.get('c/'+c,{type:'json'});
    if(!g||await s.get('x/'+c))return E('Código inválido o ya usado');
    const w=await s.setJSON('x/'+c,{by:u.n,t:Date.now()},{onlyIfNew:true});
    if(w&&w.modified===false)return E('Código inválido o ya usado');
    const r=await upd(s,nk(u.n),x=>{x.c=(x.c|0)+g.v;return{c:x.c,v:g.v}});
    if(r.err){await s.delete('x/'+c);return res(r)}
    await s.delete('c/'+c);
    return J(r);
  }

  return E('Acción desconocida');
};

export const config={path:'/api'};
