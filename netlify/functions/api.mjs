
import { getStore } from '@netlify/blobs';
import {
  randomBytes,
  scryptSync,
  timingSafeEqual,
  createHash
} from 'node:crypto';

export const config = { path: '/api' };

const db = getStore('ruleta-data');

const json = (statusCode, body) => ({
  statusCode,
  headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store'
  },
  body: JSON.stringify(body)
});

const sha = value =>
  createHash('sha256').update(String(value)).digest('hex');

const token = (n = 24) => randomBytes(n).toString('hex');
const norm = value => String(value ?? '').trim();
const username = value => norm(value).toLowerCase();
const validName = value => /^\w{3,16}$/.test(norm(value));

const price = {
  r0:0,r1:500,r2:800,r3:1000,r4:1200,
  r5:1500,r6:1800,r7:2000,r8:2300,r9:2500,
  r10:3000,r11:3500,r12:4000,r13:4500,r14:5000,
  r15:6000,r16:7000,r17:8000,r18:9000,r19:10000,

  b0:0,b1:300,b2:500,b3:700,b4:900,b5:1100,
  b6:1300,b7:1500,b8:1800,b9:2000,b10:2300,
  b11:2600,b12:3000,b13:3400,b14:3800,b15:4200,
  b16:4600,b17:5000,b18:5500,b19:6000,

  drb:20000,dfi:12000,dne:12000,dor:15000,
  dic:12000,dto:12000,dco:12000,dga:25000,

  pc0:0,pc1:300,pc2:400,pc3:500,pc4:600,
  pc5:700,pc6:800,pc7:900,pc8:1000,pc9:1100,
  pc10:1200,pc11:1300,pc12:1400,pc13:1500,
  pc14:1600,pc15:1700,pc16:1800,pc17:1900,
  pc18:2000,pc19:2100,

  hc0:0,hc1:300,hc2:400,hc3:500,hc4:600,
  hc5:700,hc6:800,hc7:900,hc8:1000,hc9:1100,
  hc10:1200,hc11:1300,hc12:1400,hc13:1500,
  hc14:1600,hc15:1700,hc16:1800,hc17:1900,
  hc18:2000,hc19:2100,

  pd0:800,pd1:1200,pd2:1600,pd3:2000,
  pd4:2400,pd5:2800,pd6:3200,pd7:3600,
  pd8:4000,pd9:4400,pd10:4800,pd11:5200,
  pd12:5600,pd13:6000,pd14:6400,pd15:6800,
  pd16:7200,pd17:7600,pd18:8000,pd19:8400,

  hd0:800,hd1:1200,hd2:1600,hd3:2000,
  hd4:2400,hd5:2800,hd6:3200,hd7:3600,
  hd8:4000,hd9:4400,hd10:4800,hd11:5200,
  hd12:5600,hd13:6000,hd14:6400,hd15:6800,
  hd16:7200,hd17:7600,hd18:8000,hd19:8400,

  rf:50000,bv:50000,
  b20:2400,b21:2800,b22:3200,b23:3600,
  b24:4000,b25:4400
};

async function getUser(name) {
  return db.get(`user:${username(name)}`, { type: 'json' });
}

async function putUser(user) {
  await db.setJSON(`user:${username(user.n)}`, user);
}

function fail(message, status = 400) {
  const e = new Error(message);
  e.statusCode = status;
  throw e;
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

function hashPassword(password, salt = token(16)) {
  return {
    salt,
    hash: scryptSync(password, salt, 64).toString('hex')
  };
}

function checkPassword(password, user) {
  const hash = scryptSync(password, user.salt, 64).toString('hex');
  return safeEqual(hash, user.pwh);
}

async function auth(body) {
  const n = norm(body.n);
  const k = norm(body.k);

  if (!n || !k) fail('Inicia sesión nuevamente.', 401);

  const user = await getUser(n);

  if (!user || !user.kh || !safeEqual(user.kh, sha(k))) {
    fail('Sesión inválida. Vuelve a entrar.', 401);
  }

  return user;
}

function publicUser(user) {
  return { n: user.n, p: user.p || '', r: user.r || '' };
}

export default async function handler(req) {
  if (req.httpMethod === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'POST, OPTIONS',
        'access-control-allow-headers': 'content-type'
      },
      body: ''
    };
  }

  if (req.httpMethod !== 'POST') {
    return json(405, { e: 'Usa POST.' });
  }

  try {
    const body = JSON.parse(req.body || '{}');
    const action = norm(body.a);

    if (action === 'reg') {
      const n = norm(body.n);
      const r = norm(body.r);
      const pw = String(body.pw || '');

      if (!validName(n)) {
        fail('Nombre inválido. Usa de 3 a 16 letras, números o _.');
      }

      if (!r || r.length > 30) fail('Pon tu nombre real.');
      if (pw.length < 6 || pw.length > 200) {
        fail('La contraseña debe tener al menos 6 caracteres.');
      }

      if (await getUser(n)) fail('Ese nombre de perfil ya existe.');

      const ph = hashPassword(pw);
      const k = token(32);

      const user = {
        n,
        r,
        p: norm(body.p || ''),
        salt: ph.salt,
        pwh: ph.hash,
        kh: sha(k),
        coins: 500,
        own: { r0: true, b0: true, pc0: true, hc0: true },
        d: body.d && typeof body.d === 'object' ? body.d : {},
        created: Date.now(),
        lastEarn: 0
      };

      await putUser(user);

      return json(200, {
        n,
        r,
        p: user.p,
        k,
        d: { ...user.d, coins: user.coins, own: user.own }
      });
    }

    if (action === 'login') {
      const user = await getUser(body.n);

      if (!user || !checkPassword(String(body.pw || ''), user)) {
        fail('Nombre o contraseña incorrectos.', 401);
      }

      const k = token(32);
      user.kh = sha(k);
      await putUser(user);

      return json(200, {
        n: user.n,
        r: user.r || '',
        p: user.p || '',
        k,
        d: {
          ...(user.d || {}),
          coins: user.coins || 0,
          own: user.own || {}
        }
      });
    }

    if (action === 'own') {
      const secret = process.env.OWNER_KEY;

      if (!secret) {
        fail('Falta configurar OWNER_KEY en Netlify.', 503);
      }

      if (!safeEqual(norm(body.key), secret)) {
        fail('Código de dueño incorrecto.', 403);
      }

      return json(200, { ok: true });
    }

    if (action === 'mk') {
      if (
        !process.env.OWNER_KEY ||
        !safeEqual(norm(body.key), process.env.OWNER_KEY)
      ) {
        fail('Código de dueño incorrecto.', 403);
      }

      const v = Math.floor(Number(body.v));

      if (!(v > 0 && v <= 100000000)) {
        fail('Cantidad inválida.');
      }

      const code = token(12).toUpperCase().match(/.{1,4}/g).join('-');

      await db.setJSON(`gift:${sha(code)}`, {
        v,
        used: false,
        created: Date.now()
      });

      return json(200, { code });
    }

    if (action === 'find') {
      const q = username(body.q);
      const listed = await db.list({ prefix: 'user:' });
      const users = [];

      for (const item of listed.blobs || []) {
        const user = await db.get(item.key, { type: 'json' });

        if (
          user &&
          user.n &&
          username(user.n).includes(q) &&
          users.length < 12
        ) {
          users.push(publicUser(user));
        }
      }

      return json(200, { u: users });
    }

    if (action === 'use') {
      const user = await auth(body);
      const code = norm(body.code).toUpperCase();

      if (!code) fail('Escribe el código de regalo.');

      const key = `gift:${sha(code)}`;
      const gift = await db.get(key, { type: 'json' });

      if (!gift || gift.used) {
        fail('Código inválido o ya utilizado.');
      }

      gift.used = true;
      gift.usedBy = user.n;
      gift.usedAt = Date.now();

      user.coins = (user.coins || 0) + gift.v;

      await db.setJSON(key, gift);
      await putUser(user);

      return json(200, { c: user.coins, v: gift.v });
    }

    if (action === 'save' || action === 'me') {
      const user = await auth(body);

      if (action === 'save') {
        if (body.d && typeof body.d === 'object') {
          const d = { ...body.d };
          delete d.coins;
          delete d.own;
          user.d = d;
        }

        if (typeof body.p === 'string' && body.p.length < 500000) {
          user.p = body.p;
        }

        await putUser(user);
      }

      return json(200, {
        c: user.coins || 0,
        p: user.p || '',
        d: {
          ...(user.d || {}),
          coins: user.coins || 0,
          own: user.own || {}
        }
      });
    }

    if (action === 'earn') {
      const user = await auth(body);
      const now = Date.now();

      if (now - (user.lastEarn || 0) < 45000) {
        fail('Espera un momento antes de recibir más monedas.');
      }

      user.coins = (user.coins || 0) + 50;
      user.lastEarn = now;

      await putUser(user);

      return json(200, { c: user.coins, v: 50 });
    }

    if (action === 'buy') {
      const user = await auth(body);
      const key = norm(body.key);
      const cost = price[key];

      if (cost === undefined) fail('Artículo no válido.');

      user.own ||= {};

      if (user.own[key]) {
        return json(200, { c: user.coins || 0, o: user.own });
      }

      if ((user.coins || 0) < cost) {
        fail('No tienes suficientes monedas.');
      }

      user.coins -= cost;
      user.own[key] = true;

      await putUser(user);

      return json(200, { c: user.coins, o: user.own });
    }

    if (action === 'grant') {
      if (
        !process.env.OWNER_KEY ||
        !safeEqual(norm(body.key), process.env.OWNER_KEY)
      ) {
        fail('Código de dueño incorrecto.', 403);
      }

      const user = await auth(body);
      const v = Math.floor(Number(body.v));

      if (!(v > 0 && v <= 100000000)) fail('Cantidad inválida.');

      user.coins = (user.coins || 0) + v;
      await putUser(user);

      return json(200, { c: user.coins });
    }

    if (action === 'gift') {
      const user = await auth(body);
      const to = await getUser(body.to);
      const amt = Math.floor(Number(body.amt));

      if (!to) fail('Jugador no encontrado.');

      if (username(to.n) === username(user.n)) {
        fail('No puedes regalarte monedas a ti mismo.');
      }

      if (!(amt > 0 && amt <= 100000000)) fail('Cantidad inválida.');

      if ((user.coins || 0) < amt) {
        fail('No tienes suficientes monedas.');
      }

      user.coins -= amt;
      to.coins = (to.coins || 0) + amt;

      await putUser(user);
      await putUser(to);

      return json(200, { c: user.coins });
    }

    return json(400, { e: 'Acción desconocida.' });
  } catch (err) {
    return json(err.statusCode || 500, {
      e: err.statusCode
        ? err.message
        : 'Error interno de la API. Revisa los registros de Netlify.'
    });
  }
    }
