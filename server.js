const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const CODE = process.env.ACCESS_CODE, PASS = process.env.ACCESS_PASSWORD, PORT = process.env.PORT || 3000;
if (!CODE || !PASS) {
  console.error('Defina ACCESS_CODE e ACCESS_PASSWORD nas variáveis do Railway.');
  process.exit(1);
}

const KEY = crypto.createHash('sha256').update('p3d|' + CODE + '|' + PASS + '|' + (process.env.SESSION_SECRET || '')).digest();
const sign = t => crypto.createHmac('sha256', KEY).update(t).digest('hex');
const hash = v => crypto.createHash('sha256').update(String(v)).digest();
const eq = (a, b) => crypto.timingSafeEqual(hash(a), hash(b));
const token = () => { const exp = String(Date.now() + 30 * 864e5); return exp + '.' + sign(exp); };
const authed = req => {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)p3d=([^;]+)/);
  if (!m) return false;
  const [e, s] = m[1].split('.');
  return !!(e && s && Number(e) > Date.now() && eq(s, sign(e)));
};

// limite de tentativas: 5 erros por IP = bloqueio de 15 min
const tries = new Map();
const ipOf = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const blocked = ip => { const t = tries.get(ip); return t && t.n >= 5 && Date.now() - t.t < 15 * 60e3; };
const fail = ip => { const t = tries.get(ip); tries.set(ip, { n: t && Date.now() - t.t < 15 * 60e3 ? t.n + 1 : 1, t: Date.now() }); };

const view = f => {
  for (const p of [path.join(__dirname, 'views', f), path.join(__dirname, f)]) if (fs.existsSync(p)) return fs.readFileSync(p);
  throw new Error('Arquivo não encontrado no repositório: ' + f + ' (esperado em views/' + f + ')');
};
const send = (res, code, type, body, h = {}) => { res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', ...h }); res.end(body); };
const secure = req => req.headers['x-forwarded-proto'] === 'https';

http.createServer((req, res) => { try {
  const url = req.url.split('?')[0], ip = ipOf(req);

  if (req.method === 'POST' && url === '/login') {
    if (blocked(ip)) return send(res, 429, 'application/json', '{"ok":false,"msg":"Muitas tentativas. Aguarde 15 minutos."}');
    let body = '';
    req.on('data', c => { body += c; if (body.length > 2048) req.destroy(); });
    req.on('end', () => {
      let d = {}; try { d = JSON.parse(body); } catch (e) {}
      if (eq(d.code || '', CODE) && eq(d.password || '', PASS)) {
        tries.delete(ip);
        return send(res, 200, 'application/json', '{"ok":true}', {
          'Set-Cookie': `p3d=${token()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}${secure(req) ? '; Secure' : ''}`
        });
      }
      fail(ip);
      send(res, 401, 'application/json', '{"ok":false,"msg":"Código ou senha incorretos."}');
    });
    return;
  }

  if (url === '/logout') return send(res, 302, 'text/plain', '', { Location: '/', 'Set-Cookie': 'p3d=; HttpOnly; Path=/; Max-Age=0' });

  if (url === '/' || url === '/index.html') {
    return authed(req) ? send(res, 200, 'text/html; charset=utf-8', view('app.html')) : send(res, 200, 'text/html; charset=utf-8', view('login.html'));
  }
  send(res, 404, 'text/plain', 'Não encontrado');
} catch (e) { console.error(e.message); send(res, 500, 'text/plain; charset=utf-8', e.message); } }).listen(PORT, () => console.log('Print3D Manager rodando na porta ' + PORT));
