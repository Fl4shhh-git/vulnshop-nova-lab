// =====================================================================
//  Control de calidad del laboratorio VulnShop + NOVA
//  Comprueba que CADA vulnerabilidad sigue siendo explotable y que NOVA
//  responde. Se corre con la tienda levantada:
//
//     node scripts/verificar.mjs                 (http://localhost:3000)
//     node scripts/verificar.mjs http://127.0.0.1:3710
//     node scripts/verificar.mjs --sin-ia        (no llama al modelo)
//
//  Deja la tienda como estaba salvo lo que vive en memoria (resenas,
//  pedidos, saldo): REINICIA el servidor despues de correrlo y antes de
//  la clase. Las fotos de prueba que sube las borra al terminar.
// =====================================================================
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const RAIZ = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const BASE = (args.find(a => a.startsWith('http')) || 'http://localhost:3000').replace(/\/$/, '');
const SIN_IA = args.includes('--sin-ia');
const PASS = 'Passw0rd1!';
// Cuentas del instructor: se leen del .env (no estan en el codigo)
const ENV = fs.existsSync(path.join(RAIZ, '.env')) ? fs.readFileSync(path.join(RAIZ, '.env'), 'utf8') : '';
const envVal = k => ((ENV.match(new RegExp('^' + k + '=(.*)$', 'm')) || [])[1] || '').trim().replace(/^'(.*)'$/, '$1');
const PASS_INSTRUCTOR = envVal('PASSWORD_INSTRUCTOR');
const CUENTAS_INSTRUCTOR = envVal('CUENTAS_INSTRUCTOR').split(';').map(x => x.split(':')[0].trim()).filter(Boolean);

let ok = 0, mal = 0;
const fallas = [];
function marcar(nombre, cond, detalle = '') {
  if (cond) { ok++; console.log('  ✔ ' + nombre); }
  else { mal++; fallas.push(nombre); console.log('  ✘ ' + nombre + (detalle ? '  -> ' + detalle : '')); }
}
async function prueba(nombre, fn) {
  try { await fn(); } catch (e) { marcar(nombre, false, e.message); }
}
const req = async (ruta, op = {}) => {
  const r = await fetch(BASE + ruta, { redirect: 'manual', ...op, headers: { ...(op.json ? { 'Content-Type': 'application/json' } : {}), ...(op.headers || {}) }, body: op.json ? JSON.stringify(op.json) : op.body });
  const texto = await r.text();
  let json = null; try { json = JSON.parse(texto); } catch { /* no es JSON */ }
  return { status: r.status, texto, json, tipo: r.headers.get('content-type') || '' };
};
const login = async (email, password = PASS) => (await req('/auth/login', { method: 'POST', json: { email, password } })).json;
const bearer = t => ({ Authorization: 'Bearer ' + t });

console.log(`\nVulnShop + NOVA - control de calidad contra ${BASE}\n`);

const vivo = await req('/login.html').catch(() => null);
if (!vivo || vivo.status !== 200) { console.log('  ✘ La tienda no responde en ' + BASE + '. Levantala con start.bat (o node server.js).\n'); process.exit(1); }

let tFelix, tMaria;
console.log('Cuentas');
await prueba('login felix / maria / admin', async () => {
  tFelix = (await login('felix@vigilantium.com')).token;
  tMaria = (await login('maria@vigilantium.com')).token;
  const a = await login('admin@vigilantium.com');
  marcar('login felix / maria / admin', tFelix && tMaria && a.token);
});
if (PASS_INSTRUCTOR && CUENTAS_INSTRUCTOR.length) await prueba('cuentas del instructor @vulnshop.com', async () => {
  const r = await Promise.all(CUENTAS_INSTRUCTOR.map(u => login(u + '@vulnshop.com', PASS_INSTRUCTOR)));
  marcar('cuentas del instructor @vulnshop.com (' + CUENTAS_INSTRUCTOR.length + ')', r.every(x => x.success), r.map(x => x.success).join(','));
});

console.log('\nLabs web');
await prueba('01 SQLi', async () => {
  const e = await req('/auth/login', { method: 'POST', json: { email: "felix@vigilantium.com'", password: 'x' } });
  const b = await login("' OR '1'='1' --", 'x');
  marcar('01 SQLi: error MySQL con la query + bypass como admin', e.status === 500 && /1064/.test(e.texto) && b.user && b.user.role === 'admin');
});
await prueba('02a IDOR DNI', async () => {
  const r = await req('/api/cuenta?dni=45678911', { headers: bearer(tFelix) });
  marcar('02a IDOR por DNI: cuenta de maria con datos_financieros', r.json && r.json.perfil.username === 'maria' && r.json.datos_financieros.cvv);
});
await prueba('02b IDOR UUID', async () => {
  const l = await req('/api/v1/usuarios');
  const u = await req('/api/v1/usuarios/' + l.json.usuarios[0].uuid);
  marcar('02b IDOR por UUID sin token (lista + perfil)', l.json.total >= 20 && u.json && u.json.datos_financieros);
});
await prueba('02c IDOR password', async () => {
  const c = await req('/api/cuenta/cambiar-password', { method: 'POST', headers: bearer(tFelix), json: { dni: '45678917', password_actual: PASS, nueva_password: 'qa-temp-123' } });
  const entra = await login('alice@vigilantium.com', 'qa-temp-123');
  // se deja la clave de alice como estaba
  await req('/api/cuenta/cambiar-password', { method: 'POST', headers: bearer(tFelix), json: { dni: '45678917', password_actual: PASS, nueva_password: PASS } });
  marcar('02c IDOR cambio de contrasena (alice cambiada y restaurada)', c.json && c.json.success && entra.success);
});
await prueba('02d IDOR documentos', async () => {
  const r = await req('/api/documento/doc005', { headers: bearer(tFelix) });
  marcar('02d IDOR documento ajeno (doc005 de maria)', r.json && r.json.propietario && r.json.propietario.nombre === 'Maria Garcia');
});
await prueba('03 XSS reflejado', async () => {
  const r = await req('/search?q=' + encodeURIComponent('<script>alert(1)</script>'));
  marcar('03 XSS reflejado en /search sin escapar', r.texto.includes('<script>alert(1)</script>'));
});
await prueba('04 XSS almacenado', async () => {
  const html = fs.readFileSync(path.join(RAIZ, 'public', 'reviews.html'), 'utf8');
  marcar('04 XSS almacenado: reviews.html pinta con innerHTML', /body\.innerHTML\s*=\s*r\.content/.test(html));
});
await prueba('05 checkout', async () => {
  const a = await req('/api/checkout', { method: 'POST', headers: bearer(tMaria), json: { product_id: 1, quantity: 1, price: 0.01 } });
  const b = await req('/api/checkout', { method: 'POST', headers: bearer(tMaria), json: { product_id: 1, quantity: 1, price: 2499, discount_percent: 100 } });
  marcar('05a precio desde el cliente (MacBook a S/ 0.01)', a.json && a.json.order.total === 0.01);
  marcar('05b descuento sin tope (100% = S/ 0)', b.json && b.json.order.total === 0);
});
await prueba('06 misconfig', async () => {
  const [ad, env, act, dbg, docs] = await Promise.all(['/admin', '/.env', '/actuator/health', '/api/debug/error', '/docs'].map(r => req(r)));
  marcar('06 /admin, /.env, /actuator, /api/debug/error, /docs expuestos', ad.json && ad.json.jwt_secret && /JWT_SECRET/.test(env.texto) && act.status === 200 && dbg.status === 500 && docs.status === 200);
});
await prueba('07 rate limiting', async () => {
  const rs = await Promise.all(Array.from({ length: 30 }, () => req('/auth/login', { method: 'POST', json: { email: 'admin@vigilantium.com', password: 'mala' } })));
  marcar('07 login sin limite (30 intentos, ningun 429)', rs.every(r => r.status === 200));
});
await prueba('08 JWT', async () => {
  const t = (await login('jorge@vigilantium.com')).token;
  await req('/auth/logout', { method: 'POST', headers: bearer(t) });
  const r = await req('/api/me', { headers: bearer(t) });
  marcar('08 el token sigue valido despues del logout', r.status === 200);
});
await prueba('09 JS', async () => {
  const js = await req('/assets/js/main.4f2a9c.js');
  const key = (js.texto.match(/vsint_[a-z0-9]+/) || [])[0];
  const sin = await req('/api/internal/v2/clientes/export');
  const con = await req('/api/internal/v2/clientes/export', { headers: { 'X-Internal-Key': key } });
  marcar('09 X-Internal-Key en el JS -> export CSV de clientes', key && sin.status === 403 && con.status === 200 && con.texto.split('\n').length > 20);
});
await prueba('10 comentario', async () => {
  const l = await req('/login.html');
  const sin = await req('/soporte-interno');
  const con = await req('/soporte-interno', { headers: { Authorization: 'Basic ' + Buffer.from('soporte:Soporte#2024').toString('base64') } });
  marcar('10 comentario HTML con credenciales -> /soporte-interno', /TODO\(jhuaman\)/.test(l.texto) && sin.status === 401 && /TCK-48/.test(con.texto));
});
await prueba('11 swagger dev', async () => {
  const d = await req('/dev'); const o = await req('/dev/openapi.json'); const n = await req('/zz-no-existe-qa');
  marcar('11 Swagger oculto en /dev (y 404 limpio para lo inexistente)', d.status === 200 && o.json && o.json.paths && n.status === 404);
});
await prueba('12 uploads', async () => {
  const lista = await req('/uploads/docs/');
  const docs = (lista.texto.match(/href="doc\d+\.jpg"/g) || []).length;
  const html = Buffer.from('<h1>QA</h1><script>document.title="qa"</script>').toString('base64');
  const up = await req('/api/perfil/foto', { method: 'POST', json: { dni: '45678934', archivo: 'qa.html', contenido: html } });
  const servido = up.json && up.json.url ? await req(up.json.url) : {};
  const comp = ((await req('/uploads/comprobantes/')).texto.match(/href="comprobante_[^"]+\.jpg"/g) || []).length;
  marcar('12 /uploads/docs listable (40 documentos)', docs === 40, docs + ' encontrados');
  marcar('12 /uploads/comprobantes listable (20 comprobantes)', comp === 20, comp + ' encontrados');
  marcar('12 subida sin token y sin validar tipo (.html servido como HTML)', up.json && up.json.success && /text\/html/.test(servido.tipo || ''));
  // limpieza de la foto de prueba
  for (const f of fs.readdirSync(path.join(RAIZ, 'public', 'uploads', 'fotos'))) if (f.startsWith('45678934_qa')) fs.rmSync(path.join(RAIZ, 'public', 'uploads', 'fotos', f));
});
await prueba('catalogo', async () => {
  const c = await req('/api/productos');
  const img = await req(c.json.productos[29].imagen);
  marcar('catalogo de 30 productos con imagenes locales', c.json.total === 30 && img.status === 200 && /svg/.test(img.tipo));
});
await prueba('reembolso', async () => {
  const r = await req('/api/reembolso', { method: 'POST', headers: bearer(tMaria), json: { order_id: 1010, monto: 999 } });
  marcar('reembolso sin validar dueno ni monto (API de la tienda)', r.json && r.json.success && r.json.pedido.userId !== 3);
});

console.log('\nNOVA');
await prueba('guia y widget', async () => {
  const g = await req('/guide.html'); const w = await req('/nova-widget.js');
  marcar('guia con 12 labs web + 4 de IA (4 prompts visibles), y widget servido', (g.texto.match(/class="num">/g) || []).length >= 12 && (g.texto.match(/class="num ia"/g) || []).length === 4 && (g.texto.match(/class="prompt-bloque"/g) || []).length === 4 && w.status === 200);
});
await prueba('estado NOVA', async () => {
  const e = await req('/api/nova/estado', { headers: bearer(tFelix) });
  marcar('NOVA configurada (API key en .env) - modelo ' + (e.json && e.json.modelo), e.json && e.json.disponible);
});
if (!SIN_IA) {
  await prueba('NOVA responde', async () => {
    const r = await req('/api/nova/chat', { method: 'POST', headers: bearer(tFelix), json: { historial: [], mensaje: '¿Cual es el estado de mi pedido #1006?' } });
    // El pedido #1006 de felix es una webcam "En camino": NOVA solo lo sabe si consulto la API de la tienda
    const ok = r.json && r.json.ok && /webcam|brio/i.test(r.json.respuesta || '');
    marcar('NOVA responde con datos reales de la tienda (pedido #1006)', ok, r.json && (r.json.error || String(r.json.respuesta).slice(0, 120)));
  });
}

console.log(`\n${mal ? '✘' : '✔'} ${ok} correctas, ${mal} con problemas${mal ? ': ' + fallas.join(' | ') : ''}`);
console.log('Recuerda: reinicia la tienda antes de la clase para dejar resenas, pedidos y saldos en cero.\n');
process.exit(mal ? 1 : 0);
