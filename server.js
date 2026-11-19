/* =====================================================================
   VulnShop - Laboratorio de Seguridad Web
   Felix Prada Silva - Vigilantium 2026
   Backend deliberadamente vulnerable para entrenamiento de pentesting.
   Solo para uso educativo local.
   ===================================================================== */

const express = require('express');
const crypto  = require('crypto');
const path    = require('path');
const fs      = require('fs');

// .env junto al server (API key de NOVA). Las variables del sistema tienen prioridad.
require('dotenv').config({ path: path.join(__dirname, '.env'), quiet: true });

const app  = express();
const PORT  = process.env.PORT ? parseInt(process.env.PORT) : 3000;
// Solo esta PC por defecto. Para que la vean otros equipos de la red del aula: HOST=0.0.0.0
const HOST  = process.env.HOST || '127.0.0.1';

// JWT debil (crackeable con hashcat -m 16500) - dominio vigilantium.com
const JWT_SECRET = 'vulnshop_secret_2024';
const JWT_TTL    = 24 * 60 * 60; // 24h

/* ---------------------------------------------------------------------
   Acceso restringido por IP (para publicar el laboratorio en internet).
   IPS_PERMITIDAS=ip1,ip2 en el .env (o en las variables del hosting).
   Si va detras de un proxy (Render, Nginx, Cloudflare) define TRUST_PROXY
   con el numero de saltos (ej. 1) para leer la IP real del visitante;
   sin eso, todas las visitas llegan con la IP del proxy.
   Las llamadas internas de NOVA a la propia API llevan una clave aleatoria
   que se genera en cada arranque, asi el filtro no las bloquea.
   --------------------------------------------------------------------- */
// Acepta IP sueltas (IPv4 o IPv6) y rangos CIDR (ej. 203.0.113.0/24 o 2001:db8:1:2::/64).
const IPS_PERMITIDAS = (process.env.IPS_PERMITIDAS || '').split(',').map(x => x.trim()).filter(Boolean);
const LISTA_IPS = new (require('net').BlockList)();
for (const entrada of IPS_PERMITIDAS) {
  const [ip, prefijo] = entrada.split('/');
  const familia = ip.includes(':') ? 'ipv6' : 'ipv4';
  try {
    if (prefijo) LISTA_IPS.addSubnet(ip, Number(prefijo), familia); else LISTA_IPS.addAddress(ip, familia);
  } catch (e) { console.error('   IPS_PERMITIDAS: entrada invalida ignorada -> ' + entrada); }
}
const ipPermitida = ip => { try { return LISTA_IPS.check(ip, ip.includes(':') ? 'ipv6' : 'ipv4'); } catch (e) { return false; } };
const CLAVE_INTERNA = crypto.randomBytes(24).toString('hex');
// Seguro: en un hosting (Render define RENDER=true) no se arranca sin lista de IP,
// para que el laboratorio vulnerable no quede abierto a todo internet por olvido.
if ((process.env.RENDER || process.env.NODE_ENV === 'production') && !IPS_PERMITIDAS.length && process.env.PERMITIR_PUBLICO !== '1') {
  console.error('  X  Falta IPS_PERMITIDAS: el laboratorio no se publica abierto a todo internet.');
  console.error('     Define IPS_PERMITIDAS=ip1,ip2 en las variables del hosting.');
  process.exit(1);
}
if (process.env.TRUST_PROXY) app.set('trust proxy', /^\d+$/.test(process.env.TRUST_PROXY) ? Number(process.env.TRUST_PROXY) : process.env.TRUST_PROXY);
if (IPS_PERMITIDAS.length) {
  app.use((req, res, next) => {
    const ip = String(req.ip || '').replace(/^::ffff:/, '');
    if (ipPermitida(ip) || req.headers['x-nova-interno'] === CLAVE_INTERNA) return next();
    console.log('   [403] IP no permitida: ' + ip + '  ' + req.method + ' ' + req.path);
    res.status(403).type('text/plain').send('403 Forbidden');
  });
}

app.use(express.json({ limit: '5mb' })); // 5 MB: la foto de perfil viaja en base64
app.use(express.urlencoded({ extended: true }));

/* ---------------------------------------------------------------------
   JWT hand-rolled (HS256) - sin dependencias nativas
   --------------------------------------------------------------------- */
function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlJson(obj) { return b64url(JSON.stringify(obj)); }
function signJWT(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now    = Math.floor(Date.now() / 1000);
  const body   = { ...payload, iat: now, exp: now + JWT_TTL };
  const data   = b64urlJson(header) + '.' + b64urlJson(body);
  const sig    = b64url(crypto.createHmac('sha256', JWT_SECRET).update(data).digest());
  return data + '.' + sig;
}
function verifyJWT(token) {
  try {
    const [h, p, s] = token.split('.');
    const expected  = b64url(crypto.createHmac('sha256', JWT_SECRET).update(h + '.' + p).digest());
    if (s !== expected) return null;
    const payload = JSON.parse(Buffer.from(p, 'base64').toString());
    // NOTA: el logout NO invalida el token; solo se valida la expiracion
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (e) { return null; }
}
function authRequired(req, res, next) {
  const hdr = req.headers.authorization || '';
  const tok = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  const payload = tok ? verifyJWT(tok) : null;
  if (!payload) return res.status(401).json({ error: 'Token invalido o ausente' });
  req.user = USERS.find(u => u.id === payload.userId);
  if (!req.user) return res.status(401).json({ error: 'Usuario no existe' });
  next();
}

/* ---------------------------------------------------------------------
   Base de datos en memoria - 20 usuarios
   DNIs en rango 45678901..45679000 - password global: Passw0rd1!
   --------------------------------------------------------------------- */
const PASSWORD_GLOBAL = 'Passw0rd1!';

const BASE = [
  ['admin',   'Carlos Mendoza',    'admin',   45678902, 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', '999888777', '1985-03-12', 'Av. Javier Prado 4200', 'Lima',      'admin', 'Gold',   18450.75, '4539'],
  ['felix',   'Felix Prada',       'felix',   45678906, 'b2c3d4e5-f6a7-8901-bcde-f12345678901', '987654321', '1993-07-22', 'Calle Los Pinos 145',   'Lima',      'user',  'Gold',   7320.40,  '5521'],
  ['maria',   'Maria Garcia',      'maria',   45678911, 'c3d4e5f6-a7b8-9012-cdef-123456789012', '956123478', '1990-11-05', 'Jr. Union 890',         'Arequipa',  'user',  'Silver', 2210.00,  '4716'],
  ['alice',   'Alice Ramirez',     'alice',   45678917, 'd4e5f6a7-b8c9-0123-defa-234567890123', '941778852', '1998-01-30', 'Av. Grau 512',          'Trujillo',  'user',  'Bronze', 540.25,   '5411'],
  ['jorge',   'Jorge Salazar',     'jorge',   45678923, 'e5f6a7b8-c9d0-1234-efab-345678901234', '963254789', '1988-09-14', 'Calle Real 77',         'Huancayo',  'user',  'Silver', 3890.90,  '4024'],
  ['lucia',   'Lucia Vargas',      'lucia',   45678929, 'f6a7b8c9-d0e1-2345-fabc-456789012345', '921458963', '1995-05-18', 'Av. La Marina 2300',    'Lima',      'user',  'Gold',   9905.10,  '5233'],
  ['pedro',   'Pedro Castillo',    'pedro',   45678934, 'a7b8c9d0-e1f2-3456-abcd-567890123456', '900321654', '1982-12-01', 'Jr. Amazonas 34',       'Iquitos',  'user',  'Bronze', 120.00,   '4485'],
  ['sofia',   'Sofia Torres',      'sofia',   45678940, 'b8c9d0e1-f2a3-4567-bcde-678901234567', '934789521', '1997-04-09', 'Av. El Sol 1450',       'Cusco',     'user',  'Silver', 1780.55,  '5599'],
  ['diego',   'Diego Flores',      'diego',   45678946, 'c9d0e1f2-a3b4-5678-cdef-789012345678', '911235478', '1991-08-27', 'Calle Bolivar 220',     'Piura',     'user',  'Gold',   6420.00,  '4130'],
  ['carla',   'Carla Rojas',       'carla',   45678952, 'd0e1f2a3-b4c5-6789-defa-890123456789', '955874123', '1994-02-14', 'Av. Brasil 980',        'Lima',      'user',  'Bronze', 305.80,   '5372'],
  ['martin',  'Martin Chavez',     'martin',  45678958, 'e1f2a3b4-c5d6-7890-efab-901234567890', '922658741', '1986-06-19', 'Jr. Lima 456',          'Tacna',     'user',  'Silver', 4110.30,  '4901'],
  ['valeria', 'Valeria Ponce',     'valeria', 45678963, 'f2a3b4c5-d6e7-8901-fabc-012345678901', '944125896', '1999-10-02', 'Av. Angamos 1120',      'Lima',      'user',  'Bronze', 89.99,    '5044'],
  ['ricardo', 'Ricardo Nunez',     'ricardo', 45678969, 'a3b4c5d6-e7f8-9012-abcd-123456789012', '933548712', '1983-03-25', 'Calle San Martin 63',   'Chiclayo',  'user',  'Gold',   12030.65, '4288'],
  ['andrea',  'Andrea Campos',     'andrea',  45678975, 'b4c5d6e7-f8a9-0123-bcde-234567890123', '966214785', '1996-07-11', 'Av. Universitaria 700', 'Lima',      'user',  'Silver', 2560.00,  '5610'],
  ['bruno',   'Bruno Herrera',     'bruno',   45678981, 'c5d6e7f8-a9b0-1234-cdef-345678901234', '900147852', '1989-11-29', 'Jr. Puno 210',          'Puno',      'user',  'Bronze', 410.40,   '4762'],
  ['paula',   'Paula Medina',      'paula',   45678986, 'd6e7f8a9-b0c1-2345-defa-456789012345', '955963214', '1992-05-07', 'Av. Arequipa 3300',     'Lima',      'user',  'Gold',   8740.20,  '5185'],
  ['gabriel', 'Gabriel Ortiz',     'gabriel', 45678991, 'e7f8a9b0-c1d2-3456-efab-567890123456', '911478523', '1987-09-16', 'Calle Tacna 88',        'Ica',       'user',  'Silver', 3320.75,  '4093'],
  ['daniela', 'Daniela Suarez',    'daniela', 45678995, 'f8a9b0c1-d2e3-4567-fabc-678901234567', '944785213', '2000-01-21', 'Av. Colonial 1560',     'Lima',      'user',  'Bronze', 60.00,    '5827'],
  ['fernando','Fernando Aguilar',  'fernando',45678998, 'a9b0c1d2-e3f4-5678-abcd-789012345678', '933214569', '1984-08-03', 'Jr. Cusco 145',         'Ayacucho',  'user',  'Silver', 5210.90,  '4356'],
  ['natalia', 'Natalia Reyes',     'natalia', 45679000, 'b0c1d2e3-f4a5-6789-bcde-890123456789', '966857412', '1993-12-13', 'Av. Salaverry 2450',    'Lima',      'user',  'Gold',   10480.00, '5719'],
];
// Cuentas extra del instructor (dominio @vulnshop.com, contrasena propia). Se definen
// en el .env para que no queden en el repositorio:
//   CUENTAS_INSTRUCTOR=usuario:DNI:Nombre Apellido:Nivel;usuario2:DNI:...
//   PASSWORD_INSTRUCTOR=...
const PASSWORD_PRUEBA = process.env.PASSWORD_INSTRUCTOR || '';
const EXTRAS = PASSWORD_PRUEBA ? (process.env.CUENTAS_INSTRUCTOR || '').split(';').map(x => x.trim()).filter(Boolean).map((x, i) => {
  const [usuario, dni, nombre, nivel] = x.split(':').map(v => v.trim());
  return [usuario, nombre || usuario, usuario, Number(dni), 'c1d2e3f4-a5b6-7890-cdef-9012345678' + String(i + 1).padStart(2, '0'),
    '98700000' + (i + 1), '1995-01-15', 'Av. Larco 100' + (i + 1), 'Lima', 'user', nivel || 'Gold', Math.max(1000, 5000 - i * 2000), '601' + (i + 1)];
}) : [];
BASE.push(...EXTRAS);
const CUENTAS_INSTRUCTOR = new Set(EXTRAS.map(r => r[0]));
const esPrueba = username => CUENTAS_INSTRUCTOR.has(username);

const BANKS = ['BCP', 'Interbank', 'BBVA', 'Scotiabank'];

const USERS = BASE.map((r, i) => {
  const [username, nombre, local, dni, uuid, telefono, fnac, direccion, ciudad, role, nivel, balance, last4] = r;
  const cuenta = String(1910 + i) + '-' + String(20000000 + dni).slice(-8) + '-0-' + (10 + (i % 89));
  const cci    = '002-' + String(1910 + i) + '-' + String(300000000000 + dni * 37).slice(-12) + '-' + (20 + i);
  const tarjeta_full = '4' + String(500000000000000 + dni * 91).slice(-15);
  return {
    id: i + 1,
    username,
    nombre,
    email: local + (esPrueba(username) ? '@vulnshop.com' : '@vigilantium.com'),
    password: esPrueba(username) ? PASSWORD_PRUEBA : PASSWORD_GLOBAL,
    dni: String(dni),
    uuid,
    telefono,
    fecha_nacimiento: fnac,
    direccion: direccion + ', ' + ciudad,
    ciudad,
    role,
    nivel_membresia: nivel,
    balance,
    tarjeta: '**** **** **** ' + last4,
    // ---- Datos sensibles: SOLO visibles consultando el backend (Burp) ----
    _cuenta_bancaria:   BANKS[i % BANKS.length] + ' ' + cuenta,
    _cci:               cci,
    _tarjeta_completa:  tarjeta_full.replace(/(.{4})/g, '$1 ').trim(),
    _cvv:               String(100 + (dni % 900)),
    _clave_web:         'Web' + last4 + '$' + (dni % 100),
    _score_crediticio:  300 + (dni % 550),
    _ingresos_mensuales:'S/ ' + (2500 + (dni % 20000)).toLocaleString('es-PE'),
    _deudas_activas:    'S/ ' + (dni % 15000).toLocaleString('es-PE'),
    _pasaporte:         'PE' + String(1000000 + (dni % 9000000)),
    _token_recuperacion: crypto.createHash('sha1').update(uuid + JWT_SECRET).digest('hex').slice(0, 32),
  };
});

const userByDni  = dni  => USERS.find(u => u.dni === String(dni));
const userByUuid = uuid => USERS.find(u => u.uuid === uuid);

/* ---------------------------------------------------------------------
   Productos + Pedidos
   --------------------------------------------------------------------- */
// costo = costo interno (piso de precio): solo lo usa NOVA, que lo tiene en su prompt.
const PRODUCTS = {
  1: { product: "MacBook Pro 16\"", brand: "Apple", category: "Laptops", price: 10999.00, costo: 8350.00, image: '/img/productos/macbook-pro-16.svg', descripcion: "Chip M4 Pro, 24 GB de RAM, 512 GB SSD y pantalla Liquid Retina XDR." },
  2: { product: "Monitor LG 4K 27\"", brand: "LG", category: "Monitores", price: 1699.00, costo: 1250.00, image: '/img/productos/monitor-lg-4k-27.svg', descripcion: "Panel IPS UHD 4K, HDR10, USB-C con carga de 90 W." },
  3: { product: "Teclado Mecanico Keychron K8", brand: "Keychron", category: "Accesorios", price: 429.00, costo: 290.00, image: '/img/productos/teclado-keychron-k8.svg', descripcion: "Tenkeyless, switches Gateron Brown, inalambrico Bluetooth." },
  4: { product: "Mouse Logitech MX Master 3S", brand: "Logitech", category: "Accesorios", price: 449.00, costo: 310.00, image: '/img/productos/mouse-logitech-mx.svg', descripcion: "Sensor de 8000 DPI, clics silenciosos y scroll MagSpeed." },
  5: { product: "Webcam 4K Logitech Brio", brand: "Logitech", category: "Accesorios", price: 899.00, costo: 620.00, image: '/img/productos/webcam-logitech-brio.svg', descripcion: "Video Ultra HD 4K, HDR y reconocimiento facial Windows Hello." },
  6: { product: "Lenovo ThinkPad X1 Carbon", brand: "Lenovo", category: "Laptops", price: 7899.00, costo: 6050.00, image: '/img/productos/lenovo-thinkpad-x1.svg', descripcion: "Intel Core Ultra 7, 32 GB de RAM, 1 TB SSD, 1.1 kg." },
  7: { product: "ASUS ROG Strix G16", brand: "ASUS", category: "Laptops", price: 6499.00, costo: 4990.00, image: '/img/productos/asus-rog-strix-g16.svg', descripcion: "Intel Core i7, RTX 4060, pantalla de 165 Hz." },
  8: { product: "HP Pavilion 15", brand: "HP", category: "Laptops", price: 2899.00, costo: 2150.00, image: '/img/productos/hp-pavilion-15.svg', descripcion: "AMD Ryzen 5, 16 GB de RAM, 512 GB SSD." },
  9: { product: "Dell XPS 13", brand: "Dell", category: "Laptops", price: 6299.00, costo: 4780.00, image: '/img/productos/dell-xps-13.svg', descripcion: "Pantalla InfinityEdge, Intel Core Ultra 7, 16 GB de RAM." },
  10: { product: "iPhone 16 Pro 256 GB", brand: "Apple", category: "Celulares", price: 5999.00, costo: 4690.00, image: '/img/productos/iphone-16-pro.svg', descripcion: "Chip A18 Pro, camara de 48 MP y titanio." },
  11: { product: "Samsung Galaxy S25 Ultra", brand: "Samsung", category: "Celulares", price: 5499.00, costo: 4180.00, image: '/img/productos/galaxy-s25-ultra.svg', descripcion: "Camara de 200 MP, S Pen integrado y Galaxy AI." },
  12: { product: "Xiaomi Redmi Note 14 Pro", brand: "Xiaomi", category: "Celulares", price: 1299.00, costo: 920.00, image: '/img/productos/redmi-note-14-pro.svg', descripcion: "Pantalla AMOLED de 120 Hz y carga rapida de 45 W." },
  13: { product: "iPad Air 11\" M2", brand: "Apple", category: "Tablets", price: 3299.00, costo: 2490.00, image: '/img/productos/ipad-air-11.svg', descripcion: "Chip M2, compatible con Apple Pencil Pro." },
  14: { product: "Samsung Galaxy Tab S9 FE", brand: "Samsung", category: "Tablets", price: 1899.00, costo: 1390.00, image: '/img/productos/galaxy-tab-s9-fe.svg', descripcion: "Pantalla de 10.9\", S Pen incluido y resistencia IP68." },
  15: { product: "Monitor Samsung Odyssey G5 32\"", brand: "Samsung", category: "Monitores", price: 1399.00, costo: 1020.00, image: '/img/productos/samsung-odyssey-g5.svg', descripcion: "Curvo QHD de 165 Hz, ideal para gaming." },
  16: { product: "Monitor Dell 24\" P2425H", brand: "Dell", category: "Monitores", price: 799.00, costo: 560.00, image: '/img/productos/dell-p2425h.svg', descripcion: "Full HD IPS ajustable en altura, para oficina." },
  17: { product: "Audifonos Sony WH-1000XM5", brand: "Sony", category: "Audio", price: 1499.00, costo: 1050.00, image: '/img/productos/sony-wh-1000xm5.svg', descripcion: "Cancelacion de ruido lider y 30 horas de bateria." },
  18: { product: "AirPods Pro (2.a generacion)", brand: "Apple", category: "Audio", price: 1099.00, costo: 790.00, image: '/img/productos/airpods-pro-2.svg', descripcion: "Cancelacion activa de ruido y audio espacial." },
  19: { product: "Parlante JBL Charge 5", brand: "JBL", category: "Audio", price: 699.00, costo: 480.00, image: '/img/productos/jbl-charge-5.svg', descripcion: "Resistente al agua IP67 y 20 horas de reproduccion." },
  20: { product: "Apple Watch Series 10", brand: "Apple", category: "Wearables", price: 2099.00, costo: 1590.00, image: '/img/productos/apple-watch-10.svg', descripcion: "Pantalla mas grande, ECG y deteccion de apnea del sueno." },
  21: { product: "Samsung Galaxy Watch7", brand: "Samsung", category: "Wearables", price: 1199.00, costo: 850.00, image: '/img/productos/galaxy-watch-7.svg', descripcion: "Monitoreo de salud con Galaxy AI y GPS de doble frecuencia." },
  22: { product: "SSD Samsung 990 PRO 1 TB", brand: "Samsung", category: "Almacenamiento", price: 549.00, costo: 380.00, image: '/img/productos/samsung-990-pro.svg', descripcion: "NVMe PCIe 4.0 de hasta 7450 MB/s." },
  23: { product: "Disco externo WD Elements 2 TB", brand: "Western Digital", category: "Almacenamiento", price: 329.00, costo: 220.00, image: '/img/productos/wd-elements-2tb.svg', descripcion: "USB 3.0, plug and play para respaldos." },
  24: { product: "Router TP-Link Archer AX55", brand: "TP-Link", category: "Redes", price: 389.00, costo: 260.00, image: '/img/productos/tp-link-ax55.svg', descripcion: "Wi-Fi 6 de doble banda AX3000." },
  25: { product: "Impresora Epson EcoTank L3250", brand: "Epson", category: "Impresoras", price: 799.00, costo: 570.00, image: '/img/productos/epson-l3250.svg', descripcion: "Multifuncional con tanque de tinta y Wi-Fi." },
  26: { product: "Silla gamer Cougar Armor One", brand: "Cougar", category: "Muebles", price: 899.00, costo: 600.00, image: '/img/productos/silla-cougar-armor-one.svg', descripcion: "Respaldo reclinable 180 grados y cojin lumbar." },
  27: { product: "Microfono HyperX QuadCast S", brand: "HyperX", category: "Audio", price: 699.00, costo: 470.00, image: '/img/productos/hyperx-quadcast-s.svg', descripcion: "USB con iluminacion RGB y 4 patrones polares." },
  28: { product: "Mando Xbox Wireless", brand: "Microsoft", category: "Gaming", price: 299.00, costo: 200.00, image: '/img/productos/mando-xbox.svg', descripcion: "Compatible con Xbox, PC y celulares." },
  29: { product: "PlayStation 5 Slim", brand: "Sony", category: "Gaming", price: 2499.00, costo: 2050.00, image: '/img/productos/ps5-slim.svg', descripcion: "1 TB de almacenamiento y control DualSense." },
  30: { product: "Tableta grafica Wacom Intuos M", brand: "Wacom", category: "Accesorios", price: 499.00, costo: 340.00, image: '/img/productos/wacom-intuos-m.svg', descripcion: "Lapiz sin bateria con 4096 niveles de presion." },
};
const STATUSES = ['delivered', 'shipped', 'pending'];

let ORDERS = [];
let orderSeq = 1001;
USERS.forEach(u => {
  const n = 2 + (u.id % 3); // 2..4 pedidos
  for (let k = 0; k < n; k++) {
    const pid = 1 + ((u.id + k) % 5);
    const p   = PRODUCTS[pid];
    ORDERS.push({
      id: orderSeq++,
      userId: u.id,
      product_id: pid,
      product: p.product,
      brand: p.brand,
      category: p.category,
      price: p.price,
      status: STATUSES[(u.id + k) % 3],
      image: p.image,
      address: u.direccion,
    });
  }
});
const ordersOf = uid => ORDERS.filter(o => o.userId === uid);

/* ---------------------------------------------------------------------
   Documentos confidenciales - 40 archivos (doc001..doc040), 2 por usuario
   Imagenes en public/uploads/docs/docNNN.jpg
   --------------------------------------------------------------------- */
const DOC_TIPOS = [
  'Contrato de Servicio', 'Documento de Identidad', 'Acuerdo de Confidencialidad (NDA)',
  'Estado de Cuenta Bancario', 'Copia de Tarjeta', 'Boleta de Pago',
  'Historial Medico', 'Codigo Fuente Interno',
];
let DOCUMENTOS = [];
USERS.forEach((u, i) => {
  if (i >= 20) return; // solo hay 40 imagenes (doc001..doc040), 2 por cada uno de los 20 usuarios originales
  for (let k = 0; k < 2; k++) {
    const n   = i * 2 + k + 1;
    const tipo = DOC_TIPOS[(i + k) % DOC_TIPOS.length];
    DOCUMENTOS.push({
      id: 'doc' + String(n).padStart(3, '0'),
      userId: u.id,
      tipo,
      titulo: tipo + ' - ' + u.nombre,
      archivo: '/uploads/docs/doc' + String(n).padStart(3, '0') + '.jpg',
      fecha: '2026-0' + (1 + (n % 8)) + '-' + String(1 + (n % 27)).padStart(2, '0'),
    });
  }
});
const docsOf = uid => DOCUMENTOS.filter(d => d.userId === uid);

/* ---------------------------------------------------------------------
   Reviews (XSS Stored)
   --------------------------------------------------------------------- */
let REVIEWS = [
  { id: 1, product_id: 1, username: 'maria',  rating: 5, content: 'Excelente laptop, muy rapida para desarrollo.' },
  { id: 2, product_id: 2, username: 'jorge',  rating: 4, content: 'Buen monitor, colores vivos. Recomendado.' },
  { id: 3, product_id: 4, username: 'lucia',  rating: 5, content: 'El mouse mas comodo que he probado.' },
];
let reviewSeq = 4;

/* =====================================================================
   RUTAS
   ===================================================================== */

/* ---- 01. SQL Injection simulada en login ---------------------------- */
function buildQuery(email, password) {
  return `SELECT * FROM usuarios WHERE email='${email}' AND password='${password}'`;
}
function isBypass(email) {
  const e = String(email).toLowerCase();
  return /('|\s)or\s+('?1'?\s*=\s*'?1|1\s*=\s*1)/.test(e) || /'\s*(--|#)/.test(e) || /admin'\s*--/.test(e);
}
function hasUnbalancedQuote(str) {
  return (String(str).match(/'/g) || []).length % 2 === 1;
}

app.post('/auth/login', (req, res) => {
  const { email = '', password = '' } = req.body || {};

  // Bypass clasico: ' OR '1'='1' --  /  admin'--
  if (isBypass(email)) {
    const admin = USERS.find(u => u.role === 'admin');
    const token = signJWT({ userId: admin.id, username: admin.username, role: admin.role, dni: admin.dni });
    return res.json({ success: true, token, user: { username: admin.username, email: admin.email, role: admin.role } });
  }

  // Comilla suelta -> error de sintaxis MySQL realista (fuga de info de BD)
  if (hasUnbalancedQuote(email) || hasUnbalancedQuote(password)) {
    return res.status(500).json({
      success: false,
      sql_error: true,
      code: 'ER_PARSE_ERROR',
      errno: 1064,
      sqlState: '42000',
      message: `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${String(email).slice(-24)}' at line 1`,
      query: buildQuery(email, password),
      driver: 'mysqli',
      database: 'vulnshop_prod',
      host: 'db-prod-01.vigilantium.com:3306',
    });
  }

  // Autenticacion normal (sin rate limiting)
  const user = USERS.find(u => u.email.toLowerCase() === String(email).toLowerCase() && u.password === password);
  if (!user) return res.json({ success: false, error: 'Credenciales invalidas' });

  const token = signJWT({ userId: user.id, username: user.username, role: user.role, dni: user.dni });
  res.json({ success: true, token, user: { username: user.username, email: user.email, role: user.role } });
});

/* ---- 08. Logout que NO invalida el token ---------------------------- */
app.post('/auth/logout', (req, res) => {
  res.json({ success: true, message: 'Sesion cerrada' });
});

/* ---- Perfil del usuario autenticado --------------------------------- */
app.get('/api/me', authRequired, (req, res) => {
  const u = req.user;
  res.json({
    id: u.id, username: u.username, nombre: u.nombre, email: u.email,
    dni: u.dni, uuid: u.uuid, role: u.role, balance: u.balance,
    nivel_membresia: u.nivel_membresia,
  });
});

/* ---- Pedidos del usuario -------------------------------------------- */
app.get('/api/orders', authRequired, (req, res) => {
  res.json({ orders: ordersOf(req.user.id) });
});

/* ---- IDOR: detalle de pedido sin validar propiedad ------------------ */
app.get('/api/orders/:id', authRequired, (req, res) => {
  const order = ORDERS.find(o => o.id === parseInt(req.params.id));
  if (!order) return res.status(404).json({ error: 'Pedido no encontrado' });
  res.json({ order }); // no verifica que order.userId === req.user.id
});

/* ---- 02a. IDOR por DNI: /api/cuenta?dni= ---------------------------- */
/*  El UI solo pinta "perfil" + "pedidos". Los bloques datos_financieros
    y datos_identidad viajan en el JSON pero NO se renderizan: solo se ven
    interceptando con Burp. IDOR: no valida que el dni sea el de la sesion. */
function perfilPublico(u) {
  return {
    nombre: u.nombre, username: u.username, nivel_membresia: u.nivel_membresia,
    dni: u.dni, uuid: u.uuid, email: u.email, telefono: u.telefono,
    fecha_nacimiento: u.fecha_nacimiento, direccion: u.direccion,
    tarjeta: u.tarjeta, balance: u.balance, role: u.role,
  };
}
function datosFinancieros(u) {
  return {
    cuenta_bancaria: u._cuenta_bancaria, cci: u._cci,
    tarjeta_completa: u._tarjeta_completa, cvv: u._cvv,
    clave_banca_web: u._clave_web, score_crediticio: u._score_crediticio,
    ingresos_mensuales: u._ingresos_mensuales, deudas_activas: u._deudas_activas,
  };
}
function datosIdentidad(u) {
  return {
    pasaporte: u._pasaporte, token_recuperacion: u._token_recuperacion,
    fecha_nacimiento: u.fecha_nacimiento, direccion_completa: u.direccion,
  };
}

app.get('/api/cuenta', authRequired, (req, res) => {
  const u = userByDni(req.query.dni);
  if (!u) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({
    perfil: perfilPublico(u),
    pedidos: ordersOf(u.id),
    datos_financieros: datosFinancieros(u),
    datos_identidad: datosIdentidad(u),
  });
});

/* ---- 02c. IDOR cambio de contrasena --------------------------------- */
/*  Se valida correctamente la password_actual... pero contra el usuario
    AUTENTICADO. El objetivo del cambio se toma de body.dni (IDOR):
    demuestras que sabes TU clave y cambias la de CUALQUIER dni.          */
app.post('/api/cuenta/cambiar-password', authRequired, (req, res) => {
  const { dni, password_actual, nueva_password } = req.body || {};
  if (!password_actual || !nueva_password)
    return res.status(400).json({ success: false, error: 'Faltan campos requeridos' });

  if (password_actual !== req.user.password)
    return res.status(401).json({ success: false, error: 'La contrasena actual es incorrecta' });

  const target = userByDni(dni) || req.user; // usa el dni del body, no el del token
  target.password = nueva_password;
  res.json({ success: true, message: `Contrasena actualizada para DNI ${target.dni}` });
});

/* ---- 03. XSS Reflejado: /search?q= (sin auth, sin escapar) ---------- */
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  const t = String(q).toLowerCase();
  const matches = Object.entries(PRODUCTS).filter(([, p]) =>
    (p.product + ' ' + p.brand + ' ' + p.category).toLowerCase().includes(t));
  const cards = matches.map(([id, p]) => `
    <div class="product-card">
      <img src="${p.image}" alt="${p.product}" style="width:100%;height:150px;object-fit:cover;border-radius:8px;margin-bottom:10px">
      <div style="color:#888;font-size:.75rem;text-transform:uppercase;letter-spacing:.5px">${p.category}</div>
      <h3 style="font-size:.95rem;margin:4px 0">${p.product}</h3>
      <div style="color:#666;font-size:.8rem;min-height:34px">${p.descripcion}</div>
      <div style="font-weight:800;margin:8px 0">S/ ${p.price.toLocaleString('es-PE', { minimumFractionDigits: 2 })}</div>
      <a href="/checkout.html?producto=${id}" class="btn btn-primary btn-sm" style="display:inline-block;width:auto">Comprar</a>
      <a href="/reviews.html?producto=${id}" style="font-size:.8rem;margin-left:8px;color:#3182ce">Opiniones</a>
    </div>`).join('');

  res.send(`<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
    <title>VulnShop - Productos</title><link rel="stylesheet" href="/styles.css"></head><body>
    <nav class="navbar"><a href="/dashboard.html" class="brand">VulnShop</a>
      <div class="nav-links">
        <a href="/dashboard.html">Inicio</a>
        <a href="/search?q=" style="color:#4cc9f0">Productos</a>
        <a href="/orders.html">Mis Pedidos</a>
        <a href="/profile.html">Mi Perfil</a>
      </div></nav>
    <div class="container">
      <div class="card">
        <form action="/search" method="GET" class="search-form">
          <input type="text" name="q" value="${q}" placeholder="Buscar laptops, celulares, audio...">
          <button class="btn btn-primary" style="width:auto">Buscar</button>
        </form>
        <p style="color:#555;margin-top:8px">${q ? 'Resultados para: <strong>' + q + '</strong>' : 'Todos los productos'} &middot; ${matches.length} productos</p>
        <div class="products-grid">${cards || '<p class="no-results">Sin resultados.</p>'}</div>
      </div>
    </div>
    <footer>&copy; 2026 VulnShop. Todos los derechos reservados.</footer>
    <script src="/assets/js/main.4f2a9c.js"></script>
    <script src="/nova-widget.js"></script>
    </body></html>`);
});

/* ---- Catalogo publico (lo usan checkout y resenas) ------------------- */
app.get('/api/productos', (req, res) => {
  res.json({ total: Object.keys(PRODUCTS).length, productos: Object.entries(PRODUCTS).map(([id, p]) => ({
    id: Number(id), nombre: p.product, marca: p.brand, categoria: p.category, precio: p.price, imagen: p.image, descripcion: p.descripcion,
  })) });
});

/* ---- 04. XSS Stored: reviews --------------------------------------- */
app.get('/api/reviews', (req, res) => {
  res.json({ reviews: REVIEWS });
});
app.post('/api/reviews', authRequired, (req, res) => {
  const { product_id, rating, content } = req.body || {};
  REVIEWS.push({
    id: reviewSeq++,
    product_id: parseInt(product_id) || 1,
    username: req.user.username,
    rating: parseInt(rating) || 5,
    content: content || '', // se guarda sin sanitizar
  });
  res.json({ success: true });
});

/* ---- 05. Frontend Bypass + Logica de Negocio: checkout -------------- */
/*  price viene del body (frontend bypass). descuento/cupon se confia del
    cliente sin validacion (business logic): cupon con % arbitrario.      */
const CUPONES = { BIENVENIDA: 10, VIGILANTIUM: 15, VSGOLD25: 25 }; // catalogo "oficial" (VSGOLD25: solo Gold, pero no se valida)
app.post('/api/checkout', authRequired, (req, res) => {
  let { product_id, quantity, price, cupon, discount_percent } = req.body || {};
  quantity = parseInt(quantity) || 1;
  price    = parseFloat(price);
  if (isNaN(price)) price = (PRODUCTS[product_id] || {}).price || 0;

  // El backend confia en el descuento enviado por el cliente (sin validar tope)
  let descuento = 0;
  if (discount_percent !== undefined && discount_percent !== null && discount_percent !== '') {
    descuento = parseFloat(discount_percent) || 0;      // 0..100+ sin control
  } else if (cupon) {
    descuento = CUPONES[String(cupon).toUpperCase()] || parseFloat(cupon) || 0;
  }

  const subtotal = price * quantity;
  const total    = subtotal - (subtotal * descuento / 100);
  const prod     = PRODUCTS[product_id] || { product: 'Producto' };

  const order = {
    id: orderSeq++, userId: req.user.id, product_id: parseInt(product_id) || 0,
    product: prod.product, brand: prod.brand, category: prod.category,
    price: total, quantity, status: 'pending', image: prod.image,
    address: req.user.direccion,
  };
  ORDERS.push(order);
  res.json({ success: true, order: { ...order, subtotal, descuento_aplicado: descuento, total } });
});

/* ---- 05c. Reembolsos (los usa NOVA) -------------------------------- */
/*  Abona el monto al saldo del usuario autenticado. No valida que el
    pedido sea suyo ni que el monto no supere lo pagado: el limite de
    S/ 200 solo existe como texto en el prompt de NOVA.                   */
let reembolsoSeq = 500001;
app.post('/api/reembolso', authRequired, (req, res) => {
  const { order_id, monto, motivo = '' } = req.body || {};
  const pedido = ORDERS.find(o => o.id === parseInt(order_id));
  if (!pedido) return res.status(404).json({ success: false, error: 'Pedido no encontrado' });
  const importe = Math.round((parseFloat(monto) || 0) * 100) / 100;
  if (importe <= 0) return res.status(400).json({ success: false, error: 'Monto invalido' });
  req.user.balance = Math.round((req.user.balance + importe) * 100) / 100;
  res.json({
    success: true,
    reembolso: { id: 'RB-' + reembolsoSeq++, order_id: pedido.id, monto: importe, motivo, abonado_a: req.user.username },
    pedido: { id: pedido.id, userId: pedido.userId, product: pedido.product, price: pedido.price },
    saldo_actual: req.user.balance,
  });
});

/* ---- 02b. IDOR por UUID (sin auth) ---------------------------------- */
app.get('/api/v1/usuarios', (req, res) => {
  res.json({
    total: USERS.length,
    usuarios: USERS.map(u => ({
      uuid: u.uuid, username: u.username, nombre: u.nombre,
      nivel_membresia: u.nivel_membresia,
    })),
  });
});
app.get('/api/v1/usuarios/:uuid', (req, res) => {
  const u = userByUuid(req.params.uuid);
  if (!u) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({
    perfil: perfilPublico(u),
    pedidos: ordersOf(u.id),
    datos_financieros: datosFinancieros(u),
  });
});

/* ---- IDOR Documentos ------------------------------------------------ */
app.get('/api/documentos', authRequired, (req, res) => {
  res.json({ documentos: docsOf(req.user.id) });
});
app.get('/api/documento/:docId', authRequired, (req, res) => {
  const doc = DOCUMENTOS.find(d => d.id === req.params.docId);
  if (!doc) return res.status(404).json({ error: 'Documento no encontrado' });
  const owner = USERS.find(u => u.id === doc.userId);
  // IDOR: no valida que el documento pertenezca al usuario autenticado
  res.json({
    documento: doc,
    propietario: {
      nombre: owner.nombre, dni: owner.dni, email: owner.email,
    },
    datos_financieros: datosFinancieros(owner),
    datos_identidad: datosIdentidad(owner),
  });
});

/* ---- 06. Security Misconfiguration ---------------------------------- */
app.get('/admin', (req, res) => {
  res.json({
    panel: 'admin-legacy v1.3',
    jwt_secret: JWT_SECRET,
    total_usuarios: USERS.length,
    usuarios: USERS.map(u => ({
      id: u.id, username: u.username, email: u.email, dni: u.dni,
      role: u.role, password: u.password, tarjeta_completa: u._tarjeta_completa,
      cvv: u._cvv, cuenta_bancaria: u._cuenta_bancaria,
    })),
    config: { db: 'mysql://root:root@db-prod-01.vigilantium.com:3306/vulnshop_prod' },
  });
});
app.get('/.env', (req, res) => {
  res.type('text/plain').send(
`# .env - VulnShop (NO subir a produccion)
NODE_ENV=production
JWT_SECRET=${JWT_SECRET}
JWT_TTL=86400
DB_HOST=db-prod-01.vigilantium.com
DB_USER=root
DB_PASSWORD=root
DB_NAME=vulnshop_prod
AWS_ACCESS_KEY_ID=${['AK', 'IA5VIGILANTIUM2026X'].join('')}
AWS_SECRET_ACCESS_KEY=${['wJalrXUtnFEMI', '/K7MDENG/bPxRfiCYVIGILANTIUM'].join('')}
STRIPE_SECRET_KEY=${['sk', '_live_', '51VgLnT2eZvKYlo8N3xR7pQwErTyUiOpAsDfGhJk'].join('')}
SMTP_HOST=smtp.vigilantium.com
SMTP_USER=no-reply@vigilantium.com
SMTP_PASS=Vig1lant1um$2026
`);
});
app.get('/actuator/health', (req, res) => {
  res.json({
    status: 'UP',
    components: {
      db: { status: 'UP', details: { database: 'MySQL', version: '8.0.34', host: 'db-prod-01.vigilantium.com' } },
      diskSpace: { status: 'UP', details: { total: 500107862016, free: 213045678123 } },
    },
    build: { node: process.version, app: 'vulnshop', version: '2.4.1', framework: 'Express 4' },
  });
});
app.get('/api/debug/error', (req, res) => {
  res.status(500).json({
    error: 'Internal Server Error',
    stack: `Error: connect ECONNREFUSED 10.0.3.14:6379
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1595:16)
    at /srv/vulnshop/node_modules/redis/lib/client.js:212:19
    at /srv/vulnshop/src/controllers/cache.js:44:7`,
    env: { NODE_ENV: 'production', REDIS_URL: 'redis://:redis2026@10.0.3.14:6379/0' },
  });
});

/* ---- Swagger simulado (FastAPI-style) ------------------------------- */
const OPENAPI = {
  openapi: '3.0.2',
  info: { title: 'VulnShop API', version: '2.4.1', description: 'API interna de VulnShop / Vigilantium 2026' },
  servers: [{ url: '/' }],
  paths: {
    '/auth/login':                { post: { summary: 'Iniciar sesion', tags: ['auth'] } },
    '/auth/logout':               { post: { summary: 'Cerrar sesion', tags: ['auth'] } },
    '/api/me':                    { get:  { summary: 'Perfil autenticado', tags: ['users'], security: [{ bearer: [] }] } },
    '/api/orders':                { get:  { summary: 'Listar pedidos', tags: ['orders'], security: [{ bearer: [] }] } },
    '/api/orders/{id}':           { get:  { summary: 'Detalle de pedido', tags: ['orders'], security: [{ bearer: [] }] } },
    '/api/cuenta':                { get:  { summary: 'Consultar cuenta por DNI', tags: ['users'], parameters: [{ name: 'dni', in: 'query', required: true }] } },
    '/api/cuenta/cambiar-password': { post: { summary: 'Cambiar contrasena', tags: ['users'] } },
    '/api/v1/usuarios':           { get:  { summary: 'Listar todos los usuarios (UUID)', tags: ['v1'] } },
    '/api/v1/usuarios/{uuid}':    { get:  { summary: 'Perfil por UUID', tags: ['v1'] } },
    '/api/documentos':            { get:  { summary: 'Mis documentos', tags: ['docs'], security: [{ bearer: [] }] } },
    '/api/documento/{docId}':     { get:  { summary: 'Ver documento por ID', tags: ['docs'], security: [{ bearer: [] }] } },
    '/api/reviews':               { get:  { summary: 'Listar resenas', tags: ['reviews'] }, post: { summary: 'Crear resena', tags: ['reviews'] } },
    '/api/checkout':              { post: { summary: 'Procesar compra', tags: ['orders'] } },
    '/api/reembolso':             { post: { summary: 'Reembolso al saldo', tags: ['orders'], security: [{ bearer: [] }] } },
    '/api/nova/chat':             { post: { summary: 'Asistente NOVA (IA)', tags: ['nova'], security: [{ bearer: [] }] } },
    '/search':                    { get:  { summary: 'Buscar productos', tags: ['catalog'] } },
    '/api/productos':             { get:  { summary: 'Catalogo de productos', tags: ['catalog'] } },
    '/admin':                     { get:  { summary: 'Panel admin', tags: ['admin'] } },
    '/actuator/health':           { get:  { summary: 'Health check', tags: ['ops'] } },
  },
};
app.get('/openapi.json', (req, res) => res.json(OPENAPI));
app.get('/docs', (req, res) => {
  const rows = Object.entries(OPENAPI.paths).map(([p, methods]) =>
    Object.entries(methods).map(([m, def]) => `
      <div style="border:1px solid #e3e8ee;border-radius:6px;margin-bottom:8px;overflow:hidden">
        <div style="display:flex;align-items:center;gap:12px;padding:10px 14px;background:#fafcff">
          <span style="font-weight:700;text-transform:uppercase;color:#fff;background:${m==='get'?'#61affe':'#49cc90'};padding:4px 12px;border-radius:4px;font-size:.75rem">${m}</span>
          <code style="font-size:.9rem">${p}</code>
          <span style="color:#3b4151;font-size:.85rem">${def.summary}</span>
          ${def.security ? '<span title="requiere token" style="margin-left:auto">&#128274;</span>' : '<span style="margin-left:auto;color:#49cc90;font-size:.75rem">sin auth</span>'}
        </div>
      </div>`).join('')).join('');
  res.send(`<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>VulnShop API - Swagger UI</title>
    <style>body{font-family:'Segoe UI',sans-serif;background:#fafafa;margin:0;color:#3b4151}
    header{background:#1b1b1b;color:#fff;padding:18px 28px}header h1{margin:0;font-size:1.3rem}
    .wrap{max-width:960px;margin:24px auto;padding:0 20px}</style></head><body>
    <header><h1>VulnShop API <span style="color:#89bf04">v${OPENAPI.info.version}</span></h1>
      <div style="font-size:.85rem;color:#aaa">OpenAPI 3.0 &middot; /openapi.json</div></header>
    <div class="wrap">${rows}</div></body></html>`);
});

/* ---- 12. Carga de archivos sin control + listado de /uploads ---------- */
/*  - POST /api/perfil/foto NO pide sesion y toma el DNI del body: cualquiera
      cambia la foto de cualquiera (A01).
    - El tipo de archivo solo se valida en el navegador (accept="image/*"):
      con Burp se sube un .html o .svg con JavaScript que la tienda sirve
      desde su propio dominio (A06, CWE-434).
    - /uploads/ tiene el listado de directorio activado: se enumeran y
      descargan las fotos y los 40 documentos confidenciales (A02).         */
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
const FOTOS_DIR   = path.join(UPLOADS_DIR, 'fotos');
fs.mkdirSync(FOTOS_DIR, { recursive: true });
const fotoDe = dni => {
  const f = fs.readdirSync(FOTOS_DIR).find(n => n.startsWith(String(dni) + '_'));
  return f ? '/uploads/fotos/' + f : null;
};

app.post('/api/perfil/foto', (req, res) => {
  const { dni, archivo = '', contenido = '' } = req.body || {};
  const u = userByDni(dni);
  if (!u) return res.status(404).json({ success: false, error: 'DNI no registrado' });
  // basename: el nombre lo elige el cliente, pero no se permite salir de uploads/fotos
  const nombre = path.basename(String(archivo)).replace(/[^\w.\-]/g, '_') || 'foto.jpg';
  const datos = Buffer.from(String(contenido).replace(/^data:[^,]*,/, ''), 'base64');
  if (!datos.length) return res.status(400).json({ success: false, error: 'Archivo vacio' });
  const previa = fotoDe(u.dni);
  if (previa) fs.rmSync(path.join(UPLOADS_DIR, 'fotos', path.basename(previa)), { force: true });
  fs.writeFileSync(path.join(FOTOS_DIR, u.dni + '_' + nombre), datos);
  res.json({ success: true, url: '/uploads/fotos/' + u.dni + '_' + nombre, tamano: datos.length });
});

app.get('/api/perfil/foto', (req, res) => {
  const u = userByDni(req.query.dni);
  if (!u) return res.status(404).json({ error: 'DNI no registrado' });
  res.json({ dni: u.dni, url: fotoDe(u.dni) });
});

app.get(/^\/uploads(\/.*)?$/, (req, res, next) => {
  const rel = decodeURIComponent(req.params[0] || '/');
  const dir = path.resolve(UPLOADS_DIR, '.' + rel);
  if (!(dir + path.sep).startsWith(UPLOADS_DIR + path.sep) && dir !== UPLOADS_DIR) return next();
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) return next(); // archivos: express.static
  if (!req.path.endsWith('/')) return res.redirect(req.path + '/');
  const filas = fs.readdirSync(dir, { withFileTypes: true }).filter(e => !e.name.startsWith('.')).map(e => {
    const st = fs.statSync(path.join(dir, e.name));
    const n = e.isDirectory() ? e.name + '/' : e.name;
    return `<tr><td><a href="${n}">${n}</a></td><td>${st.mtime.toISOString().slice(0, 16).replace('T', ' ')}</td><td align="right">${e.isDirectory() ? '-' : Math.ceil(st.size / 1024) + 'K'}</td></tr>`;
  }).join('');
  res.send(`<!DOCTYPE html><html><head><title>Index of /uploads${rel}</title></head><body>
    <h1>Index of /uploads${rel}</h1><table><tr><th align="left">Name</th><th align="left">Last modified</th><th>Size</th></tr>
    <tr><th colspan="3"><hr></th></tr>${rel !== '/' ? '<tr><td><a href="../">Parent Directory</a></td><td></td><td align="right">-</td></tr>' : ''}${filas}
    <tr><th colspan="3"><hr></th></tr></table><address>Apache/2.4.41 (Ubuntu) Server at vulnshop.pe Port 443</address></body></html>`);
});

/* ---- 09. API interna expuesta en el bundle JS del front --------------- */
/*  /assets/js/main.4f2a9c.js trae las rutas "internal" y la cabecera
    X-Internal-Key con su valor: cualquiera que abra DevTools > Sources
    (o haga grep sobre el JS) puede llamar a la API interna.             */
const INTERNAL_KEY = 'vsint_7f3a9c21e8b44d6a90c1';
function internalKey(req, res, next) {
  if (req.headers['x-internal-key'] !== INTERNAL_KEY)
    return res.status(403).json({ error: 'Falta la cabecera X-Internal-Key o es invalida' });
  next();
}
app.get('/api/internal/v2/clientes/export', internalKey, (req, res) => {
  const csv = ['id,nombre,email,dni,telefono,direccion,tarjeta_completa,cvv,cuenta_bancaria']
    .concat(USERS.map(u => [u.id, u.nombre, u.email, u.dni, u.telefono, '"' + u.direccion + '"',
      u._tarjeta_completa, u._cvv, '"' + u._cuenta_bancaria + '"'].join(','))).join('\n');
  res.type('text/csv').set('Content-Disposition', 'attachment; filename="clientes_export.csv"').send(csv);
});
app.get('/api/internal/v2/pedidos', internalKey, (req, res) => {
  res.json({ total: ORDERS.length, pedidos: ORDERS.map(o => ({ ...o, cliente: (USERS.find(u => u.id === o.userId) || {}).nombre })) });
});
app.get('/api/internal/v2/debug/config', internalKey, (req, res) => {
  res.json({ jwt_secret: JWT_SECRET, jwt_ttl: JWT_TTL, cupones: CUPONES, soporte: { usuario: 'soporte', ruta: '/soporte-interno' } });
});

/* ---- 10. Credenciales en un comentario HTML (login.html) --------------- */
/*  Un TODO olvidado en el HTML del login (Ctrl+U) revela un panel de
    soporte con usuario y clave. El panel solo tiene Basic Auth y muestra
    tickets con datos personales de los clientes.                          */
const SOPORTE_USER = 'soporte', SOPORTE_PASS = 'Soporte#2024';
app.get('/soporte-interno', (req, res) => {
  const [tipo, b64] = String(req.headers.authorization || '').split(' ');
  const [u, p] = tipo === 'Basic' && b64 ? Buffer.from(b64, 'base64').toString().split(':') : [];
  if (u !== SOPORTE_USER || p !== SOPORTE_PASS)
    return res.status(401).set('WWW-Authenticate', 'Basic realm="Soporte VulnShop"').send('Acceso restringido al equipo de soporte');
  const filas = USERS.slice(0, 12).map((x, i) => `<tr><td>TCK-${4810 + i}</td><td>${x.nombre}</td><td>${x.dni}</td><td>${x.email}</td><td>${x.telefono}</td>
    <td>${['No llega mi pedido', 'Cambio de direccion', 'Cobro duplicado', 'Olvide mi clave'][i % 4]}</td><td>${x._cuenta_bancaria}</td></tr>`).join('');
  res.send(`<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>Soporte interno - VulnShop</title>
    <link rel="stylesheet" href="/styles.css"></head><body>
    <nav class="navbar"><span class="brand">VulnShop &middot; Soporte interno</span></nav>
    <div class="container"><div class="card"><h2>Tickets abiertos</h2>
    <p style="color:#888;font-size:.85rem">Uso exclusivo del equipo de soporte. Para resetear claves usa el script del servidor.</p>
    <table class="users" style="width:100%;font-size:.82rem"><tr><th>Ticket</th><th>Cliente</th><th>DNI</th><th>Correo</th><th>Telefono</th><th>Motivo</th><th>Cuenta para devolucion</th></tr>${filas}</table>
    </div></div></body></html>`);
});

/* ---- 11. Swagger "de desarrollo" olvidado en /dev ---------------------- */
/*  No esta enlazado en ningun lado: se encuentra con fuzzing de directorios
    (ffuf/gobuster + SecLists directory-list-2.3-medium). Documenta la API
    interna, incluida la cabecera X-Internal-Key con un valor de ejemplo
    que es el real.                                                        */
const OPENAPI_DEV = {
  openapi: '3.0.2',
  info: { title: 'VulnShop Internal API (DEV)', version: '2.5.0-dev', description: 'Documentacion interna del equipo de desarrollo. NO PUBLICAR.' },
  servers: [{ url: '/' }],
  components: { securitySchemes: { internalKey: { type: 'apiKey', in: 'header', name: 'X-Internal-Key', description: 'Ej.: ' + INTERNAL_KEY } } },
  paths: {
    '/api/internal/v2/clientes/export': { get: { summary: 'Exportar todos los clientes (CSV)', tags: ['internal'], security: [{ internalKey: [] }] } },
    '/api/internal/v2/pedidos':         { get: { summary: 'Todos los pedidos con nombre del cliente', tags: ['internal'], security: [{ internalKey: [] }] } },
    '/api/internal/v2/debug/config':    { get: { summary: 'Configuracion en caliente (debug)', tags: ['internal'], security: [{ internalKey: [] }] } },
    '/api/reembolso':                   { post: { summary: 'Reembolso al saldo (lo usa NOVA)', tags: ['orders'] } },
    '/soporte-interno':                 { get: { summary: 'Panel de soporte (Basic Auth)', tags: ['soporte'] } },
    '/admin':                           { get: { summary: 'Panel admin legacy', tags: ['admin'] } },
  },
};
app.get('/dev/openapi.json', (req, res) => res.json(OPENAPI_DEV));
app.get(['/dev', '/dev/'], (req, res) => {
  const filas = Object.entries(OPENAPI_DEV.paths).map(([ruta, metodos]) => Object.entries(metodos).map(([m, d]) =>
    `<div style="border:1px solid #e3e8ee;border-radius:6px;margin-bottom:8px;padding:10px 14px;background:#fafcff;display:flex;gap:12px;align-items:center">
      <span style="font-weight:700;text-transform:uppercase;color:#fff;background:${m === 'get' ? '#61affe' : '#49cc90'};padding:4px 12px;border-radius:4px;font-size:.75rem">${m}</span>
      <code>${ruta}</code><span style="color:#3b4151;font-size:.85rem">${d.summary}</span></div>`).join('')).join('');
  res.send(`<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>VulnShop Internal API (DEV) - Swagger UI</title>
    <style>body{font-family:'Segoe UI',sans-serif;background:#fafafa;margin:0;color:#3b4151}header{background:#1b1b1b;color:#fff;padding:18px 28px}
    .wrap{max-width:960px;margin:24px auto;padding:0 20px}.auth{background:#fff3cd;border:1px solid #ffe08a;border-radius:6px;padding:10px 14px;margin-bottom:16px;font-size:.88rem}</style></head><body>
    <header><h1 style="margin:0;font-size:1.3rem">VulnShop Internal API <span style="color:#f0ad4e">${OPENAPI_DEV.info.version}</span></h1>
    <div style="font-size:.85rem;color:#aaa">OpenAPI 3.0 &middot; /dev/openapi.json &middot; ${OPENAPI_DEV.info.description}</div></header>
    <div class="wrap"><div class="auth">&#128273; Authorize &rarr; <code>X-Internal-Key: ${INTERNAL_KEY}</code> (entorno dev)</div>${filas}</div></body></html>`);
});

/* ---- NOVA: asistente IA integrado (ver nova.js) ---------------------- */
let puertoActual = PORT;
const nova = require('./nova').crearNova({
  USERS, PRODUCTS, authRequired, baseUrl: () => 'http://127.0.0.1:' + puertoActual, claveInterna: CLAVE_INTERNA,
});
nova.registrar(app);

/* ---- Estaticos ------------------------------------------------------ */
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.redirect('/login.html'));

// JSON mal formado (tipico al editar a mano en Burp): respuesta 400 y una
// sola linea en consola, sin el stack trace completo.
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    console.log('   [400] JSON invalido en ' + req.method + ' ' + req.path);
    return res.status(400).json({ error: 'JSON invalido', detalle: err.message });
  }
  next(err);
});

/* ---------------------------------------------------------------------
   Arranque con fallback de puerto (EADDRINUSE -> puerto+1)
   --------------------------------------------------------------------- */
function startServer(port, attempts = 0) {
  const server = app.listen(port, HOST, () => {
    puertoActual = port;
    console.log('  =============================================');
    console.log('   VulnShop - Laboratorio de Seguridad Web');
    console.log('   Felix Prada Silva - Vigilantium 2026');
    console.log('  =============================================');
    console.log('   Servidor:  http://localhost:' + port + '/login.html');
    console.log('   Guia:      http://localhost:' + port + '/guide.html');
    console.log('   Swagger:   http://localhost:' + port + '/docs');
    console.log('   NOVA (IA): ' + (process.env.ANTHROPIC_API_KEY ? 'activa con ' + nova.MODELO : 'SIN API KEY (configura .env)'));
    console.log('  =============================================');
    console.log('   Usuarios: 20  |  Password global: ' + PASSWORD_GLOBAL);
    if (EXTRAS.length) console.log('   + ' + EXTRAS.length + ' cuentas del instructor @vulnshop.com (definidas en .env)');
    console.log('   Acceso: ' + (IPS_PERMITIDAS.length ? 'SOLO ' + IPS_PERMITIDAS.join(', ') + (process.env.TRUST_PROXY ? ' (detras de proxy)' : '') : 'sin restriccion de IP'));
    console.log('   Proxy sugerido (Burp): 127.0.0.1:8080');
    console.log('  =============================================');
  });
  server.on('error', err => {
    if (err.code === 'EADDRINUSE' && attempts < 10) {
      console.log('   Puerto ' + port + ' ocupado, probando ' + (port + 1) + '...');
      startServer(port + 1, attempts + 1);
    } else {
      console.error('   Error al iniciar el servidor:', err.message);
      process.exit(1);
    }
  });
}
startServer(PORT);
