/* NOVA - asistente de compras (widget de chat) */
(function () {
  if (window.__novaCargada) return;
  window.__novaCargada = true;

  const css = `
  #nova-fab{position:fixed;right:22px;bottom:22px;z-index:9999;background:linear-gradient(135deg,#6d28d9,#2563eb);color:#fff;border:none;border-radius:999px;padding:13px 20px;font-weight:700;font-size:.95rem;box-shadow:0 8px 24px rgba(37,99,235,.35);cursor:pointer;display:flex;align-items:center;gap:8px}
  #nova-fab .punto{width:9px;height:9px;border-radius:50%;background:#4ade80;box-shadow:0 0 0 3px rgba(74,222,128,.3)}
  #nova-panel{position:fixed;right:22px;bottom:84px;z-index:9999;width:400px;max-width:calc(100vw - 32px);height:600px;max-height:calc(100vh - 110px);background:#fff;border-radius:16px;box-shadow:0 18px 50px rgba(15,23,42,.28);display:none;flex-direction:column;overflow:hidden;font-family:'Segoe UI',system-ui,sans-serif}
  #nova-panel.abierto{display:flex}
  #nova-panel header{background:linear-gradient(135deg,#6d28d9,#2563eb);color:#fff;padding:12px 14px;display:flex;align-items:center;gap:10px}
  #nova-panel header .av{width:34px;height:34px;border-radius:50%;background:rgba(255,255,255,.2);display:flex;align-items:center;justify-content:center;font-weight:800}
  #nova-panel header .t{flex:1;line-height:1.25}
  #nova-panel header .t b{display:block;font-size:1rem}
  #nova-panel header .t span{font-size:.75rem;opacity:.9}
  #nova-panel header button{background:rgba(255,255,255,.18);border:none;color:#fff;border-radius:8px;padding:6px 9px;font-size:.75rem;cursor:pointer}
  #nova-msgs{flex:1;overflow-y:auto;padding:14px;background:#f1f5f9;display:flex;flex-direction:column;gap:10px}
  .nova-m{max-width:88%;padding:9px 12px;border-radius:12px;font-size:.88rem;line-height:1.45;word-wrap:break-word}
  .nova-m.yo{align-self:flex-end;background:#2563eb;color:#fff;border-bottom-right-radius:4px;white-space:pre-wrap}
  .nova-m.ia{align-self:flex-start;background:#fff;color:#0f172a;border:1px solid #e2e8f0;border-bottom-left-radius:4px}
  .nova-m.ia ul{padding-left:18px;margin:4px 0}
  .nova-m.ia table{border-collapse:collapse;margin:6px 0;font-size:.82rem}
  .nova-m.ia td,.nova-m.ia th{border:1px solid #e2e8f0;padding:3px 6px}
  .nova-m.ia img{max-width:100%}
  .nova-m.err{align-self:center;background:#fef2f2;color:#991b1b;border:1px solid #fecaca;font-size:.8rem}
  .nova-pensando{align-self:flex-start;color:#64748b;font-size:.8rem;font-style:italic}
  .nova-pie{font-size:.68rem;color:#94a3b8;text-align:center;padding:4px 10px 0;background:#fff}
  #nova-form{display:flex;gap:8px;padding:8px 10px 10px;background:#fff}
  #nova-form textarea{flex:1;resize:none;border:1px solid #cbd5e1;border-radius:10px;padding:8px 10px;font-size:.88rem;font-family:inherit;height:44px;max-height:120px}
  #nova-form button{background:#2563eb;color:#fff;border:none;border-radius:10px;padding:0 16px;font-weight:700;cursor:pointer}
  #nova-form button:disabled{opacity:.5;cursor:default}`;

  const estilo = document.createElement('style');
  estilo.textContent = css;
  document.head.appendChild(estilo);

  const fab = document.createElement('button');
  fab.id = 'nova-fab';
  fab.innerHTML = '<span class="punto"></span> &iquest;Te ayudo? &middot; NOVA';
  const panel = document.createElement('div');
  panel.id = 'nova-panel';
  panel.innerHTML = `
    <header>
      <div class="av">N</div>
      <div class="t"><b>NOVA</b><span>Asistente de compras &middot; en linea</span></div>
      <button type="button" id="nova-nueva" title="Empezar una conversacion nueva">Nueva conversacion</button>
      <button type="button" id="nova-cerrar" aria-label="Cerrar">&times;</button>
    </header>
    <div id="nova-msgs"></div>
    <div class="nova-pie">NOVA usa inteligencia artificial y puede equivocarse.</div>
    <form id="nova-form">
      <textarea id="nova-txt" placeholder="Escribe tu consulta..." maxlength="2000"></textarea>
      <button type="submit" id="nova-env">Enviar</button>
    </form>`;
  document.body.appendChild(fab);
  document.body.appendChild(panel);

  const $ = s => panel.querySelector(s);
  const msgs = $('#nova-msgs');
  const token = () => localStorage.getItem('token') || '';
  const claveHist = () => 'nova_hist_' + token().slice(-16);
  let historial = [];
  let enviando = false;

  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const bajar = () => { msgs.scrollTop = msgs.scrollHeight; };

  // Las respuestas de NOVA vienen con formato (negritas, listas, tablas, enlaces).
  function burbuja(clase, contenido, conFormato) {
    const d = document.createElement('div');
    d.className = 'nova-m ' + clase;
    if (conFormato) d.innerHTML = contenido; else d.textContent = contenido;
    msgs.appendChild(d);
    bajar();
    return d;
  }

  function guardar() {
    try { sessionStorage.setItem(claveHist(), JSON.stringify(historial)); } catch (e) { /* modo privado */ }
  }

  async function bienvenida() {
    const d = burbuja('ia', '¡Hola! Soy <b>NOVA</b>, tu asistente de compras. ¿En que te ayudo hoy?', true);
    if (!token()) return;
    try {
      const h = { Authorization: 'Bearer ' + token() };
      const [me, ped] = await Promise.all([
        fetch('/api/me', { headers: h }).then(r => r.json()),
        fetch('/api/orders', { headers: h }).then(r => r.json()),
      ]);
      if (!me || !me.nombre) return;
      const ult = (ped.orders || []).slice(-1)[0];
      d.innerHTML = '¡Hola, <b>' + esc(me.nombre.split(' ')[0]) + '</b>! Soy <b>NOVA</b>, tu asistente de compras.' +
        (ult ? ' Veo que tu ultimo pedido es el <b>#' + ult.id + '</b> (' + esc(ult.product) + ').' : '') +
        ' Puedo recomendarte productos, contarte que opinan otros clientes, informarte sobre precios y promociones, o revisar el estado de tus pedidos. ¿En que te ayudo?';
    } catch (e) { /* saludo generico */ }
  }

  function restaurar() {
    msgs.innerHTML = '';
    try { historial = JSON.parse(sessionStorage.getItem(claveHist()) || '[]'); } catch (e) { historial = []; }
    if (!historial.length) return bienvenida();
    historial.forEach(m => burbuja(m.role === 'user' ? 'yo' : 'ia', m.content, m.role !== 'user'));
  }

  async function enviar(texto) {
    texto = String(texto || '').trim();
    if (!texto || enviando) return;
    if (!token()) { burbuja('err', 'Inicia sesion para hablar con NOVA.'); return; }
    enviando = true;
    $('#nova-env').disabled = true;
    burbuja('yo', texto);
    const pensando = document.createElement('div');
    pensando.className = 'nova-pensando';
    pensando.textContent = 'NOVA esta escribiendo…';
    msgs.appendChild(pensando);
    bajar();
    try {
      const r = await fetch('/api/nova/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token() },
        body: JSON.stringify({ historial, mensaje: texto }),
      });
      const data = await r.json().catch(() => ({ ok: false, error: 'No pudimos procesar tu consulta.' }));
      pensando.remove();
      if (r.status === 401) { burbuja('err', 'Tu sesion expiro. Vuelve a iniciar sesion.'); return; }
      if (!data.ok) { burbuja('err', data.error || 'NOVA no esta disponible en este momento.'); return; }
      burbuja('ia', data.respuesta, true);
      historial.push({ role: 'user', content: texto }, { role: 'assistant', content: data.respuesta });
      guardar();
    } catch (e) {
      pensando.remove();
      burbuja('err', 'Sin conexion. Intentalo de nuevo.');
    } finally {
      enviando = false;
      $('#nova-env').disabled = false;
    }
  }

  function nuevaConversacion() {
    historial = [];
    guardar();
    msgs.innerHTML = '';
    bienvenida();
  }

  function abrir() {
    panel.classList.add('abierto');
    $('#nova-txt').focus();
  }

  fab.addEventListener('click', () => panel.classList.contains('abierto') ? panel.classList.remove('abierto') : abrir());
  $('#nova-cerrar').addEventListener('click', () => panel.classList.remove('abierto'));
  $('#nova-nueva').addEventListener('click', nuevaConversacion);
  $('#nova-form').addEventListener('submit', e => {
    e.preventDefault();
    const t = $('#nova-txt').value;
    $('#nova-txt').value = '';
    enviar(t);
  });
  $('#nova-txt').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); $('#nova-form').requestSubmit(); }
  });

  // Abre el chat con una consulta (la usan los botones de sugerencias del sitio).
  window.novaAbrir = function (texto, opciones) {
    opciones = opciones || {};
    abrir();
    if (opciones.nueva !== false) nuevaConversacion();
    if (opciones.enviar) enviar(texto);
    else { $('#nova-txt').value = texto || ''; $('#nova-txt').focus(); }
  };

  restaurar();
})();
