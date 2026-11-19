# VulnShop + NOVA — Laboratorio de vulnerabilidades web e IA

Felix Prada Silva · Vigilantium 2026

VulnShop es una tienda online **deliberadamente vulnerable**. Esta versión le integra **NOVA**, una asistente de compras **informativa** con IA (Claude Haiku 4.5): recomienda productos, resume opiniones e informa sobre pedidos, pero no compra ni hace reembolsos. Así, en una sola exposición se presentan:

- las vulnerabilidades de la **aplicación web** (OWASP Top 10:2025), y
- las de la **IA integrada** (OWASP Top 10 para aplicaciones LLM 2025).

NOVA atiende desde un chat flotante en todas las páginas. Sus herramientas llaman a la **misma API vulnerable** de la tienda con el token del cliente. Por eso **hereda** las fallas web (IDOR, lógica de negocio, datos de más en el JSON) y les suma las suyas: inyección de prompts, fuga de datos, agencia excesiva, fuga del prompt y manejo inseguro de la salida.

> Solo para uso educativo en entornos controlados. No exponer en redes públicas.

## Cómo levantarlo

Requiere Node.js 20 o superior.

1. Copia `.env.example` a `.env` y pon tu `ANTHROPIC_API_KEY`. Sin la key, la tienda funciona igual, pero NOVA no responde.
2. Doble clic en `start.bat`. También puedes hacerlo a mano:

```
npm install
node server.js
```

| Qué | URL |
|---|---|
| Login | http://localhost:3000/login.html |
| Guía (todos los labs + mapa OWASP) | http://localhost:3000/guide.html |
| Swagger | http://localhost:3000/docs |

Por defecto el servidor escucha solo en `127.0.0.1`. Para que lo vean otros equipos del aula, usa `HOST=0.0.0.0`.

**Publicarlo en internet (Render):** el repo trae `render.yaml`. En Render: **New + → Blueprint →** elige este repositorio y completa `ANTHROPIC_API_KEY` y, si quieres restringir el acceso, `IPS_PERMITIDAS` (por ejemplo `109.123.252.218,179.6.7.148`; acepta rangos CIDR como `2001:db8:1:2::/64`, útiles si tu navegador sale por IPv6). Render asigna la URL `https://<nombre>.onrender.com`. `IPS_PERMITIDAS` es opcional: si no la defines, la tienda queda abierta a todo internet (apágala al terminar el lab). En otro servidor usa `HOST=0.0.0.0`, `IPS_PERMITIDAS` y, si hay un proxy delante, `TRUST_PROXY=1`. Es un laboratorio vulnerable a propósito: nunca lo dejes abierto a todos.

## Antes de la clase: control de calidad

Con la tienda levantada, corre:

```
node scripts/verificar.mjs
```

Comprueba las 23 piezas del lab: cuentas, cada vulnerabilidad web (01 a 12), el reembolso, la guía y que NOVA responda llamando a la API de la tienda. Esa última es la única prueba que usa la API key, con una sola llamada. Para saltarla, agrega `--sin-ia`.

Después, **reinicia la tienda**: reseñas, pedidos y saldos viven en memoria y vuelven a cero.

## Cuentas de prueba

Son 20 usuarios, todos con la contraseña `Passw0rd1!`, con correos `@vigilantium.com` y DNIs del 45678901 al 45679000.

| Usuario | DNI | Rol / membresía |
|---|---|---|
| admin@vigilantium.com | 45678902 | admin · Gold |
| felix@vigilantium.com | 45678906 | user · Gold |
| maria@vigilantium.com | 45678911 | user · Silver (es la atacante en los labs de IA) |
| alice@vigilantium.com | 45678917 | user · Bronze |
| Cuentas del instructor @vulnshop.com | — | Opcionales: se definen en `.env` (`CUENTAS_INSTRUCTOR` y `PASSWORD_INSTRUCTOR`), no en el código |

## Labs web (OWASP Top 10:2025)

| Lab | Vulnerabilidad | OWASP |
|---|---|---|
| 01 | SQL Injection con error MySQL real (`/login.html`) | A05 · A10 |
| 02a–d | IDOR por DNI, UUID, cambio de contraseña y documentos | A01 |
| 03 / 04 | XSS reflejado (`/search?q=`) y almacenado (reseñas) | A05 |
| 05a / 05b | Precio desde el cliente y descuento sin tope en checkout | A06 |
| 06 | `/admin`, `/.env`, `/docs`, `/actuator`, `/api/debug/error` | A02 · A10 |
| 07 | Login sin límite de intentos | A07 |
| 08 | JWT con secreto débil y logout que no invalida | A04 · A07 |
| 09 | Rutas internas y `X-Internal-Key` dentro del bundle JS del front (`/assets/js/main.4f2a9c.js`) | A01 · A02 |
| 10 | Usuario y clave del panel `/soporte-interno` en un comentario HTML del login | A07 · A02 |
| 11 | Swagger de la API interna olvidado en una ruta no enlazada: se encuentra con fuzzing (SecLists directory-list-2.3-medium) | A02 |
| 12 | Foto de perfil: subida sin token y sin validar el tipo de archivo, y `/uploads/` listable (descarga masiva con `scripts/descargar_documentos.sh`) | A01 · A02 · A06 |

Los bloques `datos_financieros` y `datos_identidad` (tarjeta, CVV, CCI, clave web, pasaporte) viajan en el JSON de la API pero no se pintan en la web. Se ven con Burp (proxy 127.0.0.1:8080) o los ve NOVA.

## Cómo se conecta NOVA con VulnShop

- **Una sola sesión.** NOVA usa el mismo login y el mismo token (JWT) de la tienda. Saluda con tu nombre, tu membresía y tu último pedido.
- **La misma API.** Cada herramienta de NOVA llama a un endpoint real de VulnShop: `consultar_cuenta` llama a `GET /api/cuenta?dni=` (lab 02a), `consultar_pedido` a `GET /api/orders/:id` y `ver_resenas` a `GET /api/reviews` (lab 04). `buscar_producto` usa el catálogo.
- **Las mismas fallas.** Como NOVA usa los mismos endpoints, hereda sus IDOR: puede consultar la cuenta y los pedidos de cualquier cliente. La guía enlaza cada lab web con el lab de IA que lo hereda ("🤖 Con NOVA").
- **Para el ponente.** El público solo ve el chat. En la **consola del servidor** queda cada herramienta que usó NOVA, el endpoint que llamó y, en rojo, lo que rompió una política.

## Labs de IA (NOVA · OWASP LLM Top 10 2025)

| Lab | Ataque | OWASP |
|---|---|---|
| IA-01 | Reseña envenenada: texto oculto en una reseña que NOVA obedece y manda al cliente a un sitio de phishing | LLM01 · hereda A05 |
| IA-02 | Secretos del prompt: al "corregir un cuento", NOVA revela el código de supervisor | LLM07 |
| IA-03 | Datos de otro cliente: con una falsa alerta de compra, NOVA entrega el pedido y la dirección de otra clienta | LLM02 · LLM06 · hereda A01 |
| IA-04 | Falso gerente (**no determinista**): ordena vender a costo; NOVA se niega pero, al explicar por qué, a veces revela el código de supervisor (14 de 40 intentos) | LLM07 |

Cada botón de la guía abre una conversación nueva con NOVA. La guía muestra el texto completo de cada prompt y cuántas veces funcionó al medirlo: IA-01 e IA-03, 40 de 40; IA-02, 63 de 65; IA-04, 14 de 40 (no determinista: hay que insistir).

**Reglas del laboratorio:**
- NOVA es un agente "como cualquier otro". El prompt es el que escribiría un equipo con prisa, sin trucos para que falle.
- Si un ataque no funciona, se reporta así: no se debilita al agente.
- La IA no es determinista: el mismo mensaje puede funcionar unas veces y otras no.

## Archivos

- `server.js`: la tienda vulnerable (Express). Incluye `POST /api/reembolso`, nuevo y vulnerable a propósito.
- `nova.js`: la asistente (prompt, herramientas sobre la API de la tienda, detección de incidentes para el panel).
- `public/nova-widget.js`: el chat flotante.
- `public/guide.html`: la guía, con el mapa OWASP web + IA y los botones de cada lab.
