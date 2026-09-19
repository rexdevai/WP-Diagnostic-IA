# WP Diagnostic AI

> Herramienta de diagnóstico para WordPress — Pipeline multiagente con IA que audita cualquier sitio WordPress en seguridad, configuración, rendimiento e integridad de archivos, y genera un reporte listo para el cliente con una lista de acciones priorizadas.

**Autor:** Rexdevai
**Versión:** 1.0.0
**Requiere:** WordPress 5.6+ · PHP 7.4+ · API key de Gemini
**Licencia:** Privada / Todos los derechos reservados

---

## Qué hace

WP Diagnostic AI es un sistema de dos partes:

1. **Una interfaz PHP** (este proyecto) que orquesta un pipeline de cinco agentes de IA contra cualquier sitio WordPress.
2. **Un plugin auxiliar ligero** (`wpdiag-endpoint`) que se instala en el sitio objetivo y expone endpoints REST de solo lectura con contexto técnico y forense.

La interfaz se conecta al sitio objetivo, recopila datos del servidor, WordPress, plugins y usuarios, ejecuta verificaciones forenses de integridad, envía todo a Gemini, y devuelve un diagnóstico estructurado. Nunca modifica el sitio objetivo.

---

## Características principales

**Pipeline de diagnóstico**
- Cadena de cinco agentes: Forense → Analizador → Verificador → Redactor → Operador
- Cada agente ve el contexto original, no solo el output del anterior
- Cada agente tiene una responsabilidad única (sin verificación cruzada entre agentes)
- Progreso en vivo vía Server-Sent Events (SSE) con polling de respaldo
- Detención temprana automática si el Analizador tiene baja confianza o el Verificador rechaza

**Análisis forense**
- Integridad del core de WordPress vía checksums oficiales de wp.org
- Integridad de temas y plugins bundled (separada del core)
- Integridad de plugins activos vía downloads.wordpress.org/plugin-checksums/
- Fallback por ZIP: descarga el ZIP oficial y calcula MD5+SHA256 localmente cuando wp.org no tiene checksums publicados
- Detección de origen por componente: `wporg_verified`, `wporg_unverified`, `premium_or_custom`, `custom_mu_plugin`, `suspicious_zone`
- Escaneo de patrones sospechosos (`eval`, `system`, `exec`, etc.) con exclusión de carpetas vendor
- Escaneo de cron filtrado (se excluyen prefijos de plugins conocidos)
- Excluye el propio plugin auxiliar de su propio escaneo forense

**Escáneres externos (API keys del usuario)**
- VirusTotal y Sucuri SiteCheck
- Ambos se introducen por el usuario en la pantalla de conexión (`Opciones avanzadas`)
- Ambos son opcionales; dejar vacío para omitir
- Los resultados aparecen en un panel dedicado **External security scans** en el reporte
- VirusTotal usa polling con detección de estabilidad (maneja el comportamiento de la API que queda en `in_progress` indefinidamente) y reporta stats parciales cuando el análisis no completa
- El Redactor menciona los escaneos limpios en la respuesta al cliente

**Automatización**
- Instalación automática del plugin auxiliar en el sitio objetivo vía automatización del panel de administración (login → upload → activación → obtención de key)
- Sin necesidad de subir archivos manualmente
- Obtención automática de la WPDiag Key tras la activación
- Inyección de hallazgos deterministas desde flags del contexto (WP_DEBUG, WP_CRON, SSL, extensiones, actualización de core) — sin depender del LLM

**Salida**
- Diagnóstico unificado con hallazgos técnicos y forenses
- Panel de escáneres externos (solo visible cuando al menos un escáner está configurado)
- Respuesta al cliente redactada automáticamente en el idioma del sitio objetivo
- Lista de acciones priorizadas con niveles de riesgo y separación ejecutable/manual
- Reporte imprimible
- Panel de datos forenses crudos para auditoría

**Interfaz**
- PHP puro + JS puro. Sin frameworks, sin build step
- UI oscura, autocontenida
- Funciona en cualquier navegador moderno (escritorio y móvil)
- Flujo manual de respaldo para sitios que bloquean login automatizado

---

## Arquitectura

    ┌───────────────────────────────────────┐
    │  Interfaz PHP (este proyecto)         │
    │  ─────────────────────────────────    │
    │  index.php    · Router + SSE + worker │
    │  pipeline.php · Orquestador           │
    │  agents.php   · 5 agentes             │
    │  forensics.php· Escáneres externos    │
    │  context.php  · Preprocesamiento      │
    │  gemini.php   · Cliente HTTP Gemini   │
    │  render.php   · Vista HTML            │
    │  app.js       · Cliente del pipeline  │
    │  style.css    · UI                    │
    └──────────────────┬────────────────────┘
                       │  HTTPS · REST
                       ▼
    ┌───────────────────────────────────────┐
    │  Sitio WordPress objetivo             │
    │  ─────────────────────────────────    │
    │  wpdiag-endpoint.php (v1.4.0)         │
    │   /wp-json/wpdiag/v1/status           │
    │   /wp-json/wpdiag/v1/context          │
    │   /wp-json/wpdiag/v1/forensics        │
    │   /wp-json/wpdiag/v1/setup-key        │
    └───────────────────────────────────────┘

---

## Requisitos

**En el servidor de la interfaz**
- PHP 7.4+ con `curl`, `json`, `session`
- Opcional: `ZipArchive` (solo necesario para la instalación automática del plugin)
- Salida HTTPS hacia generativelanguage.googleapis.com y downloads.wordpress.org
- Permisos de escritura en `sys_get_temp_dir()`

**En el sitio WordPress objetivo**
- WordPress 5.6+ (REST API y Application Passwords)
- PHP 7.4+
- HTTPS (Basic Auth lo requiere)
- Una cuenta de administrador con App Password válido (para instalación automática) o la posibilidad de instalar el plugin manualmente

**Servicios externos (todos del usuario, ninguno almacenado en el servidor)**
- **API key de Gemini** — obligatoria. Puedes crear una gratis en Google AI Studio: https://aistudio.google.com/apikey. La key debe tener acceso al modelo `gemini-3.1-flash-lite`.
- **API key de VirusTotal** — opcional. Free tier: regístrate en https://www.virustotal.com/gui/my-apikey. Límite: 4 req/min, 500/día.
- **API key de Sucuri SiteCheck** — opcional. Requiere plan de pago.

---

## Instalación

1. Sube la carpeta `wpdiag/` a tu servidor web, bajo una ruta públicamente accesible (ej: https://tu-servidor.com/wpdiag/).

2. Asegúrate de que `sys_get_temp_dir()` sea escribible por el proceso PHP.

3. Verifica que el archivo `wp-plugin/wpdiag-endpoint.php` exista dentro del proyecto (se sirve automáticamente como ZIP o PHP cuando el sitio objetivo lo necesita).

4. Abre https://tu-servidor.com/wpdiag/ en un navegador.

5. Introduce la URL del sitio objetivo y tu API key de Gemini.

6. (Opcional) Expande **Opciones avanzadas** y pega tus API keys de VirusTotal y/o Sucuri para activar los escáneres externos.

7. Si el plugin auxiliar no está instalado en el sitio objetivo, proporciona usuario y contraseña de admin de WordPress — la interfaz lo instalará automáticamente.

8. Si el plugin auxiliar ya está instalado, proporciona la WPDiag Key (disponible en Ajustes › WP Diagnostics en el sitio objetivo).

9. Ejecuta el pipeline.

---

## Escáneres externos (keys del usuario)

Ambos escáneres externos se configuran **por corrida**, desde la interfaz — no desde `config.php`. Las keys:

- Viajan en el body del POST de la request `run`
- Nunca se escriben a disco, sesión o log en el servidor de la interfaz
- Solo afectan esa corrida concreta

**VirusTotal** — free tier disponible. El escáner envía la URL, luego hace polling al endpoint de análisis hasta que:
- El status sea `completed`, o
- El conteo de motores deje de crecer por dos polls consecutivos (detección de estabilidad), o
- La ventana de polling (`WPDIAG_VT_POLL_MAX_WAIT`, por defecto 90s) expire

Si la ventana expira con datos parciales, la interfaz reporta un resultado `partial` con las estadísticas recogidas hasta el momento, en lugar de descartar todo.

**Sucuri SiteCheck** — requiere plan de pago. Si la key es inválida o falta el plan, el escáner reporta `invalid_key` y la sección muestra un mensaje informativo.

**Cuando no se proporcionan keys**, la sección se oculta por completo del reporte.

---

## Fallback manual

Si el sitio objetivo bloquea el login automatizado (2FA, plugins de seguridad, restricciones del hosting), la interfaz ofrece un flujo manual:

1. Descarga el ZIP del plugin vía `?action=plugin_zip`.
2. Instálalo manualmente en el sitio objetivo.
3. Copia la WPDiag Key desde Ajustes › WP Diagnostics.
4. Pégala en la interfaz y ejecuta el pipeline.

---

## Estructura de archivos

    wpdiag/
    ├── index.php                     Punto de entrada · router · SSE · worker
    ├── config.php                    Constantes, paleta, campos por agente
    ├── gemini.php                    Cliente HTTP para la API de Gemini
    ├── context.php                   Preprocesamiento de contexto
    ├── forensics.php                 Escáneres externos + constructor forense
    ├── agents.php                    Los 5 agentes (prompts + parsing)
    ├── pipeline.php                  Orquestador + inyección determinista
    ├── render.php                    Vista HTML
    ├── assets/
    │   ├── style.css                 Estilos de la UI
    │   └── app.js                    Cliente del pipeline
    └── wp-plugin/
        └── wpdiag-endpoint.php       Plugin auxiliar (instalado en el sitio)

---

## Notas de seguridad

- Todas las credenciales introducidas en la interfaz (usuario y contraseña de WordPress, WPDiag Key, key de Gemini, key de VirusTotal, key de Sucuri) se mantienen solo en memoria del navegador. Se envían al servidor de la interfaz en cada request pero nunca se escriben a disco, log o sesión.
- El plugin auxiliar en el sitio objetivo es estrictamente de solo lectura. Nunca modifica archivos, plugins, temas, la base de datos, ni la configuración de WordPress.
- La WPDiag Key se valida con `hash_equals()` en cada request.
- El pipeline nunca ejecuta acciones destructivas sobre el sitio objetivo. El agente Operador solo **sugiere** acciones; en v1.0.0 todas son de nivel UI (abrir un panel, copiar al portapapeles, imprimir reporte) o entradas `manual_action` que requieren que el usuario actúe en el servidor.
- Toda salida visible al usuario se escapa antes de renderizarse (`htmlspecialchars` en PHP, `textContent` en JS).
- La interfaz no acepta uploads desde el navegador; el ZIP del plugin se genera del lado del servidor bajo demanda a partir del archivo fuente.

---

## Compatibilidad

- WordPress 5.6+
- PHP 7.4+
- Cualquier navegador moderno (Chrome, Firefox, Safari, Edge)
- Funciona con o sin LiteSpeed, Cloudflare u otros CDNs — pero **purga la caché** después de instalar el plugin auxiliar para evitar 404s cacheados en `/status`
- No requiere framework externo (ni Composer, ni npm, ni build step)

---

## Créditos

Desarrollado por **Rexdevai**.
Arquitectura, diseño de agentes, prompts y flujos de integración definidos por el autor.

---

*[EN] English version available in [README.md](./README.md)*