# Configurar Brevo para enviar emails (sin dominio propio)

**Brevo** (antes Sendinblue) permite enviar hasta **300 emails/día gratis** sin verificar un dominio. Solo necesitas verificar un email que controles (Gmail, Outlook, etc.). Funciona en Render Free (usa API HTTP, no SMTP).

---

## Paso 1: Crear cuenta en Brevo

1. Ve a [brevo.com](https://www.brevo.com)
2. Clic en **Sign up free**
3. Regístrate con tu email (ej: alertas.medicamentos@gmail.com)
4. Confirma el email de verificación

---

## Paso 2: Registrar el remitente (Sender)

1. En Brevo, ve a **Settings** (engranaje) → **Senders & IP**
2. Clic en **Add a sender**
3. Completa:
   - **From name:** MediControl
   - **From email:** alertas.medicamentos@gmail.com (o el email que uses)
   - **Reply-to:** el mismo email
4. Guarda
5. Brevo enviará un **código de verificación** a ese email
6. Revisa tu bandeja, copia el código de 6 dígitos
7. Pégalo en Brevo para verificar el remitente

---

## Paso 3: Obtener la API Key

1. En Brevo, ve a **Settings** → **SMTP & API**
2. Pestaña **API Keys**
3. Clic en **Generate a new API key**
4. Nombre: `MediControl`
5. Copia la clave (empieza por `xkeysib-...`). **No la compartas.**

---

## Paso 4: Configurar en Render

1. Ve a [dashboard.render.com](https://dashboard.render.com)
2. Abre tu servicio **medicamentos-backend**
3. **Environment** → Add Variable
4. Añade:

| Key | Value |
|-----|-------|
| `BREVO_API_KEY` | xkeysib-tu-api-key-aqui |
| `FROM_EMAIL` | MediControl \<alertas.medicamentos@gmail.com\> |

5. **Importante:** Si tienes `RESEND_API_KEY` configurada, el backend usará Resend en lugar de Brevo. Para usar Brevo, **borra o vacía** `RESEND_API_KEY`.

6. Guarda. Render redesplegará automáticamente.

---

## Paso 5: Probar

1. Ve a Admin → Ajustes
2. En la sección Email deberías ver: **Proveedor: Brevo (API)**
3. Pulsa **Enviar email de prueba** a tu dirección
4. O en Admin → Usuarios, usa el botón **🔑** para un usuario y verifica que llegue el email

---

## Límites del plan gratuito

- **300 emails/día**
- Sin tarjeta de crédito
- Los emails pueden incluir branding "Sent with Brevo" (solo en algunos casos)

---

## Prioridad de proveedores de email

El backend usa el primer disponible en este orden:

1. **RESEND_API_KEY** → Resend (requiere dominio verificado para enviar a terceros)
2. **BREVO_API_KEY** → Brevo (solo verificar un email, sin dominio)
3. **SMTP_HOST + SMTP_USER + SMTP_PASS** → SMTP (Render Free bloquea puertos SMTP)

---

## Solución de problemas

**"Sender not verified"**
- Verifica el remitente en Brevo → Senders con el código que te envían por email.

**"Invalid API key"**
- Comprueba que copiaste la clave completa (xkeysib-...).
- No debe haber espacios al inicio o final.

**Sigue usando Resend**
- Borra la variable `RESEND_API_KEY` en Render para forzar el uso de Brevo.
