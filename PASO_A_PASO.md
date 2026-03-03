# MediControl — Guía paso a paso

**Objetivo:** Tener todo funcionando en Render y poder reenviar credenciales a usuarios.

---

## PASO 1: Verificar que el backend se desplegó

1. Entra a [Render Dashboard](https://dashboard.render.com)
2. Busca el servicio **medicamentos-backend** (o el nombre que tenga)
3. Comprueba que el último deploy sea **exitoso** (verde)
4. Si falló, revisa los logs y dime qué error sale

**¿Está en verde?** → Sigue al Paso 2.

---

## PASO 2: Reenviar credenciales a usuarios (Familie Micael Andrea, etc.)

1. Abre: **https://medicamentos-backend.onrender.com/admin/login**
2. Inicia sesión con tu cuenta de **superuser** (Family ID, email, contraseña)
3. En el menú lateral, haz clic en **🗑 Usuarios inactivos**
4. Verás la lista de usuarios que nunca iniciaron sesión
5. Opciones:
   - **Reenviar email** (botón por cada usuario): envía solo a ese
   - **Reenviar email a todos**: envía a todos de una vez

**Requisito:** El SMTP debe estar configurado (Paso 3).

---

## PASO 3: Configurar SMTP (para que lleguen los emails)

1. En Render Dashboard → tu servicio backend → **Environment**
2. Añade o verifica estas variables:

| Variable    | Valor ejemplo                    |
|-------------|----------------------------------|
| SMTP_HOST   | smtp.gmail.com                   |
| SMTP_PORT   | 587                              |
| SMTP_USER   | tu-email@gmail.com               |
| SMTP_PASS   | Contraseña de aplicación de Gmail |

**Para Gmail:**
- Ve a [Google Account](https://myaccount.google.com) → Seguridad
- Activa verificación en 2 pasos
- Busca "Contraseñas de aplicaciones" y genera una para "Correo"
- Usa esa contraseña en SMTP_PASS

3. Guarda y **redeploy** el servicio (Render lo hace automáticamente al guardar)

---

## PASO 4: Probar el reenvío

1. Ve a **Usuarios inactivos** en el admin
2. Haz clic en **Reenviar email** en un usuario de prueba
3. Revisa la bandeja de entrada (y spam) del email de ese usuario
4. Si no llega: revisa los logs del backend en Render

---

## PASO 5: OAuth (Google, Facebook) — OPCIONAL

Solo si quieres que los usuarios puedan entrar con "Iniciar sesión con Google" o Facebook.

### 5a. Crear credenciales en Google

1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Crea un proyecto (o elige uno)
3. **APIs y servicios** → **Credenciales** → **Crear credenciales** → **ID de cliente OAuth**
4. Tipo: **Aplicación web**
5. En "URIs de redirección autorizados" añade:
   ```
   https://medicamentos-backend.onrender.com/auth/google/callback
   ```
6. Copia el **Client ID** y el **Client Secret**

### 5b. Añadir variables en Render

En Environment del backend:

| Variable              | Valor                          |
|-----------------------|--------------------------------|
| GOOGLE_CLIENT_ID      | (el Client ID que copiaste)    |
| GOOGLE_CLIENT_SECRET  | (el Client Secret)             |
| BACKEND_PUBLIC_URL    | https://medicamentos-backend.onrender.com |
| FRONTEND_URL          | https://medicamentos-frontend.vercel.app  |

### 5c. Redeploy

Render redeploya solo. Los botones de Google y Facebook aparecerán en la pantalla de login.

---

## Resumen rápido

| Quiero...                    | Pasos                    |
|-----------------------------|--------------------------|
| Reenviar credenciales       | 2 + 3 + 4                |
| Login con Google/Facebook  | 5 (opcional)             |
| Borrar usuarios inactivos  | Paso 2, botón "Borrar"   |

---

## ¿En qué paso estás?

Dime en qué paso te quedaste o qué error ves, y te ayudo con ese punto concreto.
