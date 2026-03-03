# Configuración OAuth — Google, Facebook, Apple

## Variables de entorno (Backend)

Añade estas variables a tu `.env` o al entorno del backend (Docker, Render, etc.):

### Google
```env
GOOGLE_CLIENT_ID=tu_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=tu_client_secret
GOOGLE_CALLBACK_URL=https://tu-backend.com/auth/google/callback
```

### Facebook
```env
FACEBOOK_APP_ID=tu_app_id
FACEBOOK_APP_SECRET=tu_app_secret
FACEBOOK_CALLBACK_URL=https://tu-backend.com/auth/facebook/callback
```

### URL base (para callbacks)
```env
BACKEND_PUBLIC_URL=https://tu-backend.com
FRONTEND_URL=https://tu-app.vercel.app
```

---

## Cómo obtener las credenciales

### Google
1. Ve a [Google Cloud Console](https://console.cloud.google.com/)
2. Crea un proyecto o selecciona uno existente
3. **APIs y servicios** → **Credenciales** → **Crear credenciales** → **ID de cliente OAuth**
4. Tipo: **Aplicación web**
5. URIs de redirección autorizados: `https://tu-backend.com/auth/google/callback`
6. Copia el Client ID y Client Secret

### Facebook
1. Ve a [Facebook for Developers](https://developers.facebook.com/)
2. Crea una app o usa una existente
3. **Configuración** → **Básica** → App ID y App Secret
4. **Productos** → Añade **Inicio de sesión con Facebook**
5. En **Configuración de OAuth** → URI de redirección de OAuth válidos: `https://tu-backend.com/auth/facebook/callback`

### Apple (Sign in with Apple)
Requiere cuenta de Apple Developer (99 USD/año). Configuración más compleja:
- Services ID en Apple Developer
- Clave privada y certificados
- Paquete `passport-apple` o implementación manual

---

## Verificar en el backend

En el admin puedes ver el **auth_provider** de cada usuario:
- `email` — registro clásico (email + contraseña)
- `google` — inicio de sesión con Google
- `facebook` — inicio de sesión con Facebook

---

## Usuarios inactivos

Ruta admin: **/admin/inactive-users** (solo superuser)

Muestra usuarios que:
- Se registraron hace más de 7 días (configurable con `INACTIVE_USER_DAYS`)
- **Nunca iniciaron sesión** (`last_login IS NULL`)

Puedes borrarlos individualmente o en lote. Se elimina también la familia si queda vacía.
