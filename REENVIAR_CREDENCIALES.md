# Reenviar credenciales a usuarios sin login

## Cómo usar

1. Entra al **admin** como superuser
2. Ve a **🗑 Usuarios inactivos** (`/admin/inactive-users`)
3. Verás la lista de usuarios que **nunca iniciaron sesión**
4. Opciones:
   - **Reenviar email** (por usuario): genera nueva contraseña y envía el email
   - **Reenviar email a todos**: envía a todos de una vez
   - **Borrar seleccionados**: elimina usuarios (solo los > 7 días)

## Lista de usuarios

La lista se muestra en la página. Formato (tabla):

| Familia | Email | Nombre | ID | Family ID |
|---------|-------|--------|-----|-----------|
| Familie Micael Andrea | ... | ... | 6 | 6 |
| Familie Lu | ... | ... | 7 | 7 |
| Familie Test1 | ... | ... | 8 | 8 |

Puedes expandir **"📋 Lista de usuarios (copiar)"** para copiar la lista en formato texto.

## Requisitos

- SMTP configurado en el backend (variables SMTP_HOST, SMTP_USER, SMTP_PASS)
- Solo usuarios con `auth_provider = email` pueden recibir el reenvío
