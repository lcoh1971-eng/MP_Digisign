# 🏨 Hotel Signage — Guía de Instalación en Netlify

## Resumen de la arquitectura
```
Netlify (hosting + funciones serverless)
    └── /public/admin/       → Panel de administración
    └── /public/salon/       → Pantalla para tabletas
    └── /netlify/functions/  → API backend (Node.js)
            ├── auth.js      → Login
            ├── salones.js   → CRUD de salones
            ├── eventos.js   → CRUD de eventos + consulta activa
            └── upload.js    → Subida de imágenes
Supabase (base de datos PostgreSQL + almacenamiento de imágenes)
```

---

## PASO 1 — Crear cuenta en Supabase

1. Ve a **https://supabase.com** → "Start your project" → crea cuenta gratis
2. Crea un nuevo proyecto (elige la región más cercana, ej. us-east-1)
3. Guarda la **contraseña de la base de datos** que te pide
4. Espera ~2 minutos a que el proyecto se inicie

### 1.1 Ejecutar el schema SQL
1. En Supabase → menú izquierdo → **SQL Editor** → "New Query"
2. Pega el contenido completo del archivo `supabase-schema.sql`
3. Clic en **"RUN"**
4. Deberías ver: "Success. No rows returned"

### 1.2 Crear el bucket de imágenes
1. En Supabase → **Storage** → "New bucket"
2. Nombre: `imagenes-eventos`
3. Marca ✅ "Public bucket"
4. Clic en "Save"

### 1.3 Obtener las credenciales
En Supabase → **Settings** → **API**:
- Copia el **Project URL** → lo necesitarás como `SUPABASE_URL`
- Copia la **service_role** key (no la anon key) → lo necesitarás como `SUPABASE_SERVICE_KEY`

---

## PASO 2 — Subir el proyecto a GitHub

1. Crea una cuenta en **https://github.com** si no tienes
2. Crea un nuevo repositorio: "hotel-signage" (privado recomendado)
3. Sube todos los archivos de esta carpeta al repositorio:
   ```
   hotel-signage/
   ├── netlify.toml
   ├── supabase-schema.sql  (solo referencia, no es necesario subir)
   ├── public/
   │   ├── index.html
   │   ├── admin/index.html
   │   └── salon/index.html
   └── netlify/
       └── functions/
           ├── package.json
           ├── auth.js
           ├── salones.js
           ├── eventos.js
           └── upload.js
   ```

**Forma más fácil (sin terminal):**
- En GitHub.com → tu repo → "uploading an existing file" → arrastra toda la carpeta

---

## PASO 3 — Desplegar en Netlify

1. Ve a **https://netlify.com** → crea cuenta gratis
2. "Add new site" → "Import an existing project" → **GitHub**
3. Selecciona el repositorio `hotel-signage`
4. Configuración de build:
   - **Build command**: *(dejar vacío)*
   - **Publish directory**: `public`
   - **Functions directory**: `netlify/functions`
5. Clic en **"Deploy site"**

### 3.1 Configurar las variables de entorno
En Netlify → tu sitio → **Site configuration** → **Environment variables** → "Add variable":

| Variable               | Valor                                      |
|------------------------|--------------------------------------------|
| `SUPABASE_URL`         | URL de tu proyecto Supabase                |
| `SUPABASE_SERVICE_KEY` | service_role key de Supabase               |
| `ADMIN_PASSWORD`       | Contraseña que quieras para el admin panel |

Luego ve a **Deploys** → "Trigger deploy" → "Deploy site" para que tome las variables.

---

## PASO 4 — Verificar el despliegue

Tu sitio estará en algo como: `https://grand-palacio-signage.netlify.app`

Puedes personalizar el dominio en Netlify → **Domain management**.

### URLs del sistema:

| URL | Descripción |
|-----|-------------|
| `https://tu-sitio.netlify.app/admin` | Panel de administración |
| `https://tu-sitio.netlify.app/salon/imperial` | Tableta del Salón Imperial |
| `https://tu-sitio.netlify.app/salon/versalles` | Tableta del Salón Versalles |
| `https://tu-sitio.netlify.app/salon/mediterraneo` | Tableta del Salón Mediterráneo |

---

## PASO 5 — Configurar las tabletas

### En cada tableta Android/iPad:
1. Abre Chrome/Safari
2. Ve a la URL del salón correspondiente (ej. `/salon/imperial`)
3. **Android**: Menú (⋮) → "Agregar a pantalla de inicio" → abre como app
4. **iPad**: Compartir → "Agregar a pantalla de inicio"
5. Activa el modo kiosco para evitar que los clientes naveguen fuera:
   - **Android**: Settings → Digital Wellbeing → Screen pinning (anclar pantalla)
   - **iPad**: Settings → Guided Access → activar con código

### Mantener la pantalla siempre encendida:
- **Android**: Settings → Display → Screen timeout → "Never"
- **iPad**: Settings → Display & Brightness → Auto-Lock → "Never"

---

## PASO 6 — Personalizar el nombre del hotel

En `public/salon/index.html` y `public/admin/index.html`, busca:
```
'Grand Palacio'
'Hotel & Resorts'
```
Y reemplaza con el nombre real de tu hotel.

O pasa parámetros en la URL de la tableta:
```
/salon/imperial?hotel=Mi+Hotel&sub=Luxury+Collection
```

---

## Mantenimiento

- **Cambiar contraseña**: En Netlify → Environment variables → `ADMIN_PASSWORD`
- **Agregar salones**: Panel admin → pestaña "Salones" → "Nuevo salón"
- **Backup de datos**: En Supabase → Table Editor puedes exportar a CSV

---

## Soporte técnico

Si algo no funciona, verifica:
1. **Netlify → Functions** → que aparezcan `auth`, `salones`, `eventos`, `upload`
2. **Netlify → Deploys** → que el último deploy sea exitoso (verde)
3. **Supabase → Table Editor** → que existan las tablas `salones` y `eventos`
4. Las variables de entorno estén escritas exactamente como en la tabla anterior
