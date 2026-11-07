# CryptoGuard — Versión Estática (Web Crypto API)

Aplicación web estática autocontenida que implementa cifrado simétrico (**AES-256-GCM**) y cifrado asimétrico (**RSA-2048 OAEP-SHA256**) directamente en el navegador mediante **Web Crypto API (`window.crypto.subtle`)**, sin requerir PHP, Laravel, MySQL, Apache ni servidores backend.

---

## 1. Características Principales

- **Cifrado Simétrico del Usuario (`AES-256-GCM`)**:
  - Clave de **256 bits** generada en memoria de sesión mediante `crypto.subtle.generateKey()`.
  - Vector de Inicialización (**IV**) aleatorio de **12 bytes (96 bits)** único por cada operación.
  - **Authentication Tag** de **128 bits (16 bytes)** para verificación de integridad.
- **Cifrado Asimétrico de la Contraseña (`RSA-2048 OAEP-SHA256`)**:
  - Par de claves RSA de **2048 bits** (exponente público `65537`, hash `SHA-256`) generado en memoria de sesión.
  - Cifrado mediante la **Clave Pública** y descifrado mediante la **Clave Privada**.
  - Validación estricta del límite matemático de **190 bytes UTF-8**.
- **Descifrado y Verificación**:
  - Proceso inverso completo para ambos algoritmos y comprobación de coincidencia exacta con los valores originales.
- **Gestión de Claves y Seguridad en Memoria**:
  - Las claves se generan como no exportables (`extractable: false`) al iniciar la sesión y residen exclusivamente en memoria RAM del navegador.
  - **Cero almacenamiento persistente**: no se guardan claves ni credenciales en `localStorage`, `sessionStorage`, `cookies` ni bases de datos.
- **Historial en Memoria de Sesión**:
  - Registro de fecha/hora, tipo de operación (`ENCRYPT` / `DECRYPT`), algoritmo, estado y tiempo de ejecución con filtros interactivos.

---

## 2. Estructura del Proyecto

```text
cryptog-static/
├── index.html
├── assets/
│   ├── css/
│   │   └── styles.css
│   ├── js/
│   │   ├── crypto.js
│   │   ├── history.js
│   │   └── app.js
│   └── images/
│       └── logo.svg
└── README.md
```

Todas las referencias a hojas de estilo, scripts e imágenes utilizan **rutas relativas**, garantizando compatibilidad tanto en la raíz de un dominio (`/`) como en subdirectorios de **GitHub Pages** (`/nombre-repositorio/`).

---

## 3. Ejecución Local

Dado que la **Web Crypto API (`crypto.subtle`)** exige un **contexto seguro (`HTTPS` o `localhost`)**, abra la aplicación mediante cualquiera de las siguientes opciones locales:

### Opción A: Usando Laragon (o cualquier servidor estático en `localhost`)
Si la carpeta está en `C:\laragon\www\cryptog-static`, abra en su navegador:

```text
http://localhost/cryptog-static/
```

### Opción B: Usando el servidor estático integrado de PHP o Python (opcional)
Desde la carpeta `C:\laragon\www\cryptog-static`:

```powershell
# Con Python:
python -m http.server 8080
# Abrir: http://localhost:8080
```

---

## 4. Instrucciones para Publicar en GitHub Pages

1. **Crear un repositorio nuevo en GitHub** (por ejemplo, `cryptoguard`).
2. **Inicializar Git en la carpeta `C:\laragon\www\cryptog-static` y subir los archivos:**

```powershell
cd C:\laragon\www\cryptog-static
git init
git branch -M main
git add .
git commit -m "Initial commit: CryptoGuard Static Web Crypto API"
git remote add origin https://github.com/<TU_USUARIO>/<NOMBRE_REPOSITORIO>.git
git push -u origin main
```

3. **Activar GitHub Pages en el repositorio:**
   - Ingrese a su repositorio en GitHub y abra la pestaña **Settings** (Configuración).
   - En el menú lateral izquierdo, seleccione **Pages**.
   - En la sección **Build and deployment**:
     - En **Source**, seleccione **Deploy from a branch**.
     - En **Branch**, elija `main` y la carpeta `/ (root)`.
     - Pulse **Save**.
4. **Acceder a la aplicación publicada:**
   - Tras 1 o 2 minutos, GitHub Pages publicará automáticamente el sitio bajo HTTPS en:
     `https://<TU_USUARIO>.github.io/<NOMBRE_REPOSITORIO>/`

