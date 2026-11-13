# OpenStick Web

Servidor web en Go + panel administrativo para dispositivos **OpenStick** (MSM8916, Debian en chroot, ARM64). Sirve el sitio público y un panel de administración completo para el hotspot Wi-Fi **y** para el sistema.

> Binario único, sin dependencias externas, compilado estáticamente (`CGO_ENABLED=0`).

---

## Contenido

| Archivo | Descripción |
|---|---|
| `main.go` | Servidor completo: HTTP/HTTPS, `/pedido/`, `/api/hotspot/*`, SSE, shell, archivos, DNS/DHCP |
| `info.html` | Panel administrativo (HTML+CSS+JS en un solo archivo, sin frameworks) |
| `index.html` | Sitio público (intacto, no se modifica desde el panel) |
| `watcher.ps1` | Compila y despliega en el dispositivo por ADB al detectar cambios |
| `openstick-web.service` | Unidad systemd |
| `go.mod` | `go 1.22`, sin dependencias |
| `clone.py`, `test.ps1`, `bin/root-command.sh` | Utilidades auxiliares |

---

## Requisitos

- **Local:** Go 1.22+, PowerShell 7+, `adb` (Platform Tools).
- **Dispositivo:** OpenStick con root por ADB, Debian chroot, NetworkManager (`nmcli`), systemd.

---

## Compilar

```powershell
$env:GOOS="linux"; $env:GOARCH="arm64"; $env:CGO_ENABLED="0"
go build -trimpath -ldflags "-s -w" -o bin\server-linux-arm64 .
go vet ./...
```

---

## Despliegue

Automático con el watcher (compila, sube y reinicia el servicio):

```powershell
.\watcher.ps1
```

Manual / atómico (sube solo `server` e `info.html`, preservando `data/` y `certs/`):

```sh
cp $STAGE/server      $REMOTE/server.new
cp $STAGE/info.html   $REMOTE/info.html.new
mv -f $REMOTE/server.new    $REMOTE/server
mv -f $REMOTE/info.html.new $REMOTE/info.html
systemctl restart openstick-web.service
```

---

## Arquitectura

```
                 ┌──────────────────────────────┐
   :80  ────────▶│ http.ServeMux                │
   :443 (TLS) ──▶│  /            indexHandler   │── index.html (público)
                 │  /pedido/     pedidosHandler │── CRUD pedidos (público)
                 │  /info        infoHandler    │── panel admin
                 │  /assets/     FileServer     │
                 │  /api/hotspot/ hotspotHandler│◀──┐
                 └──────────────────────────────┘  │
                          │                       │
                          ▼                       │
              ┌───────────────────────┐           │
              │ authorizeHotspot      │◀──────────┘  Bearer / X-API-Token
              │  · cookie HttpOnly    │             (compatibilidad)
              │  · rate limiting      │
              └───────────┬───────────┘
                          ▼
              ┌───────────────────────┐
              │ Backend Wi-Fi          │
              │  networkmanager (nmcli│◀── perfil AP + MAC + rutas
              │  hostapd   (portable) │
              └───────────┬───────────┘
                          ▼
                 /sys, /proc, iwconfig, ifconfig
```

### Backend Wi-Fi

El dispositivo **no tiene** `iw`, `ip`, `hostapd` ni `rfkill`. El backend principal es **NetworkManager**:

- Perfil AP detectado dinámicamente (`nmcli con show` → `mode=ap`).
- Autenticación: cookie de sesión `os_admin_session` (HttpOnly, SameSite=Strict, 8 h con renovación) + Bearer/`X-API-Token` para scripts.
- Token administrativo de ejemplo para uso local: `OpenStick2026` (se guarda en `data/hotspot.token` con 0600). Sobreescribible con `OPENSTICK_ADMIN_TOKEN` para despliegues remotos. **Nunca se registra ni se devuelve en las respuestas.**
- Rate limiting: 8 fallos / 5 min → bloqueo de 2 min.
- Operaciones de escritura serializadas con `hotspotOpMu.TryLock()` → HTTP 409 si hay otra en curso. Las lecturas nunca se bloquean.

---

## API

Todas bajo `/api/hotspot/`. Requieren sesión (cookie) o token.

| Método | Ruta | Descripción |
|---|---|---|
| POST | `session` | Login, crea la cookie |
| GET | `session` | Valida la sesión |
| DELETE | `session` | Cierra sesión |
| GET | `status` | Estado real del hotspot |
| POST | `enable` | Encender (`nmcli con up`) y verificar |
| POST | `disable` | Apagar y verificar |
| GET | `config` | Configuración efectiva |
| POST | `config` | SSID / contraseña / interfaz / ipv4Method / security |
| GET | `mac` | MAC real + MAC de perfil |
| POST | `mac` | Aplicar MAC (verificada en sysfs) |
| GET | `clients` | Clientes DHCP + ARP reales |
| GET | `interfaces` | Interfaces Wi-Fi y capacidades |
| GET | `diagnostics` | Diagnóstico completo del sistema |
| GET | `events` | **SSE**: `status`, `clients`, `pedido` |
| POST | `shell` | Ejecutar comando como root |
| GET | `files?path=` | Listar directorio |
| GET | `file?path=` | Leer archivo (texto) |
| GET | `file/download?path=` | Descargar archivo |
| POST | `file` | Escribir archivo |
| DELETE | `file?path=` | Borrar |
| POST | `file/move` | Mover/renombrar |
| POST | `file/upload` | Subir (base64) |
| GET | `dns` | Registros DNS, upstream, configs |
| POST | `dns` | Guardar y aplicar configuración DNS |
| GET | `dhcp` | Concesiones, procesos, configs |
| POST | `dhcp/restart` | Recargar dnsmasq / hotspot |

### Ejemplos

```bash
BASE=https://openstick.local
TOKEN=OpenStick2026          # token de ejemplo para uso local

# login sin cookies
curl -sk -H "X-API-Token: $TOKEN" "$BASE/api/hotspot/status"

# estado
curl -sk "$BASE/api/hotspot/status"

# hotspot abierto (sin clave)
curl -sk -X POST -H 'Content-Type: application/json' \
     -d '{"ssid":"OpenStick","security":"open","ipv4Method":"shared"}' \
     "$BASE/api/hotspot/config"

# DHCP para los clientes (ipv4.shared = dnsmasq + NAT)
curl -sk -X POST -H 'Content-Type: application/json' \
     -d '{"ipv4Method":"shared"}' \
     "$BASE/api/hotspot/config"

# MAC aleatoria local administrada
curl -sk -X POST -H 'Content-Type: application/json' \
     -d '{"mac":"02:11:22:33:44:55","interface":"wlan0"}' \
     "$BASE/api/hotspot/mac"

# eventos en tiempo real
curl -sk -N "$BASE/api/hotspot/events"
```

---

## Panel administrativo (`/info``)

Secciones: **Login · Estado · Configuración · MAC · Clientes · Diagnóstico · Terminal · Archivos · DHCP/DNS · Pedidos**.

- **Estado:** backend, servicio, perfil, interfaz, SSID, MAC, modo, seguridad, IPv4, canal, clientes, advertencias.
- **Configuración:** SSID, contraseña, interfaz, método IPv4 (`manual`/`shared`), seguridad (`WPA2`/`abierta`). Todo se verifica tras aplicarse.
- **MAC:** lectura real, interfaz seleccionable, entrada manual o generación aleatoria (unicast administrada localmente), resultado con MAC efectiva/anterior, persistente vs temporal y rechazo del driver.
- **Clientes:** MAC, IP, interfaz, estado y **fuente** (`dhcp`, `arp`, `nl80211`). Sin IPs inventadas ni ARP obsoleto.
- **Diagnóstico:** kernel, distro, uptime, interfaces, driver, soporte AP, servicios, herramientas presentes/ausentes, limitaciones.
- **Terminal:** ejecución de comandos con salida limitada a 64 KB.
- **Archivos:** explorador con menú contextual (abrir, leer/editar, descargar, renombrar, mover, subir, borrar).
- **DHCP/DNS:** concesiones, procesos dnsmasq, registros DNS tipo `address=`, `cname=`, `txt-record=`, `ptr-record=`, `server=` y upstream, con aplicar + recarga.
- **Tiempo real:** SSE cada 5 s (estado y clientes) y notificación al registrar un pedido.

---

## Diagnóstico del hardware

| Componente | Valor |
|---|---|
| SoC | Qualcomm MSM8916, aarch64 |
| Kernel | `6.12.49-msm8916-...` |
| Distro | Debian 11 (bullseye) chroot |
| Driver Wi-Fi | `wcn36xx`, phy0, solo 2.4 GHz |
| Backend Wi-Fi | NetworkManager 1.30 (`nmcli`) |
| Perfil AP | `Hotspot` — SSID `4G-UFI`, modo `ap`, canal 6, `ipv4.method=manual` |
| Uplink | `WIFI_ETECSA` (192.168.1.87/24) |

### Limitaciones conocidas (documentadas honestamente)

- **Una sola radio Wi-Fi**: AP y cliente (uplink) son **excluyentes**. Encender el hotspot corta la subida Wi‑Fi (ADB por USB no se afecta).
- **Sin `iw`**: no hay estaciones vía nl80211; los clientes se infieren de DHCP + ARP y se marcan como *observados* si no hay confirmación.
- **Sin `ip`/`ethtool`**: los cambios de MAC usan `ifconfig`; la MAC permanente no es legible (el campo se deja vacío en lugar de inventarla).
- **Sin `hostapd`/`rfkill`**: el AP lo gestiona NetworkManager; no se puede comprobar el bloqueo por software del radio.
- **`ipv4.method=manual`** (por defecto): **no reparte IP ni hace NAT**. Usar `shared` para DHCP + NAT.

---

## Seguridad

- Token solo por cookie HttpOnly/SameSite=Strict o cabecera: nunca en `localStorage`, nunca en logs ni en respuestas.
- Rate limiting por IP en autenticación.
- Operaciones concurrentes → 409, sin bloquear las lecturas.
- `nmcli` siempre se ejecuta con `--colors no` y la salida se limpia de escapes ANSI.
- Verificación real de cada cambio (se relee el estado; no se confía en el código de salida).

---

## Solución de problemas

```bash
systemctl status openstick-web.service
journalctl -u openstick-web.service -n 100 --no-pager

# nmcli no ve los cambios de seguridad (perfil abierto <-> WPA2)
nmcli connection reload
grep -E 'key-mgmt|psk=' /etc/NetworkManager/system-connections/Hotspot.nmconnection

# dnsmasq del hotspot (compartido por NetworkManager)
ls -la /etc/NetworkManager/dnsmasq-shared.d/
systemctl restart dnsmasq        # solo si no usa el hotspot
```

> **Nota:** no dejar ficheros `.bak`/`.tmp` dentro de `/etc/NetworkManager/system-connections/`: NetworkManager los carga como perfiles duplicados y provoca comportamientos erráticos.

---

## Licencia

Uso interno / personal. Sin garantía.
