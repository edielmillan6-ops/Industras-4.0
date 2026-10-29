#!/usr/bin/env python3
"""NetWatch - monitor de red (corre en el Linux de la placa, fuera de Docker).
Dashboard: http://IP-DE-LA-PLACA:8000   |   Telegram opcional: config.json"""
import csv, errno, fcntl, hashlib, hmac, io, ipaddress, json, os, secrets, socket, sqlite3, struct, sys, threading, time, traceback
import urllib.parse, urllib.request, urllib.error
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import CookieError, SimpleCookie
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
try:
    from scapy.all import Ether, ARP, sendp
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

BASE = os.path.dirname(os.path.abspath(__file__))
P = lambda n: os.path.join(BASE, n)
if BASE not in sys.path:
    sys.path.insert(0, BASE)
from netwatch_features import FeatureStore
FEATURE_STORE = None
INTERVAL, SCAN_EVERY, TRAIN_SAMPLES, PORT = 5, 12, 120, 8000
OK, ANOMALY, NEW_DEVICE, CRITICAL, LEARNING = range(5)
START = time.time()
lock = threading.Lock()
alerts, history = deque(maxlen=100), deque(maxlen=120)
db = {}      # mac -> {ip, first, last, name, trusted}
features, model, stats = [], None, {}
ctx = {"iface": None, "net": None, "gw": None, "gw_mac": None, "n": 0, "online": set(),
       "last": None, "hold": None, "demo": ("", 0), "own_mac": None, "can_block": None,
       "scan_count": 0, "speed_running": False}
BLOCKED_FILE = P("blocked.json")
_bf = json.load(open(BLOCKED_FILE)) if os.path.exists(BLOCKED_FILE) else {}
blocked = {m: None for m in _bf} if isinstance(_bf, list) else _bf   # mac -> expira (epoch) o None
poison_lock = threading.Lock()
# El puerto sugiere un servicio habitual; no identifica la aplicación ni prueba una vulnerabilidad.
RISK_PORT_INFO = {
    21: ("FTP", "Puede transmitir credenciales sin cifrar.", "Preferir SFTP; desactivar FTP si no se usa."),
    23: ("Telnet", "Administración habitualmente sin cifrado.", "Desactivar Telnet y usar SSH; restringir acceso."),
    110: ("POP3", "El correo podría circular sin cifrado.", "Exigir TLS y autenticación segura."),
    139: ("NetBIOS", "Expone recursos compartidos heredados.", "Desactivar si no se usa; limitar a equipos autorizados."),
    143: ("IMAP", "El correo podría circular sin cifrado.", "Exigir TLS y autenticación segura."),
    445: ("SMB", "Expone archivos y recursos compartidos.", "Actualizar el equipo, desactivar SMBv1 y limitar acceso."),
    1883: ("MQTT", "Puede exponer mensajes o control IoT sin TLS.", "Exigir autenticación y TLS; limitar clientes."),
    3306: ("MySQL/MariaDB", "Expone una base de datos a la red.", "Limitar clientes autorizados, exigir TLS y actualizar."),
    3389: ("RDP", "Expone administración remota.", "Usar VPN y NLA/MFA cuando aplique; limitar acceso."),
    5432: ("PostgreSQL", "Expone una base de datos a la red.", "Limitar clientes autorizados, exigir TLS y actualizar."),
    5900: ("VNC", "Puede exponer control remoto sin protección suficiente.", "Usar VPN o túnel SSH y autenticación fuerte."),
    6379: ("Redis", "Puede exponer datos y comandos del servidor.", "Restringir con firewall, ACL y modo protegido."),
}
RISKY_PORTS = {p: details[0] for p, details in RISK_PORT_INFO.items()}
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 554, 631, 1883, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080, 8443, 8883, 9000, 9100]
SPEED_URLS = (
    "https://fsn1-speed.hetzner.com/100MB.bin",
    "https://nbg1-speed.hetzner.com/100MB.bin",
)
SPEED_SECONDS = 4
state = {"status": LEARNING, "learning": True, "samples": 0, "net": "", "own_ip": "", "gw": "", "speed": None}
CFG = {"tg_token": "", "tg_chat": "", "site": "Mi red", "allow_block": False, "port_audit_seconds": 300}
try:
    CFG.update(json.load(open(P("config.json"))))
except Exception:
    pass

# ------------------------------------------------------------ alertas / Telegram
sent = {}
tg_pending = set()
tg_lock = threading.Lock()
tg_http_lock = threading.Lock()
tg_next_at = 0.0
tg_blocked_until = 0.0

class TelegramError(RuntimeError):
    def __init__(self, message, retry_after=0):
        super().__init__(message)
        self.retry_after = max(0, float(retry_after or 0))

def tg_send(text):
    """HTTPS, texto plano y ritmo compartido por los avisos y el botón de prueba."""
    global tg_next_at, tg_blocked_until
    if not CFG.get("tg_token") or not CFG.get("tg_chat"):
        raise ValueError("Faltan tg_token o tg_chat en config.json")
    # Margen respecto a 4096 unidades UTF-16; nunca enviar un surrogate cortado.
    text = str(text).encode("utf-16-le")[:7800].decode("utf-16-le", "ignore")
    if not text:
        raise ValueError("El mensaje de Telegram está vacío")
    data = urllib.parse.urlencode({"chat_id": CFG["tg_chat"], "text": text}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{CFG['tg_token']}/sendMessage",
        data=data, headers={"User-Agent": "NetWatch/2.2"})
    with tg_http_lock:
        remaining = tg_blocked_until - time.monotonic()
        if remaining > 0:
            raise TelegramError("Telegram solicitó esperar antes de reintentar", remaining)
        time.sleep(max(0, tg_next_at - time.monotonic()))
        tg_next_at = time.monotonic() + 3.1  # También respeta el límite habitual de grupos.
        http_code = None
        try:
            with urllib.request.urlopen(req, timeout=12) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            http_code = error.code
            try:
                result = json.loads(error.read().decode("utf-8", "replace"))
            except (ValueError, OSError):
                result = {}
            finally:
                error.close()
        except (OSError, ValueError) as error:
            # No exponer URL ni token en el panel, registros o estado persistente.
            raise TelegramError(f"Telegram: fallo de conexión/respuesta ({type(error).__name__})") from None
        if not isinstance(result, dict):
            raise TelegramError("Telegram devolvió una respuesta inválida")
        if http_code is not None or not result.get("ok"):
            retry_after = result.get("parameters", {}).get("retry_after", 0)
            if retry_after:
                tg_blocked_until = time.monotonic() + float(retry_after)
            description = str(result.get("description", "Solicitud rechazada"))
            description = description.replace(str(CFG["tg_token"]), "[oculto]")[:200]
            raise TelegramError(f"Telegram HTTP {http_code or result.get('error_code', '?')}: {description}", retry_after)
        return result

def telegram_message(level, msg, kind="info", mac=None, at=None):
    """Texto plano: titulo de la red, caracteristicas y datos de la alerta.

    Se formatea antes de iniciar el hilo de envio. No toma lock porque algunas
    alertas ya se generan dentro de ese bloqueo.
    """
    def field(value, default="No disponible", limit=180):
        text = " ".join(str(value if value is not None else "").split())
        return (text or default)[:limit]
    at = time.time() if at is None else at
    events = {"new": "Dispositivo nuevo", "ports": "Puertos de riesgo abiertos",
              "arp": "Cambio de MAC del router", "anomaly": "Comportamiento anormal",
              "demo": "Simulacion de alerta", "test": "Prueba de Telegram"}
    levels = {"info": "Informacion", "warn": "Advertencia", "crit": "Critico"}
    kinds = {"phone": "Telefono o tableta", "pc": "Computadora", "router": "Router o equipo de red",
             "iot": "Dispositivo IoT", "tv": "TV o multimedia", "camera": "Camara",
             "printer": "Impresora", "private": "No identificado (MAC privada/local)",
             "unknown": "No identificado"}
    lines = ["🛡️ " + field(CFG.get("site"), "Mi red"), "NetWatch", ""]
    d = db.get(mac) if mac else None
    if d is not None:
        vendor, private, device_kind = describe(mac)
        gateway = d.get("ip") == ctx.get("gw")
        if gateway:
            device_kind = "router"
        ports = d.get("ports", [])
        ports_text = (", ".join(str(p) for p in ports) if ports else "No se detectaron abiertos") if d.get("ports_at") is not None else "Pendiente de analisis"
        lines += ["📋 Caracteristicas del dispositivo",
                  "Nombre: " + field(d.get("name"), "Router principal" if gateway else "Sin nombre asignado"),
                  "Tipo estimado: " + kinds.get(device_kind, "No identificado"),
                  "Fabricante: " + field(vendor, "No identificable por MAC local" if private else "Desconocido"),
                  "IP: " + field(d.get("ip")),
                  "MAC: " + field(mac),
                  "MAC local/privada: " + ("Si" if private else "No"),
                  "Conexion: " + ("En linea" if mac in ctx.get("online", set()) else "No visto en el ultimo escaneo"),
                  "Confianza: " + ("Confiable" if d.get("trusted") else "Sin confirmar"),
                  "Puertos TCP detectados: " + ports_text,
                  "Bloqueo NetWatch: " + ("Activo" if mac in blocked else "No aplicado"), ""]
    elif kind == "test":
        lines += ["📋 Caracteristicas del monitor",
                  "Nombre: NetWatch",
                  "IP de la placa: " + field(state.get("own_ip")),
                  "MAC de la placa: " + field(ctx.get("own_mac")), ""]
    else:
        lines += ["📋 Caracteristicas de la red",
                  "Dispositivo: No aplica (simulacion)" if kind == "demo" else "Dispositivo: No aplica (evento de red)", ""]
    lines += ["🔔 Datos de la alerta",
              "Evento: " + events.get(kind, field(kind)),
              "Nivel: " + levels.get(level, field(level)),
              "Fecha: " + time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(at)),
              "Red: " + field(state.get("net")),
              "Router: " + field(ctx.get("gw")),
              "Detalle: " + field(msg, limit=1600)]
    return "\n".join(lines)[:3900]

def tg(text, key):
    if not (CFG.get("tg_token") and CFG.get("tg_chat")):
        print("Telegram no configurado: revisa config.json", flush=True)
        return
    with tg_lock:
        if key in tg_pending or time.time() - sent.get(key, 0) < 300:
            return
        tg_pending.add(key)
    def run():
        try:
            tg_send(text)
            with tg_lock:
                sent[key] = time.time()
            print("Telegram: alerta enviada", flush=True)
        except Exception as e:
            print("Telegram: error enviando alerta:", e, flush=True)
        finally:
            with tg_lock:
                tg_pending.discard(key)
    threading.Thread(target=run, daemon=True).start()

def add_alert(level, msg, kind="info", key=None, mac=None):
    at = time.time()
    alerts.appendleft({"t": time.strftime("%H:%M:%S"), "ts": at, "level": level, "kind": kind, "msg": msg})
    print(f"[{level}] {msg}", flush=True)
    # Los eventos de puertos usan su propia cola persistente, sin enfriamiento por MAC.
    if kind in ("new", "anomaly", "arp", "demo"):
        device_mac = mac or (key if key in db else None)
        tg(telegram_message(level, msg, kind, device_mac, at), key or msg)

# ------------------------------------------------------------ base de dispositivos
def load_db():
    try: raw = json.load(open(P("devices.json")))
    except Exception:
        try: raw = {m: {"ip": ip} for m, ip in json.load(open(P("known_devices.json"))).items()}
        except Exception: raw = {}
    now = time.time()
    for m, d in raw.items():
        db[m] = {"ip": d.get("ip", ""), "first": d.get("first", now), "last": d.get("last", now),
                 "name": d.get("name", ""), "trusted": d.get("trusted", True), "protected": d.get("protected", False),
                 "ports": d.get("ports", []), "ports_at": d.get("ports_at"), "seen": d.get("seen", 1),
                 "ports_ip": d.get("ports_ip"), "ports_scope": d.get("ports_scope"),
                 "ports_unknown": d.get("ports_unknown", []), "network_scope": d.get("network_scope")}

db_file_lock = threading.Lock()
def save_db():
    try:
        with db_file_lock:
            with lock:
                payload = json.dumps(db, ensure_ascii=False)
            with open(P("devices.json.tmp"), "w", encoding="utf-8") as target:
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            os.replace(P("devices.json.tmp"), P("devices.json"))
    except Exception as e: print("save_db:", e)

OUI = {}
def load_oui():
    if os.path.exists(P("oui.json")):
        OUI.update(json.load(open(P("oui.json")))); return
    def dl():  # lista oficial IEEE de fabricantes (se descarga una vez)
        try:
            req = urllib.request.Request("https://standards-oui.ieee.org/oui/oui.csv", headers={"User-Agent": "NetWatch"})
            rows = csv.reader(urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace").splitlines())
            next(rows)
            d = {r[1].lower(): r[2] for r in rows if len(r) > 2}
            json.dump(d, open(P("oui.json"), "w")); OUI.update(d)
        except Exception as e: print("OUI:", e)
    threading.Thread(target=dl, daemon=True).start()

KINDS = [("phone", "apple,samsung,xiaomi,huawei,motorola,oneplus,oppo,vivo,realme,honor"),
         ("router", "tp-link,ubiquiti,cisco,mikrotik,tenda,d-link,netgear,zyxel,arris,sagemcom,ruckus,aruba"),
         ("pc", "intel,dell,hewlett,lenovo,asustek,acer,microsoft,liteon,azurewave,realtek"),
         ("iot", "espressif,raspberry,arduino,tuya,shelly"),
         ("tv", "lg electronics,sony,tcl,roku,amazon,sonos,hisense,nintendo"),
         ("camera", "hikvision,dahua,reolink,axis,ezviz"),
         ("printer", "epson,canon,brother,xerox,lexmark,kyocera,ricoh")]

def describe(mac):
    vendor = OUI.get(mac.replace(":", "")[:6], "")
    private = bool(int(mac[:2], 16) & 2)     # MAC aleatoria/privada (celulares modernos)
    kind = "private" if private else "unknown"
    if not private:
        for k, words in KINDS:
            if any(w in vendor.lower() for w in words.split(",")): kind = k; break
    return vendor, private, kind

# ------------------------------------------------------------ red (solo Python, sin comandos)
def get_net():
    iface = gw = None
    for line in open("/proc/net/route").read().splitlines()[1:]:
        p = line.split()
        if p[1] == "00000000" and int(p[3], 16) & 2:
            iface, gw = p[0], socket.inet_ntoa(struct.pack("<L", int(p[2], 16))); break
    if not gw: raise RuntimeError("No hay ruta por defecto (sin red?)")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect((gw, 80))
    ip = s.getsockname()[0]
    try:   # mascara real de la interfaz (puede ser /23, no solo /24)
        mask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891B, struct.pack("256s", iface[:15].encode()))[20:24])
        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    except Exception:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    s.close()
    if net.prefixlen < 22: net = ipaddress.ip_network(f"{ip}/22", strict=False)
    return iface, net, gw, ip

def _checksum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b)); s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return ~s & 0xFFFF

def icmp_rtt(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP); s.settimeout(1.0)
    try:
        body, pid = b"netwatch", os.getpid() & 0xFFFF
        pkt = struct.pack("!BBHHH", 8, 0, _checksum(struct.pack("!BBHHH", 8, 0, 0, pid, 1) + body), pid, 1) + body
        t0 = time.time(); s.sendto(pkt, (host, 0)); s.recvfrom(1024)
        return (time.time() - t0) * 1000
    finally: s.close()

def tcp_rtt(host):
    for port in (80, 53, 443):
        t0 = time.time(); s = socket.socket(); s.settimeout(0.6)
        try: s.connect((host, port))
        except ConnectionRefusedError: pass
        except OSError: continue
        finally: s.close()
        return (time.time() - t0) * 1000
    return None

def ping_rtt(host):
    try: return icmp_rtt(host)
    except OSError: return tcp_rtt(host)   # sin ICMP o bloqueado: usa TCP

def read_counters(iface):
    for line in open("/proc/net/dev"):
        if line.strip().startswith(iface + ":"):
            p = line.split(":")[1].split(); return int(p[0]), int(p[8])
    return 0, 0

def scan_devices(net, gw, iface):
    ips = [str(h) for h in net.hosts()]
    if gw not in ips: ips.append(gw)
    def poke(ip):
        s = socket.socket(); s.settimeout(0.4)
        try: s.connect((ip, 80))
        except OSError: pass
        finally: s.close()
    with ThreadPoolExecutor(64) as ex: list(ex.map(poke, ips))
    devs = {}
    for line in open("/proc/net/arp").read().splitlines()[1:]:
        p = line.split()
        if len(p) >= 6 and p[2] != "0x0" and p[3] != "00:00:00:00:00:00" and p[5] == iface:
            if ipaddress.ip_address(p[0]) in net or p[0] == gw: devs[p[3].lower()] = p[0]
    return devs

# ------------------------------------------------------------ IA
def train():
    global model
    if HAS_SKLEARN:
        model = IsolationForest(n_estimators=100, contamination=0.02, random_state=42).fit(np.array(features))
    else:
        cols = list(zip(*features)); m = [sum(c) / len(c) for c in cols]
        stats.update(m=m, s=[(sum((v - mu) ** 2 for v in c) / len(c)) ** .5 or 1.0 for c, mu in zip(cols, m)])
    add_alert("info", "Aprendizaje terminado: ya detecto comportamiento anormal")

def is_anomaly(x):
    if model is not None: return model.predict(np.array([x]))[0] == -1
    return bool(stats) and any(abs(v - m) / s > 4 for v, m, s in zip(x, stats["m"], stats["s"]))

def health():
    if state["learning"]: return None
    now, on = time.time(), ctx["online"]
    s = 100 - min(30, 10 * sum(1 for m, d in db.items() if m in on and not d["trusted"]))
    if any(a["kind"] == "arp" and now - a["ts"] < 1800 for a in alerts): s -= 40
    s -= min(30, 10 * sum(1 for a in alerts if a["kind"] == "anomaly" and now - a["ts"] < 900))
    last = [h["rtt_gw"] for h in list(history)[-6:]]
    if last and sum(v is None for v in last) >= 3: s -= 20
    if ctx["demo"][1] > now: s -= {"new": 15, "anomaly": 20, "arp": 40}[ctx["demo"][0]]
    return max(0, s)

# ------------------------------------------------------------ auditoria de puertos
PORT_ALERTS_DB = P("port_alerts.sqlite3")
audit_pending = set()
audit_lock = threading.Lock()
audit_slots = threading.BoundedSemaphore(4)
port_delivery_lock = threading.Lock()

def port_db():
    connection = sqlite3.connect(PORT_ALERTS_DB, timeout=15)
    connection.row_factory = sqlite3.Row
    return connection

def init_port_alerts():
    """No borrar un estado ilegible: detener el arranque evita repetir todas las alertas."""
    connection = port_db()
    try:
        with connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS risk_devices (
                scope TEXT NOT NULL, mac TEXT NOT NULL, ip TEXT NOT NULL,
                risky TEXT NOT NULL, PRIMARY KEY (scope, mac))""")
            connection.execute("""CREATE TABLE IF NOT EXISTS risk_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
                delivered_at REAL, error TEXT)""")
            connection.execute("CREATE INDEX IF NOT EXISTS risk_pending ON risk_events(delivered_at, id)")
            connection.execute("DELETE FROM risk_events WHERE delivered_at < ?", (time.time() - 30 * 86400,))
    finally:
        connection.close()

def port_scope():
    return f"{ctx.get('iface')}|{ctx.get('net')}|{ctx.get('gw')}|{ctx.get('gw_mac')}"

def port_risk_message(mac, ip, previous_ip, current, added, removed, unknown):
    site = " ".join(str(CFG.get("site", "Mi red")).split())[:80]
    lines = ["🛡️ NetWatch — cambio de puertos TCP", "Red: " + site,
             "IP: " + ip, "MAC: " + mac,
             "Fecha: " + time.strftime("%Y-%m-%d %H:%M:%S %Z"),
             "Servicio habitual según el puerto; aplicación y cifrado sin verificar."]
    if previous_ip and previous_ip != ip:
        lines.append("Cambio de IP: " + previous_ip + " → " + ip)
    if added:
        lines.append("Nuevos abiertos: " + ", ".join(f"{p}/TCP" for p in sorted(added)))
    if removed:
        lines.append("Ya no aceptan conexión TCP (rechazo explícito): " + ", ".join(f"{p}/TCP" for p in sorted(removed)))
    if not current:
        lines.append("Sin puertos de riesgo abiertos confirmados entre los revisados.")
    for port in sorted(set(current) | set(removed)):
        service, risk, recommendation = RISK_PORT_INFO[port]
        status = "YA NO ACEPTA TCP" if port in removed else "SIN RESPUESTA; antes abierto" if port in unknown else "ABIERTO"
        lines += ["", f"{port}/TCP — {service} — {status}",
                  "Riesgo: " + risk, "Recomendación: " + recommendation]
    lines += ["", "Un puerto abierto requiere revisión; no confirma una vulnerabilidad."]
    # El catálogo acotado garantiza espacio para todas las recomendaciones.
    message = "\n".join(lines)
    if len(message.encode("utf-16-le")) > 7700:
        raise ValueError("El catálogo de riesgos supera el tamaño de un aviso; dividir el mensaje")
    return message

def record_port_observation(mac, ip, scan, scope):
    """Estado y evento se confirman juntos. No notifica repeticiones ni cierres por timeout."""
    opened = set(scan["open"]) & set(RISKY_PORTS)
    closed = set(scan["closed"]) & set(RISKY_PORTS)
    unknown = set(scan["unknown"]) & set(RISKY_PORTS)
    profile_enabled = FEATURE_STORE is not None and FEATURE_STORE.get_settings(mac)["expected_enabled"]
    connection = port_db()
    event_id = None
    try:
        with connection:
            # Serializa observaciones concurrentes, incluso en conexiones diferentes.
            connection.execute("BEGIN IMMEDIATE")
            old = connection.execute("SELECT ip, risky FROM risk_devices WHERE scope=? AND mac=?", (scope, mac)).fetchone()
            previous = set(json.loads(old["risky"])) if old else set()
            same_ip = old is not None and old["ip"] == ip
            if old and not same_ip and not opened and not (previous & closed):
                # Un cambio de IP sin datos concluyentes no borra la última evidencia.
                return None
            # Nunca atribuir a una IP nueva puertos vistos únicamente en la IP anterior.
            current = (previous - closed) | opened if same_ip else opened
            added = current - previous if same_ip else current
            removed = previous - current if same_ip else previous & closed
            changed = current != previous if same_ip else bool(current or removed)
            connection.execute("""INSERT INTO risk_devices(scope, mac, ip, risky) VALUES(?, ?, ?, ?)
                ON CONFLICT(scope, mac) DO UPDATE SET ip=excluded.ip, risky=excluded.risky""",
                (scope, mac, ip, json.dumps(sorted(current))))
            if changed and not profile_enabled:
                message = port_risk_message(mac, ip, old["ip"] if old else None, current, added, removed, unknown)
                cursor = connection.execute("INSERT INTO risk_events(text) VALUES(?)", (message,))
                event_id = cursor.lastrowid
                connection.execute("UPDATE risk_events SET text=? WHERE id=?", (message + f"\nEvento #{event_id}", event_id))
    finally:
        connection.close()
    if event_id is not None:
        summary = f"Cambio de puertos de riesgo en {ip}: abiertos confirmados/previos {sorted(current)}; ya no aceptan TCP {sorted(removed)}. Evento #{event_id}"
        add_alert("warn" if current else "info", summary, "ports", mac=mac)
    return event_id

def deliver_port_event(now=None):
    """Entrega el evento pendiente más antiguo. Conserva orden y reintenta con espera."""
    if not (CFG.get("tg_token") and CFG.get("tg_chat")):
        return False
    explicit_now = now is not None
    now = time.time() if now is None else now
    with port_delivery_lock:
        connection = port_db()
        try:
            event = connection.execute("SELECT * FROM risk_events WHERE delivered_at IS NULL ORDER BY id LIMIT 1").fetchone()
            if event is None or event["next_attempt"] > now:
                return False
            try:
                tg_send(event["text"])
            except Exception as error:
                attempts = event["attempts"] + 1
                delay = max(min(3600, 15 * 2 ** min(attempts - 1, 8)), getattr(error, "retry_after", 0))
                detail = str(error).replace(str(CFG["tg_token"]), "[oculto]")[:240]
                failed_at = now if explicit_now else time.time()
                with connection:
                    connection.execute("UPDATE risk_events SET attempts=?, next_attempt=?, error=? WHERE id=?",
                                       (attempts, failed_at + delay, detail, event["id"]))
                print(f"Telegram: evento #{event['id']} pendiente; reintento en {delay:.0f}s: {detail}", flush=True)
            else:
                with connection:
                    connection.execute("UPDATE risk_events SET delivered_at=?, error=NULL WHERE id=?", (now if explicit_now else time.time(), event["id"]))
                print(f"Telegram: evento de puertos #{event['id']} enviado", flush=True)
            return True
        finally:
            connection.close()

def port_alert_loop():
    while True:
        try:
            delivered = deliver_port_event()
        except Exception as error:
            print("Cola de puertos: error de almacenamiento:", error, flush=True)
            delivered = False
        time.sleep(0.2 if delivered else 1)

def scan_ports(ip, extra_ports=()):
    def check(p):
        s = socket.socket(); s.settimeout(0.7)
        try:
            result = s.connect_ex((ip, p))
            category = "open" if result == 0 else "closed" if result == errno.ECONNREFUSED else "unknown"
            return p, category
        except OSError:
            return p, "unknown"
        finally: s.close()
    observation = {"open": [], "closed": [], "unknown": []}
    selected_ports = sorted(set(COMMON_PORTS) | set(extra_ports))
    if selected_ports:
        with ThreadPoolExecutor(min(16, len(selected_ports))) as ex:
            for port, category in ex.map(check, selected_ports):
                observation[category].append(port)
    return {category: sorted(ports) for category, ports in observation.items()}

def audit_device(mac, reserved=False):
    if not reserved:
        with audit_lock:
            if mac in audit_pending:
                return
            audit_pending.add(mac)
    try:
        with audit_slots:
            with lock:
                d = db.get(mac)
                if not d:
                    return
                target_ip, scope = d["ip"], port_scope()
                name = d.get("name", "")
            settings = FEATURE_STORE.get_settings(mac) if FEATURE_STORE is not None else {}
            extra = settings.get("expected_ports", []) if settings.get("expected_enabled") else []
            observation = scan_ports(target_ip, extra) if extra else scan_ports(target_ip)
            with lock:
                if db.get(mac) is not d or d["ip"] != target_ip or port_scope() != scope:
                    return
                d.update(ports=observation["open"], ports_unknown=observation["unknown"],
                         ports_at=time.time(), ports_ip=target_ip, ports_scope=scope)
                if observation["open"] or observation["closed"]:
                    d.update(watch_reachable=True, watch_checked_at=time.time())
            # Si SQLite falla, ports_at queda pendiente para volver a intentar pronto.
            try:
                record_port_observation(mac, target_ip, observation, scope)
                if FEATURE_STORE is not None:
                    FEATURE_STORE.observe_scan(scope, mac, target_ip, observation, name=name)
                    if observation["open"] or observation["closed"]:
                        FEATURE_STORE.observe_presence(scope, mac, target_ip, True, name=name)
            except Exception:
                with lock:
                    d["ports_at"] = None
                raise
            save_db()
    except Exception as error:
        print("audit_device:", error, flush=True)
    finally:
        with audit_lock:
            audit_pending.discard(mac)

def start_audit(mac):
    with audit_lock:
        if mac in audit_pending:
            return False
        audit_pending.add(mac)
    try:
        threading.Thread(target=audit_device, args=(mac, True), daemon=True).start()
    except Exception:
        with audit_lock:
            audit_pending.discard(mac)
        raise
    return True

# ------------------------------------------------------------ prueba de velocidad real
def speed_error(error):
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, socket.gaierror):
        return "DNS: la placa no pudo resolver el nombre del servidor"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "Tiempo de espera agotado al conectar o descargar"
    if isinstance(error, urllib.error.HTTPError):
        return f"El servidor respondio HTTP {error.code}"
    return str(error)[:220]

def run_speedtest():
    with lock:
        ctx["speed_running"] = True
    errors = []
    try:
        for url in SPEED_URLS:
            host = urllib.parse.urlsplit(url).hostname
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "NetWatch/2.1", "Accept-Encoding": "identity"})
                total = 0
                with urllib.request.urlopen(req, timeout=8) as response:
                    content_type = response.headers.get("Content-Type", "").lower()
                    if any(t in content_type for t in ("text/", "json", "xml")):
                        raise ValueError("Se recibio una pagina o aviso, no el archivo de prueba")
                    # Medir la transferencia despues de conectar, sin incluir DNS/TLS.
                    started = time.monotonic()
                    read_chunk = getattr(response, "read1", None) or response.read
                    while time.monotonic() - started < SPEED_SECONDS:
                        chunk = read_chunk(262144)
                        if not chunk:
                            break
                        total += len(chunk)
                    seconds = max(0.001, time.monotonic() - started)
                if not total:
                    raise ValueError("El servidor no entrego datos para medir")
                mbps = round(total * 8 / 1_000_000 / seconds, 1)
                with lock:
                    state["speed"] = {"mbps": mbps, "at": time.time(), "server": host,
                                      "bytes": total, "seconds": round(seconds, 3)}
                add_alert("info", f"Prueba de velocidad: {mbps} Mbps de descarga desde {host}")
                return
            except Exception as error:
                errors.append({"server": host, "error": speed_error(error)})
        if errors and all(e["error"].startswith("DNS:") for e in errors):
            message = "La placa no pudo resolver los servidores de prueba (DNS). Revisa su DNS y acceso a internet."
        else:
            message = "No se pudo medir: " + " | ".join(e["server"] + ": " + e["error"] for e in errors)
        with lock:
            state["speed"] = {"error": message, "at": time.time(), "attempts": errors}
        add_alert("warn", "No se pudo medir la velocidad: " + message)
    finally:
        with lock:
            ctx["speed_running"] = False

# ------------------------------------------------------------ bloqueo real (ARP)
def mac2b(m): return bytes(int(x, 16) for x in m.split(":"))
def ip2b(ip): return socket.inet_aton(ip)

def own_mac(iface):
    return open(f"/sys/class/net/{iface}/address").read().strip()

def arp_frame(opcode, src_mac, src_ip, dst_mac, dst_ip, eth_dst):
    eth = mac2b(eth_dst) + mac2b(src_mac) + b"\x08\x06"
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, opcode) + mac2b(src_mac) + ip2b(src_ip) + mac2b(dst_mac) + ip2b(dst_ip)
    return eth + arp

def send_arp(iface, frame):
    """Envio manual (RFC 826) via socket AF_PACKET. Se usa solo si scapy no esta instalado."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    try:
        s.bind((iface, 0)); s.send(frame)
    finally:
        s.close()

def send_arp_reply(sender_ip, sender_mac, target_ip, target_mac):
    """Construye y envia una respuesta ARP. Usa scapy (libreria estandar de la industria
    para esto, la misma que usan herramientas como evillimiter o kickthemout) si esta
    disponible; si no, cae automaticamente al envio manual ya probado arriba."""
    if HAS_SCAPY:
        pkt = Ether(dst=target_mac, src=sender_mac) / ARP(op=2, psrc=sender_ip, hwsrc=sender_mac, pdst=target_ip, hwdst=target_mac)
        sendp(pkt, iface=ctx["iface"], verbose=False)
    else:
        send_arp(ctx["iface"], arp_frame(2, sender_mac, sender_ip, target_mac, target_ip, target_mac))

def save_blocked():
    try: json.dump(sorted(blocked), open(BLOCKED_FILE, "w"))
    except Exception as e: print("save_blocked:", e)

def poison_once(mac, ip):
    """Dice al dispositivo que el router esta en la MAC de la placa (sin reenviar = sin internet)."""
    send_arp_reply(ctx["gw"], ctx["own_mac"], ip, mac)

def restore_once(mac, ip):
    """Avisa la MAC real del router para que el dispositivo recupere internet de inmediato."""
    if ctx["gw_mac"]:
        send_arp_reply(ctx["gw"], ctx["gw_mac"], ip, mac)

def block_device(mac, minutes=None):
    if not CFG["allow_block"]:
        return {"ok": False, "error": 'El bloqueo esta desactivado. Pon "allow_block": true en config.json, solo en redes propias o autorizadas.'}
    if ctx["can_block"] is False:
        return {"ok": False, "error": "Sin permisos: ejecuta el monitor con sudo/root para poder bloquear."}
    d = db.get(mac)
    if not d: return {"ok": False, "error": "Dispositivo no encontrado"}
    if d.get("protected") or d["ip"] == ctx["gw"]:
        return {"ok": False, "error": "Este dispositivo esta protegido y no se puede bloquear."}
    try:
        poison_once(mac, d["ip"])
    except PermissionError:
        ctx["can_block"] = False
        return {"ok": False, "error": "Sin permisos: ejecuta el monitor con sudo/root para poder bloquear."}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    ctx["can_block"] = True
    expire = time.time() + minutes * 60 if minutes else None
    with poison_lock: blocked[mac] = expire
    save_blocked()
    extra = f" por {minutes} min" if minutes else ""
    add_alert("warn", f"Dispositivo BLOQUEADO{extra}: {d['ip']} ({mac})", "block")
    return {"ok": True}

def unblock_device(mac, auto=False):
    d = db.get(mac)
    with poison_lock: blocked.pop(mac, None)
    save_blocked()
    if d:
        try: restore_once(mac, d["ip"])
        except Exception as e: print("restore:", e)
        add_alert("info", f"Dispositivo {'desbloqueado automaticamente' if auto else 'desbloqueado'}: {d['ip']} ({mac})", "unblock")
    return {"ok": True}

def poison_loop():
    while True:
        if CFG["allow_block"] and ctx["gw"] and ctx["iface"] and ctx["own_mac"]:
            now = time.time()
            with poison_lock: targets = dict(blocked)
            for mac, expire in targets.items():
                if expire and now >= expire:
                    unblock_device(mac, auto=True); continue
                d = db.get(mac)
                if d:
                    try: poison_once(mac, d["ip"])
                    except Exception as e: print("poison:", e)
        time.sleep(2)

def restore_all():
    for mac in list(blocked):
        d = db.get(mac)
        if d:
            try: restore_once(mac, d["ip"])
            except Exception: pass

def probe_device(ip, ports=()):
    """Alcance desde el monitor: ICMP o respuesta TCP, incluido rechazo explícito."""
    if ping_rtt(ip) is not None:
        return True
    for port in list(dict.fromkeys(ports))[:4]:
        channel = socket.socket()
        channel.settimeout(0.6)
        try:
            if channel.connect_ex((ip, int(port))) in (0, errno.ECONNREFUSED):
                return True
        except OSError:
            pass
        finally:
            channel.close()
    return False

def watch_cycle():
    if FEATURE_STORE is None:
        return
    with lock:
        scope, net = port_scope(), ctx.get("net")
        # Sin conectividad del monitor no atribuir una caída masiva a los equipos.
        if net is None or state.get("router_reachable") is not True:
            return
        candidates = [(mac, dict(d)) for mac, d in db.items() if d.get("network_scope") == scope]
    watched = []
    for mac, device in candidates:
        settings = FEATURE_STORE.get_settings(mac)
        if settings["watch_enabled"] and mac not in blocked:
            try:
                valid_ip = ipaddress.ip_address(device["ip"]) in net
            except ValueError:
                valid_ip = False
            if valid_ip:
                watched.append((mac, device, settings))
    def check(item):
        mac, device, settings = item
        with lock:
            reused_ip = any(other != mac and other in ctx["online"] and d["ip"] == device["ip"]
                            and d.get("network_scope") == scope for other, d in db.items())
            if reused_ip and mac in ctx["online"]:
                return  # Identidad ambigua: no atribuir el resultado a ninguno.
        # Otra MAC visible usa esa dirección: el equipo vigilado no está localizado ahí.
        reachable = False if reused_ip else probe_device(device["ip"], settings["expected_ports"] + device.get("ports", []))
        with lock:
            current = db.get(mac)
            if current is None or current["ip"] != device["ip"] or port_scope() != scope:
                return
            current_reused = any(other != mac and other in ctx["online"] and d["ip"] == device["ip"]
                                 and d.get("network_scope") == scope for other, d in db.items())
            if current_reused != reused_ip:
                return  # El mapa de identidades cambió durante la prueba.
            current["watch_reachable"] = reachable
            current["watch_checked_at"] = time.time()
        FEATURE_STORE.observe_presence(scope, mac, device["ip"], reachable, name=device.get("name", ""))
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(check, watched))

def feature_loop():
    next_watch = next_daily = 0
    while True:
        now = time.monotonic()
        try:
            if now >= next_watch:
                next_watch = now + 60
                watch_cycle()
            if now >= next_daily and FEATURE_STORE is not None:
                next_daily = now + 30
                settings = FEATURE_STORE.get_daily_settings()
                FEATURE_STORE.daily_summary(site=CFG.get("site", "Mi red"), hour=settings["hour"], enabled=settings["enabled"])
        except Exception as error:
            print("Seguimiento de dispositivos:", error, flush=True)
        time.sleep(1)


# ------------------------------------------------------------ ciclo principal
def _step():
    # Refrescar también al cambiar de Wi-Fi o de dirección durante la ejecución.
    if ctx["iface"] is None or ctx["n"] % SCAN_EVERY == 0:
        iface, net, gw, own = get_net()
        changed = (iface, net, gw) != (ctx["iface"], ctx["net"], ctx["gw"])
        own = str(own)
        own_hardware = own_mac(iface)
        with lock:
            if changed:
                ctx.update(gw_mac=None, last=None, online=set())
            ctx["iface"], ctx["net"], ctx["gw"], ctx["own_mac"] = iface, net, gw, own_hardware
            state.update(net=f"{iface} {net}", gw=gw, own_ip=own)
        if changed:
            add_alert("info", f"Red analizada: {ctx['iface']} {ctx['net']} gw {ctx['gw']}")
    status, now = OK, time.time()
    ctx["n"] += 1
    if ctx["n"] % SCAN_EVERY == 1:
        devs = scan_devices(ctx["net"], ctx["gw"], ctx["iface"])
        inventory_events = []
        with lock:
            first_run = not db
            prev_online = ctx["online"]
            ctx["online"] = set(devs)
            ctx["scan_count"] += 1
            new_macs = []
            for mac, ip in devs.items():
                d = db.get(mac)
                if d is None:
                    quiet = first_run
                    db[mac] = {"ip": ip, "first": now, "last": now, "name": "", "trusted": quiet,
                               "protected": False, "ports": [], "ports_at": None, "seen": 1}
                    inventory_events.append((mac, "discovery", f"Dispositivo detectado: {ip}", {"ip": ip}))
                    if not quiet:
                        add_alert("warn", f"Dispositivo NUEVO: {ip} ({mac})", "new", mac); status = NEW_DEVICE
                        new_macs.append(mac)
                else:
                    if d["ip"] != ip:
                        d.pop("watch_reachable", None)
                        d.pop("watch_checked_at", None)
                    d["ip"], d["last"], d["seen"] = ip, now, d.get("seen", 0) + 1
            if not state["learning"] and not first_run:
                for mac in (set(devs) - prev_online) & set(db):
                    d = db[mac]
                    if d.get("name") and mac not in new_macs:
                        add_alert("info", f"{d['name']} se conecto a la red", "presence", mac)
            gw_mac = next((m for m, ip in devs.items() if ip == ctx["gw"]), None)
            if gw_mac and not ctx["gw_mac"]: ctx["gw_mac"] = gw_mac
            elif gw_mac and gw_mac != ctx["gw_mac"]:
                add_alert("crit", f"La MAC del gateway cambio: {ctx['gw_mac']} -> {gw_mac} (posible ARP spoofing)", "arp", mac=gw_mac); status = CRITICAL
                ctx["gw_mac"] = gw_mac
            for mac in devs:
                if db[mac].get("network_scope") != port_scope():
                    db[mac].pop("watch_reachable", None)
                    db[mac].pop("watch_checked_at", None)
                db[mac]["network_scope"] = port_scope()
            current_scope = port_scope()
        if FEATURE_STORE is not None:
            for mac, kind, summary, details in inventory_events:
                FEATURE_STORE.record_event(current_scope, mac, kind, summary, details, at=now)
        save_db()
        try:
            audit_seconds = max(60, float(CFG.get("port_audit_seconds", 300)))
            if not 60 <= audit_seconds <= 86400:
                audit_seconds = 300
        except (TypeError, ValueError):
            audit_seconds = 300
        with lock:
            pending = [m for m in devs if db[m].get("ports_at") is None
                       or db[m].get("ports_ip") != db[m]["ip"]
                       or db[m].get("ports_scope") != port_scope()
                       or now - db[m]["ports_at"] >= audit_seconds]
            pending.sort(key=lambda m: db[m].get("ports_at") or 0)
        for mac in pending[:12]:
            start_audit(mac)
    rg, rn = ping_rtt(ctx["gw"]), ping_rtt("8.8.8.8")
    with lock:
        state["router_reachable"] = rg is not None
    rx, tx = read_counters(ctx["iface"]); rxb = txb = 0.0
    if ctx["last"]: rxb, txb = (rx - ctx["last"][0]) / INTERVAL, (tx - ctx["last"][1]) / INTERVAL
    ctx["last"] = (rx, tx)
    x = [rg if rg is not None else 1000.0, rn if rn is not None else 1000.0, rxb, txb, float(len(ctx["online"]))]
    if state["learning"]:
        features.append(x); status = LEARNING
        if len(features) >= TRAIN_SAMPLES:
            train()
            with lock: state["learning"] = False
    elif is_anomaly(x):
        add_alert("warn", f"Comportamiento anormal: router={x[0]:.0f}ms internet={x[1]:.0f}ms", "anomaly"); status = ANOMALY
    if status in (ANOMALY, NEW_DEVICE, CRITICAL): ctx["hold"] = (status, now + 60)
    elif status == OK and ctx["hold"] and now < ctx["hold"][1]: status = ctx["hold"][0]
    if ctx["demo"][1] > now: status = max(status, {"new": 2, "anomaly": 1, "arp": 3}[ctx["demo"][0]])
    history.append({"t": time.strftime("%H:%M:%S"), "rtt_gw": rg, "rtt_net": rn})
    with lock: state.update(status=status, samples=len(features))
    time.sleep(INTERVAL)

def step():
    try: _step()
    except Exception as e:
        traceback.print_exc(); add_alert("crit", f"Error: {type(e).__name__}: {e}", "error")
        ctx["iface"] = None; time.sleep(INTERVAL)

# ------------------------------------------------------------ acceso al panel
AUTH_FILE = P("auth.json")
AUTH_SESSIONS = {}
AUTH_SETTINGS = None
AUTH_FAILURES = {}
auth_lock = threading.Lock()
SESSION_SECONDS = 8 * 3600

def init_auth():
    global AUTH_SETTINGS
    if os.path.exists(AUTH_FILE):
        with open(AUTH_FILE, encoding="utf-8") as source:
            settings = json.load(source)
    else:
        salt = secrets.token_hex(16)
        rounds = 310000
        settings = {"username": "admin", "salt": salt, "iterations": rounds,
                    "algorithm": "pbkdf2_sha256",
                    "password_hash": hashlib.pbkdf2_hmac("sha256", b"1234", bytes.fromhex(salt), rounds).hex()}
        descriptor = os.open(AUTH_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump(settings, target)
            target.flush()
            os.fsync(target.fileno())
    if not isinstance(settings, dict) or settings.get("algorithm") != "pbkdf2_sha256":
        raise ValueError("El archivo auth.json no tiene un formato válido")
    if not isinstance(settings.get("username"), str) or not settings["username"]:
        raise ValueError("Usuario inválido en auth.json")
    if not isinstance(settings.get("iterations"), int) or not 100000 <= settings["iterations"] <= 2000000:
        raise ValueError("Parámetros de contraseña inválidos")
    if len(bytes.fromhex(settings.get("salt", ""))) != 16 or len(bytes.fromhex(settings.get("password_hash", ""))) != 32:
        raise ValueError("Hash de contraseña inválido")
    AUTH_SETTINGS = settings

def verify_credentials(username, password):
    if AUTH_SETTINGS is None:
        return False
    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 100 or len(password) > 256:
        return False
    settings = AUTH_SETTINGS
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(settings["salt"]), settings["iterations"]).hex()
    password_ok = hmac.compare_digest(candidate, settings["password_hash"])
    return hmac.compare_digest(username.encode(), settings["username"].encode()) and password_ok

def new_session():
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    now = time.time()
    with auth_lock:
        for old in [key for key, value in AUTH_SESSIONS.items() if value["expires"] <= now]:
            AUTH_SESSIONS.pop(old, None)
        if len(AUTH_SESSIONS) >= 100:
            AUTH_SESSIONS.pop(min(AUTH_SESSIONS, key=lambda key: AUTH_SESSIONS[key]["expires"]))
        AUTH_SESSIONS[token] = {"csrf": csrf, "expires": now + SESSION_SECONDS}
    return token, csrf

def session_from_cookie(cookie_header):
    try:
        cookies = SimpleCookie()
        cookies.load(cookie_header or "")
        token = cookies["nw_session"].value
    except (KeyError, ValueError, CookieError):
        return None
    with auth_lock:
        session = AUTH_SESSIONS.get(token)
        if session is None:
            return None
        if session["expires"] <= time.time():
            AUTH_SESSIONS.pop(token, None)
            return None
        return dict(session)

def reserve_login_attempt(address):
    now = time.time()
    with auth_lock:
        # Acotar memoria sin permitir que cada solicitud borre un bloqueo vigente.
        for ip in [ip for ip, attempts in AUTH_FAILURES.items() if not attempts or now - attempts[-1] >= 60]:
            AUTH_FAILURES.pop(ip, None)
        attempts = [at for at in AUTH_FAILURES.get(address, []) if now - at < 60]
        if len(attempts) >= 5 or (address not in AUTH_FAILURES and len(AUTH_FAILURES) >= 2048):
            return False
        AUTH_FAILURES[address] = attempts + [now]
        return True

# ------------------------------------------------------------ API web
def ipkey(ip): return tuple(int(p) for p in ip.split(".")) if ip.count(".") == 3 else (999,)

def snapshot():
    now = time.time(); devs = []
    profiles = FEATURE_STORE.get_all_settings() if FEATURE_STORE is not None else {}
    with lock:
        for m, d in db.items():
            v, pr, k = describe(m); gw = d["ip"] == ctx["gw"]
            risky = [p for p in d.get("ports", []) if p in RISKY_PORTS]
            pct = round(100 * d.get("seen", 0) / ctx["scan_count"], 1) if ctx["scan_count"] else 0.0
            online = m in ctx["online"]
            if profiles.get(m, {}).get("watch_enabled") and d.get("network_scope") == port_scope() and d.get("watch_reachable") is not None:
                online = d["watch_reachable"]
            devs.append({"mac": m, "ip": d["ip"], "name": d["name"], "trusted": d["trusted"], "online": online,
                         "last": d["last"], "vendor": v, "private": pr, "kind": "router" if gw else k, "gw": gw,
                         "blocked": m in blocked, "blocked_until": blocked.get(m), "protected": d.get("protected", False),
                         "ports": d.get("ports", []), "ports_at": d.get("ports_at"), "risky_ports": risky, "presence_pct": pct,
                         "ports_unknown": d.get("ports_unknown", []), "ports_ip": d.get("ports_ip")})
        if ctx["demo"][1] > now and ctx["demo"][0] == "new":
            devs.append({"mac": "02:de:ad:be:ef:01", "ip": "demo", "name": "Dispositivo de prueba", "trusted": False,
                         "online": True, "last": now, "vendor": "", "private": True, "kind": "unknown", "gw": False})
        devs.sort(key=lambda d: (not d["online"], not d["gw"], ipkey(d["ip"])))
        out = dict(state, devices=devs, alerts=list(alerts)[:40], history=list(history), health=health(),
                   uptime=int(now - START), tg=bool(CFG["tg_token"] and CFG["tg_chat"]), site=CFG["site"], train=TRAIN_SAMPLES,
                   allow_block=CFG["allow_block"], can_block=ctx["can_block"], speed_running=ctx["speed_running"], scapy=HAS_SCAPY)
    return out

def inspected_device(mac, before=None):
    if FEATURE_STORE is None:
        raise ValueError("El seguimiento todavía no está preparado")
    current = next((device for device in snapshot()["devices"] if device["mac"] == mac), None)
    if current is None or mac not in db:
        raise ValueError("Dispositivo desconocido")
    with lock:
        scope = port_scope()
    result = FEATURE_STORE.snapshot_device(scope, mac, limit=50, before=before)
    result["scope"] = scope
    result["device"] = current
    return result

def csv_bytes(header, rows):
    b = io.StringIO(); w = csv.writer(b); w.writerow(header); w.writerows(rows)
    return ("\ufeff" + b.getvalue()).encode()

def post(path, b):
    if path == "/api/device_settings":
        mac = b.get("mac")
        if mac not in db or FEATURE_STORE is None:
            raise ValueError("Dispositivo desconocido")
        previous = FEATURE_STORE.get_settings(mac)
        settings = FEATURE_STORE.save_settings(mac, b)
        if previous["watch_enabled"] != settings["watch_enabled"]:
            with lock:
                db[mac].pop("watch_reachable", None)
                db[mac].pop("watch_checked_at", None)
        # Revalidar al cambiar perfil y permitir un nuevo aviso al volver al modo general.
        if previous["expected_enabled"] and not settings["expected_enabled"]:
            connection = port_db()
            try:
                with connection:
                    connection.execute("DELETE FROM risk_devices WHERE mac=?", (mac,))
            finally:
                connection.close()
        if (previous["expected_enabled"], previous["expected_ports"]) != (settings["expected_enabled"], settings["expected_ports"]):
            with lock:
                db[mac]["ports_at"] = None
            save_db()
        return {"ok": True, "settings": settings}
    if path == "/api/incident":
        mac = b.get("mac")
        if mac not in db or FEATURE_STORE is None:
            raise ValueError("Dispositivo desconocido")
        incident = FEATURE_STORE.update_incident(port_scope(), mac, b.get("id"), b.get("status"), b.get("note", ""))
        return {"ok": True, "incident": incident}
    if path == "/api/daily_summary":
        if FEATURE_STORE is None:
            raise ValueError("El resumen todavía no está preparado")
        return {"ok": True, "daily_summary": FEATURE_STORE.save_daily_settings(b.get("enabled"), b.get("hour"))}
    if path == "/api/device" and b.get("mac") in db:
        with lock:
            if "name" in b: db[b["mac"]]["name"] = str(b["name"])[:40]
            if "trusted" in b: db[b["mac"]]["trusted"] = bool(b["trusted"])
            if "protected" in b: db[b["mac"]]["protected"] = bool(b["protected"])
        save_db(); return {"ok": True}
    if path == "/api/block" and b.get("mac"):
        return block_device(b["mac"], b.get("minutes")) if b.get("blocked") else unblock_device(b["mac"])
    if path == "/api/scan_ports" and b.get("mac") in db:
        if not b.get("mac") in ctx["online"]:
            return {"ok": False, "error": "El dispositivo no está en línea"}
        started = start_audit(b["mac"])
        return {"ok": started, "started": started, "error": None if started else "Ya hay un análisis de este dispositivo en curso"}
    if path == "/api/speedtest":
        with lock:
            if ctx["speed_running"]: return {"ok": False, "error": "Ya hay una prueba en curso"}
            ctx["speed_running"] = True
        try:
            threading.Thread(target=run_speedtest, daemon=True).start()
        except Exception as error:
            with lock: ctx["speed_running"] = False
            return {"ok": False, "error": str(error)}
        return {"ok": True, "started": True}
    if path == "/api/demo" and b.get("kind") in ("new", "anomaly", "arp"):
        k = b["kind"]; ctx["demo"] = (k, time.time() + 25)
        add_alert({"new": "warn", "anomaly": "warn", "arp": "crit"}[k],
                  {"new": "[DEMO] Dispositivo NUEVO: 192.168.0.250 (02:de:ad:be:ef:01)", "anomaly": "[DEMO] Comportamiento anormal en la red",
                   "arp": "[DEMO] La MAC del gateway cambio (posible ARP spoofing)"}[k], "demo")
        return {"ok": True}
    if path == "/api/test_telegram":
        try:
            result = tg_send(telegram_message("info", "Mensaje de prueba enviado correctamente desde NetWatch.", "test"))
            return {"ok": True, "message_id": result.get("result", {}).get("message_id")}
        except Exception as e: return {"ok": False, "error": str(e)}
    return {"ok": False}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, data, ctype, extra=None, status=200):
        self.send_response(status); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(data)
    def json(self, value, status=200, extra=None):
        self.send(json.dumps(value, ensure_ascii=False).encode(), "application/json; charset=utf-8", extra, status)
    def valid_host(self):
        try:
            parsed = urllib.parse.urlsplit("//" + self.headers.get("Host", ""))
            host = (parsed.hostname or "").lower().rstrip(".")
            if parsed.username or parsed.password:
                return False
            allowed = {"localhost", "127.0.0.1", "::1", socket.gethostname().lower(), socket.gethostname().lower() + ".local", str(state.get("own_ip", ""))}
            return host in allowed
        except ValueError:
            return False
    def same_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            parsed = urllib.parse.urlsplit(origin)
            authority = urllib.parse.urlsplit("//" + self.headers.get("Host", ""))
            return (parsed.scheme in ("http", "https") and not parsed.username and not parsed.password
                    and parsed.path in ("", "/") and not parsed.query and not parsed.fragment
                    and parsed.hostname == authority.hostname
                    and (parsed.port or (443 if parsed.scheme == "https" else 80)) == (authority.port or 80))
        except ValueError:
            return False
    def require_session(self, path):
        session = session_from_cookie(self.headers.get("Cookie"))
        if session is None:
            if path.startswith(("/api/", "/export/")):
                self.json({"ok": False, "error": "Inicia sesión para continuar"}, 401)
            else:
                self.send(b"", "text/plain", {"Location": "/login"}, 303)
        return session
    def do_GET(self):
        if not self.valid_host():
            self.json({"ok": False, "error": "Dirección del panel no permitida"}, 403)
            return
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if path == "/login":
            self.send(LOGIN_PAGE.encode(), "text/html; charset=utf-8")
            return
        session = self.require_session(path)
        if session is None:
            return
        if path == "/api/state":
            result = snapshot()
            result["csrf"] = session["csrf"]
            if FEATURE_STORE is not None:
                result["overview"] = FEATURE_STORE.overview(port_scope())
                result["daily_summary"] = FEATURE_STORE.get_daily_settings()
            self.json(result)
        elif path == "/api/device":
            try:
                query = urllib.parse.parse_qs(parsed.query)
                before = query.get("before", [None])[0]
                self.json(inspected_device(query.get("mac", [""])[0], before=int(before) if before else None))
            except (ValueError, TypeError) as error:
                self.json({"ok": False, "error": str(error)}, 400)
        elif path == "/export/devices.csv":
            s = snapshot()
            self.send(csv_bytes(["nombre", "ip", "mac", "fabricante", "confiable", "en_linea"],
                [[d["name"], d["ip"], d["mac"], d["vendor"], d["trusted"], d["online"]] for d in s["devices"]]),
                "text/csv; charset=utf-8", {"Content-Disposition": "attachment; filename=dispositivos.csv"})
        elif path == "/export/alerts.csv":
            self.send(csv_bytes(["hora", "nivel", "tipo", "mensaje"], [[a["t"], a["level"], a["kind"], a["msg"]] for a in alerts]),
                "text/csv; charset=utf-8", {"Content-Disposition": "attachment; filename=alertas.csv"})
        elif path == "/":
            self.send(PAGE.encode(), "text/html; charset=utf-8")
        else:
            self.json({"ok": False, "error": "Ruta no encontrada"}, 404)
    def do_POST(self):
        if not self.valid_host() or not self.same_origin():
            self.json({"ok": False, "error": "Origen de la solicitud no permitido"}, 403)
            return
        path = urllib.parse.urlsplit(self.path).path
        if path != "/api/login":
            session = self.require_session(path)
            if session is None:
                return
            token = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(token.encode(), session["csrf"].encode()):
                self.json({"ok": False, "error": "La sesión de la solicitud no es válida. Recarga el panel."}, 403)
                return
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length < 0 or length > 65536:
                self.json({"ok": False, "error": "Solicitud demasiado grande"}, 413)
                return
            if self.headers.get_content_type() != "application/json":
                self.json({"ok": False, "error": "Se requiere contenido JSON"}, 415)
                return
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("Se esperaba un objeto JSON")
        except (ValueError, UnicodeError):
            self.json({"ok": False, "error": "Solicitud inválida"}, 400)
            return
        if path == "/api/login":
            address = self.client_address[0]
            if not reserve_login_attempt(address):
                self.json({"ok": False, "error": "Demasiados intentos. Espera un minuto."}, 429, {"Retry-After": "60"})
                return
            if not verify_credentials(body.get("username"), body.get("password")):
                self.json({"ok": False, "error": "Usuario o contraseña incorrectos"}, 401)
                return
            with auth_lock:
                AUTH_FAILURES.pop(address, None)
            token, _ = new_session()
            self.json({"ok": True}, extra={"Set-Cookie": f"nw_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"})
        elif path == "/api/logout":
            cookies = SimpleCookie()
            cookies.load(self.headers.get("Cookie", ""))
            with auth_lock:
                AUTH_SESSIONS.pop(cookies["nw_session"].value, None)
            self.json({"ok": True}, extra={"Set-Cookie": "nw_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
        else:
            try:
                result = post(path, body)
                self.json(result, 200 if result.get("ok") else 400)
            except (ValueError, TypeError, KeyError) as error:
                self.json({"ok": False, "error": str(error)}, 400)
            except Exception:
                traceback.print_exc()
                self.json({"ok": False, "error": "No se pudo completar la operación"}, 500)

LOGIN_PAGE = r"""<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Acceso · NetWatch</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#e8ecf5;font:16px system-ui;padding:24px}main{width:min(100%,400px);padding:32px;background:#121a2e;border:1px solid #243050;border-radius:18px}h1{margin-top:0}p{color:#aebbd4;line-height:1.5}label{display:block;margin:20px 0 7px}input,button{width:100%;font:inherit;border-radius:8px;padding:12px;color:#e8ecf5;border:1px solid #344568;background:#1b2744}button{margin-top:24px;background:#356bd9;cursor:pointer;font-weight:600}button:disabled{opacity:.6}#error{color:#ffb5b5;min-height:1.5em}small{color:#aebbd4}</style></head><body><main><h1>🛡️ NetWatch</h1><p>Inicia sesión para consultar tus dispositivos y administrar el monitor.</p><form id="login"><label for="username">Usuario</label><input id="username" name="username" autocomplete="username" required maxlength="100" autofocus><label for="password">Contraseña</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="256"><button id="submit" type="submit">Entrar al panel</button><p id="error" role="alert" aria-live="polite"></p></form><small>Monitor de tu red local</small></main><script>
document.querySelector('#login').addEventListener('submit',async event=>{event.preventDefault();const button=document.querySelector('#submit'),error=document.querySelector('#error');button.disabled=true;error.textContent='';try{const response=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.querySelector('#username').value,password:document.querySelector('#password').value})});const result=await response.json();if(response.ok&&result.ok){location.replace('/');return}error.textContent=result.error||'No se pudo iniciar sesión'}catch(e){error.textContent='No se pudo conectar con NetWatch'}finally{button.disabled=false}});
</script></body></html>"""

PAGE = r"""<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWatch</title><style>
:root{--bg:#0b1020;--c:#121a2e;--l:#243050;--t:#e8ecf5;--m:#8a96b2;--ok:#2ecc8f;--warn:#ffb020;--crit:#ff4d5e;--info:#5ec2ff;--ac:#4f8cff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1200px 600px at 20% -10%,#16244a,var(--bg));color:var(--t);font-family:system-ui,sans-serif;padding:16px;max-width:1200px;margin:auto}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:14px}.logo{font-size:1.4rem}.logo small{color:var(--m);margin-left:8px;font-size:.8rem}
.pill{padding:6px 14px;border-radius:99px;font-weight:700;font-size:.9rem;border:1px solid}.pill.ok{color:var(--ok);background:#2ecc8f22}.pill.warn{color:var(--warn);background:#ffb02022}.pill.crit{color:var(--crit);background:#ff4d5e22;animation:p 1s infinite}.pill.info{color:var(--info);background:#5ec2ff22}
@keyframes p{50%{opacity:.5}}.card{background:var(--c);border:1px solid var(--l);border-radius:14px;padding:14px;margin-bottom:12px}h3{margin:0 0 10px;font-size:.95rem;color:var(--m);font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:12px}.kpis .card{margin:0}.kpi b{font-size:1.9rem;display:block}.kpi span{color:var(--m);font-size:.8rem}
.g2{display:grid;grid-template-columns:260px 1fr;gap:12px}@media(max-width:760px){.g2{grid-template-columns:1fr}}
.gauge{text-align:center}.gauge svg{width:170px}.gauge .n{font-size:2.2rem;font-weight:800}.bar{height:8px;background:var(--l);border-radius:9px;overflow:hidden}.bar i{display:block;height:100%;background:var(--ac)}
#map{width:100%;height:auto}.ln{stroke:#2e3d66;stroke-width:1}.ln.off{stroke-dasharray:3 4;opacity:.4}.nd circle{fill:#16213b;stroke-width:2}.nd.ok circle{stroke:var(--ok)}.nd.warn circle{stroke:var(--warn);fill:#ffb02033}.nd.off circle{stroke:#4a5578}.nd.hub circle{stroke:var(--ac);fill:#4f8cff33;stroke-width:3}.nd text{text-anchor:middle;font-size:13px}.nd.off{opacity:.5}
canvas{width:100%;height:170px}.lg{font-size:.75rem;margin-left:8px;text-transform:none;letter-spacing:0}
table{width:100%;border-collapse:collapse}td,th{padding:8px 6px;text-align:left;border-bottom:1px solid var(--l);font-size:.88rem}th{color:var(--m);font-weight:600}small{color:var(--m)}
.b{padding:2px 10px;border-radius:99px;font-size:.75rem;font-weight:700}.b.ok{background:#2ecc8f22;color:var(--ok)}.b.warn{background:#ffb02022;color:var(--warn)}.b.off{background:#4a557833;color:var(--m)}
button,input{background:#1b2744;color:var(--t);border:1px solid var(--l);border-radius:8px;padding:6px 10px;font:inherit;font-size:.82rem;cursor:pointer}button:hover{border-color:var(--ac)}input{cursor:text;min-width:160px}.chip.on{background:var(--ac)}
.tw{overflow-x:auto}.al{padding:8px 10px;border-left:3px solid var(--info);background:#ffffff08;margin-bottom:6px;border-radius:6px;font-size:.88rem}.al.warn{border-color:var(--warn)}.al.crit{border-color:var(--crit)}.al small{margin-right:8px}
a{color:var(--ac)}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}

button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,a:focus-visible{outline:3px solid var(--info);outline-offset:3px}button:disabled{opacity:.55;cursor:wait}
textarea,select{background:#1b2744;color:var(--t);border:1px solid var(--l);border-radius:8px;padding:9px;font:inherit}textarea{display:block;width:100%;resize:vertical}input[type=checkbox]{min-width:0;width:18px;height:18px;accent-color:var(--ac)}label{font-size:.9rem}.field{display:grid;gap:7px;margin:15px 0}.hint{display:block;color:var(--m);font-size:.82rem;line-height:1.5}.notice{color:var(--info);min-height:1.4em;font-size:.88rem;white-space:pre-wrap}.notice.error{color:#ff969e}.primary{background:var(--ac);color:white;border-color:var(--ac)}
dialog{width:min(920px,calc(100vw - 24px));max-height:90vh;background:var(--bg);color:var(--t);border:1px solid #40547f;border-radius:16px;padding:0;box-shadow:0 24px 100px #000a}dialog::backdrop{background:#040814cc}.dialog-head{padding:18px 20px 12px;border-bottom:1px solid var(--l);position:sticky;top:0;background:var(--bg);z-index:2}.dialog-head h2{font-size:1.2rem;margin:0 0 5px}.dialog-head .row{justify-content:space-between;margin:0}.dialog-head small{display:block;margin-top:4px}.dialog-body{padding:18px 20px}.tabs{display:flex;gap:7px;flex-wrap:wrap;padding:12px 20px 0}.tabs button[aria-selected=true]{background:#2e4d88;border-color:var(--ac)}.device-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.device-grid div{background:#ffffff06;padding:12px;border-radius:9px;overflow-wrap:anywhere}.device-grid dt{font-size:.8rem;color:var(--m);margin-bottom:5px}.device-grid dd{margin:0;font-size:.95rem}.incident{border:1px solid var(--l);padding:12px;border-radius:10px;margin-bottom:12px}.incident summary{cursor:pointer;line-height:1.6}.incident form{margin-top:12px}.history-entry{border-left:3px solid var(--l);padding:0 0 18px 14px}.history-entry p{margin:5px 0;line-height:1.5;overflow-wrap:anywhere}.history-entry pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.8rem;color:var(--m);margin:8px 0}.history-entry time{font-size:.78rem;color:var(--m)}.inspector-actions{border-top:1px solid var(--l);padding-top:14px;margin-top:18px}.overview{display:flex;gap:18px;flex-wrap:wrap;color:var(--m);font-size:.86rem;margin-bottom:14px}.overview strong{color:var(--t)}.settings-box{padding-top:12px}.settings-box summary{cursor:pointer;font-weight:600}.settings-box form{margin-top:14px}.empty{padding:24px 12px;color:var(--m);text-align:center;background:#ffffff04;border-radius:10px}.pane-title{font-size:1rem;margin:0 0 10px}.wrap{overflow-wrap:anywhere}@media(max-width:600px){.device-grid{grid-template-columns:1fr}.dialog-head{padding:15px}.dialog-body{padding:15px}.tabs{padding:10px 15px 0;gap:5px}.tabs button{padding:8px}.inspector-actions button{flex:1 1 auto}.history-entry pre{font-size:.72rem}}

</style>
<header><div class="logo">🛡️ <b>NetWatch</b><small id="site"></small></div><div><span id="pill" class="pill info">Cargando…</span> <small id="up"></small> <button id="logout" type="button">Cerrar sesión</button></div></header>
<div id="netMsg" class="notice" role="status" aria-live="polite"></div>
<div id="learn" class="card" hidden></div>
<div id="blockbanner" class="card" hidden style="border-color:var(--crit)"><h3 style="color:var(--crit)">⚠️ Bloqueo real activo</h3><small>Esta herramienta corta el internet de un dispositivo de verdad. Usala solo en redes que tu administras o con autorizacion explicita.</small></div>
<section class="kpis"><div class="card kpi"><b id="k1">-</b><span>Dispositivos en línea</span></div><div class="card kpi"><b id="k2">-</b><span>Sin confianza</span></div><div class="card kpi"><b id="k3">-</b><span>Alertas (24 h)</span></div><div class="card kpi"><b id="k4">-</b><span>Latencia router (ms)</span></div><div class="card kpi"><b id="k5">-</b><span>Latencia internet (ms)</span></div></section>
<section class="g2"><div class="card gauge"><h3>Salud de la red</h3><svg viewBox="0 0 140 140"><circle cx="70" cy="70" r="56" fill="none" stroke="#243050" stroke-width="12"/><circle id="gc" cx="70" cy="70" r="56" fill="none" stroke="#2ecc8f" stroke-width="12" stroke-linecap="round" stroke-dasharray="351.9" stroke-dashoffset="351.9" transform="rotate(-90 70 70)" style="transition:all .8s"/></svg><div class="n" id="gn" style="margin-top:-105px;margin-bottom:70px">--</div><div id="gl" style="color:var(--m)"></div></div>
<div class="card"><h3>Mapa de red</h3><svg id="map" viewBox="0 0 600 380"></svg></div></section>
<section class="g2">
<div class="card"><h3>Velocidad de internet</h3><div class="gauge"><svg viewBox="0 0 140 140"><circle cx="70" cy="70" r="56" fill="none" stroke="#243050" stroke-width="12"/><circle id="sc" cx="70" cy="70" r="56" fill="none" stroke="#4f8cff" stroke-width="12" stroke-linecap="round" stroke-dasharray="351.9" stroke-dashoffset="351.9" transform="rotate(-90 70 70)" style="transition:all .8s"/></svg><div class="n" id="sn" style="margin-top:-105px;margin-bottom:70px">--</div><div id="sl" style="color:var(--m)">Mbps de descarga</div><button id="sbtn" onclick="speedtest()" style="margin-top:8px">Probar ahora</button></div></div>
<div class="card"><h3>Dispositivos mas activos</h3><div id="top"></div></div>
</section>
<div class="card"><h3>Latencia (ms)<span class="lg" style="color:#4f8cff">● router</span><span class="lg" style="color:#ffb020">● internet</span><span class="lg" style="color:#ff4d5e">| sin respuesta</span></h3><canvas id="ch"></canvas></div>
<div class="card"><h3>Dispositivos</h3><div id="overview" class="overview"></div><div class="row"><input id="q" aria-label="Buscar dispositivos" placeholder="Buscar nombre, IP, MAC…"><button class="chip on" data-f="all">Todos</button><button class="chip" data-f="on">En línea</button><button class="chip" data-f="new">Sin confianza</button><button class="chip" data-f="off">Offline</button></div>
<div class="tw"><table><thead><tr><th>Dispositivo</th><th>IP</th><th>MAC</th><th>Visto</th><th>Puertos</th><th>Estado</th><th></th></tr></thead><tbody id="tb"></tbody></table></div></div>
<div class="card"><h3>Alertas</h3><div id="al"></div></div>
<div class="card"><h3>Herramientas</h3><div class="row"><b>Demo:</b><button onclick="post('/api/demo',{kind:'new'})">Simular dispositivo nuevo</button><button onclick="post('/api/demo',{kind:'anomaly'})">Simular anomalía</button><button onclick="post('/api/demo',{kind:'arp'})">Simular ARP spoofing</button></div>
<div class="row"><b>Reportes:</b><a href="/export/devices.csv">Dispositivos (CSV)</a><a href="/export/alerts.csv">Alertas (CSV)</a></div>
<div class="row"><b>Telegram:</b><span id="tg"></span><button onclick="tgtest()">Enviar prueba</button></div>

<details class="settings-box"><summary>Resumen diario por Telegram</summary>
<form id="dailyForm"><div class="row"><label class="row"><input id="dailyEnabled" type="checkbox"> Enviar un resumen cada día</label><label for="dailyHour">Hora local del Arduino</label><input id="dailyHour" type="time" value="20:00" required style="min-width:110px"><button class="primary" type="submit">Guardar resumen</button></div><small id="dailyLast">Todavía no se ha preparado un resumen.</small><div id="dailyMsg" class="notice" role="status" aria-live="polite"></div></form></details>
<div class="row"><b>Bloqueo de dispositivos:</b><span id="blk"></span> <span id="eng" style="color:var(--m);font-size:.8rem"></span></div></div>

<dialog id="inspector" aria-labelledby="inspectTitle">
<div class="dialog-head"><div class="row"><h2 id="inspectTitle">Inspeccionar dispositivo</h2><div class="row"><button id="inspectRefresh" type="button">Actualizar</button><button id="inspectClose" type="button" aria-label="Cerrar inspección">Cerrar ✕</button></div></div><small id="inspectMeta" class="wrap"></small></div>
<div class="tabs" role="tablist" aria-label="Secciones del dispositivo">
<button type="button" role="tab" id="tab-info" aria-controls="pane-info" aria-selected="true" data-pane="info">Información</button>
<button type="button" role="tab" id="tab-ports" aria-controls="pane-ports" aria-selected="false" tabindex="-1" data-pane="ports">Puertos esperados</button>
<button type="button" role="tab" id="tab-watch" aria-controls="pane-watch" aria-selected="false" tabindex="-1" data-pane="watch">Vigilancia</button>
<button type="button" role="tab" id="tab-incidents" aria-controls="pane-incidents" aria-selected="false" tabindex="-1" data-pane="incidents">Incidentes</button>
<button type="button" role="tab" id="tab-history" aria-controls="pane-history" aria-selected="false" tabindex="-1" data-pane="history">Historial</button>
</div>
<div class="dialog-body"><div id="inspectMsg" class="notice" role="status" aria-live="polite"></div>
<section id="pane-info" role="tabpanel" aria-labelledby="tab-info"><div id="deviceInfo"></div><div id="deviceActions" class="row inspector-actions"></div></section>
<section id="pane-ports" role="tabpanel" aria-labelledby="tab-ports" hidden><h3 class="pane-title">Servicios que esperas encontrar</h3><p class="hint">Activa un perfil para avisar si aparece un puerto que no esperabas o si uno esperado rechaza la conexión. Una falta de respuesta queda pendiente de comprobar.</p><form id="portsForm"><label class="row"><input type="checkbox" id="expectedEnabled"> Usar un perfil de puertos para este dispositivo</label><div class="field"><label for="expectedPorts">Puertos TCP esperados</label><textarea id="expectedPorts" rows="3" placeholder="Por ejemplo: 22, 80, 443" aria-describedby="portsHint"></textarea><span id="portsHint" class="hint">Separa los números con comas o espacios. Puedes guardar hasta 64 puertos, entre 1 y 65535. Una lista vacía permite avisar ante cualquier puerto abierto de los examinados.</span></div><div class="row"><button id="useDetectedPorts" type="button">Usar puertos detectados</button><button class="primary" type="submit">Guardar perfil</button></div><div id="portsMsg" class="notice" role="status" aria-live="polite"></div></form></section>
<section id="pane-watch" role="tabpanel" aria-labelledby="tab-watch" hidden><h3 class="pane-title">Vigilar la disponibilidad</h3><p class="hint">Recibe un aviso si este equipo deja de responder varias veces seguidas y otro cuando se recupere. La vigilancia utiliza comprobaciones de conexión, además de la lista de dispositivos. Se comprueba aproximadamente cada minuto, según la carga del monitor.</p><div id="watchStatus" class="card" aria-live="polite">Disponibilidad todavía sin confirmar.</div><form id="watchForm"><label class="row"><input id="watchEnabled" type="checkbox"> Vigilar este dispositivo</label><div class="field"><label for="watchFailures">Fallos consecutivos antes de avisar</label><select id="watchFailures"><option value="2">2 comprobaciones</option><option value="3" selected>3 comprobaciones</option><option value="4">4 comprobaciones</option><option value="5">5 comprobaciones</option><option value="6">6 comprobaciones</option><option value="7">7 comprobaciones</option><option value="8">8 comprobaciones</option><option value="9">9 comprobaciones</option><option value="10">10 comprobaciones</option></select><span class="hint">El tiempo de aviso depende de la frecuencia de las comprobaciones. Los resultados desconocidos no se cuentan como una caída confirmada.</span></div><button class="primary" type="submit">Guardar vigilancia</button><div id="watchMsg" class="notice" role="status" aria-live="polite"></div></form></section>
<section id="pane-incidents" role="tabpanel" aria-labelledby="tab-incidents" hidden><h3 class="pane-title">Seguimiento de este dispositivo</h3><p class="hint">Marca un incidente como revisado para registrar que lo viste, o como resuelto e indica qué hiciste. Un problema que reaparece puede generar un nuevo incidente.</p><div id="incidentList"></div></section>
<section id="pane-history" role="tabpanel" aria-labelledby="tab-history" hidden><h3 class="pane-title">Historial individual</h3><p class="hint">Solo se muestran eventos de este dispositivo en la red actual. La búsqueda se aplica a los eventos que ya se han cargado.</p><div class="row"><input id="historySearch" aria-label="Buscar en el historial del dispositivo" placeholder="Buscar en este historial…"><span id="historyCount" class="hint"></span></div><div id="deviceHistory"></div><button id="moreHistory" type="button" hidden>Cargar eventos anteriores</button></section>
</div></dialog>

<script>
const $=s=>document.querySelector(s),E=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ST=[['Red segura','ok'],['Comportamiento anormal','warn'],['Dispositivo nuevo','warn'],['Alerta crítica','crit'],['Aprendiendo','info']];
const IC={phone:'📱',pc:'💻',router:'📡',iot:'🔧',tv:'📺',camera:'📷',printer:'🖨️',private:'🔒',unknown:'❓'};
let S=null,flt='all',stateRequest=0;
async function api(p,options={}){
const response=await fetch(p,{credentials:'same-origin',cache:'no-store',...options});
if(response.status===401){location.reload();throw new Error('Tu sesión terminó. Vuelve a iniciar sesión.')}
let result;try{result=await response.json()}catch(error){throw new Error('El monitor devolvió una respuesta que no se pudo leer.')}
if(response.status===403)throw new Error(result.error||'No se pudo verificar tu sesión. Actualiza la página e inténtalo de nuevo.');
if(!response.ok)throw new Error(result.error||'No se pudo completar la solicitud.');
return result;
}
async function post(p,b){
try{const result=await api(p,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':S?.csrf||''},body:JSON.stringify(b||{})});if(p!='/api/logout')await load();return result}
catch(error){message('#netMsg',error.message,true);return {ok:false,error:error.message}}
}
async function tgtest(){const r=await post('/api/test_telegram');alert(r.ok?'Mensaje enviado a Telegram':'No se pudo enviar: '+(r.error||'configura config.json'))}
async function load(){const request=++stateRequest;try{const state=await api('/api/state');if(request!==stateRequest)return;S=state;draw()}catch(e){if(request!==stateRequest)return;$('#pill').textContent='Sin conexión';$('#pill').className='pill crit';message('#netMsg',e.message,true)}}
const ago=t=>{const s=Math.max(0,Date.now()/1000-t);return s<60?'hace un momento':s<3600?'hace '+Math.floor(s/60)+' min':s<86400?'hace '+Math.floor(s/3600)+' h':'hace '+Math.floor(s/86400)+' d'};
const last=a=>{for(let i=a.length-1;i>=0;i--)if(a[i]!=null)return Math.round(a[i]);return '-'};
function draw(){const [n,c]=ST[S.status];$('#pill').textContent=n;$('#pill').className='pill '+c;$('#site').textContent=S.site+' · '+S.net;
const u=S.uptime;$('#up').textContent='Activo '+(u>3600?Math.floor(u/3600)+' h ':'')+Math.floor(u%3600/60)+' min';
$('#blockbanner').hidden=!S.allow_block;
const L=$('#learn');L.hidden=!S.learning;if(S.learning)L.innerHTML=`<b>Aprendiendo lo normal de tu red…</b> <small>${S.samples}/${S.train} muestras (se notifican dispositivos nuevos tras el primer escaneo)</small><div class="bar"><i style="width:${100*S.samples/S.train}%"></i></div>`;
const D=S.devices,now=Date.now()/1000;$('#k1').textContent=D.filter(d=>d.online).length;$('#k2').textContent=D.filter(d=>d.online&&!d.trusted).length;
$('#k3').textContent=S.alerts.filter(a=>!['info','demo'].includes(a.kind)&&a.ts>now-86400).length;
const g=S.history.map(h=>h.rtt_gw),w=S.history.map(h=>h.rtt_net);$('#k4').textContent=last(g);$('#k5').textContent=last(w);
const h=S.health,gc=$('#gc');gc.style.strokeDashoffset=351.9*(1-(h??0)/100);gc.style.stroke=h==null?'#5ec2ff':h>=75?'#2ecc8f':h>=50?'#ffb020':'#ff4d5e';
$('#gn').textContent=h??'--';$('#gl').textContent=h==null?'Calculando…':h>=90?'Excelente':h>=75?'Buena':h>=50?'Regular':'En riesgo';
map();chart($('#ch'),[{v:g,c:'#4f8cff'},{v:w,c:'#ffb020'}]);table();speed();renderTopDevices()
$('#al').innerHTML=S.alerts.slice(0,25).map(a=>`<div class="al ${a.level}"><small>${a.t}</small>${E(a.msg)}</div>`).join('')||'<small>Sin alertas</small>';
$('#tg').innerHTML=S.tg?'<span class="b ok">configurado</span>':'<span class="b off">no configurado (config.json)</span>';
$('#blk').innerHTML=!S.allow_block?'<span class="b off">desactivado (allow_block en config.json)</span>':S.can_block===false?'<span class="b warn">sin permisos: corre el monitor con sudo</span>':'<span class="b ok">activo</span>';
$('#eng').textContent=S.allow_block?('motor: '+(S.scapy?'scapy':'nativo')):'';drawExtras()}
function speed(){const sp=S.speed,mx=300,v=sp&&sp.mbps?Math.min(mx,sp.mbps):0;$('#sc').style.strokeDashoffset=351.9*(1-v/mx);
$('#sn').textContent=sp&&sp.mbps?sp.mbps:(sp&&sp.error?'--':'--');
$('#sl').textContent=S.speed_running?'Midiendo descarga desde la placa…':sp&&sp.error?'Error: '+sp.error:sp&&sp.mbps?'Mbps de descarga (estimada) · '+ago(sp.at):'Sin medir aun';
$('#sbtn').disabled=!!S.speed_running;$('#sbtn').textContent=S.speed_running?'Midiendo…':'Probar ahora'}
async function speedtest(){const r=await post('/api/speedtest');if(!r.ok&&r.error)alert(r.error)}
function renderTopDevices(){const R=S.devices.filter(d=>!d.gw).sort((a,b)=>b.presence_pct-a.presence_pct).slice(0,6);
$('#top').innerHTML=R.map(d=>`<div style="margin-bottom:8px"><div style="display:flex;justify-content:space-between;font-size:.85rem"><span>${IC[d.kind]} ${E(d.name||d.vendor||d.ip)}</span><span>${d.presence_pct}%</span></div><div class="bar"><i style="width:${d.presence_pct}%"></i></div></div>`).join('')||'<small>Sin datos todavia</small>'}
function map(){const D=S.devices.filter(d=>!d.gw),cx=300,cy=190,R=[[12,150,100],[24,235,155],[48,285,180]];let i=0,P=[],h='';
for(const [cap,rx,ry] of R){const n=Math.min(cap,D.length-i);if(n<=0)break;for(let k=0;k<n;k++){const a=2*Math.PI*k/n-Math.PI/2;P.push([cx+rx*Math.cos(a),cy+ry*Math.sin(a),D[i+k]])}i+=n}
for(const [x,y,d] of P)h+=`<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" class="ln ${d.online?'':'off'}"/>`;
for(const [x,y,d] of P){const c=!d.online?'off':d.trusted?'ok':'warn';h+=`<g class="nd ${c}"><title>${E(d.name||d.vendor||d.mac)} · ${E(d.ip)}</title><circle cx="${x}" cy="${y}" r="13">${c=='warn'?'<animate attributeName="r" values="13;18;13" dur="1.6s" repeatCount="indefinite"/>':''}</circle><text x="${x}" y="${y+5}">${IC[d.kind]}</text></g>`}
h+=`<g class="nd hub"><circle cx="${cx}" cy="${cy}" r="24"/><text x="${cx}" y="${cy+7}" style="font-size:20px">📡</text></g><text x="${cx}" y="${cy+42}" style="fill:#8a96b2;font-size:11px;text-anchor:middle">${E(S.gw)}</text>`;$('#map').innerHTML=h}
function chart(cv,series){const r=devicePixelRatio||1,w=cv.clientWidth,H0=cv.clientHeight;cv.width=w*r;cv.height=H0*r;const x=cv.getContext('2d');x.scale(r,r);
const vals=series.flatMap(s=>s.v).filter(v=>v!=null),mx=Math.max(50,Math.ceil(Math.max(0,...vals)*1.2/10)*10),L=36,B=14,T=6,W=w-L-4,H=H0-B-T,n=series[0].v.length;
x.font='11px system-ui';x.lineWidth=1;for(let i=0;i<=4;i++){const y=T+H*i/4;x.strokeStyle='#243050';x.beginPath();x.moveTo(L,y);x.lineTo(L+W,y);x.stroke();x.fillStyle='#8a96b2';x.fillText(Math.round(mx*(1-i/4)),4,y+4)}
const X=i=>L+W*i/Math.max(1,n-1),Y=v=>T+H*(1-v/mx);
for(const s of series){x.strokeStyle=s.c;x.lineWidth=2;x.beginPath();let pen=false;s.v.forEach((v,i)=>{if(v==null){pen=false;return}pen?x.lineTo(X(i),Y(v)):x.moveTo(X(i),Y(v));pen=true});x.stroke();x.fillStyle='#ff4d5e';s.v.forEach((v,i)=>{if(v==null)x.fillRect(X(i)-1,T+H-8,2,8)})}}
function table(){const q=$('#q').value.toLowerCase();const R=S.devices.filter(d=>(flt=='all'||(flt=='on'&&d.online)||(flt=='new'&&!d.trusted)||(flt=='off'&&!d.online))&&`${d.name} ${d.vendor} ${d.ip} ${d.mac}`.toLowerCase().includes(q));
$('#tb').innerHTML=R.map(d=>{const c=!d.online?'off':d.trusted?'ok':'warn';
const ports=d.ports_at==null?'<small>Sin analizar</small>':
d.ports.length?`<span class="b ${d.risky_ports.length?'warn':'ok'}" title="Último análisis: ${new Date(d.ports_at*1000).toLocaleString()}">${d.risky_ports.length?'⚠ ':''}${d.ports.map(Number).join(', ')}</span>`:
'<small title="Sólo se revisan los puertos configurados">Sin abiertos confirmados</small>';
const portNote=((d.ports_unknown||[]).length?`<br><small>${d.ports_unknown.length} sin respuesta concluyente</small>`:'')+(d.ports_ip&&d.ports_ip!==d.ip?`<br><small>Último análisis: ${E(d.ports_ip)}</small>`:'');
const timeLeft=d.blocked_until?Math.max(0,Math.round((d.blocked_until*1000-Date.now())/60000)):null;
const estado=d.blocked?`<span class="b warn">Bloqueado${timeLeft!=null?' ('+timeLeft+' min)':''}</span>`:`<span class="b ${c}">${!d.online?'Offline':d.trusted?'Confiable':'Nuevo'}</span>`;
return `<tr><td>${IC[d.kind]} <b>${E(d.name||(d.gw?'Router':d.vendor)||'Dispositivo')}</b>${d.protected?' <small>🛡️</small>':''}<br><small>${E(d.vendor||(d.private?'MAC privada (aleatoria)':'Fabricante desconocido'))}</small></td><td>${E(d.ip)}</td><td><small>${E(d.mac)}</small></td><td>${d.online?'en línea':ago(d.last)}</td><td>${ports}${portNote}</td><td>${estado}</td><td style="white-space:nowrap">
<button class="primary" data-a="inspect" data-m="${E(d.mac)}">Inspeccionar</button>
</td></tr>`}).join('')}
async function deviceAction(b){const m=b.dataset.m,version=inspectionRequest;
if(b.dataset.a==='inspect'){await inspect(m);return}
if(b.dataset.a==='n'){const d=S.devices.find(x=>x.mac===m),v=prompt('Nombre del dispositivo',d?d.name:'');if(v!==null){const r=await post('/api/device',{mac:m,name:v});if(!currentInspection(m,version))return;if(!r.ok)message('#inspectMsg',r.error||'No se pudo guardar el nombre.',true);else await refreshInspection()}return}
if(b.dataset.a==='scan'){const r=await post('/api/scan_ports',{mac:m});if(!currentInspection(m,version))return;message('#inspectMsg',r.ok?'Análisis iniciado. Actualiza esta vista en unos segundos.':r.error||'No se pudo analizar.',!r.ok);return}
if(b.dataset.a==='p'){const r=await post('/api/device',{mac:m,protected:b.dataset.v==='1'});if(!currentInspection(m,version))return;if(!r.ok)message('#inspectMsg',r.error||'No se pudo guardar.',true);else await refreshInspection();return}
if(b.dataset.a==='b'){const on=b.dataset.v==='1';if(on){if(!confirm('Esto cortará el internet real de este dispositivo. ¿Confirmas?'))return;const mins=prompt('¿Minutos de bloqueo? Deja vacío para bloqueo indefinido','30');if(mins===null)return;const n=mins?Number(mins):null;if(mins&&(!Number.isInteger(n)||n<1)){message('#inspectMsg','Escribe un número entero de minutos mayor que cero.',true);return}const r=await post('/api/block',{mac:m,blocked:true,minutes:n});if(!currentInspection(m,version))return;if(!r.ok)message('#inspectMsg',r.error||'No se pudo aplicar el bloqueo.',true);else await refreshInspection();return}const r=await post('/api/block',{mac:m,blocked:false});if(!currentInspection(m,version))return;if(!r.ok)message('#inspectMsg',r.error||'No se pudo desbloquear.',true);else await refreshInspection();return}
const r=await post('/api/device',{mac:m,trusted:b.dataset.v==='1'});if(!currentInspection(m,version))return;if(!r.ok)message('#inspectMsg',r.error||'No se pudo guardar.',true);else await refreshInspection();
}
$('#tb').onclick=e=>{const b=e.target.closest('button[data-a]');if(b)deviceAction(b)};
$('#deviceActions').onclick=e=>{const b=e.target.closest('button[data-a]');if(b)deviceAction(b)};
$('#q').oninput=()=>S&&table();document.querySelectorAll('.chip').forEach(b=>b.onclick=()=>{flt=b.dataset.f;document.querySelectorAll('.chip').forEach(x=>x.classList.toggle('on',x==b));S&&table()});

let inspectedMac=null,inspection=null,inspectionRequest=0,inspectionHistory=[],nextHistory=null,dailyInitialized=false,settingsBusy=false,incidentRequest=0;
const dates=t=>{if(t==null||t==='')return 'Sin datos';const d=new Date(typeof t==='number'||/^\d+(\.\d+)?$/.test(String(t))?Number(t)*1000:t);return Number.isNaN(d.getTime())?'Sin datos':d.toLocaleString()};
const currentInspection=(mac,version)=>mac===inspectedMac&&version===inspectionRequest&&inspection!==null;
function message(selector,text,error=false){const el=$(selector);el.textContent=text||'';el.classList.toggle('error',!!error)}
function drawExtras(){const o=S.overview||{};$('#overview').innerHTML=`<span><strong>${Number(o.pending_incidents)||0}</strong> incidentes pendientes</span><span><strong>${Number(o.acknowledged_incidents)||0}</strong> revisados</span><span><strong>${Number(o.watching)||0}</strong> equipos vigilados</span><span>Abre «Inspeccionar» para ver el historial de cada equipo.</span>`;const daily=S.daily_summary||{};if(!dailyInitialized){$('#dailyEnabled').checked=!!daily.enabled;$('#dailyHour').value=daily.hour||'20:00';dailyInitialized=true}$('#dailyLast').textContent=daily.last_sent?'Último resumen programado: '+dates(daily.last_sent):'Todavía no se ha preparado un resumen.'}
function setPane(name,focus=false){const tabs=[...document.querySelectorAll('#inspector [role=tab]')];for(const b of tabs){const selected=b.dataset.pane===name;b.setAttribute('aria-selected',String(selected));b.tabIndex=selected?0:-1;$('#pane-'+b.dataset.pane).hidden=!selected;if(selected&&focus)b.focus()}}
document.querySelector('#inspector .tabs').onclick=e=>{const b=e.target.closest('button[data-pane]');if(b)setPane(b.dataset.pane)};
document.querySelector('#inspector .tabs').onkeydown=e=>{const tabs=[...document.querySelectorAll('#inspector [role=tab]')];const index=tabs.indexOf(document.activeElement);if(index<0)return;let next=index;if(e.key==='ArrowRight')next=(index+1)%tabs.length;else if(e.key==='ArrowLeft')next=(index+tabs.length-1)%tabs.length;else if(e.key==='Home')next=0;else if(e.key==='End')next=tabs.length-1;else return;e.preventDefault();setPane(tabs[next].dataset.pane,true)};
$('#inspectClose').onclick=()=>$('#inspector').close();
$('#inspector').addEventListener('close',()=>{inspectedMac=null;inspection=null;inspectionHistory=[];nextHistory=null;inspectionRequest++;incidentRequest++});
$('#inspectRefresh').onclick=()=>refreshInspection();
async function inspect(mac){inspectionRequest++;incidentRequest++;inspectedMac=mac;inspection=null;inspectionHistory=[];nextHistory=null;$('#expectedEnabled').checked=false;$('#expectedPorts').value='';$('#watchEnabled').checked=false;$('#watchFailures').value='3';$('#watchStatus').textContent='Disponibilidad todavía sin confirmar.';$('#moreHistory').hidden=true;$('#historyCount').textContent='';$('#inspectTitle').textContent='Inspeccionar dispositivo';$('#inspectMeta').textContent=mac;$('#deviceInfo').innerHTML='';$('#deviceActions').innerHTML='';$('#incidentList').innerHTML='';$('#deviceHistory').innerHTML='';$('#historySearch').value='';for(const id of ['inspectMsg','portsMsg','watchMsg'])message('#'+id,'');setPane('info');if(!$('#inspector').open)$('#inspector').showModal();await refreshInspection()}
async function refreshInspection(){if(!inspectedMac)return;const request=++inspectionRequest,mac=inspectedMac;message('#inspectMsg','Cargando dispositivo…');$('#inspectRefresh').disabled=true;try{const data=await api('/api/device?mac='+encodeURIComponent(mac));if(request!==inspectionRequest||mac!==inspectedMac)return;inspection=data;inspectionHistory=data.history||[];nextHistory=data.next_before??null;renderInspection();message('#inspectMsg','')}catch(error){if(request===inspectionRequest)message('#inspectMsg',error.message,true)}finally{if(request===inspectionRequest)$('#inspectRefresh').disabled=false}}
function renderInspection(){const d=inspection.device||{},settings=inspection.settings||{};$('#inspectTitle').textContent=d.name||d.vendor||'Dispositivo';$('#inspectMeta').textContent=(d.ip||'IP no disponible')+' · '+(d.mac||inspectedMac)+' · '+(S.net||'Red actual');const rows=[['IP',d.ip],['MAC',d.mac||inspectedMac],['Fabricante',d.vendor||(d.private?'MAC privada; fabricante sin identificar':'Sin identificar')],['Estado',d.online?'En línea':'No visto en el último descubrimiento'],['Confianza',d.trusted?'Confiable':'Sin confirmar'],['Última detección',dates(d.last)],['Puertos TCP abiertos confirmados',(d.ports||[]).join(', ')||'Ninguno confirmado'],['Último análisis de puertos',dates(d.ports_at)]];$('#deviceInfo').innerHTML='<dl class="device-grid">'+rows.map(([label,value])=>`<div><dt>${E(label)}</dt><dd>${E(value||'Sin datos')}</dd></div>`).join('')+'</dl>'+((d.ports_unknown||[]).length?`<p class="hint">${Number(d.ports_unknown.length)} puertos no dieron una respuesta concluyente.</p>`:'')+(d.ports_ip&&d.ports_ip!==d.ip?`<p class="hint">El último análisis corresponde a la IP anterior ${E(d.ports_ip)}.</p>`:'');
const m=E(inspectedMac);$('#deviceActions').innerHTML=`<button data-a="n" data-m="${m}">Cambiar nombre</button><button data-a="t" data-m="${m}" data-v="${d.trusted?0:1}">${d.trusted?'Quitar confianza':'Confiar'}</button><button data-a="scan" data-m="${m}" ${d.online?'':'disabled'}>Analizar puertos</button>`+(d.gw?'':`<button data-a="p" data-m="${m}" data-v="${d.protected?0:1}">${d.protected?'Desproteger del bloqueo':'Proteger del bloqueo'}</button>`)+(d.gw||d.protected?'':`<button data-a="b" data-m="${m}" data-v="${d.blocked?0:1}" style="color:var(--crit)">${d.blocked?'Desbloquear':'Bloquear'}</button>`);$('#expectedEnabled').checked=!!settings.expected_enabled;$('#expectedPorts').value=(settings.expected_ports||[]).join(', ');$('#watchEnabled').checked=!!settings.watch_enabled;$('#watchFailures').value=String(settings.watch_failures||3);const watch=inspection.watch||{},watchLabel=!settings.watch_enabled?'Vigilancia desactivada.':watch.online===true?'Disponible en la última comprobación.':watch.online===false?'Caída confirmada.':'Disponibilidad todavía sin confirmar.';$('#watchStatus').innerHTML=`<b>${E(watchLabel)}</b><span class="hint">${settings.watch_enabled?'Fallos consecutivos: '+(Number(watch.failures)||0)+' de '+(Number(settings.watch_failures)||3)+' · ':''}Última comprobación: ${E(dates(watch.last_checked))}</span>`;renderIncidents();renderDeviceHistory()}
function settingsPayload(){const settings=inspection.settings||{};return {mac:inspectedMac,expected_enabled:!!settings.expected_enabled,expected_ports:settings.expected_ports||[],watch_enabled:!!settings.watch_enabled,watch_failures:Number(settings.watch_failures)||3}}
async function saveDeviceSettings(form,payload,feedback){if(settingsBusy){message(feedback,'Espera a que termine el guardado en curso.',true);return}const mac=inspectedMac,version=inspectionRequest,buttons=[...document.querySelectorAll('#portsForm button[type=submit],#watchForm button[type=submit]')];settingsBusy=true;buttons.forEach(b=>b.disabled=true);message(feedback,'Guardando…');try{const r=await post('/api/device_settings',payload);if(!currentInspection(mac,version))return;if(!r.ok)throw new Error(r.error||'No se pudo guardar.');inspection.settings={...inspection.settings,...payload};message(feedback,'Configuración guardada. Se aplicará en las próximas comprobaciones.')}catch(error){if(currentInspection(mac,version))message(feedback,error.message,true)}finally{settingsBusy=false;buttons.forEach(b=>b.disabled=false)}}
$('#portsForm').onsubmit=async e=>{e.preventDefault();if(!inspection){message('#portsMsg','Espera a que se cargue el dispositivo.',true);return}const raw=$('#expectedPorts').value.trim(),parts=raw?raw.split(/[\s,;]+/).filter(Boolean):[];if(parts.some(p=>!/^\d+$/.test(p))){message('#portsMsg','Escribe únicamente números de puerto separados por comas o espacios.',true);return}const ports=[...new Set(parts.map(Number))].sort((a,b)=>a-b);if(ports.length>64||ports.some(p=>!Number.isInteger(p)||p<1||p>65535)){message('#portsMsg','Usa hasta 64 puertos, entre 1 y 65535.',true);return}await saveDeviceSettings(e.currentTarget,{...settingsPayload(),expected_enabled:$('#expectedEnabled').checked,expected_ports:ports},'#portsMsg')};
$('#useDetectedPorts').onclick=()=>{if(!inspection)return;$('#expectedPorts').value=(inspection.device.ports||[]).join(', ');message('#portsMsg','Lista copiada. Activa el perfil y guarda para aplicarla.')};
$('#watchForm').onsubmit=async e=>{e.preventDefault();if(!inspection){message('#watchMsg','Espera a que se cargue el dispositivo.',true);return}await saveDeviceSettings(e.currentTarget,{...settingsPayload(),watch_enabled:$('#watchEnabled').checked,watch_failures:Number($('#watchFailures').value)},'#watchMsg')};
const statusNames={pending:'Pendiente',acknowledged:'Revisado',resolved:'Resuelto'};
function renderIncidents(){const items=inspection.incidents||[];$('#incidentList').innerHTML=items.length?items.map(i=>{const id=Number(i.id);return `<details class="incident" ${i.status==='pending'?'open':''}><summary><span class="b ${i.status==='resolved'?'ok':i.status==='pending'?'warn':'off'}">${E(statusNames[i.status]||i.status)}</span> ${E(i.title)}<br><small>Creado: ${E(dates(i.created_at))} · Actualizado: ${E(dates(i.updated_at))}</small></summary><form data-incident="${id}"><div class="field"><label for="incident-status-${id}">Estado</label><select id="incident-status-${id}" name="status">${Object.entries(statusNames).filter(([value])=>i.status!=="resolved"||value==="resolved").map(([value,label])=>`<option value="${value}" ${i.status===value?'selected':''}>${label}</option>`).join('')}</select></div><div class="field"><label for="incident-note-${id}">Notas de seguimiento</label><textarea id="incident-note-${id}" name="note" rows="3" maxlength="1000" placeholder="Por ejemplo: desactivé Telnet y volví a analizar.">${E(i.note||'')}</textarea></div><button class="primary" type="submit">Guardar seguimiento</button><div class="notice" data-feedback role="status" aria-live="polite"></div></form></details>`}).join(''):'<div class="empty">No hay incidentes registrados para este dispositivo en la red actual.</div>'}
$('#incidentList').onsubmit=async e=>{const form=e.target.closest('form[data-incident]');if(!form)return;e.preventDefault();const mac=inspectedMac,version=inspectionRequest,button=form.querySelector('button'),feedback=form.querySelector('[data-feedback]');button.disabled=true;feedback.textContent='Guardando…';try{const r=await post('/api/incident',{mac,id:Number(form.dataset.incident),status:form.elements.status.value,note:form.elements.note.value});if(!currentInspection(mac,version))return;if(!r.ok)throw new Error(r.error||'No se pudo guardar el seguimiento.');const request=++incidentRequest,data=await api('/api/device?mac='+encodeURIComponent(mac));if(!currentInspection(mac,version)||request!==incidentRequest)return;if(inspection.scope&&data.scope&&inspection.scope!==data.scope){message('#inspectMsg','La red cambió. Actualiza la inspección para continuar.',true);return}inspection.incidents=data.incidents||[];renderIncidents();message('#inspectMsg','Seguimiento guardado.')}catch(error){if(currentInspection(mac,version)){feedback.textContent=error.message;feedback.classList.add('error')}}finally{button.disabled=false}};
function renderDeviceHistory(){const q=$('#historySearch').value.toLowerCase(),items=inspectionHistory.filter(h=>(h.summary+' '+h.kind+' '+JSON.stringify(h.details||'')).toLowerCase().includes(q));$('#historyCount').textContent=`${items.length} de ${inspectionHistory.length} eventos cargados`;$('#deviceHistory').innerHTML=items.length?items.map(h=>`<article class="history-entry"><time>${E(dates(h.ts))}</time><p>${E(h.summary)}</p>${h.details&&Object.keys(h.details).length?`<details><summary class="hint">Ver detalles</summary><pre>${E(typeof h.details==='string'?h.details:JSON.stringify(h.details,null,2))}</pre></details>`:''}</article>`).join(''):'<div class="empty">'+(q?'No hay coincidencias en los eventos cargados.':'Todavía no hay eventos registrados para este dispositivo.')+'</div>';$('#moreHistory').hidden=nextHistory==null}
$('#historySearch').oninput=renderDeviceHistory;
$('#moreHistory').onclick=async()=>{if(nextHistory==null||!inspectedMac||!inspection)return;const mac=inspectedMac,version=inspectionRequest,before=nextHistory,scope=inspection.scope,button=$('#moreHistory');button.disabled=true;try{const data=await api('/api/device?mac='+encodeURIComponent(mac)+'&before='+encodeURIComponent(before));if(!currentInspection(mac,version))return;if(scope&&data.scope&&scope!==data.scope){message('#inspectMsg','La red cambió. Actualiza la inspección para ver su historial.',true);return}const seen=new Set(inspectionHistory.map(h=>h.id));inspectionHistory.push(...(data.history||[]).filter(h=>!seen.has(h.id)));nextHistory=data.next_before??null;renderDeviceHistory()}catch(error){if(currentInspection(mac,version))message('#inspectMsg',error.message,true)}finally{button.disabled=false}};
$('#dailyForm').onsubmit=async e=>{e.preventDefault();const button=e.currentTarget.querySelector('button');button.disabled=true;message('#dailyMsg','Guardando…');const r=await post('/api/daily_summary',{enabled:$('#dailyEnabled').checked,hour:$('#dailyHour').value});button.disabled=false;message('#dailyMsg',r.ok?'Resumen diario guardado.':r.error||'No se pudo guardar.',!r.ok);if(r.ok){dailyInitialized=false;drawExtras()}};
$('#logout').onclick=async()=>{const r=await post('/api/logout');if(r.ok)location.reload()};

addEventListener('resize',()=>S&&draw());load();setInterval(load,3000);
</script></html>"""

def main():
    import atexit
    global FEATURE_STORE
    # Una sola instancia evita dos consumidores y escrituras simultáneas del inventario.
    instance_file = open(P("netwatch.lock"), "a")
    try:
        fcntl.flock(instance_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("NetWatch ya está ejecutándose en esta carpeta.")
    try:
        init_port_alerts()
        FEATURE_STORE = FeatureStore(PORT_ALERTS_DB, risk_info=RISK_PORT_INFO)
        init_auth()
    except (sqlite3.DatabaseError, ValueError, OSError, TypeError) as error:
        raise SystemExit(f"No se pudo abrir el estado o el acceso del panel: {error}. Conserva port_alerts.sqlite3 y auth.json para revisarlos.")
    load_db(); load_oui()
    print("Telegram:", "configurado" if CFG.get("tg_token") and CFG.get("tg_chat") else "NO configurado (config.json)", flush=True)
    atexit.register(restore_all)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=poison_loop, daemon=True).start()
    threading.Thread(target=port_alert_loop, daemon=True).start()
    threading.Thread(target=feature_loop, daemon=True).start()
    print(f"Dashboard en http://0.0.0.0:{PORT}", flush=True)
    while True: step()

if __name__ == "__main__":
    main()