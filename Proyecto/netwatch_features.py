"""Persistent per-device profiles, availability, incidents and reports for NetWatch.

Only Python's standard library is used. All database mutations use transactions;
notifications share the host's durable ``risk_events`` Telegram outbox.
"""
from contextlib import contextmanager
from datetime import datetime
import json
import re
import sqlite3
import time


DEFAULT_SETTINGS = {
    "expected_enabled": False,
    "expected_ports": [],
    "watch_enabled": False,
    "watch_failures": 3,
}
STATUSES = {"pending", "acknowledged", "resolved"}
PROFILE_KINDS = {"unexpected_port", "expected_closed"}
HISTORY_DAYS = 90


def _text(value, limit=300):
    return " ".join(str(value if value is not None else "").split())[:limit]


def _at(value=None):
    return time.time() if value is None else float(value)


def _ports(value):
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("Indica una lista de hasta 64 puertos.")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in value):
        raise ValueError("Los puertos deben ser números enteros entre 1 y 65535.")
    return sorted(set(value))


def _hour(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
        raise ValueError("La hora del resumen debe tener formato HH:MM, de 00:00 a 23:59.")
    return value


class FeatureStore:
    def __init__(self, path, risk_info=None):
        self.path = str(path)
        self.risk_info = dict(risk_info or {})
        with self._connection(write=True) as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS risk_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
                    delivered_at REAL, error TEXT);
                CREATE TABLE IF NOT EXISTS feature_settings (
                    mac TEXT PRIMARY KEY, settings TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS feature_global (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS feature_devices (
                    scope TEXT NOT NULL, mac TEXT NOT NULL, ip TEXT NOT NULL, name TEXT NOT NULL,
                    first_seen REAL NOT NULL, last_seen REAL NOT NULL, last_scan REAL,
                    PRIMARY KEY(scope, mac));
                CREATE TABLE IF NOT EXISTS feature_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, mac TEXT NOT NULL,
                    ts REAL NOT NULL, kind TEXT NOT NULL, summary TEXT NOT NULL, details TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS feature_history_device
                    ON feature_history(scope, mac, id DESC);
                CREATE INDEX IF NOT EXISTS feature_history_time ON feature_history(ts);
                CREATE TABLE IF NOT EXISTS feature_conditions (
                    scope TEXT NOT NULL, mac TEXT NOT NULL, kind TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL,
                    PRIMARY KEY(scope, mac, kind, port));
                CREATE TABLE IF NOT EXISTS feature_incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, mac TEXT NOT NULL,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending','acknowledged','resolved')),
                    kind TEXT NOT NULL, title TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
                    port INTEGER, resolution TEXT NOT NULL DEFAULT '');
                CREATE INDEX IF NOT EXISTS feature_incidents_device
                    ON feature_incidents(scope, mac, id DESC);
                CREATE UNIQUE INDEX IF NOT EXISTS feature_incidents_active
                    ON feature_incidents(scope, mac, kind, COALESCE(port,0))
                    WHERE status != 'resolved';
                CREATE TABLE IF NOT EXISTS feature_watch (
                    scope TEXT NOT NULL, mac TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0,
                    online INTEGER, last_checked REAL, PRIMARY KEY(scope, mac));
                CREATE TABLE IF NOT EXISTS feature_reports (
                    day TEXT PRIMARY KEY, queued_at REAL NOT NULL, event_id INTEGER NOT NULL);
            """)
            connection.execute("INSERT OR IGNORE INTO feature_global(key,value) VALUES('created_at',?)", (str(time.time()),))
            self._prune(connection, time.time())

    @contextmanager
    def _connection(self, write=False):
        connection = sqlite3.connect(self.path, timeout=20)
        connection.row_factory = sqlite3.Row
        try:
            if write:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            if write:
                connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _settings(self, connection, mac):
        row = connection.execute("SELECT settings FROM feature_settings WHERE mac=?", (mac,)).fetchone()
        settings = dict(DEFAULT_SETTINGS, expected_ports=[])
        if row:
            settings.update(json.loads(row["settings"]))
        return settings

    def get_settings(self, mac):
        with self._connection() as connection:
            return self._settings(connection, mac)

    def get_all_settings(self):
        """Return explicitly saved profiles with a single connection for dashboard snapshots."""
        with self._connection() as connection:
            result = {}
            for row in connection.execute("SELECT mac,settings FROM feature_settings"):
                settings = dict(DEFAULT_SETTINGS, expected_ports=[])
                settings.update(json.loads(row["settings"]))
                result[row["mac"]] = settings
            return result

    def _history(self, connection, scope, mac, kind, summary, details, at):
        encoded = json.dumps(details if details is not None else {}, ensure_ascii=False)
        if len(encoded) > 24000:
            raise ValueError("Los detalles del evento son demasiado extensos.")
        return connection.execute(
            "INSERT INTO feature_history(scope,mac,ts,kind,summary,details) VALUES(?,?,?,?,?,?)",
            (scope, mac, at, _text(kind, 60), _text(summary, 600), encoded)).lastrowid

    def _device(self, connection, scope, mac, ip, name, at, scan=False):
        previous = connection.execute("SELECT * FROM feature_devices WHERE scope=? AND mac=?", (scope, mac)).fetchone()
        connection.execute("""INSERT INTO feature_devices(scope,mac,ip,name,first_seen,last_seen,last_scan)
            VALUES(?,?,?,?,?,?,?) ON CONFLICT(scope,mac) DO UPDATE SET ip=excluded.ip,
            name=CASE WHEN excluded.name!='' THEN excluded.name ELSE feature_devices.name END,
            last_seen=excluded.last_seen,
            last_scan=CASE WHEN excluded.last_scan IS NOT NULL THEN excluded.last_scan ELSE feature_devices.last_scan END""",
            (scope, mac, str(ip), _text(name, 100), at, at, at if scan else None))
        if previous and previous["ip"] != str(ip):
            self._history(connection, scope, mac, "ip_change", f"IP modificada: {previous['ip']} → {ip}",
                          {"previous_ip": previous["ip"], "ip": str(ip)}, at)

    def _queue(self, connection, message):
        # Keep a conservative UTF-16 budget, including the stable local event ID.
        message = message.encode("utf-16-le")[:7600].decode("utf-16-le", "ignore")
        event_id = connection.execute("INSERT INTO risk_events(text) VALUES(?)", (message,)).lastrowid
        connection.execute("UPDATE risk_events SET text=? WHERE id=?", (message + f"\nEvento #{event_id}", event_id))
        return event_id

    def _condition(self, connection, scope, mac, kind, port, active, title, at, resolution="Condición corregida"):
        port_key = port or 0
        old = connection.execute("SELECT active FROM feature_conditions WHERE scope=? AND mac=? AND kind=? AND port=?",
                                 (scope, mac, kind, port_key)).fetchone()
        if bool(old["active"] if old else False) == bool(active):
            if active:
                # Only a new conclusive observation reaches this branch. Unknown
                # ports never replace the incident's last confirmed IP context.
                incident = connection.execute("""SELECT id,title FROM feature_incidents
                    WHERE scope=? AND mac=? AND kind=? AND COALESCE(port,0)=? AND status!='resolved'
                    ORDER BY id DESC LIMIT 1""", (scope, mac, kind, port_key)).fetchone()
                if incident and incident["title"] != title:
                    connection.execute("UPDATE feature_incidents SET title=?,updated_at=? WHERE id=?", (title, at, incident["id"]))
                    self._history(connection, scope, mac, "incident_updated", "Evidencia confirmada actualizada: " + title,
                                  {"incident_id": incident["id"], "kind": kind, "port": port, "previous_title": incident["title"]}, at)
                    if kind in PROFILE_KINDS:
                        # Profile titles change only when conclusive evidence moves
                        # to a different IP. Keep the incident and notify the context.
                        return {"id": incident["id"], "kind": kind, "port": port, "active": True,
                                "title": title, "context_changed": True}
            return None
        connection.execute("""INSERT INTO feature_conditions(scope,mac,kind,port,active) VALUES(?,?,?,?,?)
            ON CONFLICT(scope,mac,kind,port) DO UPDATE SET active=excluded.active""",
            (scope, mac, kind, port_key, int(active)))
        if active:
            incident_id = connection.execute("""INSERT INTO feature_incidents
                (scope,mac,created_at,updated_at,status,kind,title,port) VALUES(?,?,?,?,'pending',?,?,?)""",
                (scope, mac, at, at, kind, title, port)).lastrowid
            summary = "Incidente abierto: " + title
        else:
            incident = connection.execute("""SELECT id,status FROM feature_incidents
                WHERE scope=? AND mac=? AND kind=? AND COALESCE(port,0)=? ORDER BY id DESC LIMIT 1""",
                (scope, mac, kind, port_key)).fetchone()
            incident_id = incident["id"] if incident else None
            if incident and incident["status"] != "resolved":
                connection.execute("UPDATE feature_incidents SET status='resolved',updated_at=?,resolution=? WHERE id=?",
                                   (at, resolution, incident_id))
            summary = resolution + ": " + title
        self._history(connection, scope, mac, "incident_opened" if active else "incident_cleared", summary,
                      {"incident_id": incident_id, "kind": kind, "port": port, "active": bool(active)}, at)
        return {"id": incident_id, "kind": kind, "port": port, "active": bool(active), "title": title}

    def _deactivate(self, connection, mac, kinds, at, reason):
        placeholders = ",".join("?" for _ in kinds)
        rows = connection.execute(f"SELECT * FROM feature_conditions WHERE mac=? AND active=1 AND kind IN ({placeholders})",
                                  (mac, *kinds)).fetchall()
        for row in rows:
            self._condition(connection, row["scope"], mac, row["kind"], row["port"] or None, False,
                            "Configuración actualizada", at, reason)

    def save_settings(self, mac, data):
        if not isinstance(data, dict):
            raise ValueError("La configuración debe ser un objeto.")
        with self._connection(write=True) as connection:
            previous = self._settings(connection, mac)
            settings = dict(previous)
            for key in ("expected_enabled", "watch_enabled"):
                if key in data:
                    if type(data[key]) is not bool:
                        raise ValueError(f"{key} debe ser verdadero o falso.")
                    settings[key] = data[key]
            if "expected_ports" in data:
                settings["expected_ports"] = _ports(data["expected_ports"])
            if "watch_failures" in data:
                if type(data["watch_failures"]) is not int or not 2 <= data["watch_failures"] <= 10:
                    raise ValueError("La vigilancia requiere entre 2 y 10 fallos consecutivos.")
                settings["watch_failures"] = data["watch_failures"]
            if settings == previous:
                return settings
            at = time.time()
            connection.execute("INSERT INTO feature_settings(mac,settings) VALUES(?,?) ON CONFLICT(mac) DO UPDATE SET settings=excluded.settings",
                               (mac, json.dumps(settings)))
            if settings["expected_enabled"] != previous["expected_enabled"]:
                kinds = ["risk_port"] if settings["expected_enabled"] else ["unexpected_port", "expected_closed"]
                self._deactivate(connection, mac, kinds, at, "Perfil actualizado; se comprobará en el próximo análisis")
            elif settings["expected_enabled"] and settings["expected_ports"] != previous["expected_ports"]:
                expected = set(settings["expected_ports"])
                rows = connection.execute("SELECT * FROM feature_conditions WHERE mac=? AND active=1 AND kind IN ('unexpected_port','expected_closed')", (mac,)).fetchall()
                for row in rows:
                    if (row["kind"] == "unexpected_port" and row["port"] in expected) or (row["kind"] == "expected_closed" and row["port"] not in expected):
                        self._condition(connection, row["scope"], mac, row["kind"], row["port"], False,
                                        "Configuración actualizada", at, "El puerto ya no incumple el perfil configurado")
            if settings["watch_enabled"] != previous["watch_enabled"]:
                self._deactivate(connection, mac, ["watch_offline"], at, "Configuración de vigilancia actualizada")
                connection.execute("UPDATE feature_watch SET failures=0,online=NULL WHERE mac=?", (mac,))
            scopes = connection.execute("SELECT scope FROM feature_devices WHERE mac=?", (mac,)).fetchall()
            for row in scopes:
                self._history(connection, row["scope"], mac, "settings", "Perfil y vigilancia actualizados", settings, at)
            return settings

    def record_event(self, scope, mac, kind, summary, details=None, at=None):
        at = _at(at)
        with self._connection(write=True) as connection:
            self._prune(connection, at)
            if kind == "discovery" and isinstance(details, dict) and details.get("ip"):
                self._device(connection, scope, mac, details["ip"], details.get("name", ""), at)
            return self._history(connection, scope, mac, kind, summary, details, at)

    def observe_scan(self, scope, mac, ip, scan, name="", at=None):
        at = _at(at)
        opened, closed, unknown = (set(scan.get(key, [])) for key in ("open", "closed", "unknown"))
        if opened & closed or opened & unknown or closed & unknown:
            raise ValueError("Un puerto no puede tener dos resultados en el mismo análisis.")
        if any(type(port) is not int or not 1 <= port <= 65535 for port in opened | closed | unknown):
            raise ValueError("Resultado de puerto inválido.")
        with self._connection(write=True) as connection:
            self._prune(connection, at)
            self._device(connection, scope, mac, ip, name, at, scan=True)
            settings = self._settings(connection, mac)
            self._history(connection, scope, mac, "ports", "Análisis TCP: " +
                          (", ".join(map(str, sorted(opened))) + " abiertos" if opened else "sin abiertos confirmados"),
                          {"ip": str(ip), "open": sorted(opened), "closed": sorted(closed), "unknown": sorted(unknown)}, at)
            changes = []
            if settings["expected_enabled"]:
                expected = set(settings["expected_ports"])
                for port in sorted(opened | closed):
                    if port in expected:
                        change = self._condition(connection, scope, mac, "expected_closed", port, port in closed,
                                                 f"Puerto esperado {port}/TCP no acepta conexiones en {ip}", at)
                    else:
                        change = self._condition(connection, scope, mac, "unexpected_port", port, port in opened,
                                                 f"Puerto {port}/TCP abierto fuera del perfil en {ip}", at)
                    if change:
                        changes.append(change)
                if changes:
                    lines = ["NetWatch — cambios del perfil de puertos", "Dispositivo: " + (_text(name, 100) or mac),
                             "IP: " + str(ip), "MAC: " + mac,
                             "Fecha: " + datetime.fromtimestamp(at).strftime("%Y-%m-%d %H:%M:%S")]
                    blocks = []
                    for change in changes:
                        status = "Cambio de IP" if change.get("context_changed") else "Nuevo incidente" if change["active"] else "Condición corregida"
                        blocks.append(f"\n{status} #{change['id']}: {change['title']}")
                    affected = sorted({change["port"] for change in changes if change["active"]})
                    active_kinds = {change["port"]: change["kind"] for change in changes if change["active"]}
                    # Detail each risk when possible, splitting durable messages rather than cutting recommendations.
                    header = "\n".join(lines)
                    for port in affected:
                        info = self.risk_info.get(port)
                        if active_kinds[port] == "expected_closed":
                            service = info[0] if info else "Sin identificar por el número de puerto"
                            risk = "El servicio esperado no está disponible desde el monitor."
                            recommendation = "Revisar el servicio, firewall y conexión; comprobar si el perfil sigue siendo correcto."
                        else:
                            service, risk, recommendation = info if info else ("Sin identificar por el número de puerto",
                                "Servicio fuera del perfil.",
                                "Verificar si es necesario y restringir el acceso a equipos autorizados.")
                        blocks.append(f"\n\n{port}/TCP — Servicio habitual: {service}\nRiesgo: {risk}\nRecomendación: {recommendation}")
                    message = header
                    for block in blocks:
                        if len((message + block).encode("utf-16-le")) > 7400:
                            self._queue(connection, message)
                            message = header + "\nContinuación"
                        message += block
                    self._queue(connection, message)
            else:
                # The host already queues risk-port notifications; incident tracking must not duplicate them.
                for port in sorted((opened | closed) & set(self.risk_info)):
                    self._condition(connection, scope, mac, "risk_port", port, port in opened,
                                    f"Puerto de riesgo {port}/TCP ({self.risk_info[port][0]}) en {ip}", at)
            return {"changes": changes, "settings": settings}

    def observe_presence(self, scope, mac, ip, reachable, name="", at=None):
        if reachable is not None and type(reachable) is not bool:
            raise ValueError("El resultado de disponibilidad debe ser verdadero, falso o desconocido.")
        if reachable is None:
            return None
        at = _at(at)
        with self._connection(write=True) as connection:
            self._prune(connection, at)
            self._device(connection, scope, mac, ip, name, at)
            settings = self._settings(connection, mac)
            old = connection.execute("SELECT * FROM feature_watch WHERE scope=? AND mac=?", (scope, mac)).fetchone()
            old_online = old["online"] if old else None
            failures = 0 if reachable else (old["failures"] if old else 0) + 1
            online = 1 if reachable else 0 if failures >= settings["watch_failures"] else old_online
            connection.execute("""INSERT INTO feature_watch(scope,mac,failures,online,last_checked) VALUES(?,?,?,?,?)
                ON CONFLICT(scope,mac) DO UPDATE SET failures=excluded.failures,online=excluded.online,last_checked=excluded.last_checked""",
                (scope, mac, failures, online, at))
            changed = online is not None and online != old_online
            if changed:
                self._history(connection, scope, mac, "presence", "Equipo disponible" if online else "Equipo sin respuesta confirmada",
                              {"ip": str(ip), "online": bool(online), "failures": failures}, at)
            if settings["watch_enabled"] and online is not None:
                title = f"Equipo vigilado sin respuesta: {_text(name, 100) or mac} ({ip})"
                change = self._condition(connection, scope, mac, "watch_offline", None, not bool(online), title, at,
                                         "Disponibilidad recuperada")
                if change:
                    text = "NetWatch — " + ("equipo sin respuesta" if change["active"] else "equipo recuperado")
                    text += f"\nDispositivo: {_text(name, 100) or mac}\nIP: {ip}\nMAC: {mac}"
                    text += f"\nIncidente #{change['id']}\nFecha: {datetime.fromtimestamp(at).strftime('%Y-%m-%d %H:%M:%S')}"
                    text += (f"\nConfirmación: {failures} comprobaciones fallidas consecutivas.\nRecomendación: revisar alimentación, conexión y servicio."
                             if change["active"] else "\nEl equipo volvió a responder; incidente resuelto automáticamente.")
                    self._queue(connection, text)
            return {"online": bool(online) if online is not None else None, "failures": failures, "changed": changed}

    def snapshot_device(self, scope, mac, limit=100, before=None):
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("El límite debe estar entre 1 y 200.")
        if before is not None and (type(before) is not int or before < 1):
            raise ValueError("El cursor de historial no es válido.")
        with self._connection() as connection:
            query = "SELECT id,ts,kind,summary,details FROM feature_history WHERE scope=? AND mac=?"
            args = [scope, mac]
            if before is not None:
                query += " AND id<?"
                args.append(before)
            rows = connection.execute(query + " ORDER BY id DESC LIMIT ?", (*args, limit + 1)).fetchall()
            more = len(rows) > limit
            history = [dict(row, details=json.loads(row["details"])) for row in rows[:limit]]
            incidents = [dict(row) for row in connection.execute("""SELECT id,created_at,updated_at,status,kind,title,note,port,resolution
                FROM feature_incidents WHERE scope=? AND mac=? ORDER BY status='resolved',id DESC LIMIT 300""", (scope, mac))]
            watch = connection.execute("SELECT failures,online,last_checked FROM feature_watch WHERE scope=? AND mac=?", (scope, mac)).fetchone()
            watch_state = dict(watch) if watch else {"failures": 0, "online": None, "last_checked": None}
            if watch_state["online"] is not None:
                watch_state["online"] = bool(watch_state["online"])
            return {"scope": scope, "settings": self._settings(connection, mac), "history": history, "incidents": incidents,
                    "next_before": history[-1]["id"] if more and history else None,
                    "watch": watch_state}

    def update_incident(self, scope, mac, id, status, note, at=None):
        if status not in STATUSES:
            raise ValueError("Estado de incidente inválido.")
        if not isinstance(note, str) or len(note) > 1000:
            raise ValueError("La nota debe tener como máximo 1000 caracteres.")
        if type(id) is not int or id < 1:
            raise ValueError("Identificador de incidente inválido.")
        at = _at(at)
        with self._connection(write=True) as connection:
            row = connection.execute("SELECT * FROM feature_incidents WHERE id=? AND scope=? AND mac=?", (id, scope, mac)).fetchone()
            if row is None:
                raise ValueError("El incidente no pertenece a este dispositivo y red.")
            # Resolved history stays immutable; a new real occurrence creates a different incident.
            if row["status"] == "resolved" and status != "resolved":
                raise ValueError("Un incidente resuelto no se reabre manualmente; una nueva aparición crea otro.")
            if row["status"] != status or row["note"] != note:
                connection.execute("UPDATE feature_incidents SET status=?,note=?,updated_at=?,resolution=? WHERE id=?",
                                   (status, note, at, "Marcado como resuelto por el usuario" if status == "resolved" else "", id))
                self._history(connection, scope, mac, "incident_updated", f"Incidente #{id}: {status}",
                              {"incident_id": id, "status": status, "note": note}, at)
            return dict(connection.execute("SELECT id,created_at,updated_at,status,kind,title,note,port,resolution FROM feature_incidents WHERE id=?", (id,)).fetchone())

    def overview(self, scope):
        with self._connection() as connection:
            counts = {row["status"]: row["n"] for row in connection.execute(
                "SELECT status,COUNT(*) n FROM feature_incidents WHERE scope=? GROUP BY status", (scope,))}
            watching = sum(1 for row in connection.execute("SELECT DISTINCT mac FROM feature_devices WHERE scope=?", (scope,))
                           if self._settings(connection, row["mac"])["watch_enabled"])
            history = connection.execute("SELECT COUNT(*) FROM feature_history WHERE scope=?", (scope,)).fetchone()[0]
            return {"pending_incidents": counts.get("pending", 0), "acknowledged_incidents": counts.get("acknowledged", 0),
                    "watching": watching, "history_events": history}

    def get_daily_settings(self):
        with self._connection() as connection:
            row = connection.execute("SELECT value FROM feature_global WHERE key='daily_settings'").fetchone()
            result = json.loads(row["value"]) if row else {"enabled": True, "hour": "20:00"}
            report = connection.execute("SELECT queued_at,event_id FROM feature_reports ORDER BY queued_at DESC LIMIT 1").fetchone()
            result.update(last_sent=report["queued_at"] if report else None)
            return result

    def save_daily_settings(self, enabled, hour):
        if type(enabled) is not bool:
            raise ValueError("El resumen debe estar activado o desactivado.")
        hour = _hour(hour)
        with self._connection(write=True) as connection:
            connection.execute("INSERT INTO feature_global(key,value) VALUES('daily_settings',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                               (json.dumps({"enabled": enabled, "hour": hour}),))
        return self.get_daily_settings()

    def _prune(self, connection, now):
        row = connection.execute("SELECT value FROM feature_global WHERE key='last_prune'").fetchone()
        if row and now - float(row["value"]) < 86400:
            return
        cutoff = now - HISTORY_DAYS * 86400
        connection.execute("DELETE FROM feature_history WHERE ts<?", (cutoff,))
        connection.execute("DELETE FROM feature_incidents WHERE status='resolved' AND updated_at<?", (cutoff,))
        connection.execute("DELETE FROM feature_reports WHERE queued_at<?", (now - 400 * 86400,))
        connection.execute("INSERT INTO feature_global(key,value) VALUES('last_prune',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now),))

    def daily_summary(self, site="Mi red", now=None, hour="20:00", enabled=True):
        if type(enabled) is not bool:
            raise ValueError("El resumen debe estar activado o desactivado.")
        hour = _hour(hour)
        if not enabled:
            return None
        now = _at(now)
        local = datetime.fromtimestamp(now)
        if local.strftime("%H:%M") < hour:
            return None
        day = local.strftime("%Y-%m-%d")
        with self._connection(write=True) as connection:
            self._prune(connection, now)
            if connection.execute("SELECT 1 FROM feature_reports WHERE day=?", (day,)).fetchone():
                return None
            cutoff = now - 86400
            devices = connection.execute("SELECT COUNT(*) FROM feature_devices WHERE last_seen>=?", (cutoff,)).fetchone()[0]
            new = connection.execute("SELECT COUNT(*) FROM feature_devices WHERE first_seen>=?", (cutoff,)).fetchone()[0]
            scans = connection.execute("SELECT COUNT(*) FROM feature_history WHERE kind='ports' AND ts>=?", (cutoff,)).fetchone()[0]
            opened = connection.execute("SELECT COUNT(*) FROM feature_incidents WHERE created_at>=?", (cutoff,)).fetchone()[0]
            resolved = connection.execute("SELECT COUNT(*) FROM feature_incidents WHERE status='resolved' AND updated_at>=?", (cutoff,)).fetchone()[0]
            active = connection.execute("SELECT COUNT(*) FROM feature_incidents WHERE status!='resolved'").fetchone()[0]
            outages = connection.execute("SELECT COUNT(*) FROM feature_incidents WHERE kind='watch_offline' AND created_at>=?", (cutoff,)).fetchone()[0]
            lines = ["NetWatch — resumen diario", "Red: " + (_text(site, 80) or "Mi red"), "Fecha local de la placa: " + day,
                     "Periodo: últimas 24 horas de registros disponibles.",
                     f"Equipos con observaciones: {devices} (nuevos: {new})", f"Análisis TCP: {scans}",
                     f"Incidentes nuevos: {opened}; resueltos: {resolved}; pendientes de resolver: {active}",
                     f"Caídas confirmadas de equipos vigilados: {outages}"]
            networks = connection.execute("SELECT scope,COUNT(*) n FROM feature_devices WHERE last_seen>=? GROUP BY scope ORDER BY n DESC LIMIT 10", (cutoff,)).fetchall()
            if networks:
                lines.append("Observaciones por red:")
                for row in networks:
                    parts = row["scope"].split("|")
                    network = parts[1] if len(parts) > 1 else parts[0]
                    lines.append(f"• {_text(network, 90)}: {row['n']} equipos")
            lines += ["Los periodos sin ejecución de NetWatch no se contabilizan como disponibilidad.",
                      "Consulta los detalles en el historial independiente de cada dispositivo."]
            event_id = self._queue(connection, "\n".join(lines))
            connection.execute("INSERT INTO feature_reports(day,queued_at,event_id) VALUES(?,?,?)", (day, now, event_id))
            return event_id
