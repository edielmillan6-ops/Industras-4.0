#!/usr/bin/env python3
"""
NetWatch - puente entre el monitor (que corre en el Linux de la placa) y la
matriz LED (microcontrolador).

Esta app corre dentro de un contenedor Docker, que NO ve tu Wi-Fi real. Por eso
el monitor (netwatch_host.py) corre directamente en el Linux de la placa, y esta
app solo le pregunta el estado cada pocos segundos y lo manda a la matriz LED.
"""
import json
import socket
import struct
import time
import urllib.request

from arduino.app_utils import App, Bridge

PORT = 8000
POLL = 3  # segundos


def host_ip():
    """El gateway del contenedor es el Linux de la placa (host)."""
    with open("/proc/net/route") as f:
        next(f)
        for line in f:
            p = line.split()
            if p[1] == "00000000":
                return socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
    raise RuntimeError("sin ruta por defecto")


def loop():
    try:
        url = f"http://{host_ip()}:{PORT}/api/state"
        with urllib.request.urlopen(url, timeout=3) as r:
            status = int(json.load(r)["status"])
        Bridge.call("set_status", status)
    except Exception as e:
        print(f"Esperando al monitor del host ({type(e).__name__}: {e})", flush=True)
    time.sleep(POLL)


App.run(user_loop=loop)