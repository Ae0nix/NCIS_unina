"""Parametri del controller. Ogni valore si puo' cambiare con una variabile d'ambiente
SLICE_<NOME>, ad esempio:   SLICE_MODE=service ryu-manager controller/slice_controller.py
"""
import os
from types import SimpleNamespace

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULTS = {
    # topology : solo H1<->H3 (slice alta) e H2<->H4 (slice bassa), il resto e' vietato
    # service  : tutti parlano; video UDP/9999 -> slice alta, il resto -> slice bassa
    # dynamic  : come service, ma il traffico normale usa la slice alta quando il video tace
    "MODE": "dynamic",
    "VIDEO_PORT": 9999,

    "STATIC_PRIORITY": 5,        # regole proattive di base (core e consegna agli host)
    "FLOW_PRIORITY": 10,         # regole di inoltro per-flusso
    "ICMP_PRIORITY": 60,         # ping sempre ammessi (service/dynamic), sotto lo spoofing
    "ACL_PRIORITY": 50,          # drop di coppie non autorizzate
    "SPOOF_PRIORITY": 90,        # drop di MAC falsificati (vince su tutto il resto)
    "FLOW_IDLE_TIMEOUT": 10,     # s: scadenza di un flusso fermo
    "ACL_BLOCK_S": 10,           # s: durata del drop di una coppia vietata

    # anti-spoofing: off | detect (solo log) | enforce (log + drop)
    "SPOOF_MODE": "enforce",
    "SPOOF_BLOCK_S": 30,
    "SPOOF_LOG_S": 5,            # al massimo un log ogni N s per (porta, MAC)

    # slicing dinamico
    "VIDEO_IDLE_S": 3.0,         # s senza byte video => la slice alta e' libera

    # monitoraggio e dashboard
    "STATS_INTERVAL": 1.0,
    "HISTORY_LEN": 120,
    "STATE_FILE": os.path.join(BASE_DIR, "logs", "state.json"),
}


def _cast(default, raw):
    if isinstance(default, bool):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        return int(float(raw))
    if isinstance(default, float):
        return float(raw)
    return raw


def load(env=None):
    env = os.environ if env is None else env
    values = dict(DEFAULTS)
    for key, default in DEFAULTS.items():
        raw = env.get("SLICE_" + key)
        if raw is not None:
            values[key] = _cast(default, raw)
    return SimpleNamespace(**values)
