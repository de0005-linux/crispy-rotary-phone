"""JinX Core: the Xray data plane of Lumen v34.

Lumen v34 replaces the connection layer with the Super JinX design:

    client --TLS 443--> Railway edge --> nginx :PORT --+-- secret path --> Xray inbound (127.0.0.1)
                                                       +-- everything else --> Lumen panel (127.0.0.1:8000)

* five inbounds (VLESS-WS Pro, VLESS-WS Flash, Trojan-WS Fire, VMess-WS Diamond,
  VLESS-HTTPUpgrade Night), each on its own random per-install path;
* Lumen stays the single source of truth: every allowed config becomes an Xray
  client, every exit proxy / Multi-Location route becomes an Xray outbound plus a
  user routing rule, quota / expiry / IP limits are enforced by removing clients;
* the "doctor" restarts Xray when it stops answering and the reconciler keeps the
  running core identical to the panel state (self-healing, like the JinX bootstrap).

This module has no FastAPI dependency so its builders can be unit-tested alone.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import time
import uuid as _uuid
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import quote, unquote, urlencode, urlsplit

logger = logging.getLogger("jinx-core")

# ── Layout ──────────────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CORE_DIR = Path(os.environ.get("JINX_CORE_DIR", str(DATA_DIR / "jinx")))
PATHS_FILE = CORE_DIR / "paths.json"
NGINX_INC = Path(os.environ.get("JINX_NGINX_INC", str(CORE_DIR / "inbounds.inc")))
RUNTIME_DIR = Path(os.environ.get("JINX_RUNTIME_DIR", "/tmp/lumen-core"))
CONFIG_FILE = RUNTIME_DIR / "xray.json"
ACCESS_LOG = RUNTIME_DIR / "access.log"
XRAY_BIN = os.environ.get("XRAY_EXECUTABLE_PATH", "") or shutil.which("xray") or "/usr/local/bin/xray"
API_PORT = int(os.environ.get("JINX_API_PORT", "10085") or 10085)
EARLY_DATA = "?ed=2560"
ACCESS_LOG_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_TITLE = "𝗟𝘂𝗺𝗲𝗻"


def config_title() -> str:
    return (os.environ.get("CONFIG_TITLE") or DEFAULT_TITLE).strip()[:60] or DEFAULT_TITLE


@dataclass(frozen=True)
class Slot:
    id: str
    tag: str
    protocol: str      # vless | trojan | vmess
    network: str       # ws | httpupgrade
    port: int
    prefix: str
    fingerprint: str
    name: str
    group: str         # pro | jinx
    label: str


# Same five configs as Super JinX (protocol / transport / fingerprint / path are all different).
SLOTS: tuple[Slot, ...] = (
    Slot("pro", "JX-VLESS-WS-1", "vless", "ws", 10001, "/pro/", "chrome", "𝗣𝗿𝗼", "pro", "VLESS · WS"),
    Slot("flash", "JX-VLESS-WS-2", "vless", "ws", 10002, "/stream/", "firefox", "⚡ 𝗙𝗹𝗮𝘀𝗵", "jinx", "VLESS · WS"),
    Slot("fire", "JX-TROJAN-WS", "trojan", "ws", 10003, "/live/", "safari", "🔥 𝗙𝗶𝗿𝗲", "jinx", "Trojan · WS"),
    Slot("diamond", "JX-VMESS-WS", "vmess", "ws", 10004, "/gw/", "edge", "💎 𝗗𝗶𝗮𝗺𝗼𝗻𝗱", "jinx", "VMess · WS"),
    Slot("night", "JX-VLESS-HU", "vless", "httpupgrade", 10005, "/cdn/", "ios", "🌙 𝗡𝗶𝗴𝗵𝘁", "jinx", "VLESS · HTTPUpgrade"),
)
SLOT_BY_ID = {slot.id: slot for slot in SLOTS}
SLOT_BY_TAG = {slot.tag: slot for slot in SLOTS}

PROFILES: dict[str, tuple[str, ...]] = {
    "pro": ("pro",),
    "jinx": ("flash", "fire", "diamond", "night"),
    "all": ("pro", "flash", "fire", "diamond", "night"),
}
PROFILE_LABELS = {
    "pro": "Pro · 1 config (VLESS WS + early data)",
    "jinx": "JinX · 4 configs (VLESS / Trojan / VMess / HTTPUpgrade)",
    "all": "All 5 configs",
    "custom": "Custom selection",
}
DEFAULT_PROFILE = "jinx"

PRIVATE_CIDRS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
]


# ── Per-install secret paths (genpaths.py of Super JinX) ────────────────────
def _valid_paths(value: object) -> bool:
    return isinstance(value, dict) and all(
        isinstance(value.get(slot.id), str) and value[slot.id].startswith(slot.prefix) and len(value[slot.id]) > len(slot.prefix) + 8
        for slot in SLOTS
    )


def load_paths(create: bool = True) -> dict[str, str]:
    """Return {slot_id: path}. Generated once per install and kept on the volume,
    so two installs never share paths and existing configs never break."""
    try:
        data = json.loads(PATHS_FILE.read_text(encoding="utf-8"))
        if _valid_paths(data):
            return {slot.id: data[slot.id] for slot in SLOTS}
    except (OSError, ValueError):
        pass
    if not create:
        raise RuntimeError("JinX Core paths are not generated yet")
    paths = {slot.id: slot.prefix + str(_uuid.UUID(bytes=secrets.token_bytes(16), version=4)) for slot in SLOTS}
    CORE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = PATHS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(paths, indent=1), encoding="utf-8")
    os.replace(tmp, PATHS_FILE)
    logger.info("[core] new install: unique config paths generated")
    return paths


def write_nginx_include(paths: dict[str, str] | None = None) -> Path:
    paths = paths or load_paths()
    lines = [
        f"location = {paths[slot.id]} {{ proxy_pass http://127.0.0.1:{slot.port}; include /etc/nginx/ws.inc; }}"
        for slot in SLOTS
    ]
    NGINX_INC.parent.mkdir(parents=True, exist_ok=True)
    NGINX_INC.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return NGINX_INC


# ── Link / client model ─────────────────────────────────────────────────────
def link_engine(link: dict) -> str:
    engine = str(link.get("engine") or "").lower()
    return engine if engine in {"core", "native"} else "native"


def link_slots(link: dict) -> tuple[str, ...]:
    profile = str(link.get("profile") or DEFAULT_PROFILE)
    if profile == "custom":
        wanted = [s for s in (link.get("core_slots") or []) if s in SLOT_BY_ID]
        return tuple(dict.fromkeys(wanted)) or PROFILES[DEFAULT_PROFILE]
    return PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])


def core_available() -> bool:
    """Whether the optional Xray-backed JinX data plane can actually run."""
    return ENGINE.enabled and ENGINE.binary_available() if "ENGINE" in globals() else (
        os.environ.get("JINX_CORE", "on").lower() not in {"0", "off", "false", "no"}
        and bool(XRAY_BIN)
        and os.path.isfile(XRAY_BIN)
        and os.access(XRAY_BIN, os.X_OK)
    )


def _authority(address: str, port: int) -> str:
    host = str(address or "").strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{int(port or 443)}"


def _core_endpoint(link: dict, host: str) -> tuple[str, int, str]:
    address = str(link.get("address") or host).strip() or host
    port = int(link.get("port") or 443)
    sni = str(link.get("sni") or "").strip() or host
    return address, port, sni


def _core_path(slot: Slot, paths: dict[str, str]) -> str:
    path = paths[slot.id]
    return path + EARLY_DATA if slot.network == "ws" else path


def _core_vless(uid: str, slot: Slot, link: dict, host: str, paths: dict[str, str], remark: str) -> str:
    address, port, sni = _core_endpoint(link, host)
    path = _core_path(slot, paths)
    query = {
        "encryption": "none",
        "security": "tls",
        "type": "ws" if slot.network == "ws" else "httpupgrade",
        "host": host,
        "path": path,
        "sni": sni,
        "fp": slot.fingerprint,
        "alpn": "http/1.1",
    }
    return f"vless://{uid}@{_authority(address, port)}?{urlencode(query)}#{quote(remark)}"


def _core_trojan(uid: str, slot: Slot, link: dict, host: str, paths: dict[str, str], remark: str) -> str:
    address, port, sni = _core_endpoint(link, host)
    query = {
        "security": "tls",
        "type": "ws",
        "host": host,
        "path": _core_path(slot, paths),
        "sni": sni,
        "fp": slot.fingerprint,
        "alpn": "http/1.1",
    }
    return f"trojan://{uid}@{_authority(address, port)}?{urlencode(query)}#{quote(remark)}"


def _core_vmess(uid: str, slot: Slot, link: dict, host: str, paths: dict[str, str], remark: str) -> str:
    address, port, sni = _core_endpoint(link, host)
    payload = {
        "v": "2", "ps": remark, "add": address, "port": str(port), "id": uid,
        "aid": "0", "scy": "auto", "net": "ws", "type": "none",
        "host": host, "path": _core_path(slot, paths), "tls": "tls",
        "sni": sni, "fp": slot.fingerprint,
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    return "vmess://" + __import__("base64").b64encode(raw).decode()


def core_entries_for_link(link: dict, uid: str, host: str, *, multi_location: dict | None = None) -> list[dict]:
    """Serialize the five JinX client shapes from one Lumen config.

    The visible UUID remains stable for a normal config. Multi-Location uses a
    deterministic per-location client ID internally while preserving Lumen's
    shared quota and public UUID semantics.
    """
    paths = load_paths()
    locations = [None]
    if isinstance(multi_location, dict) and multi_location.get("enabled"):
        active = [x for x in (multi_location.get("locations") or []) if x.get("active")]
        if active:
            locations = active
    result: list[dict] = []
    for location in locations:
        loc_id = str(location.get("id") or "") if location else ""
        client_id = location_client_id(uid, loc_id) if loc_id else uid
        custom = str((multi_location or {}).get("remark_text") or "") if location else ""
        if location:
            remark = f"{location.get('country', '')} {location.get('flag', '')}".strip()
            if custom:
                remark += f" | {custom[:60]}"
        else:
            remark = str(link.get("remark") or link.get("label") or "Lumen")
        for slot_id in link_slots(link):
            slot = SLOT_BY_ID[slot_id]
            if slot.protocol == "trojan":
                uri = _core_trojan(client_id, slot, link, host, paths, f"{slot.name} | {remark}")
            elif slot.protocol == "vmess":
                uri = _core_vmess(client_id, slot, link, host, paths, f"{slot.name} | {remark}")
            else:
                uri = _core_vless(client_id, slot, link, host, paths, f"{slot.name} | {remark}")
            result.append({
                "vless_link": uri,
                "remark": f"{slot.name} | {remark}",
                "slot": slot.id,
                "location": (
                    {"id": location.get("id"), "country": location.get("country"),
                     "code": location.get("code"), "flag": location.get("flag")}
                    if location else None
                ),
                "shared_quota": bool(location),
            })
    return result


def normalize_profile(profile: object, core_slots: object = None) -> tuple[str, list[str]]:
    value = str(profile or DEFAULT_PROFILE).strip().lower()
    if value not in (*PROFILES, "custom"):
        raise ValueError("profile must be pro, jinx, all or custom")
    slots: list[str] = []
    if value == "custom":
        if not isinstance(core_slots, list):
            raise ValueError("custom profile needs core_slots")
        slots = [str(s) for s in core_slots if str(s) in SLOT_BY_ID]
        slots = list(dict.fromkeys(slots))
        if not slots:
            raise ValueError("choose at least one config for the custom profile")
    return value, slots


def location_client_id(uid: str, loc_id: str) -> str:
    """A stable, secret-derived client ID per Multi-Location entry.

    Xray needs one ID per inbound client; each location gets its own derived ID
    while traffic is still accounted to the same Lumen config (shared quota)."""
    try:
        base = _uuid.UUID(uid)
    except ValueError:
        base = _uuid.uuid5(_uuid.NAMESPACE_URL, uid)
    return str(_uuid.uuid5(base, "lumen-loc:" + str(loc_id)))


def email_for(uid: str, loc_id: str | None = None) -> str:
    return f"{uid}.{loc_id}" if loc_id else uid


def uid_from_email(email: str) -> str:
    return str(email or "").split(".", 1)[0]


def outbound_tag(endpoint: str) -> str:
    return "px-" + hashlib.sha256(endpoint.encode()).hexdigest()[:12]


def proxy_outbound(endpoint: str) -> dict:
    """Xray outbound for a managed/custom HTTP, HTTPS or SOCKS5 exit proxy."""
    parsed = urlsplit(endpoint)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https", "socks5"} or not parsed.hostname or not parsed.port:
        raise ValueError("unsupported exit proxy")
    server: dict[str, Any] = {"address": parsed.hostname, "port": int(parsed.port)}
    if parsed.username:
        server["users"] = [{"user": unquote(parsed.username), "pass": unquote(parsed.password or "")}]
    out: dict[str, Any] = {
        "tag": outbound_tag(endpoint),
        "protocol": "socks" if scheme == "socks5" else "http",
        "settings": {"servers": [server]},
    }
    if scheme == "https":
        out["streamSettings"] = {"security": "tls", "tlsSettings": {"serverName": parsed.hostname}}
    return out


@dataclass
class DesiredClient:
    uid: str
    email: str
    client_id: str
    slots: tuple[str, ...]
    endpoint: str | None = None


def build_config(clients: Iterable[DesiredClient], paths: dict[str, str], *, access_log: bool = True) -> dict:
    """Pure Xray config builder (no I/O)."""
    by_slot: dict[str, list[dict]] = defaultdict(list)
    proxy_outbounds: dict[str, dict] = {}
    user_rules: dict[str, list[str]] = defaultdict(list)
    for client in sorted(clients, key=lambda c: c.email):
        for slot_id in client.slots:
            slot = SLOT_BY_ID.get(slot_id)
            if slot is None:
                continue
            if slot.protocol == "trojan":
                entry = {"password": client.client_id, "email": client.email, "level": 0}
            elif slot.protocol == "vmess":
                entry = {"id": client.client_id, "email": client.email, "level": 0, "alterId": 0}
            else:
                entry = {"id": client.client_id, "email": client.email, "level": 0}
            by_slot[slot_id].append(entry)
        if client.endpoint:
            try:
                out = proxy_outbound(client.endpoint)
            except ValueError:
                continue
            proxy_outbounds[out["tag"]] = out
            user_rules[out["tag"]].append(client.email)

    inbounds: list[dict] = [{
        "tag": "api", "listen": "127.0.0.1", "port": API_PORT, "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1"},
    }]
    for slot in SLOTS:
        stream: dict[str, Any] = {"network": slot.network, "security": "none"}
        if slot.network == "ws":
            stream["wsSettings"] = {"path": paths[slot.id]}
        else:
            stream["httpupgradeSettings"] = {"path": paths[slot.id]}
        settings: dict[str, Any] = {"clients": by_slot.get(slot.id, [])}
        if slot.protocol == "vless":
            settings["decryption"] = "none"
        inbounds.append({
            "tag": slot.tag, "listen": "127.0.0.1", "port": slot.port, "protocol": slot.protocol,
            "settings": settings, "streamSettings": stream,
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        })

    rules: list[dict] = [
        {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
        {"type": "field", "ip": list(PRIVATE_CIDRS), "outboundTag": "BLOCK"},
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCK"},
    ]
    for tag in sorted(user_rules):
        rules.append({"type": "field", "user": sorted(user_rules[tag]), "outboundTag": tag})

    log: dict[str, Any] = {"loglevel": "warning"}
    log["access"] = str(ACCESS_LOG) if access_log else "none"
    return {
        "log": log,
        "api": {"tag": "api", "services": ["HandlerService", "StatsService", "LoggerService"]},
        "stats": {},
        # system resolver first (fastest inside Railway), DoH only as a backup; Xray caches answers
        "dns": {"servers": ["localhost", "https+local://1.1.1.1/dns-query", "8.8.8.8"], "queryStrategy": "UseIPv4"},
        "policy": {
            "levels": {"0": {"handshake": 4, "connIdle": 300, "uplinkOnly": 1, "downlinkOnly": 1,
                              "bufferSize": 512, "statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True,
                       "statsOutboundUplink": True, "statsOutboundDownlink": True},
        },
        "inbounds": inbounds,
        "outbounds": [
            {"protocol": "freedom", "tag": "DIRECT", "settings": {"domainStrategy": "UseIPv4"}},
            {"protocol": "blackhole", "tag": "BLOCK"},
            *[proxy_outbounds[tag] for tag in sorted(proxy_outbounds)],
        ],
        # AsIs: route without an extra DNS lookup = one round trip less per new connection
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


def config_digest(config: dict) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def skeleton(config: dict) -> dict:
    """The config without inbound clients: if it is unchanged, users can be hot-swapped."""
    clone = json.loads(json.dumps(config))
    for inbound in clone.get("inbounds", []):
        settings = inbound.get("settings")
        if isinstance(settings, dict) and "clients" in settings:
            settings["clients"] = []
    return clone


def clients_by_tag(config: dict) -> dict[str, dict[str, dict]]:
    out: dict[str, dict[str, dict]] = {}
    for inbound in config.get("inbounds", []):
        clients = (inbound.get("settings") or {}).get("clients")
        if isinstance(clients, list):
            out[inbound["tag"]] = {c["email"]: c for c in clients}
    return out


ACCESS_RE = re.compile(
    r"from (?:tcp:|udp:)?\[?(?P<ip>[0-9a-fA-F:.]+?)\]?:\d+ accepted .*?\[(?P<tag>[^\]\s]+)\s*(?:->|>>)\s*(?P<out>[^\]\s]+)\]\s*email:\s*(?P<email>\S+)"
)


def parse_access_line(line: str) -> tuple[str, str, str] | None:
    match = ACCESS_RE.search(line)
    if not match:
        return None
    ip = match.group("ip")
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip, match.group("tag"), match.group("email")


def parse_stats(payload: str) -> dict[str, int]:
    """`xray api statsquery` JSON → {email: bytes} (uplink + downlink)."""
    try:
        data = json.loads(payload or "{}")
    except ValueError:
        return {}
    totals: dict[str, int] = defaultdict(int)
    for item in data.get("stat", []) or []:
        name = str(item.get("name") or "")
        parts = name.split(">>>")
        if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        try:
            value = int(item.get("value") or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            totals[parts[1]] += value
    return dict(totals)


# ── Runtime engine ──────────────────────────────────────────────────────────
class CoreEngine:
    """Runs and heals Xray; the panel supplies the desired client set."""

    RESTART_GAP = 3.0

    def __init__(self) -> None:
        self.process: asyncio.subprocess.Process | None = None
        self.running_config: dict | None = None
        self.running_digest = ""
        self.started_at = 0.0
        self.restarts = 0
        self.hot_updates = 0
        self.last_error = ""
        self.last_restart = 0.0
        self.last_stats_ok = 0.0
        self.peers: dict[str, dict[str, dict]] = defaultdict(dict)  # uid -> ip -> {last, first, tag}
        self.banned_until: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self._log_pos = 0
        self.enabled = os.environ.get("JINX_CORE", "on").lower() not in {"0", "off", "false", "no"}

    # availability --------------------------------------------------------
    def binary_available(self) -> bool:
        return bool(XRAY_BIN) and os.path.isfile(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK)

    def alive(self) -> bool:
        return self.process is not None and self.process.returncode is None

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "binary": self.binary_available(),
            "running": self.alive(),
            "pid": self.process.pid if self.alive() and self.process else None,
            "uptime_s": int(time.time() - self.started_at) if self.alive() else 0,
            "restarts": self.restarts,
            "hot_updates": self.hot_updates,
            "last_error": self.last_error,
            "stats_ok": bool(self.last_stats_ok and time.time() - self.last_stats_ok < 60),
            "clients": sum(len(v) for v in clients_by_tag(self.running_config or {}).values()),
            "slots": [{"id": s.id, "name": s.name, "label": s.label, "group": s.group, "fingerprint": s.fingerprint} for s in SLOTS],
            "banned": len([u for u, t in self.banned_until.items() if t > time.time()]),
        }

    # process control -----------------------------------------------------
    async def _spawn(self, config: dict) -> None:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CONFIG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, CONFIG_FILE)
        env = dict(os.environ)
        env.setdefault("XRAY_LOCATION_ASSET", os.environ.get("XRAY_ASSETS_PATH", "/usr/local/share/xray"))
        self.process = await asyncio.create_subprocess_exec(
            XRAY_BIN, "run", "-c", str(CONFIG_FILE),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE, env=env,
        )
        self.started_at = time.time()
        self.running_config = config
        self.running_digest = config_digest(config)
        asyncio.create_task(self._drain_stderr(self.process))
        await asyncio.sleep(0.4)
        if not self.alive():
            self.last_error = "xray exited right after start (check the config / binary)"
            raise RuntimeError(self.last_error)

    async def _drain_stderr(self, proc: asyncio.subprocess.Process) -> None:
        if proc.stderr is None:
            return
        with contextlib.suppress(Exception):
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                text = line.decode(errors="replace").strip()
                if text:
                    logger.info("[xray] %s", text[:400])
                    if "failed" in text.lower() or "error" in text.lower():
                        self.last_error = text[:300]

    async def stop(self) -> None:
        proc, self.process = self.process, None
        if proc is None or proc.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), 5)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()

    async def restart(self, config: dict, reason: str) -> None:
        wait = self.RESTART_GAP - (time.time() - self.last_restart)
        if wait > 0:
            await asyncio.sleep(wait)
        await self.stop()
        self.last_restart = time.time()
        self.restarts += 1
        logger.info("[doctor] core (re)start: %s", reason)
        await self._spawn(config)

    async def _api(self, *args: str, timeout: float = 8.0) -> tuple[int, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                XRAY_BIN, "api", *args, f"--server=127.0.0.1:{API_PORT}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
            return proc.returncode or 0, (out or b"").decode(errors="replace") or (err or b"").decode(errors="replace")
        except (OSError, asyncio.TimeoutError) as exc:
            return 1, str(exc)

    # reconcile -----------------------------------------------------------
    async def apply(self, config: dict) -> str:
        """Make the running core equal to ``config``. Returns what was done."""
        async with self._lock:
            digest = config_digest(config)
            if self.alive() and digest == self.running_digest:
                return "unchanged"
            if not self.alive() or self.running_config is None or skeleton(config) != skeleton(self.running_config):
                await self.restart(config, "configuration changed" if self.alive() else "core not running")
                return "restarted"
            old, new = clients_by_tag(self.running_config), clients_by_tag(config)
            ok = True
            for tag, wanted in new.items():
                current = old.get(tag, {})
                removed = [e for e in current if e not in wanted or current[e] != wanted[e]]
                added = [wanted[e] for e in wanted if e not in current or current[e] != wanted[e]]
                if removed:
                    code, _ = await self._api("rmu", f"-tag={tag}", *removed)
                    ok = ok and code == 0
                if added and ok:
                    payload = {"inbounds": [next(dict(i, settings={**i["settings"], "clients": added})
                                                 for i in config["inbounds"] if i["tag"] == tag)]}
                    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
                    patch = RUNTIME_DIR / f"adu-{tag}.json"
                    patch.write_text(json.dumps(payload), encoding="utf-8")
                    code, _ = await self._api("adu", str(patch))
                    ok = ok and code == 0
                if not ok:
                    break
            if not ok:
                await self.restart(config, "hot user update failed")
                return "restarted"
            self.running_config = config
            self.running_digest = digest
            # keep the on-disk copy identical so a crash-restart uses the same users
            with contextlib.suppress(OSError):
                CONFIG_FILE.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
            self.hot_updates += 1
            return "hot-updated"

    async def query_traffic(self) -> dict[str, int]:
        if not self.alive():
            return {}
        code, out = await self._api("statsquery", "-pattern", "user>>>", "-reset")
        if code != 0:
            return {}
        self.last_stats_ok = time.time()
        return parse_stats(out)

    async def healthy(self) -> bool:
        if not self.alive():
            return False
        code, _ = await self._api("statsquery", "-pattern", "inbound>>>api", timeout=5)
        if code == 0:
            self.last_stats_ok = time.time()
        return code == 0

    # access log → live peers / IP limits ----------------------------------
    def read_access_log(self) -> None:
        try:
            size = ACCESS_LOG.stat().st_size
        except OSError:
            return
        if size < self._log_pos:
            self._log_pos = 0
        try:
            with ACCESS_LOG.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._log_pos)
                chunk = handle.read(2 * 1024 * 1024)
                self._log_pos = handle.tell()
        except OSError:
            return
        now = time.time()
        for line in chunk.splitlines():
            parsed = parse_access_line(line)
            if not parsed:
                continue
            ip, tag, email = parsed
            uid = uid_from_email(email)
            peer = self.peers[uid].get(ip)
            if peer is None:
                self.peers[uid][ip] = {"first": now, "last": now, "tag": tag, "count": 1}
            else:
                peer["last"] = now
                peer["tag"] = tag
                peer["count"] = int(peer.get("count", 0)) + 1
        if size > ACCESS_LOG_MAX_BYTES:
            with contextlib.suppress(OSError):
                os.truncate(ACCESS_LOG, 0)
            self._log_pos = 0

    def prune_peers(self, window: float = 120.0) -> None:
        cutoff = time.time() - window
        for uid in list(self.peers):
            for ip in list(self.peers[uid]):
                if self.peers[uid][ip]["last"] < cutoff:
                    del self.peers[uid][ip]
            if not self.peers[uid]:
                del self.peers[uid]

    def live_ips(self, uid: str, window: float = 90.0) -> set[str]:
        cutoff = time.time() - window
        return {ip for ip, info in self.peers.get(uid, {}).items() if info["last"] >= cutoff}

    def is_banned(self, uid: str) -> bool:
        until = self.banned_until.get(uid, 0)
        if until and until < time.time():
            self.banned_until.pop(uid, None)
            return False
        return bool(until)

    def ban(self, uid: str, seconds: float = 180.0) -> None:
        self.banned_until[uid] = time.time() + seconds
        self.peers.pop(uid, None)


ENGINE = CoreEngine()


async def desired_clients(
    links: dict[str, dict],
    is_allowed: Callable[[dict], bool],
    multi_location_for_link: Callable[[dict], tuple[Any, Any]],
    resolve_exit: Callable[[dict, str], Any],
) -> list[DesiredClient]:
    """Turn the panel state into Xray clients (fails closed on any exit error)."""
    result: list[DesiredClient] = []
    for uid, link in links.items():
        if link_engine(link) != "core" or not is_allowed(link) or ENGINE.is_banned(uid):
            continue
        slots = link_slots(link)
        _sub, ml = multi_location_for_link(link)
        if ml is not None:
            for loc in [l for l in (ml.get("locations") or []) if l.get("active")]:
                try:
                    selection = await resolve_exit(link, str(loc.get("id") or ""))
                except Exception:
                    continue  # never fall back to direct for a location route
                if not selection:
                    continue
                result.append(DesiredClient(uid, email_for(uid, loc.get("id")), location_client_id(uid, loc.get("id")),
                                            slots, selection.get("endpoint")))
            continue
        endpoint = None
        if str(link.get("exit_proxy_mode") or "direct") != "direct":
            try:
                selection = await resolve_exit(link, "")
            except Exception:
                continue  # selected exit is unavailable → the config stays closed
            endpoint = (selection or {}).get("endpoint")
            if not endpoint:
                continue
        result.append(DesiredClient(uid, email_for(uid), uid, slots, endpoint))
    return result


def cli() -> None:
    """`python jinx_core.py paths` — run by the entrypoint before nginx starts."""
    import sys
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    command = sys.argv[1] if len(sys.argv) > 1 else "paths"
    if command == "paths":
        write_nginx_include(load_paths())
        print("[core] config paths ready")
    else:
        raise SystemExit("usage: python jinx_core.py paths")


if __name__ == "__main__":
    cli()
