#!/usr/bin/env python3
"""
Indeed Job Notifier — Tk UI, 5 parallel role workers, shared rotating proxy
───────────────────────────────────────────────────────────────────────────
A desktop app (stdlib Tkinter, no extra deps) that watches Indeed searches
and notifies when a new posting appears.

Design
    • Filters are edited in the UI and persisted to config.json:
        roles          – one search phrase per line (one worker per role)
        region         – US remote  |  worldwide remote
        easy apply     – Easy Apply only  |  all postings
        job types      – full-time / part-time / contract (checkboxes)
    • One worker thread per role, all scraping in parallel — the worker
      count follows the number of roles rather than a fixed ceiling.
    • All workers share ONE proxy at a time (SharedProxy). When any worker
      hits a captcha / bot challenge, the proxy is rotated once, globally,
      and every worker rebuilds its browser onto the new one.
    • Headless by default — a challenge cannot be solved by hand, so it is
      treated as a proxy failure and triggers rotation instead.
    • seen_jobs.json maps job-id -> first-seen timestamp, so duplicates are
      impossible and pruning actually drops the OLDEST entries.
    • safe_proxies.json remembers every proxy that actually returned job
      cards. On a block the next proxy is taken from that safe list first,
      and only once it is exhausted does discovery take over.
    • New jobs are posted to Mattermost as one message per cycle, titled
      "Indeed New Jobs" (webhook read from .env).

Usage
    python indeed_notifier.py            # launch the UI
    python indeed_notifier.py --nogui    # headless watch loop, saved config
    python indeed_notifier.py --nogui --once
    python indeed_notifier.py --nogui --reseed
    python indeed_notifier.py --checkip  # show egress IP, test Indeed

Dependencies
    pip install playwright requests && playwright install chromium
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlencode, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── Paths & constants ─────────────────────────────────────────────────────────

HERE = Path(__file__).resolve().parent
STATE_FILE = HERE / "seen_jobs.json"
CONFIG_FILE = HERE / "config.json"
SAFE_LIST_FILE = HERE / "safe_proxies.json"
ENV_FILE = HERE / ".env"

STATE_CAP = 5000              # keep the newest N job ids
WORKER_ADVISORY = 10          # log a heads-up past this many concurrent browsers

NAV_TIMEOUT = 30_000          # ms — a dead free proxy should be discarded fast
RESULT_WAIT = 25              # s to wait for job cards to render
FEED_DELAY = (2, 5)           # random pause between a worker's retries
CAPTCHA_RETRIES = 8           # proxy rotations to try before failing a role
                              # (most free proxies are dead or challenged, so be generous)
CYCLE_TIMEOUT = 900           # s before a cycle gives up on stuck workers

ALERT_AFTER_FAILURES = 3
STALE_AFTER_HOURS = 6

# ── Proxy configuration ───────────────────────────────────────────────────────

PROXY_POOL_SIZE = 25
PROXY_VALIDATE_TIMEOUT = 8
PROXY_COOLDOWN_SECONDS = 900
PROXY_REFILL_BATCH = 120
PROXY_REFILL_INTERVAL = 90
PROXY_WARMUP_WAIT = 180       # s to wait for a first proxy before polling

# Measured against the live lists: of 250 candidates each, 0/250 free HTTP
# proxies could reach indeed.com over TLS, while 98/250 SOCKS5 relays opened
# a CONNECT to indeed.com:443. So the validation batch is weighted heavily
# toward SOCKS5 — testing HTTP proxies is nearly all wasted time.
SOCKS5_BATCH_SHARE = 0.8

# Safe list: proxies that have actually returned Indeed job cards. These are
# tried before anything from the freshly-scraped pool, and get a shorter
# cooldown after a failure because they are proven rather than speculative.
SAFE_COOLDOWN_SECONDS = 300
SAFE_LIST_CAP = 50
SAFE_EVICT_MARGIN = 10        # drop once failures exceed successes by this much

PROXY_LIST_URLS = [
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=protocolipport&format=text",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&proxy_format=protocolipport&format=text",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://api.openproxylist.xyz/http.txt",
]

# Sources that publish bare "ip:port" but are actually SOCKS5, so the scheme
# has to be supplied by us rather than guessed as http://.
SOCKS5_BARE_SOURCES = {
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
}

_HOSTPORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})$")
_BAD_HOSTS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}

# Notification channels
SLACK_WEBHOOK_URL = None
DISCORD_WEBHOOK_URL = None
MACOS_NOTIFY = True
EMAIL_CONFIG = None

# ── .env ──────────────────────────────────────────────────────────────────────

def load_env(path: Path = ENV_FILE) -> None:
    """Minimal KEY=VALUE loader — avoids a python-dotenv dependency.

    Real environment variables always win, so an operator can override a
    checked-in .env without editing it.
    """
    if not path.exists():
        return
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    except OSError as exc:
        print(f"[WARN] could not read {path.name}: {exc}", file=sys.stderr)


load_env()


# ── Safe proxy list ───────────────────────────────────────────────────────────

class SafeList:
    """Proxies proven to return Indeed job cards, persisted across restarts.

    A proxy is promoted here only after a scrape actually succeeded through
    it — never merely for passing validation, which says nothing about
    whether Indeed will serve it.
    """

    def __init__(self, path: Path = SAFE_LIST_FILE):
        self.path = path
        self._lock = threading.Lock()
        self.entries: dict[str, dict] = {}
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            log.error("%s unreadable (%s) — starting with an empty safe list.",
                      self.path.name, exc)
            return
        if not isinstance(raw, dict):
            return
        for server, stats in raw.items():
            if not isinstance(stats, dict):
                continue
            self.entries[str(server)] = {
                "successes": int(stats.get("successes", 0)),
                "failures": int(stats.get("failures", 0)),
                "last_success": float(stats.get("last_success", 0)),
                "last_failure": float(stats.get("last_failure", 0)),
            }
        if self.entries:
            log.info("Safe list: %d proven proxy/proxies loaded.", len(self.entries))

    def _save_locked(self) -> None:
        try:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.entries, indent=2, sort_keys=True))
            tmp.replace(self.path)
        except OSError as exc:
            log.error("Could not write %s: %s", self.path.name, exc)

    def record_success(self, server: str) -> None:
        with self._lock:
            entry = self.entries.setdefault(
                server, {"successes": 0, "failures": 0, "last_success": 0.0, "last_failure": 0.0})
            first_time = entry["successes"] == 0
            entry["successes"] += 1
            entry["last_success"] = time.time()
            if first_time:
                log.info("Safe list + %s (proven working).", server)
            self._prune_locked()
            self._save_locked()

    def record_failure(self, server: str) -> None:
        with self._lock:
            entry = self.entries.get(server)
            if not entry:
                return
            entry["failures"] += 1
            entry["last_failure"] = time.time()
            if entry["failures"] - entry["successes"] > SAFE_EVICT_MARGIN:
                del self.entries[server]
                log.info("Safe list − %s (stopped working).", server)
            self._save_locked()

    @staticmethod
    def _score(entry: dict) -> tuple:
        return (entry["successes"] - entry["failures"], entry["last_success"])

    def _prune_locked(self) -> None:
        if len(self.entries) <= SAFE_LIST_CAP:
            return
        best = sorted(self.entries.items(), key=lambda kv: self._score(kv[1]),
                      reverse=True)[:SAFE_LIST_CAP]
        self.entries = dict(best)

    def candidates(self, now: float, blocked: set[str]) -> list[str]:
        """Proven proxies, best first, skipping ones inside their cooldown."""
        with self._lock:
            ready = [
                (server, entry) for server, entry in self.entries.items()
                if server not in blocked
                and now - entry["last_failure"] > SAFE_COOLDOWN_SECONDS
            ]
        ready.sort(key=lambda kv: self._score(kv[1]), reverse=True)
        return [server for server, _ in ready]

    def __len__(self) -> int:
        with self._lock:
            return len(self.entries)


# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("indeed_notifier")


class QueueLogHandler(logging.Handler):
    """Ships formatted records to the UI thread through a queue."""

    def __init__(self, sink: queue.Queue):
        super().__init__()
        self.sink = sink
        self.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S"))

    def emit(self, record):
        try:
            self.sink.put_nowait((record.levelno, self.format(record)))
        except Exception:
            pass


# ── Configuration ─────────────────────────────────────────────────────────────

REGION_US = "us_remote"
REGION_WORLDWIDE = "worldwide_remote"

JOB_TYPES = ("fulltime", "parttime", "contract")
JOB_TYPE_LABELS = {"fulltime": "Full-time", "parttime": "Part-time", "contract": "Contract"}

# Titles that are clearly not individual-contributor software/AI engineering.
# Matched on whole words, so "manager" will not fire inside "management".
DEFAULT_TITLE_EXCLUDE = [
    # leadership / non-IC
    "manager", "director", "vp", "vice president", "head of", "chief",
    "product owner", "scrum master", "agile coach", "consultant",
    # adjacent-but-not-engineering
    "analyst", "quality assurance", "qa", "support engineer", "product builder",
    "sales", "account executive", "recruiter", "instructor", "teacher",
    "intern", "internship",
    # enterprise / legacy stacks that match on seniority alone
    "solutions architect", "services architect", "enterprise architect",
    "salesforce", "sap", "ibmi", "sharepoint", "servicenow", "workday",
]

DEFAULT_ROLES = [
    "Senior AI Engineer GenAI",
    "Senior Full Stack Engineer",
    "Senior Software Engineer AI",
    "Staff Software Engineer",
    "LLM Agentic Engineer",
]


@dataclass
class Config:
    roles: list[str] = field(default_factory=lambda: list(DEFAULT_ROLES))
    region: str = REGION_US
    easy_apply_only: bool = False
    job_types: list[str] = field(default_factory=lambda: ["fulltime"])
    # Indeed pads a thin result page with loosely-related postings, so the
    # title is filtered here as well. Include = title must contain at least
    # one of these (empty means "no constraint"); exclude always wins.
    title_include: list[str] = field(default_factory=list)
    title_exclude: list[str] = field(default_factory=lambda: list(DEFAULT_TITLE_EXCLUDE))
    fromage: int = 7               # only postings from the last N days
    poll_interval: int = 600       # seconds between cycles
    poll_jitter: float = 0.2
    headless: bool = True
    use_proxy: bool = True

    @classmethod
    def load(cls) -> "Config":
        if not CONFIG_FILE.exists():
            return cls()
        try:
            raw = json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            log.error("config.json unreadable (%s) — using defaults.", exc)
            return cls()
        cfg = cls()
        for key, value in raw.items():
            if hasattr(cfg, key):
                setattr(cfg, key, value)
        cfg.normalise()
        return cfg

    def save(self) -> None:
        self.normalise()
        tmp = CONFIG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2))
        tmp.replace(CONFIG_FILE)

    def normalise(self) -> None:
        self.roles = [r.strip() for r in self.roles if r and r.strip()]
        if not self.roles:
            self.roles = list(DEFAULT_ROLES[:1])
        if self.region not in (REGION_US, REGION_WORLDWIDE):
            self.region = REGION_US
        self.job_types = [t for t in self.job_types if t in JOB_TYPES]
        self.title_include = [t.strip() for t in self.title_include if t and t.strip()]
        self.title_exclude = [t.strip() for t in self.title_exclude if t and t.strip()]
        self.fromage = max(1, min(int(self.fromage), 30))
        self.poll_interval = max(60, int(self.poll_interval))

    @property
    def job_type_set(self) -> set[str]:
        return set(self.job_types)


# ── Shared proxy ──────────────────────────────────────────────────────────────

class SharedProxy:
    """The single proxy every worker uses, plus coordinated rotation.

    Workers compare their local generation against `generation`. When a
    worker hits a captcha it calls `rotate(gen)`; only the first caller for
    a given generation actually rotates, so five simultaneous challenges
    burn one proxy, not five.
    """

    def __init__(self, manager: "ProxyManager"):
        self._manager = manager
        self._lock = threading.Lock()
        self._current: dict | None = None
        self._generation = 0

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def current(self) -> tuple[dict | None, int]:
        """Return (proxy, generation), acquiring one if we have none yet."""
        with self._lock:
            if self._current is None and self._manager.enabled:
                self._current = self._manager.get_proxy()
                if self._current:
                    self._generation += 1
                    log.info("Proxy in use: %s", self._current["server"])
            return self._current, self._generation

    def rotate(self, seen_generation: int, reason: str = "captcha") -> tuple[dict | None, int]:
        """Swap the proxy if nobody else already did for this generation."""
        with self._lock:
            if seen_generation != self._generation:
                return self._current, self._generation      # somebody beat us to it
            if self._current:
                self._manager.mark_failed(self._current["server"])
                log.warning("Rotating away from %s (%s).", self._current["server"], reason)
            self._current = self._manager.get_proxy() if self._manager.enabled else None
            self._generation += 1
            if self._current:
                log.info("Proxy in use: %s", self._current["server"])
            else:
                log.warning("No proxy available — falling back to a direct connection.")
            return self._current, self._generation

    def mark_success(self) -> None:
        with self._lock:
            if self._current:
                self._manager.mark_success(self._current["server"])

    def describe(self) -> str:
        with self._lock:
            return self._current["server"] if self._current else "direct"


# ── Proxy manager ─────────────────────────────────────────────────────────────

class ProxyManager:
    """Fetches, validates and hands out free HTTP/SOCKS5 proxies."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.pool: list[dict] = []
        self.failures: dict[str, float] = {}
        self.safe = SafeList()
        self._lock = threading.Lock()
        self._refill_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._first_proxy = threading.Event()
        self._session = self._create_session()

        if self.enabled:
            self._start_refill_thread()
        else:
            log.info("Proxy rotation disabled — using a direct connection.")

    # -- lifecycle ------------------------------------------------------------

    @staticmethod
    def _create_session() -> requests.Session:
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _start_refill_thread(self) -> None:
        if self._refill_thread and self._refill_thread.is_alive():
            return
        self._stop.clear()
        self._refill_thread = threading.Thread(target=self._refill_loop, daemon=True)
        self._refill_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._refill_thread:
            self._refill_thread.join(timeout=3)

    def wait_for_proxy(self, timeout: float = PROXY_WARMUP_WAIT) -> bool:
        """Block until the pool actually holds a proxy (or timeout)."""
        if not self.enabled:
            return False
        if self.pool_size():
            return True
        log.info("Warming up the proxy pool (up to %ds)…", int(timeout))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self._stop.is_set():
            if self._first_proxy.wait(min(2.0, max(0.1, deadline - time.monotonic()))):
                if self.pool_size():
                    return True
            if self.pool_size():
                return True
        return False

    def pool_size(self) -> int:
        with self._lock:
            return len(self.pool)

    # -- refill ---------------------------------------------------------------

    def _refill_loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self.pool_size() >= PROXY_POOL_SIZE:
                    self._sleep(PROXY_REFILL_INTERVAL)
                    continue

                candidates = self._fetch_candidates()
                if not candidates:
                    log.debug("No proxy candidates fetched.")
                    self._sleep(PROXY_REFILL_INTERVAL)
                    continue

                verified = self._validate_batch(self._compose_batch(candidates))

                if verified:
                    with self._lock:
                        known = {p["server"] for p in self.pool}
                        for p in verified:
                            if len(self.pool) >= PROXY_POOL_SIZE:
                                break
                            if p["server"] not in known:
                                self.pool.append(p)
                                known.add(p["server"])
                        size = len(self.pool)
                    log.info("Proxy pool: %d working proxies.", size)
                    if size:
                        self._first_proxy.set()
                else:
                    log.debug("No proxies validated this cycle.")

                self._sleep(PROXY_REFILL_INTERVAL)
            except Exception as exc:
                log.error("Proxy refill error: %s", exc)
                self._sleep(30)

    def _sleep(self, seconds: float) -> None:
        self._stop.wait(seconds)

    def _fetch_candidates(self) -> list[str]:
        """Return unique proxy URLs, preserving each source's real scheme."""
        seen: set[str] = set()
        candidates: list[str] = []
        for url in PROXY_LIST_URLS:
            default_scheme = "socks5" if url in SOCKS5_BARE_SOURCES else "http"
            try:
                resp = self._session.get(url, timeout=15)
                if resp.status_code != 200:
                    continue
                for line in resp.text.splitlines():
                    proxy = self._normalise(line, default_scheme)
                    if proxy and proxy not in seen:
                        seen.add(proxy)
                        candidates.append(proxy)
            except Exception as exc:
                log.debug("Failed to fetch %s: %s", url, exc)
        return candidates

    @staticmethod
    def _normalise(line: str, default_scheme: str) -> str | None:
        """`1.2.3.4:8080` / `socks5://1.2.3.4:1080` -> a canonical proxy URL."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        scheme = default_scheme
        if "://" in line:
            scheme, _, line = line.partition("://")
            scheme = scheme.lower()
            if scheme in ("socks5h", "socks4"):
                scheme = "socks5"
            if scheme not in ("http", "https", "socks5"):
                return None
        m = _HOSTPORT_RE.match(line)
        if not m:
            return None
        host, port = m.group(1), int(m.group(2))
        if host in _BAD_HOSTS or not (0 < port < 65536):
            return None
        return f"{scheme}://{host}:{port}"

    @staticmethod
    def _compose_batch(candidates: list[str]) -> list[str]:
        """Weight the batch toward SOCKS5 — see SOCKS5_BATCH_SHARE."""
        socks = [c for c in candidates if c.startswith("socks5")]
        http = [c for c in candidates if not c.startswith("socks5")]
        random.shuffle(socks)
        random.shuffle(http)
        if socks:
            want_socks = int(PROXY_REFILL_BATCH * SOCKS5_BATCH_SHARE)
            batch = socks[:want_socks] + http[:PROXY_REFILL_BATCH - want_socks]
        else:
            batch = http[:PROXY_REFILL_BATCH]
        random.shuffle(batch)
        return batch

    # -- validation -----------------------------------------------------------

    def _validate_batch(self, proxies: list[str]) -> list[dict]:
        validated: list[dict] = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._validate_one, p): p for p in proxies}
            for future in as_completed(futures):
                if self._stop.is_set():
                    break
                try:
                    result = future.result()
                except Exception:
                    continue
                if result:
                    validated.append(result)
        return validated

    def _validate_one(self, proxy_url: str) -> dict | None:
        scheme = urlparse(proxy_url).scheme
        ok = self._validate_socks5(proxy_url) if scheme == "socks5" else self._validate_http(proxy_url)
        return {"server": proxy_url} if ok else None

    @staticmethod
    def _validate_http(proxy_url: str) -> bool:
        """A CONNECT-capable proxy must be able to reach Indeed over TLS."""
        try:
            resp = requests.get(
                "https://www.indeed.com/robots.txt",
                proxies={"http": proxy_url, "https": proxy_url},
                timeout=PROXY_VALIDATE_TIMEOUT,
                headers={"User-Agent": UA},
                allow_redirects=True,
            )
            return resp.status_code < 400 and "indeed" in resp.text.lower()[:2000]
        except Exception:
            return False

    @staticmethod
    def _validate_socks5(proxy_url: str) -> bool:
        """Speak enough SOCKS5 to prove the relay can open indeed.com:443.

        `requests` cannot use SOCKS without PySocks, but Playwright accepts
        socks5:// directly — so the handshake is done here with stdlib
        sockets rather than dropping these sources on the floor.
        """
        parsed = urlparse(proxy_url)
        host, port = parsed.hostname, parsed.port
        if not host or not port:
            return False
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=PROXY_VALIDATE_TIMEOUT)
            sock.settimeout(PROXY_VALIDATE_TIMEOUT)

            sock.sendall(b"\x05\x01\x00")                    # greet: no auth
            greeting = sock.recv(2)
            if len(greeting) != 2 or greeting[0] != 0x05 or greeting[1] != 0x00:
                return False

            target = b"www.indeed.com"
            request = b"\x05\x01\x00\x03" + bytes([len(target)]) + target + struct.pack("!H", 443)
            sock.sendall(request)                            # CONNECT by hostname
            reply = sock.recv(4)
            return len(reply) >= 2 and reply[0] == 0x05 and reply[1] == 0x00
        except Exception:
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    # -- hand-out -------------------------------------------------------------

    def get_proxy(self) -> dict | None:
        """Proven proxies first, then whatever the refill thread discovered."""
        if not self.enabled:
            return None
        with self._lock:
            now = time.time()
            self.failures = {s: t for s, t in self.failures.items()
                             if now - t <= PROXY_COOLDOWN_SECONDS}
            blocked = set(self.failures)

            # 1. the safe list — proxies that really did return job cards
            for server in self.safe.candidates(now, blocked):
                log.info("Trying safe-list proxy %s", server)
                return {"server": server}

            # 2. fall back to the freshly-validated pool
            self.pool = [p for p in self.pool if p["server"] not in blocked]
            if not self.pool:
                return None
            proxy = self.pool.pop(0)
            self.pool.append(proxy)                          # round-robin
            return dict(proxy)

    def mark_failed(self, proxy_url: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.failures[proxy_url] = time.time()
            self.pool = [p for p in self.pool if p["server"] != proxy_url]
            if not self.pool:
                self._first_proxy.clear()
        self.safe.record_failure(proxy_url)

    def mark_success(self, proxy_url: str) -> None:
        """Called only after a scrape really returned job cards."""
        if not self.enabled:
            return
        with self._lock:
            self.failures.pop(proxy_url, None)
        self.safe.record_success(proxy_url)

    def safe_size(self) -> int:
        return len(self.safe)


# ── Model ─────────────────────────────────────────────────────────────────────

@dataclass
class Job:
    guid: str
    search: str
    title: str
    company: str
    location: str
    link: str
    posted: str = ""
    salary: str = ""
    snippet: str = ""
    easy_apply: bool = False
    job_types: set[str] = field(default_factory=set)


class SourceError(Exception):
    pass


class SourceBlocked(SourceError):
    """A bot challenge — with no human to solve it, rotate the proxy."""


# ── Scraping ──────────────────────────────────────────────────────────────────

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")

BASE_URL = "https://www.indeed.com/jobs"
REMOTE_ATTR = "DSQF7"            # Indeed's "Remote" job attribute

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_MOSAIC_RE = re.compile(
    r'window\.mosaic\.providerData\["mosaic-provider-jobcards"\]\s*=\s*(\{.*?\});',
    re.S,
)
_CHALLENGE_TITLES = ("just a moment", "security check", "blocked",
                     "additional verification", "attention required", "access denied")
_CHALLENGE_MARKERS = ("challenge-platform", "cf-challenge", "hcaptcha.com",
                      "g-recaptcha", "px-captcha", "_Incapsula_")

_JOB_TYPE_ALIASES = {
    "full-time": "fulltime", "fulltime": "fulltime", "full time": "fulltime",
    "part-time": "parttime", "parttime": "parttime", "part time": "parttime",
    "contract": "contract", "contractor": "contract",
}


def _clean(html: str, limit: int = 300) -> str:
    text = _WS_RE.sub(" ", _TAG_RE.sub(" ", html or "")).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _is_challenge(html: str, title: str) -> bool:
    if any(t in (title or "").lower() for t in _CHALLENGE_TITLES):
        return True
    return any(marker in html for marker in _CHALLENGE_MARKERS)


def _normalise_job_types(values) -> set[str]:
    out = set()
    for value in values or ():
        key = str(value).strip().lower()
        if key in _JOB_TYPE_ALIASES:
            out.add(_JOB_TYPE_ALIASES[key])
    return out


def build_url(cfg: Config, role: str) -> str:
    """Push what Indeed enforces server-side into the URL.

    Region and a *single* job type map onto real query filters. Multiple job
    types have no reliable URL form, so those are filtered client-side in
    `passes_filters` instead.
    """
    params: dict[str, object] = {"q": role, "sort": "date", "fromage": cfg.fromage}
    params["l"] = "United States" if cfg.region == REGION_US else ""

    sc_bits = [f"attr({REMOTE_ATTR})"]
    if len(cfg.job_types) == 1:
        sc_bits.append(f"jt({cfg.job_types[0]})")
    params["sc"] = "0kf:" + "".join(sc_bits) + ";"
    return f"{BASE_URL}?{urlencode(params)}"


_TERM_SPLIT_RE = re.compile(r"[,\n]")
_NON_WORD_RE = re.compile(r"[^a-z0-9]+")


def parse_terms(text: str) -> list[str]:
    """Split a filter box on commas or newlines, dropping blanks."""
    return [t.strip() for t in _TERM_SPLIT_RE.split(text or "") if t.strip()]


def _normalise_title(text: str) -> str:
    """Lowercase, collapse punctuation to spaces, pad with spaces.

    The padding is what makes a plain substring test whole-word-safe, and
    folding punctuation means 'full stack' also matches 'Full-Stack' and
    'Full/Stack' — variants Indeed uses interchangeably.
    """
    return " " + _NON_WORD_RE.sub(" ", (text or "").lower()).strip() + " "


def title_matches(title: str, terms: list[str]) -> str | None:
    """Return the first term present in `title` as a whole word, else None."""
    haystack = _normalise_title(title)
    for term in terms:
        needle = _normalise_title(term)
        if needle.strip() and needle in haystack:
            return term.strip()
    return None


def passes_filters(job: Job, cfg: Config) -> bool:
    if cfg.easy_apply_only and not job.easy_apply:
        return False

    hit = title_matches(job.title, cfg.title_exclude)
    if hit:
        log.debug("dropped '%s' — title excludes %r", job.title, hit)
        return False
    if cfg.title_include and not title_matches(job.title, cfg.title_include):
        log.debug("dropped '%s' — title matches no include term", job.title)
        return False
    wanted = cfg.job_type_set
    # Only reject when Indeed actually told us the type — many cards omit it,
    # and dropping those would hide most of the feed.
    if wanted and job.job_types and not (job.job_types & wanted):
        return False
    return True


class IndeedWorker(threading.Thread):
    """Owns one browser, scrapes one role per task, shares the global proxy."""

    def __init__(self, index: int, shared: SharedProxy, cfg: Config,
                 tasks: queue.Queue, results: queue.Queue, stop_event: threading.Event):
        super().__init__(daemon=True, name=f"worker-{index}")
        self.index = index
        self.shared = shared
        self.cfg = cfg
        self.tasks = tasks
        self.results = results
        self.stop_event = stop_event
        self._pw = None
        self._browser = None
        self._ctx = None
        self._page = None
        self._generation = -1

    # -- browser --------------------------------------------------------------

    def _ensure_browser(self):
        proxy, generation = self.shared.current()

        if self._page is not None and not self._page.is_closed() and generation == self._generation:
            return self._page
        if self._page is not None:
            self.close()                                  # proxy changed underneath us

        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        try:
            launch_opts: dict = {
                "channel": "chrome",
                "headless": self.cfg.headless,
                "args": ["--disable-blink-features=AutomationControlled"],
            }
            if proxy:
                launch_opts["proxy"] = {"server": proxy["server"]}
            self._browser = self._pw.chromium.launch(**launch_opts)
            self._ctx = self._browser.new_context(
                user_agent=UA,
                viewport={"width": 1440, "height": 950},
                locale="en-US",
            )
            self._ctx.set_default_navigation_timeout(NAV_TIMEOUT)
            self._page = self._ctx.new_page()
        except Exception:
            self.close()
            raise

        self._generation = generation
        return self._page

    def close(self) -> None:
        for closer in (getattr(self._ctx, "close", None),
                       getattr(self._browser, "close", None),
                       getattr(self._pw, "stop", None)):
            try:
                if closer:
                    closer()
            except Exception:
                pass
        self._pw = self._browser = self._ctx = self._page = None
        self._generation = -1

    # -- main loop ------------------------------------------------------------

    def run(self) -> None:
        try:
            while not self.stop_event.is_set():
                try:
                    role = self.tasks.get(timeout=0.5)
                except queue.Empty:
                    continue
                if role is None:                          # shutdown sentinel
                    self.tasks.task_done()
                    break
                try:
                    jobs = self._scrape_with_rotation(role)
                    self.results.put(("ok", role, jobs))
                except SourceBlocked as exc:
                    self.results.put(("blocked", role, str(exc)))
                except SourceError as exc:
                    self.results.put(("error", role, str(exc)))
                except Exception as exc:
                    log.debug("worker %d unexpected: %s", self.index, exc)
                    self.results.put(("error", role, f"unexpected: {exc}"))
                finally:
                    self.tasks.task_done()
        finally:
            self.close()

    def _scrape_with_rotation(self, role: str) -> list[Job]:
        """Scrape one role, rotating the shared proxy on each challenge."""
        last_error = "no attempt made"
        for attempt in range(1, CAPTCHA_RETRIES + 1):
            if self.stop_event.is_set():
                raise SourceError("stopped")
            generation = self.shared.generation      # what this attempt runs against
            try:
                jobs = self._scrape(role)
                self.shared.mark_success()
                return jobs
            except SourceBlocked as exc:
                last_error = str(exc)
                log.warning("'%s': %s (attempt %d/%d)", role, exc, attempt, CAPTCHA_RETRIES)
                self.shared.rotate(generation, reason="captcha")
                self.close()
                if attempt < CAPTCHA_RETRIES:
                    time.sleep(random.uniform(*FEED_DELAY))
            except SourceError as exc:
                last_error = str(exc)
                log.debug("'%s': %s (attempt %d/%d)", role, exc, attempt, CAPTCHA_RETRIES)
                # A navigation failure is usually the proxy dying, too.
                self.shared.rotate(generation, reason="navigation failure")
                self.close()
                if attempt < CAPTCHA_RETRIES:
                    time.sleep(random.uniform(*FEED_DELAY))
        raise SourceBlocked(f"gave up after {CAPTCHA_RETRIES} proxies: {last_error}")

    def _scrape(self, role: str) -> list[Job]:
        try:
            page = self._ensure_browser()
        except Exception as exc:
            raise SourceError(f"browser launch failed: {exc}") from exc
        url = build_url(self.cfg, role)
        try:
            page.goto(url, wait_until="domcontentloaded")
        except Exception as exc:
            raise SourceError(f"navigation failed: {exc}") from exc

        html = self._wait_for_results(page, role)
        jobs = self._parse_mosaic(html, role) or self._parse_dom(page, role)
        return jobs

    def _wait_for_results(self, page, label: str) -> str:
        deadline = time.monotonic() + RESULT_WAIT
        while True:
            try:
                html = page.content()
                title = page.title() or ""
            except Exception:
                if time.monotonic() > deadline:
                    raise SourceError(f"'{label}': page never settled")
                time.sleep(1)
                continue

            if "data-jk=" in html or "mosaic-provider-jobcards" in html:
                return html
            if _is_challenge(html, title):
                raise SourceBlocked(f"'{label}': bot challenge")
            if time.monotonic() > deadline:
                raise SourceError(f"'{label}': no job cards rendered")
            time.sleep(1.5)

    def _parse_mosaic(self, html: str, label: str) -> list[Job]:
        m = _MOSAIC_RE.search(html)
        if not m:
            return []
        try:
            blob = json.loads(m.group(1))
            results = (blob.get("metaData", {})
                       .get("mosaicProviderJobCardsModel", {})
                       .get("results")) or []
        except Exception as exc:
            log.debug("mosaic parse failed for '%s': %s", label, exc)
            return []

        jobs = []
        for r in results:
            key = r.get("jobkey")
            if not key:
                continue

            salary = (r.get("salarySnippet") or {}).get("text", "")
            if not salary and r.get("extractedSalary"):
                es = r["extractedSalary"]
                lo, hi, unit = es.get("min"), es.get("max"), (es.get("type") or "").lower()
                if lo and hi:
                    salary = f"${lo:,.0f}-${hi:,.0f} {unit}".strip()

            remote = (r.get("remoteWorkModel") or {}).get("text", "")
            location = r.get("formattedLocation", "")
            if remote and remote.lower() not in location.lower():
                location = f"{location} · {remote}".strip(" ·")

            jobs.append(Job(
                guid=key,
                search=label,
                title=r.get("displayTitle") or r.get("title") or "Unknown title",
                company=r.get("truncatedCompany") or r.get("company") or "Unknown company",
                location=location,
                link=f"https://www.indeed.com/viewjob?jk={key}",
                posted=r.get("formattedRelativeTime", ""),
                salary=salary,
                snippet=_clean(r.get("snippet", "")),
                easy_apply=bool(r.get("indeedApplyable")),
                job_types=self._extract_job_types(r),
            ))
        return jobs

    @staticmethod
    def _extract_job_types(result: dict) -> set[str]:
        found = _normalise_job_types(result.get("jobTypes") or ())
        for group in result.get("taxonomyAttributes") or ():
            if (group.get("label") or "").lower() in ("job-types", "job types", "jobtype"):
                found |= _normalise_job_types(
                    a.get("label") for a in (group.get("attributes") or ())
                )
        return found

    def _parse_dom(self, page, label: str) -> list[Job]:
        try:
            raw = page.evaluate(
                """() => [...document.querySelectorAll('[data-jk]')].map(el => {
                    const t = s => el.querySelector(s)?.innerText?.trim() || '';
                    return {
                        jk: el.getAttribute('data-jk'),
                        title: t('h2.jobTitle span[title]') || t('h2.jobTitle'),
                        company: t('[data-testid="company-name"]'),
                        location: t('[data-testid="text-location"]'),
                        salary: t('[data-testid="attribute_snippet_testid"]'),
                        meta: el.innerText || '',
                    };
                })"""
            ) or []
        except Exception as exc:
            log.debug("DOM parse failed for '%s': %s", label, exc)
            return []

        if raw:
            log.warning("'%s': JSON blob missing — used the DOM fallback.", label)
        jobs = []
        for r in raw:
            if not r.get("jk"):
                continue
            meta = (r.get("meta") or "").lower()
            jobs.append(Job(
                guid=r["jk"], search=label,
                title=r.get("title") or "Unknown title",
                company=r.get("company") or "Unknown company",
                location=r.get("location", ""),
                link=f"https://www.indeed.com/viewjob?jk={r['jk']}",
                salary=r.get("salary", ""),
                easy_apply="easily apply" in meta,
                job_types={v for k, v in _JOB_TYPE_ALIASES.items() if k in meta},
            ))
        return jobs


# ── State ─────────────────────────────────────────────────────────────────────

def load_state() -> tuple[dict[str, float], bool, float]:
    """Return (guid -> first-seen epoch, seeded, last_success)."""
    if not STATE_FILE.exists():
        return {}, False, 0.0
    try:
        raw = json.loads(STATE_FILE.read_text())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError, ValueError) as exc:
        log.error("State file unreadable (%s) — starting fresh.", exc)
        return {}, False, 0.0

    now = time.time()
    if isinstance(raw, list):                                   # legacy: bare list
        log.info("Migrating legacy state file (%d keys).", len(raw))
        return {g: now for g in raw}, True, 0.0
    if isinstance(raw, dict) and "guids" in raw:                # legacy: {"guids": [...]}
        guids = raw.get("guids") or []
        log.info("Migrating state file (%d keys).", len(guids))
        return ({g: now for g in guids},
                bool(raw.get("seeded")),
                float(raw.get("last_success", 0)))

    jobs = raw.get("jobs") or {}
    seen = {str(g): float(t) for g, t in jobs.items()}
    return seen, bool(raw.get("seeded")), float(raw.get("last_success", 0))


def save_state(seen: dict[str, float], seeded: bool, last_success: float) -> None:
    """Persist state, dropping the OLDEST ids once over STATE_CAP."""
    if len(seen) > STATE_CAP:
        newest = sorted(seen.items(), key=lambda kv: kv[1], reverse=True)[:STATE_CAP]
        seen.clear()
        seen.update(newest)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(
        {"seeded": seeded, "last_success": last_success, "jobs": seen}, indent=2
    ))
    tmp.replace(STATE_FILE)


# ── Notifications ─────────────────────────────────────────────────────────────

def notify_console(job: Job) -> None:
    line = "─" * 68
    print(f"\n{line}")
    print(f"  🆕  NEW JOB  ·  {job.search}")
    print(f"  Title   : {job.title}")
    print(f"  Company : {job.company}")
    if job.location:
        print(f"  Location: {job.location}")
    if job.salary:
        print(f"  Salary  : {job.salary}")
    if job.posted:
        print(f"  Posted  : {job.posted}")
    if job.easy_apply:
        print("  Apply   : Indeed Apply ✅")
    print(f"  Link    : {job.link}")
    if job.snippet:
        print(f"  Snippet : {job.snippet}")
    print(line)


def notify_macos(title: str, body: str) -> None:
    if not MACOS_NOTIFY or sys.platform != "darwin":
        return
    esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
    try:
        subprocess.run(
            ["osascript", "-e",
             f'display notification "{esc(body)}" with title "{esc(title)}"'],
            check=False, capture_output=True, timeout=10,
        )
    except Exception as exc:
        log.debug("macOS notification failed: %s", exc)


def _post(url: str, payload: dict, what: str) -> None:
    try:
        requests.post(url, json=payload, timeout=10).raise_for_status()
    except Exception as exc:
        log.error("%s notification failed: %s", what, exc)


def notify_slack(text: str) -> None:
    if SLACK_WEBHOOK_URL:
        _post(SLACK_WEBHOOK_URL,
              {"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]},
              "Slack")


def notify_discord(text: str) -> None:
    if DISCORD_WEBHOOK_URL:
        _post(DISCORD_WEBHOOK_URL, {"content": text}, "Discord")


def notify_email(subject: str, body: str) -> None:
    if not EMAIL_CONFIG:
        return
    import smtplib
    from email.mime.text import MIMEText
    cfg = EMAIL_CONFIG
    msg = MIMEText(body)
    msg["Subject"], msg["From"], msg["To"] = subject, cfg["sender"], cfg["recipient"]
    try:
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=20) as s:
            s.starttls()
            s.login(cfg["sender"], cfg["password"])
            s.sendmail(cfg["sender"], cfg["recipient"], msg.as_string())
    except Exception as exc:
        log.error("Email notification failed: %s", exc)


MATTERMOST_TITLE = "Indeed New Jobs"
MATTERMOST_BATCH = 20            # attachments per post; Mattermost rejects huge payloads


def _mattermost_verify() -> object:
    """CA bundle for the webhook host, or plain verification if unset.

    The Mattermost host may sit behind an internal CA (e.g. Caddy's local
    authority) that certifi does not carry. Pointing at a bundle keeps TLS
    verified instead of switching it off.
    """
    bundle = os.getenv("MATTERMOST_CA_BUNDLE", "").strip()
    if not bundle:
        return True
    path = Path(bundle)
    if not path.is_absolute():
        path = HERE / path
    if path.exists():
        return str(path)
    log.warning("MATTERMOST_CA_BUNDLE %s not found — using default CA roots.", path)
    return True


def notify_mattermost(jobs: list[Job]) -> None:
    """Post a cycle's new jobs to Mattermost as one titled message."""
    url = os.getenv("MATTERMOST_WEBHOOK_URL")
    if not url or not jobs:
        return
    verify = _mattermost_verify()

    for start in range(0, len(jobs), MATTERMOST_BATCH):
        chunk = jobs[start:start + MATTERMOST_BATCH]
        part = ""
        if len(jobs) > MATTERMOST_BATCH:
            part = f" ({start // MATTERMOST_BATCH + 1}/{(len(jobs) - 1) // MATTERMOST_BATCH + 1})"

        attachments = []
        for job in chunk:
            fields = []
            if job.location:
                fields.append({"short": True, "title": "Location", "value": job.location})
            if job.salary:
                fields.append({"short": True, "title": "Salary", "value": job.salary})
            if job.posted:
                fields.append({"short": True, "title": "Posted", "value": job.posted})
            types = ", ".join(sorted(JOB_TYPE_LABELS.get(t, t) for t in job.job_types))
            if job.easy_apply:
                types = (types + " · Easy Apply").strip(" ·")
            if types:
                fields.append({"short": True, "title": "Type", "value": types})
            attachments.append({
                "color": "#2557a7",
                "title": f"{job.title} — {job.company}",
                "title_link": job.link,
                "text": job.snippet,
                "footer": job.search,
                "fields": fields,
            })

        payload = {
            "username": MATTERMOST_TITLE,
            "text": f"#### {MATTERMOST_TITLE}{part}\n**{len(jobs)}** new posting(s)",
            "attachments": attachments,
        }
        try:
            resp = requests.post(url, json=payload, timeout=15, verify=verify)
            resp.raise_for_status()
        except Exception as exc:
            log.error("Mattermost notification failed: %s", exc)
            return
    log.info("Posted %d job(s) to Mattermost as '%s'.", len(jobs), MATTERMOST_TITLE)


def dispatch(job: Job, console: bool = True) -> None:
    if console:
        notify_console(job)
    bits = " · ".join(x for x in (job.company, job.location, job.salary) if x)
    notify_slack(f"*🆕 {job.search}*\n*<{job.link}|{job.title}>*\n{bits}")
    notify_discord(f"**🆕 {job.search}**\n**{job.title}**\n{bits}\n🔗 {job.link}")
    notify_macos(f"🆕 {job.title}", bits or job.company)
    notify_email(f"[Indeed] {job.title} @ {job.company}",
                 f"{job.search}\n\n{job.title}\n{bits}\n{job.link}\n\n{job.snippet}")


def alert(subject: str, body: str) -> None:
    log.error("%s — %s", subject, body)
    notify_slack(f"*⚠️ {subject}*\n{body}")
    notify_discord(f"**⚠️ {subject}**\n{body}")
    notify_macos(f"⚠️ {subject}", body)
    notify_email(f"[Indeed Notifier] {subject}", body)


# ── Controller ────────────────────────────────────────────────────────────────

class Controller:
    """Runs poll cycles: fan roles out to workers, merge, diff, persist."""

    def __init__(self, cfg: Config, on_job=None, on_status=None):
        self.cfg = cfg
        self.on_job = on_job                    # callback(Job) for the UI table
        self.on_status = on_status              # callback(dict) for the status bar
        self.stop_event = threading.Event()
        self.proxy_manager = ProxyManager(enabled=cfg.use_proxy)
        self.shared = SharedProxy(self.proxy_manager)
        self.tasks: queue.Queue = queue.Queue()
        self.results: queue.Queue = queue.Queue()
        self.workers: list[IndeedWorker] = []
        self.seen: dict[str, float] = {}
        self.seeded = False
        self.last_success = 0.0
        self._thread: threading.Thread | None = None

    # -- lifecycle ------------------------------------------------------------

    def start(self, once: bool = False, reseed: bool = False) -> None:
        self._thread = threading.Thread(
            target=self._run, args=(once, reseed), daemon=True, name="controller")
        self._thread.start()

    def stop(self, timeout: float = 20.0) -> None:
        self.stop_event.set()
        for _ in self.workers:
            self.tasks.put(None)
        if self._thread:
            self._thread.join(timeout=timeout)
        self.proxy_manager.stop()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _spawn_workers(self, count: int) -> None:
        for i in range(count):
            worker = IndeedWorker(i, self.shared, self.cfg,
                                  self.tasks, self.results, self.stop_event)
            worker.start()
            self.workers.append(worker)

    def _status(self, **kw) -> None:
        if self.on_status:
            payload = {
                "proxy": self.shared.describe(),
                "pool": self.proxy_manager.pool_size(),
                "safe": self.proxy_manager.safe_size(),
                "seen": len(self.seen),
            }
            payload.update(kw)
            try:
                self.on_status(payload)
            except Exception:
                pass

    # -- main loop ------------------------------------------------------------

    def _run(self, once: bool, reseed: bool) -> None:
        self.seen, self.seeded, self.last_success = load_state()
        if reseed:
            self.seen, self.seeded = {}, False
            log.info("--reseed: discarding previous state.")

        roles = self.cfg.roles
        self._spawn_workers(len(roles))
        if len(roles) > WORKER_ADVISORY:
            log.warning("%d roles means %d concurrent browsers — expect heavy "
                        "memory use and more contention on the shared proxy.",
                        len(roles), len(roles))
        log.info("%d worker(s) for %d role(s); one shared proxy; headless=%s.",
                 len(self.workers), len(roles), self.cfg.headless)
        log.info("Known jobs: %d. Cycle every ~%ds.", len(self.seen), self.cfg.poll_interval)

        if self.cfg.use_proxy:
            if not self.proxy_manager.wait_for_proxy():
                log.warning("No proxy validated in time — starting on a direct connection.")
            self.shared.current()               # pin a proxy before the first cycle

        consecutive_failures = 0
        alerted_stale = False

        try:
            while not self.stop_event.is_set():
                announce = self.seeded
                if not self.seeded:
                    log.info("First run — seeding state, no alerts will fire.")

                log.info("Polling %d role(s)…", len(roles))
                self._status(state="polling")
                new_jobs, ok, failed = self._cycle(roles, announce)

                if ok:
                    self.last_success = time.time()
                    consecutive_failures = 0
                    alerted_stale = False
                    if not self.seeded:
                        self.seeded = True
                        log.info("Seeded %d listing(s). Now watching for new ones…", len(self.seen))
                    elif new_jobs:
                        log.info("✅ %d new job(s).", len(new_jobs))
                    else:
                        log.info("No new jobs.")
                    save_state(self.seen, self.seeded, self.last_success)
                else:
                    consecutive_failures += 1
                    log.error("All %d role(s) failed (%d cycle(s) in a row).",
                              failed, consecutive_failures)
                    if consecutive_failures == ALERT_AFTER_FAILURES:
                        alert("Indeed notifier is not fetching",
                              f"All roles failed {consecutive_failures} cycles in a row. "
                              "Free proxies may all be blocked — try --no-proxy or new sources.")

                if self.last_success and not alerted_stale:
                    hours = (time.time() - self.last_success) / 3600
                    if hours >= STALE_AFTER_HOURS:
                        alerted_stale = True
                        alert("Indeed notifier has gone stale",
                              f"No successful fetch in {hours:.1f}h.")

                if once or self.stop_event.is_set():
                    break

                backoff = 1 + min(consecutive_failures, 5)
                delay = (self.cfg.poll_interval * backoff *
                         random.uniform(1 - self.cfg.poll_jitter, 1 + self.cfg.poll_jitter))
                log.info("Next cycle in %ds.", int(delay))
                self._status(state=f"sleeping {int(delay)}s")
                self.stop_event.wait(delay)
        except Exception as exc:
            log.exception("Controller crashed: %s", exc)
        finally:
            save_state(self.seen, self.seeded, self.last_success)
            self.stop_event.set()
            for _ in self.workers:
                self.tasks.put(None)
            for worker in self.workers:
                worker.join(timeout=15)
            self.workers.clear()
            self.proxy_manager.stop()
            log.info("Stopped. %d job(s) tracked.", len(self.seen))
            self._status(state="stopped")

    def _cycle(self, roles: list[str], announce: bool) -> tuple[list[Job], int, int]:
        """One pass: every role scraped in parallel on the same proxy."""
        for role in roles:
            self.tasks.put(role)

        new_jobs: list[Job] = []
        ok = failed = 0
        now = time.time()
        # Guard against a worker thread dying and leaving the cycle waiting
        # on a result that will never arrive.
        deadline = time.monotonic() + CYCLE_TIMEOUT

        for _ in roles:
            while True:
                if self.stop_event.is_set():
                    return new_jobs, ok, failed
                if time.monotonic() > deadline:
                    missing = len(roles) - ok - failed
                    log.error("Cycle timed out with %d role(s) unfinished.", missing)
                    return new_jobs, ok, failed + missing
                try:
                    status, role, payload = self.results.get(timeout=1)
                    break
                except queue.Empty:
                    continue

            if status != "ok":
                failed += 1
                log.error("  %-32s %s: %s", role, status.upper(), payload)
                continue

            ok += 1
            jobs = [j for j in payload if passes_filters(j, self.cfg)]
            fresh = 0
            for job in jobs:
                if job.guid in self.seen:            # dedup against known ids
                    continue
                self.seen[job.guid] = now
                new_jobs.append(job)
                fresh += 1
                if announce:
                    dispatch(job, console=not self.on_job)
                    if self.on_job:
                        self.on_job(job)
                elif self.on_job:
                    self.on_job(job)
            log.info("  %-32s %2d listed / %2d after filters / %2d new",
                     role, len(payload), len(jobs), fresh)

        if announce and new_jobs:
            notify_mattermost(new_jobs)

        self._status(state="idle", new=len(new_jobs))
        return new_jobs, ok, failed


# ── Tk UI ─────────────────────────────────────────────────────────────────────

def launch_ui() -> None:
    import tkinter as tk
    from tkinter import ttk, messagebox

    cfg = Config.load()
    log_queue: queue.Queue = queue.Queue()
    ui_queue: queue.Queue = queue.Queue()
    logging.getLogger().addHandler(QueueLogHandler(log_queue))

    root = tk.Tk()
    root.title("Indeed Job Notifier")
    root.geometry("1080x760")
    root.minsize(920, 620)

    state = {"controller": None}

    # -- filters panel --------------------------------------------------------

    outer = ttk.Frame(root, padding=10)
    outer.pack(fill="both", expand=True)

    filters = ttk.LabelFrame(outer, text="Filters", padding=10)
    filters.pack(fill="x")

    top = ttk.Frame(filters)
    top.pack(fill="x")

    left = ttk.Frame(top)
    left.pack(side="left", fill="both", expand=True)
    ttk.Label(left, text="Roles (one per line — each gets its own worker and browser)"
              ).pack(anchor="w")
    roles_text = tk.Text(left, height=6, width=44, wrap="none",
                         font=("Menlo", 11), relief="solid", borderwidth=1)
    roles_text.pack(fill="both", expand=True, pady=(4, 0))
    roles_text.insert("1.0", "\n".join(cfg.roles))

    right = ttk.Frame(top)
    right.pack(side="left", fill="y", padx=(16, 0))

    region_var = tk.StringVar(value=cfg.region)
    ttk.Label(right, text="Region").grid(row=0, column=0, sticky="w", pady=(0, 2))
    ttk.Radiobutton(right, text="US remote", value=REGION_US,
                    variable=region_var).grid(row=1, column=0, sticky="w")
    ttk.Radiobutton(right, text="Worldwide remote", value=REGION_WORLDWIDE,
                    variable=region_var).grid(row=2, column=0, sticky="w")

    easy_var = tk.StringVar(value="easy" if cfg.easy_apply_only else "all")
    ttk.Label(right, text="Application").grid(row=0, column=1, sticky="w", padx=(24, 0), pady=(0, 2))
    ttk.Radiobutton(right, text="All postings", value="all",
                    variable=easy_var).grid(row=1, column=1, sticky="w", padx=(24, 0))
    ttk.Radiobutton(right, text="Easy Apply only", value="easy",
                    variable=easy_var).grid(row=2, column=1, sticky="w", padx=(24, 0))

    ttk.Label(right, text="Job type").grid(row=3, column=0, sticky="w", pady=(10, 2))
    jt_vars = {t: tk.BooleanVar(value=t in cfg.job_types) for t in JOB_TYPES}
    jt_row = ttk.Frame(right)
    jt_row.grid(row=4, column=0, columnspan=2, sticky="w")
    for t in JOB_TYPES:
        ttk.Checkbutton(jt_row, text=JOB_TYPE_LABELS[t], variable=jt_vars[t]).pack(side="left", padx=(0, 12))

    opts = ttk.Frame(right)
    opts.grid(row=5, column=0, columnspan=2, sticky="w", pady=(12, 0))
    ttk.Label(opts, text="Posted within (days)").pack(side="left")
    fromage_var = tk.StringVar(value=str(cfg.fromage))
    ttk.Spinbox(opts, from_=1, to=30, width=4, textvariable=fromage_var).pack(side="left", padx=(6, 18))
    ttk.Label(opts, text="Every (sec)").pack(side="left")
    interval_var = tk.StringVar(value=str(cfg.poll_interval))
    ttk.Spinbox(opts, from_=60, to=86400, increment=60, width=7,
                textvariable=interval_var).pack(side="left", padx=(6, 0))

    toggles = ttk.Frame(right)
    toggles.grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 0))
    headless_var = tk.BooleanVar(value=cfg.headless)
    proxy_var = tk.BooleanVar(value=cfg.use_proxy)
    ttk.Checkbutton(toggles, text="Headless", variable=headless_var).pack(side="left", padx=(0, 12))
    ttk.Checkbutton(toggles, text="Rotate free proxies", variable=proxy_var).pack(side="left")

    # -- title filters --------------------------------------------------------

    titles = ttk.Frame(filters)
    titles.pack(fill="x", pady=(12, 0))
    titles.columnconfigure(0, weight=1)
    titles.columnconfigure(1, weight=1)

    def make_term_box(column: int, heading: str, hint: str, initial: list[str]):
        """A multi-line term editor with a live count of parsed terms."""
        frame = ttk.Frame(titles)
        frame.grid(row=0, column=column, sticky="nsew", padx=(0, 10) if column == 0 else (10, 0))
        header = ttk.Frame(frame)
        header.pack(fill="x")
        ttk.Label(header, text=heading).pack(side="left")
        count = ttk.Label(header, text="", foreground="#777")
        count.pack(side="right")
        ttk.Label(frame, text=hint, foreground="#777").pack(anchor="w")

        wrap = ttk.Frame(frame)
        wrap.pack(fill="both", expand=True, pady=(4, 0))
        box = tk.Text(wrap, height=4, wrap="word", font=("Menlo", 10),
                      relief="solid", borderwidth=1)
        bar = ttk.Scrollbar(wrap, orient="vertical", command=box.yview)
        box.configure(yscrollcommand=bar.set)
        box.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y")
        box.insert("1.0", ", ".join(initial))

        def refresh(_event=None):
            n = len(parse_terms(box.get("1.0", "end")))
            count.configure(text="no terms — allows everything" if not n
                            else f"{n} term{'s' if n != 1 else ''}")
        box.bind("<KeyRelease>", refresh)
        refresh()
        return box

    include_box = make_term_box(
        0, "Title must include",
        "Any one of these must appear. Leave empty to allow every title.",
        cfg.title_include)
    exclude_box = make_term_box(
        1, "Title must NOT include",
        "Any match is dropped. Wins over the include list.",
        cfg.title_exclude)

    # -- controls -------------------------------------------------------------

    controls = ttk.Frame(outer)
    controls.pack(fill="x", pady=(10, 6))
    start_btn = ttk.Button(controls, text="▶  Start")
    stop_btn = ttk.Button(controls, text="■  Stop", state="disabled")
    save_btn = ttk.Button(controls, text="Save filters")
    reseed_var = tk.BooleanVar(value=False)
    start_btn.pack(side="left")
    stop_btn.pack(side="left", padx=(8, 0))
    save_btn.pack(side="left", padx=(8, 0))
    ttk.Checkbutton(controls, text="Re-seed (no alerts on first cycle)",
                    variable=reseed_var).pack(side="left", padx=(16, 0))

    status_var = tk.StringVar(value="idle")
    ttk.Label(controls, textvariable=status_var, foreground="#555").pack(side="right")

    # -- results + log --------------------------------------------------------

    panes = ttk.PanedWindow(outer, orient="vertical")
    panes.pack(fill="both", expand=True)

    results_frame = ttk.LabelFrame(panes, text="New jobs (double-click to open)", padding=6)
    columns = ("title", "company", "location", "salary", "type", "posted", "role")
    tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=10)
    widths = {"title": 300, "company": 170, "location": 160, "salary": 140,
              "type": 90, "posted": 90, "role": 170}
    for col in columns:
        tree.heading(col, text=col.title())
        tree.column(col, width=widths[col], anchor="w")
    vsb = ttk.Scrollbar(results_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side="left", fill="both", expand=True)
    vsb.pack(side="right", fill="y")
    panes.add(results_frame, weight=3)

    log_frame = ttk.LabelFrame(panes, text="Log", padding=6)
    log_text = tk.Text(log_frame, height=10, wrap="word", font=("Menlo", 10),
                       relief="solid", borderwidth=1, state="disabled")
    log_sb = ttk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
    log_text.configure(yscrollcommand=log_sb.set)
    log_text.pack(side="left", fill="both", expand=True)
    log_sb.pack(side="right", fill="y")
    log_text.tag_configure("WARNING", foreground="#b26b00")
    log_text.tag_configure("ERROR", foreground="#c0392b")
    panes.add(log_frame, weight=2)

    links: dict[str, str] = {}

    def open_selected(_event=None):
        for item in tree.selection():
            url = links.get(item)
            if url:
                webbrowser.open(url)

    tree.bind("<Double-1>", open_selected)
    tree.bind("<Return>", open_selected)

    # -- config <-> widgets ---------------------------------------------------

    def collect_config() -> Config | None:
        roles = [r.strip() for r in roles_text.get("1.0", "end").splitlines() if r.strip()]
        if not roles:
            messagebox.showwarning("No roles", "Add at least one role to search for.")
            return None
        if len(roles) > WORKER_ADVISORY and not messagebox.askokcancel(
                "That is a lot of workers",
                f"{len(roles)} roles will launch {len(roles)} browsers at once, "
                "all sharing one proxy.\n\nStart anyway?"):
            return None

        selected_types = [t for t in JOB_TYPES if jt_vars[t].get()]
        try:
            fromage = int(fromage_var.get())
            interval = int(interval_var.get())
        except ValueError:
            messagebox.showwarning("Invalid number", "Days and interval must be whole numbers.")
            return None

        new_cfg = Config(
            roles=roles,
            region=region_var.get(),
            easy_apply_only=easy_var.get() == "easy",
            job_types=selected_types,
            title_include=parse_terms(include_box.get("1.0", "end")),
            title_exclude=parse_terms(exclude_box.get("1.0", "end")),
            fromage=fromage,
            poll_interval=interval,
            headless=headless_var.get(),
            use_proxy=proxy_var.get(),
        )
        new_cfg.normalise()
        return new_cfg

    def set_filters_state(enabled: bool) -> None:
        widget_state = "normal" if enabled else "disabled"
        for box in (roles_text, include_box, exclude_box):
            box.configure(state=widget_state)
        for frame in (right, jt_row, opts, toggles):
            for child in frame.winfo_children():
                try:
                    child.configure(state=widget_state)
                except tk.TclError:
                    pass

    def do_save(show: bool = True) -> Config | None:
        new_cfg = collect_config()
        if not new_cfg:
            return None
        new_cfg.save()
        if show:
            log.info("Filters saved to %s", CONFIG_FILE.name)
        return new_cfg

    # -- start / stop ---------------------------------------------------------

    def add_job_row(job: Job) -> None:
        ui_queue.put(("job", job))

    def push_status(payload: dict) -> None:
        ui_queue.put(("status", payload))

    def do_start() -> None:
        new_cfg = do_save(show=False)
        if not new_cfg:
            return
        for item in tree.get_children():
            tree.delete(item)
        links.clear()

        controller = Controller(new_cfg, on_job=add_job_row, on_status=push_status)
        state["controller"] = controller
        controller.start(reseed=reseed_var.get())
        reseed_var.set(False)
        start_btn.configure(state="disabled")
        stop_btn.configure(state="normal")
        set_filters_state(False)
        status_var.set("starting…")

    def do_stop() -> None:
        controller = state.get("controller")
        if not controller:
            return
        status_var.set("stopping…")
        stop_btn.configure(state="disabled")

        def worker():
            controller.stop()
            ui_queue.put(("stopped", None))

        threading.Thread(target=worker, daemon=True).start()

    start_btn.configure(command=do_start)
    stop_btn.configure(command=do_stop)
    save_btn.configure(command=lambda: do_save(show=True))

    # -- pumps ----------------------------------------------------------------

    def drain() -> None:
        drained = 0
        while drained < 200:
            try:
                level, line = log_queue.get_nowait()
            except queue.Empty:
                break
            drained += 1
            tag = "ERROR" if level >= logging.ERROR else ("WARNING" if level >= logging.WARNING else "")
            log_text.configure(state="normal")
            log_text.insert("end", line + "\n", tag)
            if float(log_text.index("end-1c").split(".")[0]) > 800:
                log_text.delete("1.0", "200.0")
            log_text.configure(state="disabled")
            log_text.see("end")

        while True:
            try:
                kind, payload = ui_queue.get_nowait()
            except queue.Empty:
                break
            if kind == "job":
                job = payload
                types = ", ".join(sorted(JOB_TYPE_LABELS.get(t, t) for t in job.job_types))
                if job.easy_apply:
                    types = (types + " · Easy").strip(" ·")
                item = tree.insert("", 0, values=(
                    job.title, job.company, job.location, job.salary,
                    types, job.posted, job.search))
                links[item] = job.link
            elif kind == "status":
                status_var.set(
                    "{state} · proxy {proxy} · safe {safe} · pool {pool} · tracked {seen}".format(
                        state=payload.get("state", "—"),
                        proxy=payload.get("proxy", "—"),
                        safe=payload.get("safe", 0),
                        pool=payload.get("pool", 0),
                        seen=payload.get("seen", 0)))
            elif kind == "stopped":
                state["controller"] = None
                start_btn.configure(state="normal")
                stop_btn.configure(state="disabled")
                set_filters_state(True)
                status_var.set("idle")

        controller = state.get("controller")
        if controller and not controller.is_running() and stop_btn.instate(["!disabled"]):
            ui_queue.put(("stopped", None))

        root.after(200, drain)

    def on_close() -> None:
        controller = state.get("controller")
        if controller and controller.is_running():
            if not messagebox.askokcancel("Quit", "A watch is running. Stop it and quit?"):
                return
            controller.stop(timeout=10)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(200, drain)
    log.info("Ready. Edit your filters, then press Start.")
    root.mainloop()


# ── CLI ───────────────────────────────────────────────────────────────────────

def run_headless(once: bool, reseed: bool, no_proxy: bool) -> None:
    cfg = Config.load()
    if no_proxy:
        cfg.use_proxy = False
    controller = Controller(cfg)
    controller.start(once=once, reseed=reseed)
    try:
        while controller.is_running():
            time.sleep(0.5)
    except KeyboardInterrupt:
        log.info("Stopping…")
        controller.stop()


def check_ip() -> None:
    """Report the egress IP for the current proxy and test Indeed."""
    from playwright.sync_api import sync_playwright

    manager = ProxyManager(enabled=True)
    try:
        manager.wait_for_proxy()
        proxy = manager.get_proxy()
        print("\n  proxy     : {}".format(proxy["server"] if proxy else "none (direct)"))

        pw = sync_playwright().start()
        launch_opts = {"channel": "chrome", "headless": True}
        if proxy:
            launch_opts["proxy"] = {"server": proxy["server"]}
        browser = pw.chromium.launch(**launch_opts)
        page = browser.new_context(user_agent=UA).new_page()
        page.set_default_navigation_timeout(NAV_TIMEOUT)
        try:
            info = {}
            for url in ("https://ipinfo.io/json", "https://api.ipify.org?format=json"):
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=20000)
                    text = page.inner_text("pre") if page.query_selector("pre") else page.inner_text("body")
                    info = json.loads(text)
                    if info.get("ip"):
                        break
                except Exception:
                    continue

            print("  egress IP : {}".format(info.get("ip") or "could not determine"))
            print("  org/ASN   : {}".format(info.get("org") or "could not determine"))
            if info.get("city") or info.get("country"):
                print("  location  : {}, {}".format(info.get("city", "?"), info.get("country", "?")))

            print("\n  testing indeed.com …")
            t0 = time.monotonic()
            page.goto("https://www.indeed.com/jobs?q=engineer&l=Remote",
                      wait_until="domcontentloaded")
            html, title = page.content(), page.title() or ""
            if "data-jk=" in html or "mosaic-provider-jobcards" in html:
                print("  ✅ job cards rendered in {:.0f}s".format(time.monotonic() - t0))
            elif _is_challenge(html, title):
                print("  ❌ bot challenge — this proxy would be rotated away")
            else:
                print("  ⚠️  no job cards rendered")
        finally:
            browser.close()
            pw.stop()
    finally:
        manager.stop()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Watch Indeed searches — UI, 5 workers, shared rotating proxy.")
    ap.add_argument("--nogui", action="store_true", help="run the watch loop without the UI")
    ap.add_argument("--once", action="store_true", help="one cycle, then exit (implies --nogui)")
    ap.add_argument("--reseed", action="store_true", help="discard state and re-seed silently")
    ap.add_argument("--no-proxy", action="store_true", help="disable proxy rotation")
    ap.add_argument("--checkip", action="store_true", help="show the current egress IP and test Indeed")
    args = ap.parse_args()

    if args.checkip:
        check_ip()
    elif args.nogui or args.once:
        run_headless(once=args.once, reseed=args.reseed, no_proxy=args.no_proxy)
    else:
        launch_ui()
