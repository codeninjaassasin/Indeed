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
    • seen_jobs.json maps job-id -> first-seen timestamp AND role@company ->
      first-seen, so a job repeats neither by id nor as the same role at the
      same company (reposts / different ids collapse); pruning drops the OLDEST.
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
SESSION_FILE = HERE / "indeed_session.json"   # persisted Indeed login cookies
WIREPROXY_BIN = HERE / "wireproxy"            # optional: Surfshark WireGuard proxy binary
WIREPROXY_CONF_DIR = HERE / "vpn"             # directory of *.conf wireproxy files

# Read-only fork of the sibling project's proven proxy list. Never written.
SIBLING_PROXY_FILE = HERE.parent / "Auto Email Scraper" / "autoemail" / "data" / "proxies.json"

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
# When all workers fail due to proxy blocks, wait this long before the next
# attempt — much shorter than the normal poll interval so we keep trying.
FAILURE_RETRY_SECONDS = 30

# ── Proxy configuration ───────────────────────────────────────────────────────

PROXY_POOL_SIZE = 50
PROXY_VALIDATE_TIMEOUT = 8
PROXY_COOLDOWN_SECONDS = 120  # retry a failed free-list proxy after 2 min
PROXY_REFILL_BATCH = 120
PROXY_REFILL_INTERVAL = 90
PROXY_WARMUP_WAIT = 30        # sibling proxies load instantly; short warmup

# Stage-2 content validation: a proxy that passes the cheap TCP handshake is
# then asked to actually render Indeed job cards in a real browser. Only IPs
# Indeed *serves* (not merely reachable ones) pass — datacenter IPs get
# bounced to a login/challenge wall and are rejected here. Proven proxies are
# promoted straight to the safe list. Browsers are heavy, so keep this batch
# small and its concurrency low.
PROXY_CONTENT_VALIDATE = True
PROXY_CONTENT_CONCURRENCY = 4
PROXY_CONTENT_BATCH = 20       # TCP-passers to browser-test per refill cycle
PROXY_CONTENT_TIMEOUT = 22     # s for the challenge to clear into job cards

# Measured against the live lists: of 250 candidates each, 0/250 free HTTP
# proxies could reach indeed.com over TLS, while 98/250 SOCKS5 relays opened
# a CONNECT to indeed.com:443. So the validation batch is weighted heavily
# toward SOCKS5 — testing HTTP proxies is nearly all wasted time.
SOCKS5_BATCH_SHARE = 0.8

# Safe list: proxies that have actually returned Indeed job cards. These are
# tried before anything from the freshly-scraped pool, and get a shorter
# cooldown after a failure because they are proven rather than speculative.
SAFE_COOLDOWN_SECONDS = 60    # retry a safe-list proxy after 1 min (we have many)
SAFE_LIST_CAP = 500           # room for the full sibling list
SAFE_EVICT_CONSECUTIVE = 8   # evict only after 8 consecutive failures

PROXY_LIST_URLS = [
    # SOCKS5 — these bypass Indeed's TLS-level blocks far better than HTTP CONNECT
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&proxy_format=protocolipport&format=text",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    # HTTP as fallback — low hit rate against Indeed but worth scanning
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=protocolipport&format=text",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
]

# Sources that publish bare "ip:port" lines that are actually SOCKS5.
SOCKS5_BARE_SOURCES = {
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
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
                "consecutive_failures": int(stats.get("consecutive_failures", 0)),
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
            entry = self.entries.setdefault(server, {
                "successes": 0, "failures": 0, "consecutive_failures": 0,
                "last_success": 0.0, "last_failure": 0.0,
            })
            first_time = entry["successes"] == 0
            entry["successes"] += 1
            entry["consecutive_failures"] = 0
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
            entry["consecutive_failures"] = entry.get("consecutive_failures", 0) + 1
            entry["last_failure"] = time.time()
            if entry["consecutive_failures"] >= SAFE_EVICT_CONSECUTIVE:
                del self.entries[server]
                log.info("Safe list − %s (%d consecutive failures).",
                         server, SAFE_EVICT_CONSECUTIVE)
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

    def seed_from_sibling(self, path: Path) -> int:
        """Load proven proxies from the sibling Auto Email Scraper project.

        The file is read-only — we never write back to it.  Proxies are ranked
        by (successes - blocks) and seeded into the safe list so they are tried
        before anything from the free-list scrape.
        """
        if not path.exists():
            return 0
        try:
            raw = json.loads(path.read_text())
        except Exception as exc:
            log.warning("Could not read sibling proxy list (%s): %s", path.name, exc)
            return 0

        entries = raw.get("proxies", []) + raw.get("reachable", [])
        # Sort best first: most successes relative to blocks, most recently seen
        def score(e):
            return (e.get("successes", 0) - e.get("blocks", 0),
                    str(e.get("lastSuccess") or e.get("checkedAt") or ""))

        entries.sort(key=score, reverse=True)

        added = 0
        with self._lock:
            for e in entries:
                server = e.get("server")
                if not server or server in self.entries:
                    continue
                self.entries[server] = {
                    "successes": e.get("successes", 1),
                    "failures": e.get("blocks", 0),
                    "consecutive_failures": 0,
                    "last_success": 0.0,
                    "last_failure": 0.0,
                }
                added += 1
            self._prune_locked()
        return added


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
    """Fetches, validates and hands out free HTTP/SOCKS5 proxies.

    When local_proxies is given (e.g. Surfshark wireproxy URLs), those are
    used as the primary pool and free-list scraping is skipped entirely.
    """

    def __init__(self, enabled: bool = True, local_proxies: list[str] | None = None):
        self.enabled = enabled
        self.pool: list[dict] = []
        self.failures: dict[str, float] = {}
        self.safe = SafeList()
        self._lock = threading.Lock()
        self._local_proxies: list[str] = local_proxies or []
        self._refill_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._first_proxy = threading.Event()
        self._session = self._create_session()

        # ── tracing counters (read by the UI) ───────────────────────────────
        self._stats_lock = threading.Lock()
        self._stats = {
            "candidates": 0,      # unique proxies fetched last cycle
            "tcp_tested": 0,      # stage-1 handshake attempts last cycle
            "tcp_ok": 0,          # stage-1 reachable last cycle
            "probed_total": 0,    # cumulative browser content-checks
            "served_total": 0,    # cumulative proxies that returned job cards
            "testing_now": 0,     # proxies currently in a browser content-check
            "cycles": 0,          # refill cycles completed
            "last_served": [],    # server strings that served cards last cycle
        }

        if self.enabled:
            n = self.safe.seed_from_sibling(SIBLING_PROXY_FILE)
            if n:
                log.info("Seeded %d proven proxy/proxies from sibling project (best-first).", n)
                self._first_proxy.set()
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
        # Seed with local VPN proxies immediately so the first cycle doesn't
        # have to wait for the free-list scrape to finish.
        if self._local_proxies:
            with self._lock:
                for url in self._local_proxies:
                    self.pool.append({"server": url})
            self._first_proxy.set()
            log.info("Proxy pool: %d local VPN proxy/proxies loaded (Surfshark).", len(self._local_proxies))
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
                # When local VPN proxies are configured, just keep them topped up;
                # skip the free-list scrape entirely (it would almost always fail).
                if self._local_proxies:
                    if self._stop.wait(PROXY_REFILL_INTERVAL):
                        break
                    with self._lock:
                        known = {p["server"] for p in self.pool}
                        for url in self._local_proxies:
                            if url not in known and url not in self.failures:
                                self.pool.append({"server": url})
                    continue

                if self.pool_size() >= PROXY_POOL_SIZE:
                    self._sleep(PROXY_REFILL_INTERVAL)
                    continue

                candidates = self._fetch_candidates()
                self._stat_set(candidates=len(candidates))
                if not candidates:
                    log.debug("No proxy candidates fetched.")
                    self._sleep(PROXY_REFILL_INTERVAL)
                    continue

                # Stage 1 — cheap TCP/handshake reachability filter.
                batch = self._compose_batch(candidates)
                reachable = self._validate_batch(batch)
                self._stat_set(tcp_tested=len(batch), tcp_ok=len(reachable))

                # Stage 2 — authoritative: does the proxy actually get served
                # Indeed job cards in a real browser? Only these are trusted.
                if reachable and PROXY_CONTENT_VALIDATE:
                    verified = self._content_verify_batch(reachable)
                else:
                    verified = reachable
                self._stat_inc("cycles")

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

    # -- stage 2: content verification (real browser → real job cards) --------

    def _content_verify_batch(self, reachable: list[dict]) -> list[dict]:
        """Browser-test the TCP-reachable proxies; keep only those Indeed
        actually serves job cards through. Winners are promoted to the safe
        list so they survive restarts and are tried first next time."""
        batch = reachable[:PROXY_CONTENT_BATCH]
        log.info("Content-checking %d reachable proxy/proxies through a real "
                 "browser…", len(batch))
        self._stat_set(testing_now=len(batch), last_served=[])
        served: list[dict] = []
        try:
            with ThreadPoolExecutor(max_workers=PROXY_CONTENT_CONCURRENCY) as executor:
                futures = {executor.submit(self._content_verify_one, p["server"]): p
                           for p in batch}
                for future in as_completed(futures):
                    self._stat_inc("probed_total")
                    self._stat_inc("testing_now", -1)
                    if self._stop.is_set():
                        break
                    try:
                        ok = future.result()
                    except Exception:
                        ok = False
                    if ok:
                        server = futures[future]["server"]
                        served.append({"server": server})
                        self.safe.record_success(server)   # bank it — proven once
                        self._stat_inc("served_total")
                        with self._stats_lock:
                            self._stats["last_served"] = \
                                self._stats.get("last_served", []) + [server]
                        log.info("  ✅ proxy serves Indeed: %s", server)
        finally:
            self._stat_set(testing_now=0)
        if not served:
            log.info("  no proxy served job cards this cycle.")
        return served

    @staticmethod
    def _content_verify_one(proxy_url: str) -> bool:
        """Load Indeed's job search through the proxy in a headless browser and
        report whether real job cards rendered (vs a login/challenge wall)."""
        from playwright.sync_api import sync_playwright
        url = "https://www.indeed.com/jobs?q=Software+Engineer&l=Remote"
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    proxy={"server": proxy_url},
                    args=["--disable-blink-features=AutomationControlled",
                          "--no-sandbox", "--disable-dev-shm-usage"])
                ctx = browser.new_context(user_agent=UA,
                                          viewport={"width": 1440, "height": 900},
                                          locale="en-US")
                ctx.add_init_script(
                    "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
                page = ctx.new_page()
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=20000)
                except Exception:
                    browser.close()
                    return False
                deadline = time.monotonic() + PROXY_CONTENT_TIMEOUT
                served = False
                while time.monotonic() < deadline:
                    try:
                        html = page.content()
                    except Exception:
                        break
                    if "data-jk=" in html or "mosaic-provider-jobcards" in html:
                        served = True
                        break
                    if "login-required" in page.url:
                        break
                    time.sleep(2)
                browser.close()
                return served
        except Exception:
            return False

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

    # -- tracing --------------------------------------------------------------

    def _stat_set(self, **kw) -> None:
        with self._stats_lock:
            self._stats.update(kw)

    def _stat_inc(self, key: str, by: int = 1) -> None:
        with self._stats_lock:
            self._stats[key] = self._stats.get(key, 0) + by

    def stats(self) -> dict:
        """Live proxy funnel snapshot for the UI."""
        now = time.time()
        with self._lock:
            pool = len(self.pool)
            blocked = sum(1 for t in self.failures.values()
                          if now - t <= PROXY_COOLDOWN_SECONDS)
        with self._stats_lock:
            s = dict(self._stats)
        s.update({
            "enabled": self.enabled,
            "pool": pool,              # content-verified, ready to hand out
            "safe": self.safe_size(),  # proven, persisted across restarts
            "blocked": blocked,        # in failure cooldown
        })
        return s


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


def pair_key(job: "Job") -> str:
    """Identity for role+company deduplication.

    Two postings for the same role at the same company collapse to one key,
    even when Indeed assigns them different job ids (reposts, or the same job
    surfacing under several role searches). Title and company are normalised
    the same way filters are, so 'Full-Stack Engineer' == 'Full Stack Engineer'.
    """
    return _normalise_title(job.title).strip() + " @@ " + _normalise_title(job.company).strip()


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
                "headless": self.cfg.headless,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ],
            }
            # Use installed Chrome if available (less detectable than Chromium),
            # but fall back to Playwright's bundled Chromium without crashing.
            try:
                test_browser = self._pw.chromium.launch(channel="chrome", headless=True)
                test_browser.close()
                launch_opts["channel"] = "chrome"
            except Exception:
                pass
            if proxy:
                launch_opts["proxy"] = {"server": proxy["server"]}
            self._browser = self._pw.chromium.launch(**launch_opts)
            ctx_opts: dict = {
                "user_agent": UA,
                "viewport": {"width": 1440, "height": 950},
                "locale": "en-US",
            }
            # Reuse a saved logged-in Indeed session if one exists. Without it,
            # Indeed redirects anonymous traffic to a login wall behind
            # Cloudflare Turnstile that a headless browser cannot pass.
            if SESSION_FILE.exists():
                ctx_opts["storage_state"] = str(SESSION_FILE)
            self._ctx = self._browser.new_context(**ctx_opts)
            # Mask automation fingerprints that Indeed/Cloudflare detect
            self._ctx.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
                Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
                window.chrome = {runtime: {}, loadTimes: function(){}, csi: function(){},
                                 app: {isInstalled: false}};
                const origQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (p) =>
                    p.name === 'notifications'
                        ? Promise.resolve({state: Notification.permission})
                        : origQuery(p);
            """)
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

def load_state() -> tuple[dict[str, float], dict[str, float], bool, float]:
    """Return (guid -> first-seen epoch, role@company -> first-seen epoch,
    seeded, last_success)."""
    if not STATE_FILE.exists():
        return {}, {}, False, 0.0
    try:
        raw = json.loads(STATE_FILE.read_text())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError, ValueError) as exc:
        log.error("State file unreadable (%s) — starting fresh.", exc)
        return {}, {}, False, 0.0

    now = time.time()
    if isinstance(raw, list):                                   # legacy: bare list
        log.info("Migrating legacy state file (%d keys).", len(raw))
        return {g: now for g in raw}, {}, True, 0.0
    if isinstance(raw, dict) and "guids" in raw:                # legacy: {"guids": [...]}
        guids = raw.get("guids") or []
        log.info("Migrating state file (%d keys).", len(guids))
        return ({g: now for g in guids}, {},
                bool(raw.get("seeded")),
                float(raw.get("last_success", 0)))

    jobs = raw.get("jobs") or {}
    seen = {str(g): float(t) for g, t in jobs.items()}
    pairs_raw = raw.get("pairs") or {}
    pairs = {str(k): float(t) for k, t in pairs_raw.items()}
    return seen, pairs, bool(raw.get("seeded")), float(raw.get("last_success", 0))


def _cap(d: dict[str, float]) -> None:
    """Drop the OLDEST entries once a seen-map exceeds STATE_CAP, in place."""
    if len(d) > STATE_CAP:
        newest = sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:STATE_CAP]
        d.clear()
        d.update(newest)


def save_state(seen: dict[str, float], seen_pairs: dict[str, float],
               seeded: bool, last_success: float) -> None:
    """Persist state, dropping the OLDEST ids once over STATE_CAP."""
    _cap(seen)
    _cap(seen_pairs)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(
        {"seeded": seeded, "last_success": last_success,
         "jobs": seen, "pairs": seen_pairs}, indent=2
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
        self._wireproxy: WireproxyManager | None = None
        local_proxies: list[str] = []
        if cfg.use_proxy:
            wm = WireproxyManager()
            if wm.available():
                log.info("wireproxy binary + vpn/ configs found — starting Surfshark tunnels…")
                self._wireproxy = wm
                local_proxies = wm.start(warmup=8.0)
        self.proxy_manager = ProxyManager(enabled=cfg.use_proxy, local_proxies=local_proxies)
        self.shared = SharedProxy(self.proxy_manager)
        self.tasks: queue.Queue = queue.Queue()
        self.results: queue.Queue = queue.Queue()
        self.workers: list[IndeedWorker] = []
        self.seen: dict[str, float] = {}
        self.seen_pairs: dict[str, float] = {}   # role@company -> first-seen
        self.seeded = False
        self.last_success = 0.0
        self._thread: threading.Thread | None = None
        self._filter_lock = threading.Lock()

    # -- lifecycle ------------------------------------------------------------

    def update_title_filters(self, include: list[str], exclude: list[str]) -> bool:
        """Swap the title filters on a running watch. Returns True if changed.

        Only the title lists are hot-swappable: roles decide how many workers
        exist, and the rest are baked into the search URL, so those still
        need a restart.
        """
        with self._filter_lock:
            if include == self.cfg.title_include and exclude == self.cfg.title_exclude:
                return False
            self.cfg.title_include = list(include)
            self.cfg.title_exclude = list(exclude)
            return True

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
        if self._wireproxy:
            self._wireproxy.stop()

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
        self.seen, self.seen_pairs, self.seeded, self.last_success = load_state()
        if reseed:
            self.seen, self.seen_pairs, self.seeded = {}, {}, False
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
                    save_state(self.seen, self.seen_pairs, self.seeded, self.last_success)
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

                if consecutive_failures > 0:
                    # All proxies failed — keep retrying quickly until we find
                    # a working one instead of sleeping for the full poll interval.
                    delay = FAILURE_RETRY_SECONDS * random.uniform(0.8, 1.2)
                    log.info("Proxy cycle failed — retrying in %ds (trying next proxies).", int(delay))
                    self._status(state=f"retrying in {int(delay)}s")
                else:
                    jitter = random.uniform(1 - self.cfg.poll_jitter, 1 + self.cfg.poll_jitter)
                    delay = self.cfg.poll_interval * jitter
                    log.info("Next cycle in %ds.", int(delay))
                    self._status(state=f"sleeping {int(delay)}s")
                self.stop_event.wait(delay)
        except Exception as exc:
            log.exception("Controller crashed: %s", exc)
        finally:
            save_state(self.seen, self.seen_pairs, self.seeded, self.last_success)
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
                pkey = pair_key(job)
                # Drop exact reposts (same id) AND any other posting for the
                # same role at the same company, even under a different id.
                if job.guid in self.seen or pkey in self.seen_pairs:
                    self.seen[job.guid] = now
                    self.seen_pairs[pkey] = now
                    continue
                self.seen[job.guid] = now
                self.seen_pairs[pkey] = now
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
    root.lift()
    root.attributes("-topmost", True)
    root.after(200, lambda: root.attributes("-topmost", False))

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
        "Any one of these must appear. Empty allows every title. Editable while running.",
        cfg.title_include)
    exclude_box = make_term_box(
        1, "Title must NOT include",
        "Any match is dropped. Wins over include. Editable while running.",
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
        roles_text.configure(state=widget_state)
        # include/exclude stay editable on purpose — they apply to a running
        # watch without stopping it.
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

    pending_apply = {"id": None}

    def apply_title_filters() -> None:
        """Push the term boxes into the running watch and onto disk."""
        pending_apply["id"] = None
        include = parse_terms(include_box.get("1.0", "end"))
        exclude = parse_terms(exclude_box.get("1.0", "end"))

        controller = state.get("controller")
        if controller and controller.is_running():
            if controller.update_title_filters(include, exclude):
                log.info("Filters updated live — %d include / %d block term(s); "
                         "applies from the next batch of results.",
                         len(include), len(exclude))
        try:
            stored = Config.load()
            stored.title_include, stored.title_exclude = include, exclude
            stored.save()
        except Exception as exc:
            log.error("Could not save title filters: %s", exc)

    def schedule_apply(_event=None) -> None:
        if pending_apply["id"] is not None:
            root.after_cancel(pending_apply["id"])
        pending_apply["id"] = root.after(1200, apply_title_filters)

    for term_box in (include_box, exclude_box):
        term_box.bind("<KeyRelease>", schedule_apply, add="+")

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
    root.update_idletasks()
    root.update()
    root.mainloop()


# ── Web UI ────────────────────────────────────────────────────────────────────

_WEB_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Indeed Job Notifier</title>
<style>
:root{--bg:#0f1117;--surf:#1a1d27;--bd:#2d3148;--tx:#e2e8f0;--mu:#64748b;
      --ac:#4f8ef7;--gr:#22c55e;--re:#ef4444;--ye:#f59e0b}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font:13px/1.5 Menlo,monospace;height:100vh;overflow:hidden}
header{display:flex;align-items:center;gap:10px;padding:10px 18px;
       border-bottom:1px solid var(--bd);background:var(--surf);flex-shrink:0}
header h1{font-size:14px;font-weight:600;flex:1}
#status-text{font-size:12px;color:var(--mu)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--mu);flex-shrink:0}
.dot.on{background:var(--gr);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
button{padding:5px 14px;border-radius:6px;border:none;cursor:pointer;
       font:13px/1 Menlo,monospace;font-weight:600;transition:opacity .15s}
button:hover{opacity:.8}
#btn-start{background:var(--gr);color:#000}
#btn-stop{background:var(--re);color:#fff}
#btn-start:disabled,#btn-stop:disabled{opacity:.4;cursor:not-allowed}
#btn-save{background:var(--ac);color:#fff}
.badge{font-size:10px;padding:2px 7px;border-radius:4px;font-weight:600}
.badge-off{background:var(--re);color:#fff}
.badge-on{background:var(--gr);color:#000}
.layout{display:grid;grid-template-columns:360px 1fr;height:calc(100vh - 45px);overflow:hidden}
aside{border-right:1px solid var(--bd);overflow-y:auto;display:flex;flex-direction:column}
.filters{padding:14px;flex:1}
.fh{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--mu);margin-bottom:10px}
.field{margin-bottom:12px}
.field>label{display:block;font-size:11px;color:var(--mu);margin-bottom:3px}
textarea,input[type=text],input[type=number]{
  width:100%;background:var(--bg);border:1px solid var(--bd);border-radius:5px;
  color:var(--tx);padding:5px 8px;font:12px/1.4 Menlo,monospace;resize:vertical}
textarea:focus,input:focus{outline:none;border-color:var(--ac)}
.cg{display:flex;flex-direction:column;gap:5px}
.cg label,.rg label{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--tx)}
.rg{display:flex;flex-direction:column;gap:5px}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.save-row{padding:10px 14px;border-top:1px solid var(--bd);display:flex;justify-content:flex-end}
main{display:flex;flex-direction:column;overflow:hidden}
.tabs{display:flex;border-bottom:1px solid var(--bd);background:var(--surf);flex-shrink:0}
.tab{padding:7px 18px;font-size:12px;cursor:pointer;border-bottom:2px solid transparent;
     color:var(--mu);transition:color .15s}
.tab.active{color:var(--tx);border-bottom-color:var(--ac)}
.panel{flex:1;overflow:hidden;display:none;flex-direction:column}
.panel.active{display:flex}
#log-out{flex:1;overflow-y:auto;padding:8px 12px;font-size:11.5px;line-height:1.7;
          white-space:pre-wrap;word-break:break-all}
.INFO{color:#94a3b8}.WARNING{color:var(--ye)}.ERROR{color:var(--re)}
#jobs-panel{overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
th{position:sticky;top:0;background:var(--surf);padding:7px 10px;text-align:left;
   color:var(--mu);font-size:10px;text-transform:uppercase;border-bottom:1px solid var(--bd)}
td{padding:7px 10px;border-bottom:1px solid var(--bd);vertical-align:top}
td a{color:var(--ac);text-decoration:none}
td a:hover{text-decoration:underline}
.ea{background:var(--gr);color:#000;font-size:9px;padding:1px 4px;border-radius:3px;vertical-align:middle}
#proxies-panel{overflow-y:auto}
.px-wrap{padding:16px}
.px-h{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--mu);
      margin:14px 0 8px}
.px-h:first-child{margin-top:0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.tile{background:var(--surf);border:1px solid var(--bd);border-radius:8px;padding:12px 14px}
.tile-hi{border-color:var(--ac)}
.tile-ok .tn{color:var(--gr)}
.tn{font-size:26px;font-weight:700;line-height:1;font-variant-numeric:tabular-nums}
.tl{font-size:11px;color:var(--tx);margin-top:6px;line-height:1.35}
.tl span{color:var(--mu)}
.px-hdr-badge{font-size:11px;color:var(--mu);margin-left:6px}
.px-list{background:var(--surf);border:1px solid var(--bd);border-radius:8px;padding:10px 12px;
         font-size:11.5px;color:var(--gr);white-space:pre-wrap;word-break:break-all;min-height:32px}
</style>
</head>
<body>
<header>
  <h1>Indeed Job Notifier</h1>
  <span id="px-summary" class="px-hdr-badge">proxies: —</span>
  <span id="status-text">idle</span>
  <div class="dot" id="dot"></div>
  <button id="btn-start">&#9654; Start</button>
  <button id="btn-stop">&#9646;&#9646; Stop</button>
</header>
<div class="layout">
  <aside>
    <div class="filters">
      <div class="fh">Filters</div>
      <div class="field">
        <label>Roles (one per line — each gets its own worker)</label>
        <textarea id="roles" rows="7"></textarea>
      </div>
      <div class="field">
        <label>Region</label>
        <div class="rg">
          <label><input type="radio" name="region" value="us_remote"> US Remote</label>
          <label><input type="radio" name="region" value="worldwide_remote"> Worldwide Remote</label>
        </div>
      </div>
      <div class="field">
        <label>Application</label>
        <div class="cg">
          <label><input type="checkbox" id="easy_apply_only"> Easy Apply only</label>
        </div>
      </div>
      <div class="field">
        <label>Job types</label>
        <div class="cg">
          <label><input type="checkbox" class="jt" value="fulltime"> Full-time</label>
          <label><input type="checkbox" class="jt" value="parttime"> Part-time</label>
          <label><input type="checkbox" class="jt" value="contract"> Contract</label>
        </div>
      </div>
      <div class="field">
        <label>Title must include (comma-separated)</label>
        <input type="text" id="title_include">
      </div>
      <div class="field">
        <label>Title must NOT include (comma-separated)</label>
        <input type="text" id="title_exclude">
      </div>
      <div class="row2">
        <div class="field"><label>Posted within (days)</label><input type="number" id="fromage" min="1" max="30"></div>
        <div class="field"><label>Poll interval (s)</label><input type="number" id="poll_interval" min="60"></div>
      </div>
      <div class="field">
        <div class="cg">
          <label><input type="checkbox" id="use_proxy"> Use proxy rotation</label>
          <label><input type="checkbox" id="headless"> Headless browser</label>
        </div>
      </div>
    </div>
    <div class="save-row"><button id="btn-save">Save filters</button></div>
  </aside>
  <main>
    <div class="tabs">
      <div class="tab active" data-tab="log">Logs</div>
      <div class="tab" data-tab="jobs">Jobs <span id="jcount"></span></div>
      <div class="tab" data-tab="proxies">Proxies</div>
    </div>
    <div class="panel active" id="log-panel"><div id="log-out"></div></div>
    <div class="panel" id="jobs-panel">
      <table>
        <thead><tr><th>Title</th><th>Company</th><th>Location</th><th>Salary</th></tr></thead>
        <tbody id="jobs-body"></tbody>
      </table>
    </div>
    <div class="panel" id="proxies-panel">
      <div class="px-wrap">
        <div class="px-h">Live — ready to use now</div>
        <div class="tiles">
          <div class="tile tile-hi"><div class="tn" id="px-pool">0</div><div class="tl">Verified pool<br><span>serving job cards</span></div></div>
          <div class="tile tile-hi"><div class="tn" id="px-safe">0</div><div class="tl">Safe list<br><span>proven &amp; saved</span></div></div>
          <div class="tile"><div class="tn" id="px-testing">0</div><div class="tl">Testing now<br><span>in browser check</span></div></div>
          <div class="tile"><div class="tn" id="px-blocked">0</div><div class="tl">Blocked<br><span>in cooldown</span></div></div>
        </div>
        <div class="px-h">This discovery cycle</div>
        <div class="tiles">
          <div class="tile"><div class="tn" id="px-cand">0</div><div class="tl">Candidates<br><span>fetched from lists</span></div></div>
          <div class="tile"><div class="tn" id="px-tcp">0</div><div class="tl">TCP reachable<br><span>of <span id="px-tcptested">0</span> tested</span></div></div>
          <div class="tile"><div class="tn" id="px-cycles">0</div><div class="tl">Cycles<br><span>completed</span></div></div>
        </div>
        <div class="px-h">Cumulative (since start)</div>
        <div class="tiles">
          <div class="tile"><div class="tn" id="px-probed">0</div><div class="tl">Browser-probed<br><span>real /jobs loads</span></div></div>
          <div class="tile tile-ok"><div class="tn" id="px-served">0</div><div class="tl">Served cards<br><span>promoted to safe</span></div></div>
          <div class="tile"><div class="tn" id="px-rate">—</div><div class="tl">Hit rate<br><span>served / probed</span></div></div>
        </div>
        <div class="px-h">Served this cycle</div>
        <div id="px-served-list" class="px-list">none yet</div>
      </div>
    </div>
  </main>
</div>
<script>
const $=id=>document.getElementById(id);
let jcount=0;

document.querySelectorAll('.tab').forEach(t=>t.addEventListener('click',()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));
  t.classList.add('active');
  $(`${t.dataset.tab}-panel`).classList.add('active');
}));

async function loadCfg(){
  const c=await fetch('/api/config').then(r=>r.json());
  $('roles').value=(c.roles||[]).join('\n');
  document.querySelectorAll('input[name=region]').forEach(r=>r.checked=r.value===c.region);
  $('easy_apply_only').checked=!!c.easy_apply_only;
  document.querySelectorAll('.jt').forEach(cb=>cb.checked=(c.job_types||[]).includes(cb.value));
  $('title_include').value=(c.title_include||[]).join(', ');
  $('title_exclude').value=(c.title_exclude||[]).join(', ');
  $('fromage').value=c.fromage??7;
  $('poll_interval').value=c.poll_interval??600;
  $('use_proxy').checked=c.use_proxy!==false;
  $('headless').checked=c.headless!==false;
}

function collectCfg(){
  const terms=s=>s.split(/[,\n]+/).map(t=>t.trim()).filter(Boolean);
  return{
    roles:$('roles').value.split('\n').map(r=>r.trim()).filter(Boolean),
    region:document.querySelector('input[name=region]:checked')?.value||'us_remote',
    easy_apply_only:$('easy_apply_only').checked,
    job_types:[...$('jobs-panel')||document.querySelectorAll('.jt:checked')].map(cb=>cb.value),
    title_include:terms($('title_include').value),
    title_exclude:terms($('title_exclude').value),
    fromage:parseInt($('fromage').value)||7,
    poll_interval:parseInt($('poll_interval').value)||600,
    use_proxy:$('use_proxy').checked,
    headless:$('headless').checked,
  };
}

// fix collectCfg job_types
function collectCfgFixed(){
  const terms=s=>s.split(/[,\n]+/).map(t=>t.trim()).filter(Boolean);
  return{
    roles:$('roles').value.split('\n').map(r=>r.trim()).filter(Boolean),
    region:document.querySelector('input[name=region]:checked')?.value||'us_remote',
    easy_apply_only:$('easy_apply_only').checked,
    job_types:[...document.querySelectorAll('.jt:checked')].map(cb=>cb.value),
    title_include:terms($('title_include').value),
    title_exclude:terms($('title_exclude').value),
    fromage:parseInt($('fromage').value)||7,
    poll_interval:parseInt($('poll_interval').value)||600,
    use_proxy:$('use_proxy').checked,
    headless:$('headless').checked,
  };
}

async function saveCfg(){
  await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(collectCfgFixed())});
}

$('btn-save').addEventListener('click',async()=>{
  await saveCfg();
  $('btn-save').textContent='Saved!';
  setTimeout(()=>$('btn-save').textContent='Save filters',1500);
});

$('btn-start').addEventListener('click',async()=>{await saveCfg();await fetch('/api/start',{method:'POST'})});
$('btn-stop').addEventListener('click',()=>fetch('/api/stop',{method:'POST'}));

const logEl=$('log-out');
function addLog(level,msg){
  const d=document.createElement('div');
  d.className=level;d.textContent=msg;
  logEl.appendChild(d);
  if(logEl.children.length>600)logEl.removeChild(logEl.firstChild);
  logEl.scrollTop=logEl.scrollHeight;
}

function addJob(j){
  jcount++;$('jcount').textContent=`(${jcount})`;
  const tr=document.createElement('tr');
  const ea=j.easy_apply?'<span class="ea">Easy</span> ':'';
  tr.innerHTML=`<td>${ea}<a href="${j.link}" target="_blank">${j.title}</a></td>
    <td>${j.company}</td><td>${j.location||''}</td><td>${j.salary||''}</td>`;
  $('jobs-body').prepend(tr);
}

function setRunning(on,state){
  $('btn-start').disabled=on;
  $('btn-stop').disabled=!on;
  $('dot').className='dot'+(on?' on':'');
  if(state)$('status-text').textContent=state;
}

function connectSSE(){
  const es=new EventSource('/api/stream');
  es.onmessage=e=>{
    const d=JSON.parse(e.data);
    if(d.type==='log')addLog(d.level,d.msg);
    else if(d.type==='job')addJob(d.job);
    else if(d.type==='status'){setRunning(d.running,d.state);}
  };
  es.onerror=()=>{es.close();setTimeout(connectSSE,3000)};
}

function setTxt(id,v){const e=$(id);if(e)e.textContent=v;}
async function pollProxies(){
  try{
    const s=await fetch('/api/proxystats').then(r=>r.json());
    setTxt('px-pool',s.pool);
    setTxt('px-safe',s.safe);
    setTxt('px-testing',s.testing_now);
    setTxt('px-blocked',s.blocked);
    setTxt('px-cand',s.candidates);
    setTxt('px-tcp',s.tcp_ok);
    setTxt('px-tcptested',s.tcp_tested);
    setTxt('px-cycles',s.cycles);
    setTxt('px-probed',s.probed_total);
    setTxt('px-served',s.served_total);
    setTxt('px-rate', s.probed_total ? ((100*s.served_total/s.probed_total).toFixed(1)+'%') : '—');
    $('px-served-list').textContent=(s.last_served&&s.last_served.length)?s.last_served.join('\n'):'none yet';
    const sum = s.enabled
      ? `proxies: ${s.pool} ready · ${s.safe} safe · ${s.testing_now} testing · ${s.blocked} blocked`
      : 'proxies: off';
    setTxt('px-summary', sum);
  }catch(e){}
}

fetch('/api/jobs').then(r=>r.json()).then(js=>js.slice().reverse().forEach(addJob));
fetch('/api/status').then(r=>r.json()).then(s=>{setRunning(s.running,s.state);});
loadCfg();
connectSSE();
pollProxies();
setInterval(pollProxies,2000);
</script>
</body>
</html>"""


def launch_web(port: int = 9876) -> None:
    try:
        from flask import Flask, jsonify, request as freq, Response, stream_with_context
    except ImportError:
        log.error("Flask not installed. Run: pip install flask")
        sys.exit(1)

    app = Flask(__name__)
    _state: dict = {"controller": None, "status": {}}
    _jobs: list = []
    _clients: list = []
    _cli_lock = threading.Lock()

    class _SSELog(logging.Handler):
        def emit(self, record):
            msg = self.format(record)
            data = json.dumps({"type": "log", "level": record.levelname, "msg": msg})
            with _cli_lock:
                for q in list(_clients):
                    try:
                        q.put_nowait(data)
                    except queue.Full:
                        pass

    h = _SSELog()
    h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                     datefmt="%H:%M:%S"))
    logging.getLogger().addHandler(h)

    def _broadcast(payload: dict) -> None:
        data = json.dumps(payload)
        with _cli_lock:
            for q in list(_clients):
                try:
                    q.put_nowait(data)
                except queue.Full:
                    pass

    @app.route("/")
    def index():
        return _WEB_HTML

    @app.route("/api/config")
    def get_config():
        return jsonify(asdict(Config.load()))

    @app.route("/api/config", methods=["POST"])
    def set_config():
        data = freq.get_json(force=True) or {}
        cfg = Config.load()
        for key, value in data.items():
            if hasattr(cfg, key):
                setattr(cfg, key, value)
        cfg.save()
        return jsonify({"ok": True})

    @app.route("/api/start", methods=["POST"])
    def api_start():
        ctrl = _state.get("controller")
        if ctrl and ctrl.is_running():
            return jsonify({"ok": False, "error": "Already running"})
        cfg = Config.load()

        def on_job(job):
            entry = {
                "title": job.title, "company": job.company,
                "location": job.location, "link": job.link,
                "salary": job.salary, "easy_apply": job.easy_apply,
            }
            _jobs.insert(0, entry)
            del _jobs[200:]
            _broadcast({"type": "job", "job": entry})

        def on_status(status):
            _state["status"] = status
            ctrl = _state.get("controller")
            _broadcast({"type": "status", "running": bool(ctrl and ctrl.is_running()), **status})

        new_ctrl = Controller(cfg, on_job=on_job, on_status=on_status)
        new_ctrl.start()
        _state["controller"] = new_ctrl
        return jsonify({"ok": True})

    @app.route("/api/stop", methods=["POST"])
    def api_stop():
        ctrl = _state.get("controller")
        if ctrl:
            threading.Thread(target=ctrl.stop, kwargs={"timeout": 10}, daemon=True).start()
        return jsonify({"ok": True})

    @app.route("/api/status")
    def api_status():
        ctrl = _state.get("controller")
        return jsonify({
            "running": bool(ctrl and ctrl.is_running()),
            **_state.get("status", {}),
        })

    @app.route("/api/jobs")
    def api_jobs():
        return jsonify(_jobs)

    @app.route("/api/proxystats")
    def api_proxystats():
        ctrl = _state.get("controller")
        if ctrl and getattr(ctrl, "proxy_manager", None):
            return jsonify(ctrl.proxy_manager.stats())
        return jsonify({"enabled": False, "pool": 0, "safe": 0, "blocked": 0,
                        "candidates": 0, "tcp_tested": 0, "tcp_ok": 0,
                        "probed_total": 0, "served_total": 0, "testing_now": 0,
                        "cycles": 0, "last_served": []})

    @app.route("/api/stream")
    def api_stream():
        q: queue.Queue = queue.Queue(maxsize=500)
        ctrl = _state.get("controller")
        try:
            q.put_nowait(json.dumps({
                "type": "status",
                "running": bool(ctrl and ctrl.is_running()),
                **_state.get("status", {}),
            }))
        except queue.Full:
            pass
        with _cli_lock:
            _clients.append(q)

        def generate():
            try:
                while True:
                    try:
                        yield f"data: {q.get(timeout=25)}\n\n"
                    except queue.Empty:
                        yield 'data: {"type":"ping"}\n\n'
            finally:
                with _cli_lock:
                    try:
                        _clients.remove(q)
                    except ValueError:
                        pass

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    import logging as _logging
    _logging.getLogger("werkzeug").setLevel(_logging.WARNING)
    log.info("Web UI → http://localhost:%d", port)
    from werkzeug.serving import run_simple
    run_simple("0.0.0.0", port, app, threaded=True, use_reloader=False)


# ── Surfshark wireproxy manager ───────────────────────────────────────────────

class WireproxyManager:
    """Starts local wireproxy tunnels from vpn/*.conf and hands out SOCKS5 URLs.

    Each .conf file becomes one process exposing a SOCKS5 port as declared in
    its [Socks5] BindAddress line.  Processes are launched lazily on first
    call to start() and killed on stop().  Only configs whose tunnels actually
    handshake within the warmup period are promoted to the ready pool.
    """

    def __init__(self, conf_dir: Path = WIREPROXY_CONF_DIR,
                 binary: Path = WIREPROXY_BIN):
        self.conf_dir = conf_dir
        self.binary = binary
        self._procs: list[tuple[subprocess.Popen, str, int]] = []  # (proc, name, port)
        self._ready: list[str] = []   # socks5://127.0.0.1:<port>
        self._lock = threading.Lock()

    def available(self) -> bool:
        return self.binary.exists() and self.conf_dir.exists()

    def start(self, warmup: float = 8.0) -> list[str]:
        if not self.available():
            return []
        confs = sorted(self.conf_dir.glob("*.conf"))
        if not confs:
            return []

        launched = []
        for conf in confs:
            port = self._extract_port(conf)
            if not port:
                continue
            try:
                proc = subprocess.Popen(
                    [str(self.binary), "-c", str(conf)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self._procs.append((proc, conf.stem, port))
                launched.append((conf.stem, port))
                log.debug("wireproxy: launched %s on port %d (pid %d)", conf.stem, port, proc.pid)
            except Exception as exc:
                log.warning("wireproxy: could not start %s: %s", conf.stem, exc)

        if not launched:
            return []

        # Wait for tunnels to come up, then validate each with a TCP connect
        log.info("wireproxy: waiting %.0fs for %d tunnel(s) to connect…", warmup, len(launched))
        time.sleep(warmup)

        ready = []
        for name, port in launched:
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=3)
                sock.close()
                url = f"socks5://127.0.0.1:{port}"
                ready.append(url)
                log.info("wireproxy: ✅ %s ready on port %d", name, port)
            except Exception:
                log.warning("wireproxy: ❌ %s not responding on port %d", name, port)

        with self._lock:
            self._ready = ready
        if ready:
            log.info("wireproxy: %d/%d tunnel(s) ready — using Surfshark VPN proxies.", len(ready), len(launched))
        else:
            log.warning("wireproxy: no tunnels came up (WireGuard handshake may have failed — check your Surfshark configs).")
        return ready

    def stop(self) -> None:
        for proc, name, port in self._procs:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._procs.clear()
        with self._lock:
            self._ready.clear()

    def proxies(self) -> list[str]:
        with self._lock:
            return list(self._ready)

    @staticmethod
    def _extract_port(conf: Path) -> int | None:
        try:
            for line in conf.read_text().splitlines():
                if line.strip().startswith("BindAddress"):
                    _, _, addr = line.partition("=")
                    port_str = addr.strip().rsplit(":", 1)[-1]
                    return int(port_str)
        except Exception:
            pass
        return None


# ── Login session capture ─────────────────────────────────────────────────────

def login_indeed() -> None:
    """Open a visible browser so the user can log into Indeed, then save the
    session to indeed_session.json for headless scraping.

    Indeed's Cloudflare Turnstile requires human interaction — once the user
    logs in, the resulting cookies bypass the challenge in all future runs.
    """
    print("\n  Opening a browser window — please log into Indeed, then close the window.\n")
    print("  Session will be saved to:", SESSION_FILE)
    print("  (You only need to do this once; the session persists across restarts.)\n")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright not installed — run: pip install playwright && playwright install chromium")
        sys.exit(1)

    with sync_playwright() as pw:
        # Use installed Chrome so it has the real fingerprint
        launch_opts: dict = {
            "headless": False,
            "args": ["--no-sandbox"],
        }
        try:
            test = pw.chromium.launch(channel="chrome", headless=True)
            test.close()
            launch_opts["channel"] = "chrome"
        except Exception:
            pass

        browser = pw.chromium.launch(**launch_opts)
        ctx = browser.new_context(
            user_agent=UA,
            viewport={"width": 1440, "height": 900},
            locale="en-US",
        )
        page = ctx.new_page()
        page.goto("https://secure.indeed.com/account/login", wait_until="domcontentloaded", timeout=30000)

        print("  Waiting for you to log in and for Indeed's home page to appear…")
        try:
            page.wait_for_url("**/jobs**", timeout=180000)
        except Exception:
            pass

        # Also wait for the session cookie to arrive
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            cookies = ctx.cookies()
            if any(c["name"] in ("CTK", "INDEED_CSRF_TOKEN", "LG", "JSESSIONID") for c in cookies):
                break
            time.sleep(1)

        ctx.storage_state(path=str(SESSION_FILE))
        browser.close()

    print(f"\n  ✅ Session saved to {SESSION_FILE}")
    print("     Run 'python indeed_notifier.py --web' (or --nogui) to start watching.\n")


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
    ap.add_argument("--web", action="store_true", help="launch web UI (default port 9876)")
    ap.add_argument("--port", type=int, default=9876, help="port for --web mode (default 9876)")
    ap.add_argument("--once", action="store_true", help="one cycle, then exit (implies --nogui)")
    ap.add_argument("--reseed", action="store_true", help="discard state and re-seed silently")
    ap.add_argument("--no-proxy", action="store_true", help="disable proxy rotation")
    ap.add_argument("--checkip", action="store_true", help="show the current egress IP and test Indeed")
    ap.add_argument("--login", action="store_true",
                    help="open a visible browser to log into Indeed and save session cookies")
    args = ap.parse_args()

    if args.login:
        login_indeed()
    elif args.checkip:
        check_ip()
    elif args.nogui or args.once:
        run_headless(once=args.once, reseed=args.reseed, no_proxy=args.no_proxy)
    elif args.web:
        launch_web(port=args.port)
    else:
        launch_web(port=args.port)
