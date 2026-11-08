from __future__ import annotations

import json
import os
import re
import ipaddress
import sqlite3
import tempfile
import configparser
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlparse

DOMAIN_CATEGORIES = {
    "ordinary": "Обычный сайт",
    "unknown": "Неизвестный сайт",
    "suspicious": "Подозрительный сайт",
    "software_distribution": "Распространение стороннего ПО",
}

CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Browser SQLite files can remain busy while a browser is running. These limits
# prevent a single profile from keeping the GUI in an indeterminate state forever.
DEFAULT_PROFILE_TIMEOUT_SECONDS = 35.0
DEFAULT_TOTAL_TIMEOUT_SECONDS = 180.0
LIVE_READ_RETRY_SECONDS = 4.0
LIVE_READ_BUSY_TIMEOUT_MS = 350


class BrowserSourceTimeout(TimeoutError):
    """A browser profile exceeded its bounded read/backup time."""


class _BrowserDeadline:
    def __init__(self, seconds: float, label: str, cancel_check: Callable[[], None] | None = None):
        self.seconds = max(0.1, float(seconds))
        self.label = label
        self.deadline = time.monotonic() + self.seconds
        self.cancel_check = cancel_check
        self.pending_exception: BaseException | None = None

    def check(self) -> None:
        if self.cancel_check:
            self.cancel_check()
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BrowserSourceTimeout(
                f"Источник {self.label} не завершил чтение за {self.seconds:.0f} с. "
                "Он помечен как timeout; остальные источники будут обработаны дальше."
            )

    def sqlite_progress(self) -> int:
        """SQLite progress handler: return non-zero to interrupt long SQL queries."""
        try:
            self.check()
            return 0
        except BaseException as exc:
            self.pending_exception = exc
            return 1

    def raise_pending(self) -> None:
        if self.pending_exception is not None:
            exc = self.pending_exception
            self.pending_exception = None
            raise exc


def normalize_domain(value: str) -> str:
    """Return a normalized host/domain without scheme, port or leading www."""
    raw = str(value or "").strip().casefold()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        host = (urlparse(raw).hostname or "").strip(".").casefold()
        if host:
            return host.encode("idna").decode("ascii")
    except Exception:
        return ""
    return ""


def _valid_domain_rule_host(host: str) -> bool:
    """Conservative validation for a host extracted from a pasted URL/domain."""
    value = str(host or "").strip(".\t ").casefold()
    if not value or len(value) > 253 or any(ch.isspace() for ch in value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if value == "localhost":
        return True
    labels = value.split(".")
    if len(labels) < 2:
        return False
    return all(
        1 <= len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is not None
        for label in labels
    )


def parse_domain_rule_input(value: str) -> tuple[list[str], list[str]]:
    """
    Parse one or many URLs/domains pasted into the custom domain-rule field.

    Supported separators: comma, semicolon, pipe, newline, and a colon between
    entries (including ``URL1 : URL2`` and ``URL1:URL2`` when the second entry
    starts with an explicit URL scheme/www). Colons belonging to URL schemes,
    IPv6 literals, and numeric ports are preserved. Returns unique normalized
    hosts and the original invalid fragments.
    """
    raw_text = str(value or "").strip()
    if not raw_text:
        return [], []

    standard_chunks = re.split(r"[,;|\r\n]+", raw_text)
    # A colon is a list separator when whitespace surrounds it, or when the
    # next item visibly begins as another absolute URL. This avoids splitting
    # https://, IPv6 literals, and ordinary host:port values.
    colon_separator = re.compile(
        r"\s+:\s+|\s*:\s*(?=(?:https?://|ftp://|www\.))",
        flags=re.IGNORECASE,
    )

    candidates: list[str] = []
    for chunk in standard_chunks:
        colon_parts = colon_separator.split(chunk)
        for part in colon_parts:
            # Also accept bare host lists without spaces, e.g.
            # ``first.example:second.example``. A numeric suffix such as
            # ``example.com:8080`` is intentionally not treated as a list item.
            if "://" not in part and not part.strip().startswith("["):
                part = re.sub(
                    r"(?<=\S):(?=(?:[\w-]+\.)+[\w-]+(?:[/:?#]|$))",
                    " ; ", part, flags=re.UNICODE,
                )
            candidates.extend(item.strip() for item in part.split(";") if item.strip())

    valid: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        token = candidate.strip().strip('"\'<>(){}')
        # Common punctuation copied after a URL is not part of its hostname.
        token = token.rstrip(".,")
        domain = normalize_domain(token)
        if not domain or not _valid_domain_rule_host(domain):
            invalid.append(candidate)
            continue
        if domain not in seen:
            seen.add(domain)
            valid.append(domain)
    return valid, invalid


def classify_domain(domain: str, domain_rules: dict[str, str] | None = None) -> tuple[str, str]:
    host = normalize_domain(domain)
    if not host:
        return "unknown", "Домен не удалось определить по URL."
    rules = domain_rules or {}
    matches: list[tuple[int, str, str]] = []
    for raw_domain, category in rules.items():
        rule_domain = normalize_domain(raw_domain)
        if rule_domain and category in DOMAIN_CATEGORIES and (host == rule_domain or host.endswith("." + rule_domain)):
            matches.append((len(rule_domain), rule_domain, category))
    if matches:
        _specificity, rule_domain, category = max(matches, key=lambda item: (item[0], item[1]))
        return category, f"Совпадение с наиболее специфичным пользовательским правилом: {rule_domain}."
    return "unknown", "Пользовательское правило не задано. Неизвестная категория не означает подозрительность."


def _browser_profile_databases() -> list[tuple[str, str, Path]]:
    """Discover known browser history databases in the current user's profile.

    USERPROFILE is preferred on Windows because Path.home() can resolve to a
    different account when the application is elevated under alternate
    credentials. No other Windows user profiles are traversed.
    """
    home_value = os.environ.get("USERPROFILE") or str(Path.home())
    home = Path(os.path.expandvars(home_value)).expanduser()
    local_value = os.environ.get("LOCALAPPDATA")
    roaming_value = os.environ.get("APPDATA")
    local = Path(os.path.expandvars(local_value)).expanduser() if local_value else (home / "AppData" / "Local" if os.name == "nt" else None)
    roaming = Path(os.path.expandvars(roaming_value)).expanduser() if roaming_value else (home / "AppData" / "Roaming" if os.name == "nt" else None)
    candidates: list[tuple[str, str, Path]] = []

    chromium_roots: list[tuple[str, Path]] = []
    if local:
        chromium_roots.extend([
            ("Google Chrome", local / "Google" / "Chrome" / "User Data"),
            ("Google Chrome Beta", local / "Google" / "Chrome Beta" / "User Data"),
            ("Google Chrome Dev", local / "Google" / "Chrome Dev" / "User Data"),
            ("Google Chrome Canary", local / "Google" / "Chrome SxS" / "User Data"),
            ("Microsoft Edge", local / "Microsoft" / "Edge" / "User Data"),
            ("Microsoft Edge Beta", local / "Microsoft" / "Edge Beta" / "User Data"),
            ("Microsoft Edge Dev", local / "Microsoft" / "Edge Dev" / "User Data"),
            ("Microsoft Edge Canary", local / "Microsoft" / "Edge SxS" / "User Data"),
            ("Brave", local / "BraveSoftware" / "Brave-Browser" / "User Data"),
            ("Chromium", local / "Chromium" / "User Data"),
            ("Vivaldi", local / "Vivaldi" / "User Data"),
            ("Yandex Browser", local / "Yandex" / "YandexBrowser" / "User Data"),
        ])
    linux_config = home / ".config"
    chromium_roots.extend([
        ("Google Chrome", linux_config / "google-chrome"),
        ("Microsoft Edge", linux_config / "microsoft-edge"),
        ("Brave", linux_config / "BraveSoftware" / "Brave-Browser"),
        ("Chromium", linux_config / "chromium"),
        ("Vivaldi", linux_config / "vivaldi"),
        ("Opera", linux_config / "opera"),
        ("Yandex Browser", linux_config / "yandex-browser"),
    ])

    for browser, root in chromium_roots:
        if not root.is_dir():
            continue
        profile_dirs: list[Path] = []
        # The profile directory names are enumerated from this browser's own
        # User Data folder; Local State is not needed and is never modified.
        try:
            profile_dirs = [p for p in root.iterdir() if p.is_dir() and (
                p.name == "Default" or p.name.startswith("Profile ")
                or p.name in {"Guest Profile", "System Profile"}
            )]
        except OSError:
            profile_dirs = [root / "Default"]
        if not profile_dirs:
            profile_dirs = [root / "Default"]
        for profile in sorted(profile_dirs, key=lambda p: (p.name != "Default", p.name.casefold())):
            history = profile / "History"
            try:
                if history.is_file():
                    candidates.append((browser, profile.name, history))
            except OSError:
                continue

    opera_roots: list[tuple[str, Path]] = []
    if roaming:
        opera_roots.extend([
            ("Opera", roaming / "Opera Software" / "Opera Stable"),
            ("Opera GX", roaming / "Opera Software" / "Opera GX Stable"),
        ])
    if local:
        opera_roots.extend([
            ("Opera", local / "Programs" / "Opera"),
            ("Opera GX", local / "Programs" / "Opera GX"),
        ])
    opera_roots.extend([
        ("Opera", home / ".config" / "opera"),
        ("Opera GX", home / ".config" / "opera-gx"),
    ])
    for browser, root in opera_roots:
        history = root / "History"
        try:
            if history.is_file():
                candidates.append((browser, root.name, history))
        except OSError:
            continue

    # Firefox normally stores profiles under Profiles/, but profiles.ini can
    # point to a custom absolute directory or a relative directory elsewhere.
    firefox_roots: list[Path] = []
    if roaming:
        firefox_roots.extend([
            roaming / "Mozilla" / "Firefox" / "Profiles",
            roaming / "Mozilla" / "Firefox",
        ])
    if local:
        firefox_roots.extend([
            local / "Mozilla" / "Firefox" / "Profiles",
            local / "Mozilla" / "Firefox",
        ])
    firefox_roots.append(home / ".mozilla" / "firefox")
    firefox_seen: set[str] = set()
    for root in firefox_roots:
        if not root.is_dir():
            continue
        profile_candidates: list[tuple[str, Path]] = []
        profiles_ini = root.parent / "profiles.ini" if root.name.casefold() == "profiles" else root / "profiles.ini"
        if profiles_ini.is_file():
            parser = configparser.ConfigParser(interpolation=None)
            try:
                parser.read(profiles_ini, encoding="utf-8")
                for section in parser.sections():
                    if not section.casefold().startswith("profile"):
                        continue
                    raw_path = parser.get(section, "Path", fallback="").strip()
                    if not raw_path:
                        continue
                    is_relative = parser.getboolean(section, "IsRelative", fallback=True)
                    profile_path = (profiles_ini.parent / raw_path) if is_relative else Path(os.path.expandvars(raw_path)).expanduser()
                    profile_candidates.append((parser.get(section, "Name", fallback=profile_path.name), profile_path))
            except (OSError, configparser.Error, ValueError):
                pass
        try:
            profile_candidates.extend((p.name, p) for p in root.iterdir() if p.is_dir())
        except OSError:
            pass
        for profile_name, profile in profile_candidates:
            places = profile / "places.sqlite"
            try:
                key = str(places.resolve()).casefold()
                if key not in firefox_seen and places.is_file():
                    firefox_seen.add(key)
                    candidates.append(("Mozilla Firefox", profile_name, places))
            except OSError:
                continue

    unique: list[tuple[str, str, Path]] = []
    seen_paths: set[str] = set()
    for browser, profile, path in candidates:
        try:
            key = os.path.normcase(str(path.resolve())).casefold()
        except OSError:
            key = os.path.normcase(str(path.absolute())).casefold()
        if key not in seen_paths:
            seen_paths.add(key)
            unique.append((browser, profile, path))
    return unique[:200]


def _sqlite_open_live_readonly(
    path: Path,
    cancel_check: Callable[[], None] | None = None,
    progress: Callable[[str], None] | None = None,
    retry_seconds: float = LIVE_READ_RETRY_SECONDS,
) -> sqlite3.Connection:
    """Open an active browser SQLite database as a consistent read-only snapshot.

    Unlike copying only the main ``History`` file, this uses SQLite's own locking
    and journal/WAL handling. The explicit read transaction pins one consistent
    snapshot while the browser can keep writing newer visits. It never opens the
    source in read-write mode and never uses ``immutable=1`` (which could ignore
    live WAL data).
    """
    check = cancel_check or (lambda: None)
    report = progress or (lambda _message: None)
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
    except (OSError, ValueError):
        raise

    retry_seconds = max(0.0, float(retry_seconds))
    retry_deadline = time.monotonic() + retry_seconds
    attempt = 0
    while True:
        check()
        attempt += 1
        connection: sqlite3.Connection | None = None
        try:
            # A short SQLite busy timeout gives the outer retry loop frequent
            # opportunities to check cancellation and the per-profile deadline.
            connection = sqlite3.connect(
                uri, uri=True, timeout=LIVE_READ_BUSY_TIMEOUT_MS / 1000.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute(f"PRAGMA busy_timeout={int(LIVE_READ_BUSY_TIMEOUT_MS)}")
            connection.execute("BEGIN")
            # This first read establishes the SQLite snapshot. In WAL mode it
            # includes committed WAL pages even while Chrome/Edge remains open.
            connection.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
            check()
            report(
                f"Открыта активная база {path.name} в режиме read-only; "
                "читаю согласованный снимок SQLite с учётом WAL…"
            )
            return connection
        except sqlite3.OperationalError as exc:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            message = str(exc).casefold()
            is_busy = any(token in message for token in (
                "database is locked", "database is busy", "table is locked",
                "sqlite_busy", "sqlite_locked",
            ))
            if not is_busy or time.monotonic() >= retry_deadline:
                raise
            remaining = max(0.0, retry_deadline - time.monotonic())
            report(
                f"Браузер продолжает использовать {path.name}; повторяю безопасное "
                f"read-only подключение ({attempt}), осталось ожидания {remaining:.1f} с…"
            )
            check()
            time.sleep(min(0.15, remaining))
        except BaseException:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            raise


def _sqlite_readonly_backup(
    path: Path,
    cancel_check: Callable[[], None] | None = None,
    progress: Callable[[str], None] | None = None,
) -> tuple[sqlite3.Connection, tempfile.TemporaryDirectory]:
    """Create a bounded, read-only SQLite backup in a temporary directory.

    The deadline is enforced from SQLite's backup callback. A continuously busy
    browser database therefore cannot trap the worker in backup() forever.
    """
    progress = progress or (lambda _message: None)
    check = cancel_check or (lambda: None)
    temp_dir = tempfile.TemporaryDirectory(prefix="pav_browser_")
    target = Path(temp_dir.name) / "browser_copy.sqlite"
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
    except (OSError, ValueError):
        temp_dir.cleanup()
        raise

    source = None
    destination = None
    started = time.monotonic()
    last_report = 0.0
    try:
        check()
        # A short busy timeout lets the progress callback regain control instead
        # of waiting for many seconds on every retry.
        source = sqlite3.connect(uri, uri=True, timeout=0.25)
        source.execute("PRAGMA query_only=ON")
        source.execute("PRAGMA busy_timeout=250")
        destination = sqlite3.connect(target, timeout=0.25)
        destination.execute("PRAGMA busy_timeout=250")
        try:
            page_size = int(source.execute("PRAGMA page_size").fetchone()[0] or 4096)
        except Exception:
            page_size = 4096

        def backup_progress(status: int, remaining: int, total: int) -> None:
            nonlocal last_report
            check()
            now = time.monotonic()
            if now - last_report >= 0.65 or remaining <= 0:
                copied_pages = max(0, int(total) - int(remaining))
                copied_mb = copied_pages * page_size / (1024 * 1024)
                total_mb = max(0, int(total)) * page_size / (1024 * 1024)
                if status in (getattr(sqlite3, "SQLITE_BUSY", 5), getattr(sqlite3, "SQLITE_LOCKED", 6)):
                    progress(f"Ожидаю доступ к базе {path.name}: SQLite временно занята; прошло {time.monotonic() - started:.0f} с…")
                else:
                    progress(
                        f"Копирую {path.name}: {copied_pages:,}/{int(total):,} страниц "
                        f"({copied_mb:.1f}/{total_mb:.1f} МБ)".replace(",", " ")
                    )
                last_report = now

        progress(f"Открыта база {path.name}; создаю временную копию в режиме чтения…")
        # Incremental batches invoke backup_progress frequently, allowing a hard
        # timeout and responsive cancellation even for active/large profiles.
        source.backup(destination, pages=128, progress=backup_progress, sleep=0.02)
        check()
        destination.close()
        destination = None
        source.close()
        source = None
        result_uri = target.resolve().as_uri() + "?mode=ro"
        result = sqlite3.connect(result_uri, uri=True, timeout=2.0)
        result.row_factory = sqlite3.Row
        result.execute("PRAGMA query_only=ON")
        check()
        progress(f"Временная копия {path.name} готова; читаю записи истории…")
        return result, temp_dir
    except BaseException:
        if source is not None:
            source.close()
        if destination is not None:
            destination.close()
        temp_dir.cleanup()
        raise


def _chrome_time(value: Any) -> str:
    try:
        micros = int(value or 0)
        if micros <= 0:
            return ""
        dt = CHROME_EPOCH + timedelta(microseconds=micros)
        return dt.astimezone().isoformat(sep=" ", timespec="seconds")
    except Exception:
        return ""


def _firefox_time(value: Any) -> str:
    try:
        micros = int(value or 0)
        if micros <= 0:
            return ""
        return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc).astimezone().isoformat(sep=" ", timespec="seconds")
    except Exception:
        return ""


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {str(row[1]).casefold() for row in connection.execute(f'PRAGMA table_info("{table}")')}
    except sqlite3.Error:
        return set()


def _event(timestamp: str, kind: str, description: str, source: Path, browser: str, profile: str,
           url: str = "", title: str = "", domain_rules: dict[str, str] | None = None,
           details: dict[str, Any] | None = None, command: str = "") -> dict[str, Any]:
    parsed = urlparse(url) if url else None
    domain = normalize_domain(parsed.hostname if parsed else "")
    category, category_note = classify_domain(domain, domain_rules)
    local_day = timestamp[:10] if timestamp else ""
    local_clock = timestamp[11:19] if len(timestamp) >= 19 else ""
    payload = dict(details or {})
    payload.update({
        "browser": browser,
        "profile": profile,
        "url": url,
        "domain": domain,
        "domain_category": category,
        "domain_category_note": category_note,
        "title": title,
        "read_only": True,
        "note": "Запись прочитана из локальной базы истории браузера через временную копию. Посещение или запись о загрузке не доказывает запуск либо использование файла.",
    })
    return {
        "timestamp": timestamp,
        "date": local_day,
        "time": local_clock,
        "time_basis": "Временная метка из базы истории браузера; отображена в локальном часовом поясе.",
        "kind": kind,
        "description": description,
        "command": command,
        "source": str(source),
        "user": "",
        "details": payload,
    }


def _path_basename(value: Any) -> str:
    """Return a file name from either Windows or POSIX paths."""
    raw = str(value or "").rstrip("\\/")
    return re.split(r"[\\/]", raw)[-1] if raw else ""


def _latest_chromium_download_urls(
    connection: sqlite3.Connection,
    download_rows: list[sqlite3.Row],
    cancel_check: Callable[[], None] | None = None,
) -> dict[int, str]:
    """Read final URLs from modern Chromium downloads_url_chains when available."""
    try:
        tables = {str(r[0]).casefold() for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "downloads_url_chains" not in tables or not download_rows:
            return {}
        download_columns = _table_columns(connection, "downloads")
        chain_columns = _table_columns(connection, "downloads_url_chains")
        if not {"id"}.issubset(download_columns) or not {"id", "url"}.issubset(chain_columns):
            return {}
        order_column = "chain_index" if "chain_index" in chain_columns else "rowid"
        query = (
            "SELECT c.id, c.url FROM downloads_url_chains c "
            "JOIN (SELECT id FROM downloads ORDER BY start_time DESC LIMIT ?) d ON d.id=c.id "
            f"ORDER BY c.id, c.{order_column} DESC"
        )
        result: dict[int, str] = {}
        for item in connection.execute(query, (len(download_rows),)):
            if cancel_check:
                cancel_check()
            try:
                key = int(item["id"])
            except (TypeError, ValueError):
                continue
            result.setdefault(key, str(item["url"] or ""))
        return result
    except sqlite3.Error:
        return {}

def _scan_chromium(connection: sqlite3.Connection, browser: str, profile: str, path: Path,
                   rules: dict[str, str], limit: int,
                   cancel_check: Callable[[], None] | None = None) -> tuple[list[dict[str, Any]], int, int]:
    rows: list[dict[str, Any]] = []
    visits_count = 0
    downloads_count = 0
    tables = {str(r[0]).casefold() for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "urls" in tables and "visits" in tables:
        query = """SELECT u.url, COALESCE(u.title, '') AS title, u.visit_count,
                          v.visit_time, v.id AS visit_id
                   FROM visits v JOIN urls u ON u.id = v.url
                   ORDER BY v.visit_time DESC LIMIT ?"""
        for item in connection.execute(query, (limit,)):
            if cancel_check:
                cancel_check()
            url = str(item["url"] or "")
            ts = _chrome_time(item["visit_time"])
            rows.append(_event(ts, "browser_visit", "Посещение сайта в истории браузера", path, browser, profile,
                               url, str(item["title"] or ""), rules,
                               {"visit_id": item["visit_id"], "visit_count_for_url": item["visit_count"], "browser_time_raw": item["visit_time"]}))
            visits_count += 1
    if "downloads" in tables:
        columns = _table_columns(connection, "downloads")
        required = {"start_time"}
        if required.issubset(columns):
            download_rows = list(connection.execute("SELECT * FROM downloads ORDER BY start_time DESC LIMIT ?", (limit,)))
            chain_urls = _latest_chromium_download_urls(connection, download_rows, cancel_check)
            for item in download_rows:
                if cancel_check:
                    cancel_check()
                data = dict(item)
                download_id = data.get("id")
                try:
                    normalized_download_id = int(download_id) if download_id is not None else None
                except (TypeError, ValueError, OverflowError):
                    normalized_download_id = None
                chain_url = chain_urls.get(normalized_download_id, "") if normalized_download_id is not None else ""
                url = str(data.get("tab_url") or data.get("site_url") or data.get("url") or data.get("referrer") or chain_url or "")
                start = _chrome_time(data.get("start_time"))
                end = _chrome_time(data.get("end_time"))
                target = str(data.get("target_path") or data.get("current_path") or "")
                rows.append(_event(start, "browser_download", "Запись о загрузке в браузере", path, browser, profile,
                                   url, _path_basename(target), rules,
                                   {"target_path": target, "download_start": start, "download_end": end,
                                    "download_url_chain_final": chain_url,
                                    "received_bytes": data.get("received_bytes"), "total_bytes": data.get("total_bytes"),
                                    "state": data.get("state"), "danger_type": data.get("danger_type"),
                                    "interrupt_reason": data.get("interrupt_reason"), "browser_time_raw": data.get("start_time")},
                                   command=target))
                downloads_count += 1
    return rows, visits_count, downloads_count


def _scan_firefox(connection: sqlite3.Connection, browser: str, profile: str, path: Path,
                  rules: dict[str, str], limit: int,
                  cancel_check: Callable[[], None] | None = None) -> tuple[list[dict[str, Any]], int, int]:
    rows: list[dict[str, Any]] = []
    visits_count = 0
    downloads_count = 0
    tables = {str(r[0]).casefold() for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "moz_places" in tables and "moz_historyvisits" in tables:
        query = """SELECT p.url, COALESCE(p.title, '') AS title, p.visit_count,
                          v.visit_date, v.id AS visit_id
                   FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id
                   ORDER BY v.visit_date DESC LIMIT ?"""
        for item in connection.execute(query, (limit,)):
            if cancel_check:
                cancel_check()
            url = str(item["url"] or "")
            ts = _firefox_time(item["visit_date"])
            rows.append(_event(ts, "browser_visit", "Посещение сайта в истории Firefox", path, browser, profile,
                               url, str(item["title"] or ""), rules,
                               {"visit_id": item["visit_id"], "visit_count_for_url": item["visit_count"], "browser_time_raw": item["visit_date"]}))
            visits_count += 1

    # Legacy Firefox versions used moz_downloads. Newer versions may store
    # download annotations; inspect only annotation metadata, never passwords/cookies.
    if "moz_downloads" in tables:
        cols = _table_columns(connection, "moz_downloads")
        if "source" in cols:
            for item in connection.execute("SELECT * FROM moz_downloads LIMIT ?", (limit,)):
                if cancel_check:
                    cancel_check()
                data = dict(item)
                url = str(data.get("source") or "")
                target = str(data.get("target") or data.get("name") or "")
                raw_time = data.get("startTime") or data.get("start_time") or data.get("endTime")
                ts = _firefox_time(raw_time)
                rows.append(_event(ts, "browser_download", "Запись о загрузке в Firefox (legacy DB)", path, browser, profile,
                                   url, _path_basename(target) if target else "", rules,
                                   {"target_path": target, "state": data.get("state"), "browser_time_raw": raw_time}, command=target))
                downloads_count += 1

    if {"moz_annos", "moz_anno_attributes", "moz_places"}.issubset(tables):
        query = """SELECT p.url, a.content, n.name
                   FROM moz_annos a JOIN moz_anno_attributes n ON n.id=a.anno_attribute_id
                   LEFT JOIN moz_places p ON p.id=a.place_id
                   WHERE lower(n.name) LIKE '%download%' LIMIT ?"""
        for item in connection.execute(query, (limit,)):
            if cancel_check:
                cancel_check()
            raw = str(item["content"] or "")
            metadata: Any = None
            try:
                metadata = json.loads(raw)
            except Exception:
                metadata = raw
            if isinstance(metadata, dict):
                target = str(metadata.get("targetFile") or metadata.get("target") or metadata.get("file") or metadata.get("destinationFileURI") or "")
                source_url = str(metadata.get("sourceURI") or metadata.get("source") or item["url"] or "")
                raw_time = metadata.get("startTime") or metadata.get("endTime") or ""
            else:
                target = raw if "file://" in raw or re.search(r"(?i)\.(?:exe|jar|zip|7z|py|dll)(?:$|[?#])", raw) else ""
                source_url = str(item["url"] or "")
                raw_time = ""
            if not target and not source_url:
                continue
            rows.append(_event(_firefox_time(raw_time), "browser_download", "Метаданные загрузки из Firefox annotation", path, browser, profile,
                               source_url, _path_basename(target) if target else "", rules,
                               {"target_path": target, "annotation": str(item["name"] or ""), "raw_metadata_available": bool(raw)}, command=target))
            downloads_count += 1
    return rows, visits_count, downloads_count


def scan_browser_history(progress: Callable[[str], None] | None = None,
                         domain_rules: dict[str, str] | None = None,
                         limit_per_profile: int = 10000,
                         cancel_check: Callable[[], None] | None = None,
                         per_profile_timeout: float = DEFAULT_PROFILE_TIMEOUT_SECONDS,
                         total_timeout: float = DEFAULT_TOTAL_TIMEOUT_SECONDS) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Read current-user Chromium/Firefox history with per-profile/overall limits.

    First, active databases are opened directly in SQLite read-only mode inside a
    consistent transaction. SQLite reads committed WAL data while the browser
    remains open. If direct live access is unavailable, a read-only SQLite backup
    is attempted. Slow or locked profiles receive a bounded status and do not
    block later profiles. Cancellation interrupts backup and long SQL queries.
    """
    progress = progress or (lambda _message: None)
    check_cancel = cancel_check or (lambda: None)
    rules = {normalize_domain(k): v for k, v in (domain_rules or {}).items() if normalize_domain(k) and v in DOMAIN_CATEGORIES}
    events: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    warnings: list[str] = []
    scan_started = time.monotonic()
    check_cancel()
    profiles = _browser_profile_databases()
    check_cancel()
    found_browsers = {browser for browser, _profile, _path in profiles}
    supported = (
        "Google Chrome", "Google Chrome Beta", "Google Chrome Dev", "Google Chrome Canary",
        "Microsoft Edge", "Microsoft Edge Beta", "Microsoft Edge Dev", "Microsoft Edge Canary",
        "Brave", "Opera", "Opera GX", "Chromium", "Vivaldi", "Yandex Browser", "Mozilla Firefox",
    )
    for browser in supported:
        if browser not in found_browsers:
            sources.append({"type": "browser_history", "browser": browser, "status": "not_found", "records": 0,
                            "note": "Профиль браузера по стандартным путям текущего пользователя не найден; возможны нестандартный путь, другой профиль Windows или переносной браузер."})

    if not profiles:
        progress("Профили браузеров по стандартным путям не найдены. Проверь другой профиль Windows или нестандартное расположение браузера.")

    profile_count = len(profiles)
    for profile_index, (browser, profile, path) in enumerate(profiles, start=1):
        check_cancel()
        elapsed_total = time.monotonic() - scan_started
        if elapsed_total >= max(1.0, float(total_timeout)):
            note = (f"Общий лимит проверки браузеров ({total_timeout:.0f} с) исчерпан. "
                    "Оставшиеся профили не проверялись; это не означает отсутствие истории.")
            warnings.append(note)
            for pending_browser, pending_profile, pending_path in profiles[profile_index - 1:]:
                sources.append({"type": "browser_history", "browser": pending_browser, "profile": pending_profile,
                                "path": str(pending_path), "status": "not_scanned", "records": 0, "note": note})
            progress(note)
            break

        source = {"type": "browser_history", "browser": browser, "profile": profile, "path": str(path),
                  "status": "unknown", "records": 0}
        connection = None
        temp_dir = None
        deadline = _BrowserDeadline(per_profile_timeout, f"{browser}/{profile}", check_cancel)
        pending_sqlite_interrupt: list[BaseException] = []
        try:
            try:
                database_size = path.stat().st_size
            except OSError:
                database_size = 0
            progress(
                f"Читаю профиль {profile_index}/{profile_count}: {browser} / {profile}; "
                f"база {database_size / (1024 * 1024):.1f} МБ; лимит {per_profile_timeout:.0f} с"
            )
            deadline.check()
            read_mode = "live_readonly"
            try:
                connection = _sqlite_open_live_readonly(
                    path, cancel_check=deadline.check, progress=progress,
                )
            except sqlite3.Error as live_error:
                deadline.check()
                progress(
                    f"Прямое read-only чтение {browser}/{profile} недоступно "
                    f"({str(live_error)[:160]}). Пробую согласованную SQLite-копию…"
                )
                connection, temp_dir = _sqlite_readonly_backup(
                    path, cancel_check=deadline.check, progress=progress,
                )
                read_mode = "sqlite_backup"

            def sqlite_progress_handler() -> int:
                try:
                    deadline.check()
                    return 0
                except BaseException as exc:
                    pending_sqlite_interrupt.append(exc)
                    return 1

            # Interrupt expensive ORDER BY/JOIN operations if a database has an
            # unusual schema or lacks the indexes present in normal browser DBs.
            connection.set_progress_handler(sqlite_progress_handler, 10000)
            deadline.check()
            if browser == "Mozilla Firefox":
                rows, visits, downloads = _scan_firefox(connection, browser, profile, path, rules, limit_per_profile, deadline.check)
            else:
                rows, visits, downloads = _scan_chromium(connection, browser, profile, path, rules, limit_per_profile, deadline.check)
            deadline.check()
            events.extend(rows)
            source.update({
                "status": "available", "records": len(rows), "visits": visits, "downloads": downloads,
                "database_size_bytes": database_size, "read_mode": read_mode,
                "note": (
                    "Активная база прочитана в read-only транзакции SQLite; зафиксированный снимок "
                    "включает доступные committed WAL-записи. Браузер не закрывался, данные базы "
                    "утилитой не изменялись."
                    if read_mode == "live_readonly" else
                    "Для чтения использована временная копия через SQLite Backup API; исходная база "
                    "не открывалась на запись и не изменялась утилитой."
                ),
            })
            progress(f"Готово: {browser} / {profile} — посещений {visits}, загрузок {downloads}.")
        except BrowserSourceTimeout as exc:
            source.update({"status": "timeout", "note": str(exc)})
            warnings.append(str(exc))
            progress(f"Пропускаю медленный источник {browser} / {profile}; перехожу к следующему.")
        except PermissionError as exc:
            source.update({"status": "inaccessible", "note": str(exc)[:700]})
            warnings.append(f"Нет доступа к истории {browser} ({profile}): {exc}")
        except sqlite3.Error as exc:
            if pending_sqlite_interrupt:
                interrupted = pending_sqlite_interrupt[-1]
                if isinstance(interrupted, BrowserSourceTimeout):
                    source.update({"status": "timeout", "note": str(interrupted)})
                    warnings.append(str(interrupted))
                else:
                    raise interrupted
            else:
                try:
                    deadline.check()
                except BrowserSourceTimeout as timeout_exc:
                    source.update({"status": "timeout", "note": str(timeout_exc)})
                    warnings.append(str(timeout_exc))
                else:
                    source.update({"status": "error", "note": str(exc)[:700]})
                    warnings.append(f"Не удалось прочитать SQLite истории {browser} ({profile}): {exc}")
        except Exception as exc:
            # Cancellation is propagated to the scan controller, not downgraded
            # to an ordinary per-profile read error. A timeout is recorded and
            # the scanner proceeds to the next profile.
            if pending_sqlite_interrupt:
                interrupted = pending_sqlite_interrupt[-1]
                if isinstance(interrupted, BrowserSourceTimeout):
                    source.update({"status": "timeout", "note": str(interrupted)})
                    warnings.append(str(interrupted))
                else:
                    raise interrupted
            else:
                try:
                    deadline.check()
                except BrowserSourceTimeout as timeout_exc:
                    source.update({"status": "timeout", "note": str(timeout_exc)})
                    warnings.append(str(timeout_exc))
                except BaseException:
                    raise
                else:
                    source.update({"status": "error", "note": str(exc)[:700]})
                    warnings.append(f"Ошибка анализа истории {browser} ({profile}): {exc}")
        finally:
            if connection is not None:
                try:
                    connection.set_progress_handler(None, 0)
                except sqlite3.Error:
                    pass
                connection.close()
            if temp_dir is not None:
                temp_dir.cleanup()
        sources.append(source)

    check_cancel()
    events.sort(key=lambda row: str(row.get("timestamp", "")), reverse=True)
    return events, sources, warnings

