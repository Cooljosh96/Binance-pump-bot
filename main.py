#!/usr/bin/env python3
"""Binance USDT listing and unusual-volume Telegram alert bot.

The bot intentionally uses only Python's standard library. It polls Binance's
public Spot API, keeps a small local state file, and sends alerts through the
Telegram Bot API.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


DEFAULT_BINANCE_API_BASE = "https://data-api.binance.vision"
BINANCE_API_FALLBACKS = (
    "https://data-api.binance.vision",
    "https://api.binance.com",
    "https://api1.binance.com",
    "https://api2.binance.com",
    "https://api3.binance.com",
)
TELEGRAM_API_BASE = "https://api.telegram.org"
DEFAULT_STATE_FILE = "data/binance-alert-state.json"
USER_AGENT = "binance-usdt-alert-bot/1.0"

logger = logging.getLogger("binance-alert-bot")


def env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}, got {value}")
    return value


def env_float(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}, got {value}")
    return value


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false, got {raw!r}")


def format_usdt(value: float) -> str:
    if value >= 1_000_000_000:
        return f"${value / 1_000_000_000:.2f}B"
    if value >= 1_000_000:
        return f"${value / 1_000_000:.2f}M"
    if value >= 1_000:
        return f"${value / 1_000:.1f}K"
    return f"${value:,.0f}"


def format_price(value: float) -> str:
    if value == 0:
        return "n/a"
    if value >= 1:
        return f"{value:,.4f}".rstrip("0").rstrip(".")
    return f"{value:.8f}".rstrip("0").rstrip(".")


def format_age(milliseconds: int) -> str:
    age_seconds = max(0, int(time.time() - milliseconds / 1000))
    if age_seconds < 60:
        return f"{age_seconds}s ago"
    if age_seconds < 3600:
        return f"{age_seconds // 60}m ago"
    if age_seconds < 86400:
        return f"{age_seconds // 3600}h {(age_seconds % 3600) // 60}m ago"
    return f"{age_seconds // 86400}d ago"


@dataclass(frozen=True)
class Config:
    telegram_bot_token: str
    telegram_chat_id: str
    poll_interval_seconds: int
    volume_multiplier: float
    minimum_quote_volume_usdt: float
    baseline_alpha: float
    volume_alert_cooldown_seconds: int
    pump_price_change_percent: float
    pump_volume_spike: float
    pump_cooldown_seconds: int
    pump_history_samples: int
    new_listing_window_hours: int
    request_timeout_seconds: int
    binance_api_base_url: str
    state_file: Path
    dry_run: bool

    @classmethod
    def from_environment(cls) -> "Config":
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        dry_run = env_bool("DRY_RUN", False)

        missing = []
        if not token and not dry_run:
            missing.append("TELEGRAM_BOT_TOKEN")
        if not chat_id and not dry_run:
            missing.append("TELEGRAM_CHAT_ID")
        if missing:
            joined = ", ".join(missing)
            raise ValueError(
                f"Missing required environment variable(s): {joined}. "
                "Set them in Replit Secrets/environment variables, or set DRY_RUN=true "
                "to validate Binance polling without sending Telegram messages."
            )

        return cls(
            telegram_bot_token=token,
            telegram_chat_id=chat_id,
            poll_interval_seconds=env_int("POLL_INTERVAL_SECONDS", 60, 10),
            volume_multiplier=env_float("VOLUME_MULTIPLIER", 3.0, 1.1),
            minimum_quote_volume_usdt=env_float(
                "MIN_QUOTE_VOLUME_USDT", 1_000_000.0, 0
            ),
            baseline_alpha=env_float("BASELINE_ALPHA", 0.2, 0.01),
            volume_alert_cooldown_seconds=env_int(
                "VOLUME_ALERT_COOLDOWN_SECONDS", 21_600, 0
            ),
            pump_price_change_percent=env_float(
                "PUMP_PRICE_CHANGE_PERCENT", 3.0, 0.1
            ),
            pump_volume_spike=env_float("PUMP_VOLUME_SPIKE", 2.0, 1.1),
            pump_cooldown_seconds=env_int("PUMP_COOLDOWN_SECONDS", 1_800, 0),
            pump_history_samples=env_int("PUMP_HISTORY_SAMPLES", 6, 3),
            new_listing_window_hours=env_int("NEW_LISTING_WINDOW_HOURS", 24, 1),
            request_timeout_seconds=env_int("REQUEST_TIMEOUT_SECONDS", 20, 5),
            binance_api_base_url=os.getenv(
                "BINANCE_API_BASE_URL", DEFAULT_BINANCE_API_BASE
            ).rstrip("/"),
            state_file=Path(os.getenv("STATE_FILE", DEFAULT_STATE_FILE)),
            dry_run=dry_run,
        )


class JsonState:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {
            "known_symbols": {},
            "volume_baselines": {},
            "last_alerts": {},
            "pump_history": {},
            "initialized_at": None,
        }
        self.is_new = not path.exists()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.data.update(loaded)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not load state file %s: %s; starting fresh", self.path, exc)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(f"{self.path.suffix}.tmp")
        temporary.write_text(
            json.dumps(self.data, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        temporary.replace(self.path)


class HttpClient:
    def __init__(self, timeout_seconds: int) -> None:
        self.timeout_seconds = timeout_seconds

    def get_json(self, url: str) -> Any:
        request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"HTTP {exc.code} from {url}: {body}") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Request failed for {url}: {exc}") from exc

    def post_form(self, url: str, values: dict[str, str]) -> Any:
        encoded = "&".join(f"{quote(key)}={quote(value)}" for key, value in values.items())
        request = Request(
            url,
            data=encoded.encode("utf-8"),
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"HTTP {exc.code} from Telegram: {body}") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Telegram request failed: {exc}") from exc


class BinanceClient:
    def __init__(self, http: HttpClient, primary_base_url: str) -> None:
        self.http = http
        self.base_urls = tuple(dict.fromkeys([primary_base_url, *BINANCE_API_FALLBACKS]))

    def _get_json(self, path: str) -> Any:
        errors: list[str] = []
        for base_url in self.base_urls:
            try:
                return self.http.get_json(f"{base_url}{path}")
            except RuntimeError as exc:
                errors.append(f"{base_url}: {exc}")
                logger.warning("Binance endpoint failed: %s", exc)
        raise RuntimeError(
            "All configured Binance market-data endpoints failed. "
            + " | ".join(errors)
        )

    def usdt_symbols(self) -> dict[str, dict[str, Any]]:
        payload = self._get_json("/api/v3/exchangeInfo")
        if not isinstance(payload, dict) or not isinstance(payload.get("symbols"), list):
            raise RuntimeError("Binance exchangeInfo returned an unexpected response")

        result: dict[str, dict[str, Any]] = {}
        for symbol in payload["symbols"]:
            if not isinstance(symbol, dict):
                continue
            if (
                symbol.get("quoteAsset") == "USDT"
                and symbol.get("status") == "TRADING"
                and symbol.get("isSpotTradingAllowed", True)
            ):
                name = symbol.get("symbol")
                if isinstance(name, str):
                    result[name] = symbol
        return result

    def twenty_four_hour_tickers(self) -> dict[str, dict[str, Any]]:
        payload = self._get_json("/api/v3/ticker/24hr")
        if not isinstance(payload, list):
            raise RuntimeError("Binance 24hr ticker returned an unexpected response")

        result: dict[str, dict[str, Any]] = {}
        for ticker in payload:
            if not isinstance(ticker, dict):
                continue
            symbol = ticker.get("symbol")
            if isinstance(symbol, str):
                result[symbol] = ticker
        return result


class TelegramClient:
    def __init__(self, http: HttpClient, token: str, chat_id: str, dry_run: bool) -> None:
        self.http = http
        self.token = token
        self.chat_id = chat_id
        self.dry_run = dry_run

    def send_message(self, text: str) -> None:
        if self.dry_run:
            logger.info("DRY RUN Telegram message:\n%s", text.replace("<", "").replace(">", ""))
            return

        url = f"{TELEGRAM_API_BASE}/bot{self.token}/sendMessage"
        payload = self.http.post_form(
            url,
            {
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": "true",
            },
        )
        if not isinstance(payload, dict) or not payload.get("ok"):
            raise RuntimeError(f"Telegram rejected the message: {payload}")


def html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def make_new_listing_alert(symbol: str, listing: dict[str, Any], ticker: dict[str, Any]) -> str:
    price = float(ticker.get("lastPrice") or 0)
    quote_volume = float(ticker.get("quoteVolume") or 0)
    onboard_date = int(listing.get("onboardDate") or 0)
    listed_line = format_age(onboard_date) if onboard_date > 0 else "recently observed"
    return (
        "🆕 <b>New Binance USDT listing</b>\n\n"
        f"<b>{html_escape(symbol)}</b>\n"
        f"Listed: {html_escape(listed_line)}\n"
        f"Price: <code>{format_price(price)} USDT</code>\n"
        f"24h volume: <b>{format_usdt(quote_volume)}</b>\n"
        f'<a href="https://www.binance.com/en/trade/{symbol}?type=spot">Open on Binance</a>'
    )


def make_volume_alert(
    symbol: str,
    ticker: dict[str, Any],
    current_volume: float,
    baseline: float,
    multiplier: float,
) -> str:
    price = float(ticker.get("lastPrice") or 0)
    price_change = float(ticker.get("priceChangePercent") or 0)
    direction = "+" if price_change >= 0 else ""
    return (
        "📈 <b>Unusual Binance volume</b>\n\n"
        f"<b>{html_escape(symbol)}</b>\n"
        f"24h volume: <b>{format_usdt(current_volume)}</b>\n"
        f"Baseline: {format_usdt(baseline)}\n"
        f"Spike: <b>{current_volume / baseline:.1f}×</b> "
        f"(threshold {multiplier:.1f}×)\n"
        f"24h price change: <b>{direction}{price_change:.2f}%</b>\n"
        f"Price: <code>{format_price(price)} USDT</code>\n"
        f'<a href="https://www.binance.com/en/trade/{symbol}?type=spot">Open on Binance</a>'
    )


def make_pump_alert(
    symbol: str,
    ticker: dict[str, Any],
    price: float,
    price_change: float,
    volume_ratio: float,
    window_minutes: float,
    volume_spike_threshold: float,
) -> str:
    price_change_sign = "+" if price_change >= 0 else ""
    price_change_line = f"{price_change_sign}{price_change:.2f}%"
    return (
        "🚨 <b>Binance pump alert</b>\n\n"
        f"<b>{html_escape(symbol)}</b>\n"
        f"Price: <code>{format_price(price)} USDT</code>\n"
        f"Price change: <b>{price_change_line}</b> in {window_minutes:.1f}m\n"
        f"Volume-rate spike: <b>{volume_ratio:.1f}×</b> "
        f"(threshold {volume_spike_threshold:.1f}×)\n"
        f"24h volume: <b>{format_usdt(float(ticker.get('quoteVolume') or 0))}</b>\n"
        f'<a href="https://www.binance.com/en/trade/{symbol}?type=spot">Open on Binance</a>'
    )


class AlertBot:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.http = HttpClient(config.request_timeout_seconds)
        self.binance = BinanceClient(self.http, config.binance_api_base_url)
        self.telegram = TelegramClient(
            self.http,
            config.telegram_bot_token,
            config.telegram_chat_id,
            config.dry_run,
        )
        self.state = JsonState(config.state_file)
        self.stop_requested = False

    def request_stop(self, _signum: int, _frame: Any) -> None:
        logger.info("Shutdown requested; stopping after the current cycle")
        self.stop_requested = True

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, self.request_stop)

        logger.info(
            "Starting Binance alert bot: poll=%ss, multiplier=%.1fx, minimum volume=%s, api=%s, state=%s",
            self.config.poll_interval_seconds,
            self.config.volume_multiplier,
            format_usdt(self.config.minimum_quote_volume_usdt),
            self.config.binance_api_base_url,
            self.config.state_file,
        )
        if self.config.dry_run:
            logger.warning("DRY_RUN=true; Telegram messages will only be logged")

        while not self.stop_requested:
            started = time.monotonic()
            try:
                self.check_once()
            except Exception:
                logger.exception("Check cycle failed; will retry on the next cycle")
            elapsed = time.monotonic() - started
            sleep_seconds = max(1, self.config.poll_interval_seconds - int(elapsed))
            if not self.stop_requested:
                time.sleep(sleep_seconds)

        self.state.save()
        logger.info("Bot stopped cleanly")

    def check_once(self) -> None:
        listings = self.binance.usdt_symbols()
        tickers = self.binance.twenty_four_hour_tickers()
        now = int(time.time())
        known_symbols: dict[str, int] = self.state.data.setdefault("known_symbols", {})
        baselines: dict[str, float] = self.state.data.setdefault("volume_baselines", {})
        last_alerts: dict[str, int] = self.state.data.setdefault("last_alerts", {})
        pump_history: dict[str, list[list[float]]] = self.state.data.setdefault(
            "pump_history", {}
        )

        alerts_sent = 0
        first_run = self.state.data.get("initialized_at") is None
        listing_window_ms = self.config.new_listing_window_hours * 60 * 60 * 1000

        for symbol, listing in listings.items():
            ticker = tickers.get(symbol)
            if not ticker:
                continue

            current_volume = float(ticker.get("quoteVolume") or 0)
            if current_volume < 0:
                continue

            onboard_date = int(listing.get("onboardDate") or 0)
            is_recent_listing = (
                onboard_date > 0
                and (now * 1000 - onboard_date) <= listing_window_ms
            )
            is_new_to_bot = symbol not in known_symbols

            if is_new_to_bot:
                should_alert = not first_run or is_recent_listing
                known_symbols[symbol] = now
                if should_alert:
                    self.send_alert(make_new_listing_alert(symbol, listing, ticker), f"new listing {symbol}")
                    alerts_sent += 1

            previous_baseline = float(baselines.get(symbol, 0) or 0)
            if previous_baseline > 0 and current_volume >= self.config.minimum_quote_volume_usdt:
                last_alert = int(last_alerts.get(f"volume:{symbol}", 0) or 0)
                cooldown_over = now - last_alert >= self.config.volume_alert_cooldown_seconds
                if current_volume >= previous_baseline * self.config.volume_multiplier and cooldown_over:
                    self.send_alert(
                        make_volume_alert(
                            symbol,
                            ticker,
                            current_volume,
                            previous_baseline,
                            self.config.volume_multiplier,
                        ),
                        f"unusual volume {symbol}",
                    )
                    last_alerts[f"volume:{symbol}"] = now
                    alerts_sent += 1

            if previous_baseline <= 0:
                baselines[symbol] = current_volume
            else:
                alpha = self.config.baseline_alpha
                baselines[symbol] = (alpha * current_volume) + ((1 - alpha) * previous_baseline)

            history = pump_history.setdefault(symbol, [])
            history.append([float(now), float(ticker.get("lastPrice") or 0), current_volume])
            if len(history) > self.config.pump_history_samples:
                del history[:-self.config.pump_history_samples]

            if len(history) >= self.config.pump_history_samples:
                first_timestamp, old_price, _ = history[0]
                _, price, _ = history[-1]
                price_change = ((price - old_price) / old_price * 100) if old_price > 0 else 0
                volume_changes = [
                    history[index][2] - history[index - 1][2]
                    for index in range(1, len(history))
                ]
                previous_changes = volume_changes[:-1]
                recent_change = volume_changes[-1]
                positive_previous_changes = [
                    change for change in previous_changes if change > 0
                ]
                average_previous_change = (
                    sum(positive_previous_changes) / len(positive_previous_changes)
                    if positive_previous_changes
                    else 0
                )
                volume_ratio = (
                    recent_change / average_previous_change
                    if average_previous_change > 0
                    else 0
                )
                pump_last_alert = int(
                    last_alerts.get(f"pump:{symbol}", 0) or 0
                )
                pump_cooldown_over = (
                    now - pump_last_alert >= self.config.pump_cooldown_seconds
                )
                if (
                    price_change >= self.config.pump_price_change_percent
                    and volume_ratio >= self.config.pump_volume_spike
                    and pump_cooldown_over
                ):
                    window_minutes = max(0.1, (now - first_timestamp) / 60)
                    self.send_alert(
                        make_pump_alert(
                            symbol,
                            ticker,
                            price,
                            price_change,
                            volume_ratio,
                            window_minutes,
                            self.config.pump_volume_spike,
                        ),
                        f"pump {symbol}",
                    )
                    last_alerts[f"pump:{symbol}"] = now
                    alerts_sent += 1

        self.state.data["initialized_at"] = self.state.data.get("initialized_at") or now
        self.state.save()
        logger.info(
            "Checked %d USDT pairs; %d alert(s); %d known pair(s); %d pump histories",
            len(listings),
            alerts_sent,
            len(known_symbols),
            len(pump_history),
        )

    def send_alert(self, message: str, description: str) -> None:
        try:
            self.telegram.send_message(message)
            logger.info("Sent %s alert", description)
        except Exception:
            logger.exception("Could not send %s alert", description)


def configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main() -> None:
    configure_logging()
    try:
        config = Config.from_environment()
        AlertBot(config).run()
    except ValueError as exc:
        logger.error("%s", exc)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
