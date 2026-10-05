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

    def unusual_5m_volume(self, symbol: str, lookback_candles: int = 12) -> tuple[float, float, float] | None:
        """Return latest closed 5m volume, prior 1h average, and spike ratio."""
        limit = lookback_candles + 2
        try:
            payload = self._get_json(
                f"/api/v3/klines?symbol={symbol}&interval=5m&limit={limit}"
            )
        except RuntimeError as exc:
            logger.warning("Could not fetch 5m volume for %s: %s", symbol, exc)
            return None

        if not isinstance(payload, list) or len(payload) < lookback_candles + 1:
            return None

        # Ignore the currently forming candle.
        closed = payload[:-1]
        latest = closed[-1]
        previous = closed[-(lookback_candles + 1):-1]
        try:
            latest_volume = float(latest[7])
            average_volume = sum(float(kline[7]) for kline in previous) / len(previous)
        except (IndexError, TypeError, ValueError, ZeroDivisionError):
            return None

        if average_volume <= 0:
            return None
        return latest_volume, average_volume, latest_volume / average_volume

    def taker_buy_sell_volume(
        self, symbol: str, interval: str = "5m"
    ) -> tuple[float, float] | None:
        """Return buy and sell quote volume for the latest closed candle.

        Binance kline field 10 is taker-buy quote volume. The remainder of
        the candle's quote volume is treated as sell volume.
        """
        try:
            payload = self._get_json(
                f"/api/v3/klines?symbol={symbol}&interval={interval}&limit=2"
            )
        except RuntimeError as exc:
            logger.warning("Could not fetch buy/sell volume for %s: %s", symbol, exc)
            return None

        if not isinstance(payload, list) or not payload:
            return None

        kline = payload[-2] if len(payload) >= 2 else payload[-1]

        try:
            total_quote_volume = float(kline[7])
            buy_quote_volume = float(kline[10])
        except (IndexError, TypeError, ValueError):
            return None

        sell_quote_volume = max(0.0, total_quote_volume - buy_quote_volume)
        return buy_quote_volume, sell_quote_volume

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


def make_buy_sell_line(buy_sell: tuple[float, float] | None) -> str:
    if buy_sell is None:
        return "Buy/Sell volume: unavailable for latest closed 5m candle\n"

    buy_volume, sell_volume = buy_sell
    total = buy_volume + sell_volume
    if total <= 0:
        return "Buy/Sell volume: unavailable for latest closed 5m candle\n"

    buy_pct = buy_volume / total * 100
    sell_pct = sell_volume / total * 100

    if buy_pct >= 60:
        pressure = "🔥 STRONG BUY pressure"
    elif buy_pct >= 55:
        pressure = "🟢 BUY pressure"
    elif sell_pct >= 60:
        pressure = "⚠️ STRONG SELL pressure"
    elif sell_pct >= 55:
        pressure = "🔴 SELL pressure"
    else:
        pressure = "⚪ BALANCED"

    return (
        f"Buy volume (5m): 🟢 <b>{format_usdt(buy_volume)}</b> ({buy_pct:.0f}%)\n"
        f"Sell volume (5m): 🔴 <b>{format_usdt(sell_volume)}</b> ({sell_pct:.0f}%)\n"
        f"Pressure: <b>{pressure}</b>\n"
    )


def make_unusual_5m_volume_alert(
    symbol: str,
    ticker: dict[str, Any],
    latest_volume: float,
    average_volume: float,
    multiplier: float,
    buy_sell: tuple[float, float] | None = None,
) -> str:
    price = float(ticker.get("lastPrice") or 0)
    price_change = float(ticker.get("priceChangePercent") or 0)
    direction = "+" if price_change >= 0 else ""
    return (
        "📈 <b>Unusual Binance volume</b>\n\n"
        f"<b>{html_escape(symbol)}</b>\n"
        f"5m volume: <b>{format_usdt(latest_volume)}</b>\n"
        f"Previous 1h avg (5m): {format_usdt(average_volume)}\n"
        f"Spike: <b>{latest_volume / average_volume:.1f}×</b> "
        f"(threshold {multiplier:.1f}×)\n"
        f"24h volume: <b>{format_usdt(float(ticker.get('quoteVolume') or 0))}</b>\n"
        f"24h price change: <b>{direction}{price_change:.2f}%</b>\n"
        f"{make_buy_sell_line(buy_sell)}"
        f"Price: <code>{format_price(price)} USDT</code>\n"
        f'📈 <a href="https://www.tradingview.com/chart/?symbol=BINANCE:{symbol}">Open on TradingView</a>\n'
        f'🟡 <a href="https://www.binance.com/en/trade/{symbol}?type=spot">Open on Binance</a>'
    )


def make_volume_alert(
    symbol: str,
    ticker: dict[str, Any],
    current_volume: float,
    baseline: float,
    multiplier: float,
    buy_sell: tuple[float, float] | None = None,
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
        f"{make_buy_sell_line(buy_sell)}"
        f"Price: <code>{format_price(price)} USDT</code>\n"
        f'📈 <a href="https://www.tradingview.com/chart/?symbol=BINANCE:{symbol}">Open on TradingView</a>\n'
        f'🟡 <a href="https://www.binance.com/en/trade/{symbol}?type=spot">Open on Binance</a>'
    )


def make_pump_alert(
    symbol: str,
    ticker: dict[str, Any],
    price: float,
    price_change: float,
    volume_ratio: float,
    window_minutes: float,
    volume_spike_threshold: float,
    buy_sell: tuple[float, float] | None = None,
) -> str:
    price_change_sign = "+" if price_change >= 0 else ""
    price_change_line = f"{price_change_sign}{price_change:.2f}%"
    return (
        "🚨 <b>Binance pump alert</b>\n\n"
        f"<b>{html_escape(symbol)}</b>\\n"
        f"Price: <code>{format_price(price)} USDT</code>\n"
        f"Price change: <b>{price_change_line}</b> in {window_minutes:.1f}m\n"
        f"Volume-rate spike: <b>{volume_ratio:.1f}×</b> "
        f"(threshold {volume_spike_threshold:.1f}×)\n"
        f"24h volume: <b>{format_usdt(float(ticker.get('quoteVolume') or 0))}</b>\n"
        f"{make_buy_sell_line(buy_sell)}"
        f'📈 <a href="https://www.tradingview.com/chart/?symbol=BINANCE:{symbol}">Open on TradingView</a>\n'
        f'🟡 <a href="https://www.binance.com/en/trade/{symbol}?type=spot">Open on Binance</a>'
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
            self.co
