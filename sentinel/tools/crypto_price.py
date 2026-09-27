"""Cryptocurrency price tool with pluggable backends (CoinGecko, Binance).

CoinGecko provides rich data (multi-currency, 24h change, market cap).
Binance provides real-time USD ticker for major trading pairs.
Both are unauthenticated read-only endpoints.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# Moved to sentinel.core.exceptions (SH-3) — re-exported here.
from sentinel.core.exceptions import CryptoPriceError


@dataclass
class CryptoPrice:
    """Normalised price result from any backend."""

    coin: str
    price_usd: float
    price_gbp: float | None = None
    change_24h: float | None = None
    market_cap_usd: float | None = None
    source: str = ""


# Major coin map: frozenset of aliases -> (coingecko_id, binance_symbol)
MAJOR_COIN_MAP: dict[frozenset[str], tuple[str, str]] = {
    frozenset({"bitcoin", "btc"}): ("bitcoin", "BTCUSDT"),
    frozenset({"ethereum", "eth"}): ("ethereum", "ETHUSDT"),
    frozenset({"solana", "sol"}): ("solana", "SOLUSDT"),
    frozenset({"xrp", "ripple"}): ("ripple", "XRPUSDT"),
    frozenset({"cardano", "ada"}): ("cardano", "ADAUSDT"),
    frozenset({"polkadot", "dot"}): ("polkadot", "DOTUSDT"),
    frozenset({"chainlink", "link"}): ("chainlink", "LINKUSDT"),
    frozenset({"avalanche", "avax"}): ("avalanche-2", "AVAXUSDT"),
    frozenset({"dogecoin", "doge"}): ("dogecoin", "DOGEUSDT"),
    frozenset({"polygon", "matic"}): ("matic-network", "MATICUSDT"),
}

# Flattened lookup: alias -> (coingecko_id, binance_symbol)
_ALIAS_LOOKUP: dict[str, tuple[str, str]] = {}
for _aliases, _ids in MAJOR_COIN_MAP.items():
    for _alias in _aliases:
        _ALIAS_LOOKUP[_alias] = _ids


def normalise_coin(coin: str) -> tuple[str, str | None]:
    """Normalise user input to (coingecko_id, binance_symbol | None).

    Returns (coin_as_is, None) for unknown coins.
    """
    key = coin.lower().strip()
    if key in _ALIAS_LOOKUP:
        return _ALIAS_LOOKUP[key]
    return (key, None)


class CryptoBackend(ABC):
    """Abstract base for crypto price backends."""

    @abstractmethod
    async def fetch(self, symbol: str) -> CryptoPrice:
        """Fetch price for a symbol. Symbol format is backend-specific."""


class CoinGeckoBackend(CryptoBackend):
    """CoinGecko /simple/price backend — rich data, 1-5 min lag."""

    def __init__(self, api_url: str, timeout: int = 10):
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout

    async def fetch(self, coin_id: str) -> CryptoPrice:
        """Fetch price by CoinGecko coin ID (e.g. 'bitcoin')."""
        logger.debug(
            "fetch called", extra={"event": "crypto_price.fetch", "coin_id": coin_id}
        )  # auto:entry
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{self._api_url}/simple/price",
                    params={
                        "ids": coin_id,
                        "vs_currencies": "gbp,usd",
                        "include_24hr_change": "true",
                        "include_market_cap": "true",
                    },
                )
        except httpx.TimeoutException as exc:
            raise CryptoPriceError(f"CoinGecko request timed out: {exc}") from exc
        except httpx.ConnectError as exc:
            raise CryptoPriceError(f"CoinGecko unavailable: {exc}") from exc

        if resp.status_code == 429:
            raise CryptoPriceError("CoinGecko rate limited")
        if resp.status_code != 200:
            raise CryptoPriceError(f"CoinGecko returned {resp.status_code}")

        data = resp.json()
        coin_data = data.get(coin_id, {})
        if not coin_data:
            raise CryptoPriceError(f"No data for coin: {coin_id}")

        return CryptoPrice(
            coin=coin_id,
            price_usd=coin_data.get("usd", 0.0),
            price_gbp=coin_data.get("gbp"),
            change_24h=coin_data.get("usd_24h_change"),
            market_cap_usd=coin_data.get("usd_market_cap"),
            source="coingecko",
        )


class BinanceBackend(CryptoBackend):
    """Binance /ticker/price backend — real-time, USD only."""

    def __init__(self, api_url: str, timeout: int = 10):
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout

    async def fetch(self, binance_symbol: str) -> CryptoPrice:
        """Fetch price by Binance trading pair (e.g. 'BTCUSDT')."""
        logger.debug(
            "fetch called",
            extra={"event": "crypto_price.fetch", "binance_symbol": binance_symbol},
        )  # auto:entry
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{self._api_url}/ticker/price",
                    params={"symbol": binance_symbol},
                )
        except httpx.TimeoutException as exc:
            raise CryptoPriceError(f"Binance request timed out: {exc}") from exc
        except httpx.ConnectError as exc:
            raise CryptoPriceError(f"Binance unavailable: {exc}") from exc

        if resp.status_code == 429:
            raise CryptoPriceError("Binance rate limited")
        if resp.status_code != 200:
            raise CryptoPriceError(f"Binance returned {resp.status_code}")

        data = resp.json()
        price = float(data.get("price", 0.0))

        # Reverse-lookup the canonical coin name from the Binance symbol
        coin_name = binance_symbol.replace("USDT", "").lower()
        for _aliases, (cg_id, bsym) in MAJOR_COIN_MAP.items():
            if bsym == binance_symbol:
                coin_name = cg_id
                break

        return CryptoPrice(
            coin=coin_name,
            price_usd=price,
            price_gbp=None,
            change_24h=None,
            market_cap_usd=None,
            source="binance",
        )


def _format_market_cap(cap: float) -> str:
    """Format market cap with T/B suffix."""
    if cap >= 1_000_000_000_000:
        return f"${cap / 1_000_000_000_000:.2f}T"
    if cap >= 1_000_000_000:
        return f"${cap / 1_000_000_000:.2f}B"
    return f"${cap:,.0f}"


def format_price(result: CryptoPrice) -> str:
    """Format a CryptoPrice for LLM/human consumption."""
    logger.debug(
        "format_price called",
        extra={
            "event": "crypto_price.format_price",
            "result_len": len(result) if hasattr(result, "__len__") else 0,
        },
    )  # auto:entry
    coin_upper = result.coin.upper()
    # Find the ticker symbol (shortest alias = most likely the ticker, e.g. "btc" not "bitcoin")
    for aliases, (cg_id, _) in MAJOR_COIN_MAP.items():
        if cg_id == result.coin:
            coin_upper = min(aliases, key=len).upper()
            break

    parts = []

    if result.price_gbp is not None:
        parts.append(
            f"{coin_upper}: £{result.price_gbp:,.0f} / ${result.price_usd:,.0f}"
        )
    else:
        parts.append(f"{coin_upper}: ${result.price_usd:,.0f}")

    if result.change_24h is not None:
        arrow = "↑" if result.change_24h >= 0 else "↓"
        parts.append(f"({arrow}{abs(result.change_24h):.2f}% 24h)")

    if result.market_cap_usd is not None:
        parts.append(f"— Market cap: {_format_market_cap(result.market_cap_usd)}")

    return " ".join(parts)
