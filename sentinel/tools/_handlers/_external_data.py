"""External data handler mixin — web search, X search, crypto, weather.

Extracted from executor.py during Phase 1 structural refactor.
The mixin expects these attributes on self (provided by ToolExecutor):
  - _engine: PolicyEngine instance
  - _trust_level: current trust level
"""

import logging

from sentinel.core.models import DataSource, TaggedData, TrustLevel
from sentinel.security.provenance import create_tagged_data
from sentinel.tools._handlers._registry import tool_handler
from sentinel.tools._handlers._types import ToolError

logger = logging.getLogger(__name__)


class ExternalDataHandlerMixin:
    """External data tool handlers (web search, X search, crypto, weather)."""

    @tool_handler(
        "web_search",
        description="Search the web for current information. Results are UNTRUSTED external data. Use for real-time data, news, current events — not for general knowledge questions.",
        args={
            "query": "string (search query)",
            "count": "integer (number of results, default 5, max 10)",
        },
        group="external_data",
        order=40,
    )
    async def _web_search(self, args: dict) -> tuple[TaggedData, dict | None]:
        """Execute a web search via the configured backend."""
        logger.debug(
            "_web_search called",
            extra={
                "event": "_external_data._web_search",
                "args_len": len(args) if hasattr(args, "__len__") else 0,
            },
        )  # auto:entry
        from sentinel.core.config import settings
        from sentinel.tools.web_search import (
            SearchError,
            create_search_backend,
            format_results,
        )

        if not settings.web_search_enabled:
            raise ToolError("Web search is disabled")

        query = args.get("query", "").strip()
        if not query:
            raise ToolError("Search query is required")

        try:
            count = min(int(args.get("count", 5)), settings.web_search_max_results)
        except (ValueError, TypeError):
            raise ToolError("'count' must be a valid integer")

        try:
            backend = create_search_backend(settings)
            results = await backend.search(query, count)
        except SearchError as e:
            logger.warning(
                "web_search: backend error",
                extra={"event": "_external_data.web_search.error", "error": str(e)},
                exc_info=True,
            )
            raise ToolError("Web search failed:") from e

        content = format_results(results)
        return await create_tagged_data(
            content=content,
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from=f"web_search:{settings.web_search_backend}",
        ), None

    @tool_handler(
        "x_search",
        description="Search X (Twitter) for posts, trends, and discussions about a topic. Use for social media activity, public sentiment, trending topics, what people are saying. Results are UNTRUSTED external data.",
        args={
            "query": "string (what to search for on X)",
            "count": "integer (max posts to consider, default 5, max 10)",
        },
        group="external_data",
        order=40,
    )
    async def _x_search(self, args: dict) -> tuple[TaggedData, dict | None]:
        """Search X (Twitter) via Grok API."""
        logger.debug(
            "_x_search called",
            extra={
                "event": "_external_data._x_search",
                "args_len": len(args) if hasattr(args, "__len__") else 0,
            },
        )  # auto:entry
        from sentinel.core.config import settings
        from sentinel.tools.x_search import XSearchError, search_x

        if not settings.x_search_enabled:
            raise ToolError("X search is disabled")

        query = args.get("query", "").strip()
        if not query:
            raise ToolError("Search query is required")

        try:
            content = await search_x(
                query,
                api_url=settings.x_search_api_url,
                api_key_file=settings.x_search_api_key_file,
                model=settings.x_search_model,
                timeout=settings.x_search_timeout,
            )
        except XSearchError as e:
            logger.warning(
                "x_search: backend error",
                extra={"event": "_external_data.x_search.error", "error": str(e)},
                exc_info=True,
            )
            raise ToolError("X search failed:") from e

        return await create_tagged_data(
            content=content,
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from="x_search:grok",
        ), None

    @tool_handler(
        "crypto_price",
        description="Get current cryptocurrency price and market data. Returns price in GBP and USD, 24h change, and market cap. Use backend 'coingecko' for rich data.",
        args={
            "coin": "string (cryptocurrency name or symbol, e.g. 'bitcoin', 'BTC', 'ethereum')",
            "currency": "string (optional, output currencies, default 'gbp,usd')",
            "backend": "string (optional, 'coingecko' for rich data or 'binance' for real-time USD, default 'coingecko')",
        },
        group="external_data",
        order=40,
    )
    async def _crypto_price(self, args: dict) -> tuple[TaggedData, dict | None]:
        """Fetch cryptocurrency price via CoinGecko or Binance."""
        import time

        from sentinel.core.config import settings
        from sentinel.core.context import get_task_id
        from sentinel.tools.crypto_price import (
            BinanceBackend,
            CoinGeckoBackend,
            CryptoPriceError,
            format_price,
            normalise_coin,
        )

        logger.debug(
            "_crypto_price called",
            extra={"event": "crypto.price", "symbol": args.get("symbol", "")},
        )
        if not settings.crypto_enabled:
            logger.debug(
                "_crypto_price: not_crypto_enabled",
                extra={
                    "event": "_external_data._crypto_price.match",
                    "reason": "not_crypto_enabled",
                },
            )  # auto:neg
            raise ToolError("Crypto price tool is disabled")
        logger.debug(
            "_crypto_price: not_crypto_enabled_passed",
            extra={
                "event": "_external_data._crypto_price.passed",
                "reason": "not_crypto_enabled_passed",
            },
        )  # auto:neg

        coin_input = args.get("coin", "").strip()
        if not coin_input:
            logger.debug(
                "_crypto_price: not_coin_input",
                extra={
                    "event": "_external_data._crypto_price.match",
                    "reason": "not_coin_input",
                },
            )  # auto:neg
            raise ToolError("Coin name or symbol is required")

        backend_name = args.get("backend", "binance").lower()
        cg_id, binance_sym = normalise_coin(coin_input)

        logger.info(
            "Crypto price request",
            extra={
                "event": "crypto.price_request",
                "coin": cg_id,
                "backend": backend_name,
                "task_id": get_task_id(),
            },
        )

        start = time.monotonic()

        # If Binance requested but coin not in major map, fall back to CoinGecko
        if backend_name == "binance" and binance_sym is None:
            logger.warning(
                "Coin not in major map, falling back to CoinGecko",
                extra={
                    "event": "crypto.price_fallback",
                    "coin": cg_id,
                    "original_backend": "binance",
                },
            )
            backend_name = "coingecko"

        try:
            if backend_name == "binance":
                logger.debug(
                    "_crypto_price: backend_name_eq_binance",
                    extra={
                        "event": "_external_data._crypto_price.match",
                        "reason": "backend_name_eq_binance",
                    },
                )  # auto:neg
                backend = BinanceBackend(
                    api_url=settings.crypto_binance_api_url,
                    timeout=settings.crypto_timeout,
                )
                result = await backend.fetch(binance_sym)
            else:
                logger.debug(
                    "_crypto_price: backend_name_eq_binance",
                    extra={
                        "event": "_external_data._crypto_price.clean",
                        "reason": "backend_name_eq_binance",
                    },
                )  # auto:neg
                backend = CoinGeckoBackend(
                    api_url=settings.crypto_coingecko_api_url,
                    timeout=settings.crypto_timeout,
                )
                result = await backend.fetch(cg_id)
        except CryptoPriceError as e:
            logger.exception(
                "Crypto price fetch failed",
                extra={
                    "event": "crypto.price_error",
                    "coin": cg_id,
                    "backend": backend_name,
                    "error": str(e),
                },
            )
            raise ToolError("Crypto price failed:") from e

        latency_ms = round((time.monotonic() - start) * 1000)
        logger.info(
            "Crypto price result",
            extra={
                "event": "crypto.price_result",
                "coin": cg_id,
                "backend": backend_name,
                "price_usd": result.price_usd,
                "latency_ms": latency_ms,
            },
        )

        content = format_price(result)
        return await create_tagged_data(
            content=content,
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from=f"crypto_price:{backend_name}",
        ), None

    @tool_handler(
        "weather",
        description="Get current weather and forecast for a location. Defaults to Aylesbury if no location specified. Uses Met Office for UK locations, Open-Meteo for worldwide.",
        args={
            "location": "string (optional, place name e.g. 'Leeds', 'Tokyo', 'New York')",
        },
        group="external_data",
        order=40,
    )
    async def _weather(self, args: dict) -> tuple[TaggedData, dict | None]:
        """Fetch weather via Met Office (UK) or Open-Meteo (worldwide)."""
        import time

        from sentinel.core.config import settings
        from sentinel.core.context import get_task_id
        from sentinel.tools.weather import (
            GeocodingService,
            MetOfficeBackend,
            OpenMeteoBackend,
            WeatherError,
            format_weather,
        )

        if not settings.weather_enabled:
            raise ToolError("Weather tool is disabled")

        location = args.get("location", "").strip()
        if not location:
            location = settings.weather_default_location

        logger.info(
            "Weather request",
            extra={
                "event": "weather.request",
                "location": location,
                "task_id": get_task_id(),
            },
        )

        start = time.monotonic()

        # Geocode
        geocoder = GeocodingService(
            api_url=settings.weather_geocoding_api_url,
            timeout=settings.weather_timeout,
        )
        try:
            geo = await geocoder.geocode(location)
        except WeatherError as e:
            logger.warning(
                "weather: geocoding error",
                extra={"event": "_external_data.weather.geocode_error", "error": str(e)},
                exc_info=True,
            )
            raise ToolError("Geocoding failed:") from e

        lat = geo["latitude"]
        lon = geo["longitude"]
        country = geo["country_code"]
        display_name = geo["display_name"]

        # Route: UK -> Met Office, else -> Open-Meteo
        backend_name = "metoffice" if country == "GB" else "openmeteo"

        logger.info(
            "Weather backend selected",
            extra={
                "event": "weather.backend_selected",
                "location": display_name,
                "backend": backend_name,
            },
        )

        try:
            if backend_name == "metoffice":
                try:
                    from sentinel.tools.web_search import _load_api_key

                    api_key = _load_api_key(settings.weather_metoffice_api_key_file)
                except Exception:  # catch-all: API key load fallback
                    # If key can't be loaded, fall back to Open-Meteo
                    logger.warning(
                        "Met Office API key unavailable, falling back to Open-Meteo",
                        extra={
                            "event": "weather.metoffice_fallback",
                            "location": display_name,
                            "error": "API key not found",
                        },
                        exc_info=True,
                    )
                    backend_name = "openmeteo"

            if backend_name == "metoffice":
                mo_backend = MetOfficeBackend(
                    api_url=settings.weather_metoffice_api_url,
                    api_key=api_key,
                    timeout=settings.weather_timeout,
                )
                try:
                    result = await mo_backend.fetch(lat, lon, display_name)
                except WeatherError as e:
                    # Met Office failed — fall back to Open-Meteo
                    logger.warning(
                        "Met Office failed, falling back to Open-Meteo",
                        extra={
                            "event": "weather.metoffice_fallback",
                            "location": display_name,
                            "error": str(e),
                        },
                        exc_info=True,
                    )
                    backend_name = "openmeteo"

            if backend_name == "openmeteo":
                om_backend = OpenMeteoBackend(
                    api_url=settings.weather_openmeteo_api_url,
                    timeout=settings.weather_timeout,
                )
                result = await om_backend.fetch(lat, lon, display_name)

        except WeatherError as e:
            logger.exception(
                "All weather backends failed",
                extra={
                    "event": "weather.error",
                    "location": display_name,
                    "error": str(e),
                },
            )
            raise ToolError("Weather failed:") from e

        latency_ms = round((time.monotonic() - start) * 1000)
        logger.info(
            "Weather result",
            extra={
                "event": "weather.result",
                "location": display_name,
                "backend": backend_name,
                "temperature_c": result.temperature_c,
                "latency_ms": latency_ms,
            },
        )

        content = format_weather(result)
        return await create_tagged_data(
            content=content,
            source=DataSource.WEB,
            trust_level=TrustLevel.UNTRUSTED,
            originated_from=f"weather:{backend_name}",
        ), None
