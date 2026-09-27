"""Weather tool with dual backends (Met Office UK, Open-Meteo worldwide).

Geocodes location names via Open-Meteo's free geocoding API, then routes
UK locations to Met Office Weather DataHub and everywhere else to Open-Meteo.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

# Moved to sentinel.core.exceptions (SH-3) — re-exported here.
from sentinel.core.exceptions import WeatherError


@dataclass
class WeatherResult:
    """Normalised weather result from any backend."""

    location: str
    temperature_c: float
    conditions: str
    wind_speed_mph: float
    wind_direction: str
    humidity_pct: int
    forecast: list[dict] | None = None
    source: str = ""


# WMO Weather interpretation codes (WMO 4677)
WMO_WEATHER_CODES: dict[int, str] = {
    0: "clear sky",
    1: "mainly clear",
    2: "partly cloudy",
    3: "overcast",
    45: "fog",
    48: "depositing rime fog",
    51: "light drizzle",
    53: "moderate drizzle",
    55: "dense drizzle",
    56: "light freezing drizzle",
    57: "dense freezing drizzle",
    61: "light rain",
    63: "moderate rain",
    65: "heavy rain",
    66: "light freezing rain",
    67: "heavy freezing rain",
    71: "light snow",
    73: "moderate snow",
    75: "heavy snow",
    77: "snow grains",
    80: "light rain showers",
    81: "moderate rain showers",
    82: "violent rain showers",
    85: "light snow showers",
    86: "heavy snow showers",
    95: "thunderstorm",
    96: "thunderstorm with light hail",
    99: "thunderstorm with heavy hail",
}

# Met Office significant weather codes
MET_OFFICE_WEATHER_CODES: dict[int, str] = {
    0: "clear night",
    1: "sunny day",
    2: "partly cloudy night",
    3: "partly cloudy day",
    5: "mist",
    6: "fog",
    7: "cloudy",
    8: "overcast",
    9: "light rain shower night",
    10: "light rain shower day",
    11: "drizzle",
    12: "light rain",
    13: "heavy rain shower night",
    14: "heavy rain shower day",
    15: "heavy rain",
    16: "sleet shower night",
    17: "sleet shower day",
    18: "sleet",
    19: "hail shower night",
    20: "hail shower day",
    21: "hail",
    22: "light snow shower night",
    23: "light snow shower day",
    24: "light snow",
    25: "heavy snow shower night",
    26: "heavy snow shower day",
    27: "heavy snow",
    28: "thunder shower night",
    29: "thunder shower day",
    30: "thunder",
}


def _degrees_to_compass(degrees: float) -> str:
    """Convert wind direction degrees to compass bearing."""
    directions = [
        "N",
        "NNE",
        "NE",
        "ENE",
        "E",
        "ESE",
        "SE",
        "SSE",
        "S",
        "SSW",
        "SW",
        "WSW",
        "W",
        "WNW",
        "NW",
        "NNW",
    ]
    idx = round(degrees / 22.5) % 16
    return directions[idx]


def _kmh_to_mph(kmh: float) -> float:
    """Convert km/h to mph."""
    return round(kmh * 0.621371, 1)


def _ms_to_mph(ms: float) -> float:
    """Convert m/s to mph."""
    return round(ms * 2.23694, 1)


class GeocodingService:
    """Open-Meteo geocoding with in-memory cache."""

    def __init__(self, api_url: str, timeout: int = 10):
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout
        # ASYNCIO SAFETY: Instance dict mutated across awaits in geocode().
        # TOCTOU between cache check and cache write is benign — worst case is a
        # duplicate API call, not data corruption. Single-threaded event loop
        # guarantees individual dict operations are atomic.
        self._cache: dict[str, dict] = {}

    async def geocode(self, location: str) -> dict:
        """Geocode a location name to lat/lon/country.

        Returns dict with keys: latitude, longitude, country_code, display_name.
        """
        # Strip whitespace and trailing punctuation that LLMs often pass through
        location = location.strip().rstrip("?!.,;:")
        cache_key = location.lower()

        if cache_key in self._cache:
            logger.debug(
                "Geocode cache hit",
                extra={"event": "geocode.cache_hit", "location": location},
            )
            return self._cache[cache_key]

        logger.debug(
            "Geocode cache miss",
            extra={"event": "geocode.cache_miss", "location": location},
        )

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{self._api_url}/search",
                    params={"name": location, "count": 1},
                )
        except httpx.TimeoutException as exc:
            raise WeatherError(f"Geocoding timed out: {exc}") from exc
        except httpx.ConnectError as exc:
            raise WeatherError(f"Geocoding unavailable: {exc}") from exc

        if resp.status_code != 200:
            raise WeatherError(f"Geocoding returned {resp.status_code}")

        data = resp.json()
        results = data.get("results", [])
        if not results:
            raise WeatherError(f"No results for location: {location}")

        hit = results[0]
        result = {
            "latitude": hit["latitude"],
            "longitude": hit["longitude"],
            "country_code": hit.get("country_code", ""),
            "display_name": hit.get("name", location),
        }

        self._cache[cache_key] = result
        logger.debug(
            "Geocoded location",
            extra={
                "event": "weather.geocode",
                "location": location,
                "lat": result["latitude"],
                "lon": result["longitude"],
                "country_code": result["country_code"],
                "cache_hit": False,
            },
        )
        return result


class WeatherBackend(ABC):
    """Abstract base for weather backends."""

    @abstractmethod
    async def fetch(self, lat: float, lon: float, location_name: str) -> WeatherResult:
        """Fetch weather for coordinates."""


class OpenMeteoBackend(WeatherBackend):
    """Open-Meteo forecast backend — free, worldwide, no auth."""

    def __init__(self, api_url: str, timeout: int = 10):
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout

    async def fetch(self, lat: float, lon: float, location_name: str) -> WeatherResult:
        """Fetch current weather + 3-day forecast."""
        logger.debug(
            "fetch called",
            extra={
                "event": "weather.fetch",
                "lat": lat,
                "lon": lon,
                "location_name": location_name,
            },
        )  # auto:entry
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{self._api_url}/forecast",
                    params={
                        "latitude": lat,
                        "longitude": lon,
                        "current": "temperature_2m,weather_code,wind_speed_10m,wind_direction_10m,relative_humidity_2m",
                        "daily": "weather_code,temperature_2m_max,temperature_2m_min",
                        "timezone": "auto",
                        "forecast_days": 3,
                    },
                )
        except httpx.TimeoutException as exc:
            raise WeatherError(f"Open-Meteo request timed out: {exc}") from exc
        except httpx.ConnectError as exc:
            raise WeatherError(f"Open-Meteo unavailable: {exc}") from exc

        if resp.status_code != 200:
            raise WeatherError(f"Open-Meteo returned {resp.status_code}")

        data = resp.json()
        current = data.get("current", {})
        daily = data.get("daily", {})

        weather_code = current.get("weather_code", -1)
        conditions = WMO_WEATHER_CODES.get(weather_code, "unknown")

        wind_kmh = current.get("wind_speed_10m", 0)
        wind_dir = current.get("wind_direction_10m", 0)

        # Build daily forecast
        forecast = []
        times = daily.get("time", [])
        codes = daily.get("weather_code", [])
        maxs = daily.get("temperature_2m_max", [])
        mins = daily.get("temperature_2m_min", [])
        for i in range(len(times)):
            forecast.append(
                {
                    "date": times[i],
                    "max_c": maxs[i] if i < len(maxs) else None,
                    "min_c": mins[i] if i < len(mins) else None,
                    "conditions": WMO_WEATHER_CODES.get(
                        codes[i] if i < len(codes) else -1,
                        "unknown",
                    ),
                }
            )

        return WeatherResult(
            location=location_name,
            temperature_c=current.get("temperature_2m", 0.0),
            conditions=conditions,
            wind_speed_mph=_kmh_to_mph(wind_kmh),
            wind_direction=_degrees_to_compass(wind_dir),
            humidity_pct=int(current.get("relative_humidity_2m", 0)),
            forecast=forecast or None,
            source="openmeteo",
        )


class MetOfficeBackend(WeatherBackend):
    """Met Office Weather DataHub Global Spot backend — UK only, API key required."""

    def __init__(self, api_url: str, api_key: str, timeout: int = 10):
        self._api_url = api_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    async def fetch(self, lat: float, lon: float, location_name: str) -> WeatherResult:
        """Fetch current weather from Met Office Global Spot."""
        logger.debug(
            "fetch called",
            extra={
                "event": "weather.fetch",
                "lat": lat,
                "lon": lon,
                "location_name": location_name,
            },
        )  # auto:entry
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{self._api_url}/point/hourly",
                    params={
                        "latitude": lat,
                        "longitude": lon,
                    },
                    headers={
                        "apikey": self._api_key,
                        "Accept": "application/json",
                    },
                )
        except httpx.TimeoutException as exc:
            raise WeatherError(f"Met Office request timed out: {exc}") from exc
        except httpx.ConnectError as exc:
            raise WeatherError(f"Met Office unavailable: {exc}") from exc

        if resp.status_code == 429:
            raise WeatherError("Met Office rate limited (360/day)")
        if resp.status_code != 200:
            raise WeatherError(f"Met Office returned {resp.status_code}")

        data = resp.json()
        features = data.get("features", [])
        if not features:
            raise WeatherError("Met Office returned no features")

        ts = features[0].get("properties", {}).get("timeSeries", [])
        if not ts:
            raise WeatherError("Met Office returned no timeSeries")

        # Use the first (most recent) time step
        current = ts[0]
        weather_code = current.get("significantWeatherCode", -1)
        conditions = MET_OFFICE_WEATHER_CODES.get(weather_code, "unknown")

        wind_ms = current.get("windSpeed10m", 0)
        wind_dir = current.get("windDirectionFrom10m", 0)

        return WeatherResult(
            location=location_name,
            temperature_c=current.get("screenTemperature", 0.0),
            conditions=conditions,
            wind_speed_mph=_ms_to_mph(wind_ms),
            wind_direction=_degrees_to_compass(wind_dir),
            humidity_pct=int(current.get("screenRelativeHumidity", 0)),
            forecast=None,
            source="metoffice",
        )


def format_weather(result: WeatherResult) -> str:
    """Format a WeatherResult for LLM/human consumption."""
    line = (
        f"{result.location}: {result.temperature_c:.0f}°C, {result.conditions}, "
        f"wind {result.wind_speed_mph:.0f}mph {result.wind_direction}, "
        f"humidity {result.humidity_pct}%"
    )

    if result.forecast:
        parts = []
        for day in result.forecast:
            date = day.get("date", "?")
            # Shorten ISO date to day name if possible
            try:
                from datetime import datetime

                dt = datetime.fromisoformat(date)
                date = dt.strftime("%a")
            except (ValueError, TypeError):
                logger.debug(
                    "format_weather: ValueError | TypeError suppressed",
                    extra={"event": "weather.format_weather.suppressed"},
                    exc_info=True,
                )
            max_c = day.get("max_c")
            min_c = day.get("min_c")
            cond = day.get("conditions", "?")
            if max_c is not None and min_c is not None:
                parts.append(f"{date} {max_c:.0f}°C/{min_c:.0f}°C {cond}")
            else:
                parts.append(f"{date} {cond}")
        line += f"\nForecast: {', '.join(parts)}"

    return line
