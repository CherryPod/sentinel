"""Shared rate limiter instance for Sentinel API routes.

Imported by app.py and any route module that uses @limiter.limit().
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
