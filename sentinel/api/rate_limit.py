"""Shared rate limiter instance for Sentinel API routes.

Imported by app.py and any route module that uses @limiter.limit().
"""

import logging

from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)


limiter = Limiter(key_func=get_remote_address)
