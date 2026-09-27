"""Application initialization sub-package.

Each module handles one tier of the startup sequence:
  database.py    — PostgreSQL pools, data stores, owner bootstrap
  security.py    — PIN auth, policy engine, scanners, scan pipeline
  orchestrator.py — Ollama health, planner, tool executor, integrations
  channels.py    — messaging channels, routines, heartbeat, route wiring
  shutdown.py    — ordered 11-step shutdown sequence

The thin lifespan() context manager in sentinel.api.lifecycle calls these
in order and owns the module-level globals that tests patch.
"""

import logging

logger = logging.getLogger(__name__)
