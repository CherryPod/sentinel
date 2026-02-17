"""Route modules for the Sentinel API.

DI Contract — init() globals pattern
=====================================

Every route module in this package follows the same dependency-injection
pattern used throughout the codebase (contacts.py, red_team.py, etc.).
This avoids introducing FastAPI ``Depends()`` into a codebase that uses
it nowhere, and keeps test setup trivial.

Pattern (reference implementation: ``sentinel/api/contacts.py``):

1. **Router**
   ``router = APIRouter(prefix="/api")``
   (or no prefix for non-API routes like static files / health)

2. **Module-level globals** — prefixed with underscore, initialised to
   ``None``.  One per dependency (store, service, config value).
   ::

       _orchestrator: Any = None
       _session_store: Any = None

3. **init() function** — called once from ``app.py`` lifespan to inject
   real dependencies.  Signature uses ``**kwargs`` or explicit params.
   ::

       def init(*, orchestrator, session_store, **_kwargs) -> None:
           global _orchestrator, _session_store
           _orchestrator = orchestrator
           _session_store = session_store

4. **_get_*() accessors** — each global has a helper that returns it or
   raises HTTP 503 if lifespan hasn't run yet.  Route handlers call
   these, never the raw global.
   ::

       def _get_orchestrator():
           if _orchestrator is None:
               raise HTTPException(503, "Orchestrator not available")
           return _orchestrator

5. **Testing** — two approaches, both proven in the codebase:

   a. Call ``module.init(orchestrator=mock, ...)`` in test setup, then
      hit the real router via ``TestClient``.  (Used by test_contact_api)

   b. Build a minimal ``FastAPI()`` app in the fixture, include the
      router, call ``init()``, yield a ``TestClient``.  Keeps test
      isolation tight — each test file owns its app instance.

   Either way: no monkey-patching, no ``Depends()`` overrides, no
   special test harness.
"""
