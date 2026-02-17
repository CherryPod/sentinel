"""Tests for router configuration settings."""

from sentinel.core.config import Settings


class TestRouterConfig:
    def test_router_enabled_default_true(self):
        s = Settings()
        assert s.router_enabled is True

    def test_router_classifier_timeout_default(self):
        s = Settings()
        assert s.router_classifier_timeout == 10.0

    def test_router_classifier_model_default_empty(self):
        s = Settings()
        assert s.router_classifier_model == ""
