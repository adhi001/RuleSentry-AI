from pytest import raises

from rulesentry.engine import ENGINE_REGISTRY, EngineRegistry, SigmaSubsetEngine


def test_default_registry_exposes_sigma_engine():
    assert ENGINE_REGISTRY.available_formats() == ("sigma",)
    assert isinstance(ENGINE_REGISTRY.get("SIGMA"), SigmaSubsetEngine)


def test_registry_rejects_duplicate_engine_registration():
    registry = EngineRegistry()
    registry.register(SigmaSubsetEngine())
    with raises(ValueError, match="already registered"):
        registry.register(SigmaSubsetEngine())


def test_registry_can_replace_engine_explicitly():
    registry = EngineRegistry()
    registry.register(SigmaSubsetEngine())
    replacement = SigmaSubsetEngine()
    registry.register(replacement, replace=True)
    assert registry.get("sigma") is replacement


def test_registry_reports_unknown_format_and_available_formats():
    with raises(ValueError, match="Available formats: sigma"):
        ENGINE_REGISTRY.get("splunk")
