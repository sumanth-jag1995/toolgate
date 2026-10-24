import sys

import pytest
from servicing_agent.config import ConfigError, ModelConfig, load_models
from servicing_agent.models import make_chat_model

SECRET = "sk-or-SUPERSECRETVALUE123"


def test_openrouter_factory_uses_base_url_and_key_from_env():
    cfg = ModelConfig(provider="openrouter", model="openai/gpt-4o-mini", max_tokens=77)
    model = make_chat_model(cfg, env={"OPENROUTER_API_KEY": SECRET})
    assert model.model_name == "openai/gpt-4o-mini"
    assert model.openai_api_base == "https://openrouter.ai/api/v1"
    assert model.openai_api_key.get_secret_value() == SECRET
    assert model.temperature == 0.0
    assert model.max_tokens == 77


def test_custom_base_url():
    cfg = ModelConfig(
        provider="openrouter", model="m", base_url="http://localhost:1/v1"
    )
    model = make_chat_model(cfg, env={"OPENROUTER_API_KEY": SECRET})
    assert model.openai_api_base == "http://localhost:1/v1"


def test_missing_key_names_variable_not_value():
    cfg = ModelConfig(provider="openrouter", model="m", api_key_env="MY_KEY_VAR")
    with pytest.raises(ConfigError) as exc:
        make_chat_model(cfg, env={"OTHER": SECRET})
    assert "MY_KEY_VAR" in str(exc.value)
    assert SECRET not in str(exc.value)


def test_bedrock_without_extra_raises_config_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "langchain_aws", None)
    with pytest.raises(ConfigError, match=r"servicing-agent\[bedrock\]"):
        make_chat_model(
            ModelConfig(provider="bedrock", model="anthropic.claude"), env={}
        )


def test_unknown_provider_rejected(tmp_path):
    p = tmp_path / "models.yaml"
    p.write_text("a:\n  provider: nope\n  model: x\n")
    with pytest.raises(ConfigError) as exc:
        load_models(p)
    assert str(p) in str(exc.value)
    with pytest.raises(ConfigError):
        make_chat_model(ModelConfig(provider="nope", model="x"), env={})  # type: ignore[arg-type]


def test_malformed_yaml_rejected(tmp_path):
    p = tmp_path / "models.yaml"
    p.write_text("a: [unclosed\n")
    with pytest.raises(ConfigError):
        load_models(p)


def test_load_models_ok(tmp_path):
    p = tmp_path / "models.yaml"
    p.write_text("fast:\n  provider: openrouter\n  model: m1\n  temperature: 0.2\n")
    models = load_models(p)
    assert models["fast"] == ModelConfig(
        provider="openrouter", model="m1", temperature=0.2
    )


def test_repr_hides_key():
    cfg = ModelConfig(provider="openrouter", model="m")
    model = make_chat_model(cfg, env={"OPENROUTER_API_KEY": SECRET})
    assert SECRET not in repr(model)
    assert SECRET not in str(model)
    assert SECRET not in repr(cfg)


def test_bedrock_branch_builds_with_fake_module(monkeypatch):
    import types

    seen: dict = {}

    class FakeConverse:
        def __init__(self, **kwargs):
            seen.update(kwargs)

    fake = types.ModuleType("langchain_aws")
    fake.ChatBedrockConverse = FakeConverse  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "langchain_aws", fake)
    cfg = ModelConfig(
        provider="bedrock",
        model="some.model-id",
        region="us-east-1",
        temperature=0.0,
        max_tokens=512,
    )
    make_chat_model(cfg, env={})
    assert seen == {
        "model_id": "some.model-id",
        "region_name": "us-east-1",
        "temperature": 0.0,
        "max_tokens": 512,
    }


def test_bedrock_without_region_passes_no_region(monkeypatch):
    import types

    seen: dict = {}

    class FakeConverse:
        def __init__(self, **kwargs):
            seen.update(kwargs)

    fake = types.ModuleType("langchain_aws")
    fake.ChatBedrockConverse = FakeConverse  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "langchain_aws", fake)
    make_chat_model(ModelConfig(provider="bedrock", model="m"), env={})
    assert "region_name" not in seen


def test_bedrock_missing_extra_is_config_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "langchain_aws", None)
    with pytest.raises(ConfigError, match=r"servicing-agent\[bedrock\]"):
        make_chat_model(
            ModelConfig(provider="bedrock", model="m", region="us-east-1"), env={}
        )


def test_region_field_loads_from_yaml(tmp_path):
    p = tmp_path / "models.yaml"
    p.write_text("a:\n  provider: bedrock\n  model: m\n  region: eu-west-1\n")
    assert load_models(p)["a"].region == "eu-west-1"
