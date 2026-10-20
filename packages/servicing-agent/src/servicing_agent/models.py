"""Chat-model provider factory (OpenRouter now, Amazon Bedrock swappable)."""

from __future__ import annotations

import os
from collections.abc import Mapping

from langchain_core.language_models.chat_models import BaseChatModel

from servicing_agent.config import ConfigError, ModelConfig

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def make_chat_model(
    cfg: ModelConfig, *, env: Mapping[str, str] = os.environ
) -> BaseChatModel:
    if cfg.provider == "openrouter":
        key = env.get(cfg.api_key_env)
        if not key:
            raise ConfigError(
                None, f"missing API key: environment variable {cfg.api_key_env}"
            )
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=cfg.model,
            base_url=cfg.base_url or OPENROUTER_BASE_URL,
            api_key=key,  # type: ignore[arg-type]  # coerced to SecretStr
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,  # type: ignore[call-arg]
        )
    if cfg.provider == "bedrock":
        try:
            from langchain_aws import ChatBedrockConverse
        except ImportError:
            raise ConfigError(None, "install servicing-agent[bedrock]") from None
        return ChatBedrockConverse(
            model_id=cfg.model, temperature=cfg.temperature, max_tokens=cfg.max_tokens
        )
    raise ConfigError(None, "unknown provider")
