"""Tier 2: pretrained prompt-injection classifier, run locally on CPU via ONNX.

Optional extra: ``pip install "toolgate-pin[classifier]"``. The model weights
(~700 MB) are downloaded from Hugging Face on first use into the HF cache,
pinned to one commit.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from typing import Any

MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
# Commit of the model repo (Apache-2.0, ships onnx/model.onnx), checked 2026-10-18.
MODEL_REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"
ONNX_FILE = "onnx/model.onnx"
TOKENIZER_FILE = "onnx/tokenizer.json"
INJECTION_INDEX = 1  # id2label in onnx/config.json: 0 SAFE, 1 INJECTION
MAX_TOKENS = 512


def available() -> bool:
    """True when onnxruntime, tokenizers and huggingface_hub are importable."""
    return all(
        importlib.util.find_spec(m) is not None
        for m in ("onnxruntime", "tokenizers", "huggingface_hub")
    )


def texts_of(tool: dict[str, Any]) -> list[str]:
    """The tool description, then every description inside inputSchema."""
    out: list[str] = []
    if isinstance(tool.get("description"), str):
        out.append(tool["description"])

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "description" and isinstance(value, str):
                    out.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(tool.get("inputSchema"))
    return [t for t in out if t.strip()]


class ClassifierLoadError(RuntimeError):
    """The model could not be loaded; raised again, without retrying, on every
    later ``score`` call of the same instance."""


class Classifier:
    def __init__(self, *, revision: str = MODEL_REVISION) -> None:
        self.revision = revision
        self._session: Any = None
        self._tokenizer: Any = None
        # Exception type of a failed load (never a message: it may hold a URL).
        self.load_error: str | None = None

    def _ensure_loaded(self) -> None:
        if self.load_error is not None:
            raise ClassifierLoadError(
                f"classifier model unavailable ({self.load_error})"
            )
        if self._session is not None:
            return
        try:
            self._load()
        except Exception as exc:
            self.load_error = type(exc).__name__
            raise ClassifierLoadError(
                f"classifier model unavailable ({self.load_error})"
            ) from exc

    def _load(self) -> None:
        # Symlinks are unavailable on many Windows setups; the cache still works.
        os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
        from huggingface_hub import hf_hub_download, try_to_load_from_cache
        from onnxruntime import InferenceSession
        from tokenizers import Tokenizer

        cached = try_to_load_from_cache(MODEL_ID, ONNX_FILE, revision=self.revision)
        if not isinstance(cached, str):
            print(
                f"toolgate-pin: downloading classifier model {MODEL_ID} "
                "(~700 MB, first use only)",
                file=sys.stderr,
            )
        model = hf_hub_download(MODEL_ID, ONNX_FILE, revision=self.revision)
        tok = hf_hub_download(MODEL_ID, TOKENIZER_FILE, revision=self.revision)
        tokenizer = Tokenizer.from_file(tok)
        tokenizer.enable_truncation(max_length=MAX_TOKENS)
        self._tokenizer = tokenizer
        self._session = InferenceSession(model, providers=["CPUExecutionProvider"])

    def _score_text(self, text: str) -> float:
        import numpy as np

        enc = self._tokenizer.encode(text)
        feeds = {
            "input_ids": np.array([enc.ids], dtype=np.int64),
            "attention_mask": np.array([enc.attention_mask], dtype=np.int64),
        }
        names = {i.name for i in self._session.get_inputs()}
        logits = self._session.run(
            None, {k: v for k, v in feeds.items() if k in names}
        )[0][0]
        exp = np.exp(logits - logits.max())
        return float((exp / exp.sum())[INJECTION_INDEX])

    def score(self, tool: dict[str, Any]) -> float:
        """Max injection probability over the description and parameter descriptions."""
        self._ensure_loaded()
        return max((self._score_text(t) for t in texts_of(tool)), default=0.0)
