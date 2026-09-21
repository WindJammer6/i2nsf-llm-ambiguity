"""Provider-neutral policy-generation calls for OpenAI and Google models."""
from __future__ import annotations

import importlib.metadata
import os
import time
from typing import Any, TypeVar

from pydantic import BaseModel

OPENAI_API_KEY = "YOUR-OPENAI-API-KEY-HERE"
GEMINI_API_KEY = "YOUR-GEMINI-API-KEY-HERE"


POLICY_MODELS = {
    "gpt-4o-mini": {
        "provider": "openai",
        "api_model": "gpt-4o-mini",
        "structured_output": "openai-pydantic-parse",
    },
    "gemini-2.5-flash": {
        "provider": "google",
        "api_model": "gemini-2.5-flash",
        "structured_output": "google-response-schema-pydantic",
    },
    "gemini-2.5-flash-lite": {
        "provider": "google",
        "api_model": "gemini-2.5-flash-lite",
        "structured_output": "google-response-schema-pydantic",
    },
    "gemini-flash-latest": {
        "provider": "google",
        "api_model": "gemini-flash-latest",
        "structured_output": "google-response-schema-pydantic",
    },
    "gemini-3.6-flash": {
        "provider": "google",
        "api_model": "gemini-3.6-flash",
        "structured_output": "google-interactions-json-schema-pydantic",
    },
    "gemini-3.5-flash": {
        "provider": "google",
        "api_model": "gemini-3.5-flash",
        "structured_output": "google-interactions-json-schema-pydantic",
    },    
    "gemini-3.5-flash-lite": {
        "provider": "google",
        "api_model": "gemini-3.5-flash-lite",
        "structured_output": "google-generate-content-json-schema-pydantic",
    },
}
DEFAULT_POLICY_MODEL = "gpt-4o-mini"
DEFAULT_TEMPERATURE = 1.0
DEFAULT_MAX_OUTPUT_TOKENS = 16384
DEFAULT_GEMINI_THINKING_BUDGET = 0
GOOGLE_REQUEST_TIMEOUT_MS = 90_000
GOOGLE_HTTP_RETRY_ATTEMPTS = 2

_active_model = os.getenv("POLICY_GENERATION_MODEL", DEFAULT_POLICY_MODEL)
_temperature = DEFAULT_TEMPERATURE
_max_output_tokens = DEFAULT_MAX_OUTPUT_TOKENS
_gemini_thinking_budget = DEFAULT_GEMINI_THINKING_BUDGET
_openai_client = None
_google_client = None

ModelT = TypeVar("ModelT", bound=BaseModel)

def get_openai_api_key() -> str:
    """Return an environment override or the local hardcoded OpenAI key."""
    return os.getenv("OPENAI_API_KEY") or OPENAI_API_KEY


def get_gemini_api_key() -> str:
    """Return an environment override or the local hardcoded Gemini key."""
    return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or GEMINI_API_KEY


def configure_policy_model(
    model: str,
    *,
    temperature: float = DEFAULT_TEMPERATURE,
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
    gemini_thinking_budget: int = DEFAULT_GEMINI_THINKING_BUDGET,
) -> dict[str, Any]:
    """Select the policy-generation model for subsequent pipeline calls."""
    if model not in POLICY_MODELS:
        allowed = ", ".join(sorted(POLICY_MODELS))
        raise ValueError(f"Unsupported policy model {model!r}. Choose one of: {allowed}")
    if max_output_tokens <= 0:
        raise ValueError("max_output_tokens must be positive")
    global _active_model, _temperature, _max_output_tokens, _gemini_thinking_budget
    _active_model = model
    _temperature = float(temperature)
    _max_output_tokens = int(max_output_tokens)
    _gemini_thinking_budget = int(gemini_thinking_budget)
    return get_policy_generation_config()


def _package_version(package: str) -> str | None:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


def get_policy_generation_config() -> dict[str, Any]:
    spec = POLICY_MODELS[_active_model]
    return {
        "provider": spec["provider"],
        "model": _active_model,
        "api_model": spec["api_model"],
        "structured_output_method": spec["structured_output"],
        "temperature": _temperature,
        "max_output_tokens": _max_output_tokens,
        "gemini_thinking_budget": _gemini_thinking_budget if spec["provider"] == "google" else None,
        "openai_sdk_version": _package_version("openai"),
        "google_genai_sdk_version": _package_version("google-genai"),
    }


def _resolve_model(model: str | None) -> tuple[str, dict[str, str]]:
    selected = model or _active_model
    if selected not in POLICY_MODELS:
        raise ValueError(
            f"Unknown policy model {selected!r}; configure one of {sorted(POLICY_MODELS)}"
        )
    return selected, POLICY_MODELS[selected]


def _get_openai_client():
    global _openai_client
    if _openai_client is None:
        api_key = get_openai_api_key()
        from openai import OpenAI

        _openai_client = OpenAI(api_key=api_key)
    return _openai_client


def _get_google_client():
    global _google_client
    if _google_client is None:
        api_key = get_gemini_api_key()
        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:
            raise RuntimeError(
                "Gemini support requires the google-genai package. Install project requirements first."
            ) from exc
        _google_client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(
                timeout=GOOGLE_REQUEST_TIMEOUT_MS,
                retry_options=types.HttpRetryOptions(attempts=GOOGLE_HTTP_RETRY_ATTEMPTS),
            ),
        )
    return _google_client


def _google_config(
    *,
    system_prompt: str,
    response_schema=None,
    temperature: float | None = None,
    max_output_tokens: int | None = None,
    thinking_budget: int | None = None,
):
    try:
        from google.genai import types
    except ImportError as exc:
        raise RuntimeError(
            "Gemini support requires the google-genai package. Install project requirements first."
        ) from exc
    kwargs: dict[str, Any] = {
        "system_instruction": system_prompt,
        "temperature": _temperature if temperature is None else temperature,
        "max_output_tokens": _max_output_tokens if max_output_tokens is None else max_output_tokens,
    }
    if thinking_budget is not None:
        kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=thinking_budget)
    if response_schema is not None:
        kwargs.update(
            response_mime_type="application/json",
            response_schema=response_schema,
        )
    return types.GenerateContentConfig(**kwargs)


def generate_text(
    system_prompt: str,
    user_content: str,
    *,
    model: str | None = None,
    temperature: float | None = None,
    max_output_tokens: int | None = None,
) -> str:
    """Generate plain text using the configured policy-generation provider."""
    _, spec = _resolve_model(model)
    call_temperature = _temperature if temperature is None else float(temperature)
    call_max_output_tokens = _max_output_tokens if max_output_tokens is None else int(max_output_tokens)
    if spec["provider"] == "openai":
        response = _get_openai_client().chat.completions.create(
            model=spec["api_model"],
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            temperature=call_temperature,
            max_tokens=call_max_output_tokens,
        )
        content = response.choices[0].message.content
    else:
        response = _get_google_client().models.generate_content(
            model=spec["api_model"],
            contents=user_content,
            config=_google_config(
                system_prompt=system_prompt,
                temperature=call_temperature,
                max_output_tokens=call_max_output_tokens,
                thinking_budget=_gemini_thinking_budget if spec["api_model"] == "gemini-3.5-flash" else None,
            ),
        )
        content = response.text
    if not content or not content.strip():
        raise RuntimeError(f"{spec['api_model']} returned an empty policy-generation response.")
    return content.strip()


def _is_retriable_google_error(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    if status in {429, 500, 502, 503, 504}:
        return True
    lowered = str(exc).lower()
    return any(marker in lowered for marker in ("rate limit", "resource exhausted", "high demand", "temporarily unavailable", "timeout"))


def _generate_google_structured_text(
    *,
    api_model: str,
    schema: type[ModelT],
    system_prompt: str,
    user_content: str,
) -> str:
    interaction_input = f"{system_prompt}\n\nUser request:\n{user_content}"
    for attempt in range(4):
        try:
            interaction = _get_google_client().interactions.create(
                model=api_model,
                input=interaction_input,
                response_format={
                    "type": "text",
                    "mime_type": "application/json",
                    "schema": schema.model_json_schema(),
                },
            )
            return interaction.output_text
        except Exception as exc:
            if attempt == 3 or not _is_retriable_google_error(exc):
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError(f"{api_model} returned no structured output.")


def _generate_google_content_structured_text(
    *,
    api_model: str,
    schema: type[ModelT],
    system_prompt: str,
    user_content: str,
) -> str:
    from google.genai import types

    for attempt in range(4):
        try:
            response = _get_google_client().models.generate_content(
                model=api_model,
                contents=user_content,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=_temperature,
                    max_output_tokens=_max_output_tokens,
                    response_mime_type="application/json",
                    response_json_schema=schema.model_json_schema(),
                ),
            )
            return response.text
        except Exception as exc:
            if attempt == 3 or not _is_retriable_google_error(exc):
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError(f"{api_model} returned no structured output.")


def generate_structured(
    schema: type[ModelT],
    system_prompt: str,
    user_content: str,
    *,
    model: str | None = None,
) -> ModelT:
    """Generate and validate a Pydantic object with provider-native structured output."""
    _, spec = _resolve_model(model)
    if spec["provider"] == "openai":
        client = _get_openai_client()
        parse_api = getattr(client.chat.completions, "parse", None)
        if parse_api is None:
            parse_api = client.beta.chat.completions.parse
        response = parse_api(
            model=spec["api_model"],
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            temperature=_temperature,
            max_tokens=_max_output_tokens,
            response_format=schema,
        )
        message = response.choices[0].message
        if getattr(message, "refusal", None):
            raise RuntimeError(f"Structured policy generation refused: {message.refusal}")
        parsed = getattr(message, "parsed", None)
    else:
        structured_backend = spec["structured_output"]
        generator = (
            _generate_google_content_structured_text
            if structured_backend == "google-generate-content-json-schema-pydantic"
            else _generate_google_structured_text
        )
        output_text = generator(
            api_model=spec["api_model"], schema=schema, system_prompt=system_prompt, user_content=user_content
        )
        parsed = schema.model_validate_json(output_text)
    if isinstance(parsed, schema):
        return parsed
    if parsed is None:
        raise RuntimeError(f"{spec['api_model']} returned no parsed structured policy object.")
    return schema.model_validate(parsed)
