# -*- coding: utf-8 -*-
from __future__ import annotations
import os, json, time
from typing import List, Dict, Any, Optional
from urllib import request as urlreq
from urllib.error import URLError, HTTPError

# .env 지원
try:
    from dotenv import load_dotenv
    load_dotenv()  # 프로젝트 루트의 .env 로드 (없어도 무시)
except Exception:
    pass

def _http_post_json(url: str, payload: dict, headers: Optional[dict] = None, timeout: int = 60) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urlreq.Request(url, data=data, headers={"Content-Type": "application/json", **(headers or {})}, method="POST")
    with urlreq.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))

def _messages_to_prompt(messages: List[Dict[str, str]]) -> str:
    """Gemini 호환: role을 포함해 하나의 프롬프트 문자열로 합침."""
    parts = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        parts.append(f"[{role}]\n{content}\n")
    return "\n".join(parts).strip()

def chat_completion(
    backend: str,
    model: str,
    messages: List[Dict[str, str]],
    temperature: float = 0.2,
    max_tokens: int = 1500,
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
    retries: int = 2,
) -> str:
    """
    backend: "ollama" | "openai" | "gemini"
    messages: [{"role":"system"|"user"|"assistant","content":"..."}]
    """
    backend = (backend or "ollama").lower()
    last_err = None

    for _ in range(retries + 1):
        try:
            # ---------------------------
            # 1) Ollama / LM Studio
            # ---------------------------
            if backend == "ollama":
                base = endpoint or os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434")
                url = base.rstrip("/") + "/api/chat"
                payload = {
                    "model": model,
                    "messages": messages,
                    "options": {"temperature": temperature},
                    "stream": False
                }
                res = _http_post_json(url, payload)
                return res.get("message", {}).get("content", "").strip()

            # ---------------------------
            # 2) OpenAI
            # ---------------------------
            elif backend == "openai":
                key = api_key or os.getenv("OPENAI_API_KEY")
                if not key:
                    raise RuntimeError("OPENAI_API_KEY not set")
                base = endpoint or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
                url = base.rstrip("/") + "/chat/completions"
                payload = {
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }
                headers = {"Authorization": f"Bearer {key}"}
                res = _http_post_json(url, payload, headers=headers)
                return res["choices"][0]["message"]["content"].strip()

            # ---------------------------
            # 3) Google Gemini
            # ---------------------------
            elif backend == "gemini":
                # pip install google-generativeai
                import google.generativeai as genai

                key = api_key or os.getenv("GEMINI_API_KEY")
                if not key:
                    raise RuntimeError("GEMINI_API_KEY not set")

                # endpoint 커스터마이즈가 필요하면 환경변수로 설정 가능:
                # os.environ["GOOGLE_API_BASE"] = endpoint  # (보통 기본값 사용)
                genai.configure(api_key=key)

                # messages -> 하나의 prompt 문자열로 합침
                prompt = _messages_to_prompt(messages)

                model_obj = genai.GenerativeModel(model)
                res = model_obj.generate_content(
                    prompt,
                    generation_config={
                        "temperature": temperature,
                        "max_output_tokens": max_tokens,
                    }
                )
                # SDK 응답은 safety/finish 이유 등 포함. 텍스트만 꺼냄
                # v1.5 기준: res.text가 최종 텍스트
                return (res.text or "").strip()

            else:
                raise ValueError(f"Unsupported backend: {backend}")

        except (URLError, HTTPError, KeyError, RuntimeError, ValueError, Exception) as e:
            last_err = e
            time.sleep(0.8)

    raise RuntimeError(f"LLM request failed: {last_err}")
