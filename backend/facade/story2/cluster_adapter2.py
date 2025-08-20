# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Optional, Dict, Any
from pathlib import Path
import json, re

# 클러스터 리포트에서 JSON 비슷한 블록을 최대한 복원해서 파싱

def _extract_json_like(text: str) -> Optional[str]:
    starts = [m.start() for m in re.finditer(r"\{", text)]
    for s in starts:
        stack = 0
        for i in range(s, len(text)):
            ch = text[i]
            if ch == "{":
                stack += 1
            elif ch == "}":
                stack -= 1
                if stack == 0:
                    candidate = text[s:i+1]
                    if len(candidate) >= 10:
                        return candidate
    return None


def load_cluster_report(path: str | Path) -> Dict[str, Any]:
    """텍스트/JSON 상관없이 로드 → {raw, parsed?} 구조로 반환.
    - JSON 파싱 실패 시 일부 라인을 summary_lines로 제공.
    """
    p = Path(path)
    raw = p.read_text(encoding="utf-8", errors="ignore").strip()

    # 1) JSON 직파싱 시도
    try:
        return {"raw": raw, "parsed": json.loads(raw)}
    except Exception:
        pass

    # 2) 본문에서 JSON 유사 블록 추출→정리→파싱
    js = _extract_json_like(raw)
    if js:
        try:
            return {"raw": raw, "parsed": json.loads(js)}
        except Exception:
            cleaned = js
            if cleaned.strip().startswith("```"):
                cleaned = cleaned.strip("`")
                cleaned = cleaned[cleaned.find("\n")+1:]
                if "```" in cleaned:
                    cleaned = cleaned[:cleaned.rfind("```")]
            last_brace = cleaned.rfind("}")
            if last_brace != -1:
                cleaned = cleaned[:last_brace+1]
            try:
                return {"raw": raw, "parsed": json.loads(cleaned)}
            except Exception:
                pass

    # 3) 실패 시 앞부분만 요약 라인 제공
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    return {"raw": raw, "parsed": None, "summary_lines": lines[:60]}
