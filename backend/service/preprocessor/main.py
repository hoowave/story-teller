# backend/service/preprocessor/main.py
"""
Preprocessor Runner (no server)
- 입력: ZIP / 폴더 / 단일 파일(.csv/.log/.txt)
- 동작: api.py와 동일한 파이프라인으로 파싱/엔티티 추출/힌트 산출
- 출력: 콘솔 요약(입력/출력) + 선택적 JSON 저장(ingest_id/format/count/sample/[events])
"""

import os, io, glob, re, json, zipfile, argparse, uuid
from collections import Counter, defaultdict
from typing import List, Dict, Any, Iterable, Tuple, Optional
from datetime import datetime, timezone

# 내부 모듈 (api.py의 유틸 재사용)
from .schema import Event
from .extractors import extract_entities, infer_hints
from .api import _rows_from_file, _ext, ALLOWED_EXTS

# ---------------------------
# 유틸
# ---------------------------
def _safe(name: str) -> str:
    return re.sub(r"[^-\w_.]+", "_", name)

def _iter_inputs(input_path: str) -> Iterable[Tuple[str, bytes]]:
    """
    입력이 ZIP이면: ZIP 내부 허용 확장자만 (name, raw_bytes)
    폴더이면: 재귀적으로 허용 확장자 파일들
    단일 파일이면: 한 개
    """
    p = os.path.abspath(input_path)
    if os.path.isfile(p) and p.lower().endswith(".zip"):
        with zipfile.ZipFile(p, "r") as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                if _ext(name) in ALLOWED_EXTS:
                    yield name, zf.read(name)
        return

    if os.path.isdir(p):
        for ext in ALLOWED_EXTS:
            for fp in glob.glob(os.path.join(p, "**", f"*{ext}"), recursive=True):
                with open(fp, "rb") as f:
                    yield fp, f.read()
        return

    # 단일 파일
    if os.path.isfile(p) and _ext(p) in ALLOWED_EXTS:
        with open(p, "rb") as f:
            yield os.path.basename(p), f.read()
        return

    raise FileNotFoundError(f"Unsupported input: {input_path}")

def _parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        # 'Z' → '+00:00'
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def _pretty_sample(events: List[Event], max_sample: int = 3) -> None:
    print("- sample:")
    for i, e in enumerate(events[:max_sample], 1):
        d = e.model_dump()
        ents = d.get("entities") or {}
        print(f"  [{i}] id={d.get('ingest_id')[:8]}.. ts={d.get('ts')} type={d.get('event_type_hint')} sev={d.get('severity_hint')}")
        print(f"      ips={ents.get('ips', [])[:3]} users={ents.get('users', [])[:3]} files={ents.get('files', [])[:2]} procs={ents.get('processes', [])[:2]}")
        raw = (d.get("raw") or d.get("msg") or "")[:140].replace("\n", " ")
        print(f"      raw[:140]={raw!r}")

# ---------------------------
# 핵심 실행 로직
# ---------------------------
def run_preprocessor(input_path: str, full: bool = False, save_json: Optional[str] = None, sample_limit: int = 3) -> Dict[str, Any]:
    ingest_id = str(uuid.uuid4())
    all_events: List[Event] = []
    formats = set()
    file_counts = Counter()
    files_seen = 0

    # 입력 수집
    for name, raw_bytes in _iter_inputs(input_path):
        files_seen += 1
        file_counts[_ext(name)] += 1
        try:
            rows, fmt = _rows_from_file(name, raw_bytes)
            formats.add(fmt)
        except Exception:
            continue

        for r in rows:
            if not r.get("ts"):
                continue
            msg = r.get("msg") or r.get("raw", "")
            ents = extract_entities(msg)
            for ipk in ("src_ip", "dst_ip"):
                v = r.get(ipk)
                if v and v not in ents.ips:
                    ents.ips.append(v)

            log_type = r.get("log_type")
            meta = r.get("meta") if isinstance(r.get("meta"), dict) else {}
            meta.setdefault("file", name)

            etype, sev = infer_hints(msg, log_type=log_type, meta=meta)

            all_events.append(
                Event(
                    ingest_id=ingest_id,
                    ts=r["ts"],
                    source_type=log_type,
                    src_ip=r.get("src_ip"),
                    dst_ip=r.get("dst_ip"),
                    src_port=r.get("src_port"),
                    dst_port=r.get("dst_port"),
                    proto=r.get("proto"),
                    msg=msg,
                    event_type_hint=etype,
                    severity_hint=sev,
                    entities=ents,
                    raw=r.get("raw", ""),
                    meta=meta,
                    parsing_confidence=0.95 if (etype or ents.ips or ents.users or ents.processes) else 0.78,
                )
            )

    # ---------------------------
    # 입력 요약 (Data In)
    # ---------------------------
    print("\n=== [입력 데이터 요약] ===")
    print(f"- 입력 타입: {'ZIP' if input_path.lower().endswith('.zip') else ('폴더' if os.path.isdir(input_path) else '파일')}")
    print(f"- 입력 경로: {input_path}")
    print(f"- 스캔한 파일 개수: {files_seen} (csv:{file_counts['.csv']}, log:{file_counts['.log']}, txt:{file_counts['.txt']})")

    # ---------------------------
    # 전처리 결과 요약 (Data Out)
    # ---------------------------
    print("\n=== [전처리 결과 요약] ===")
    print(f"- ingest_id: {ingest_id}")
    print(f"- 포맷 추정: { '+'.join(sorted(formats)) if formats else 'unknown' }")
    print(f"- 이벤트 총계: {len(all_events)}")

    # 분포 (event_type/severity/source_type)
    by_type = Counter(e.event_type_hint for e in all_events if e.event_type_hint)
    by_sev = Counter(e.severity_hint for e in all_events if e.severity_hint)
    by_src = Counter(e.source_type for e in all_events if e.source_type)

    # 엔티티 상위
    ips = Counter(ip for e in all_events for ip in (e.entities.ips if e.entities else []))
    users = Counter(u for e in all_events for u in (e.entities.users if e.entities else []))

    # 타임라인
    times = [ _parse_iso(e.ts) for e in all_events ]
    times = [ t for t in times if t is not None ]
    if times:
        t_min, t_max = min(times), max(times)
        dur = (t_max - t_min).total_seconds()
    else:
        t_min = t_max = None
        dur = 0.0

    def _top(counter: Counter, k=5):
        return ", ".join([f"{a}({b})" for a, b in counter.most_common(k)]) or "-"

    print(f"- 타입 분포(top5): { _top(by_type) }")
    print(f"- 심각도 분포: { _top(by_sev) }")
    print(f"- 소스 타입 분포: { _top(by_src) }")
    print(f"- IP 상위(top5): { _top(ips) }")
    print(f"- 사용자 상위(top5): { _top(users) }")
    if t_min and t_max:
        print(f"- 시간 범위: {t_min.isoformat()} ~ {t_max.isoformat()} (총 {dur:.1f}s)")

    # 샘플
    print()
    _pretty_sample(all_events, max_sample=sample_limit)

    # ---------------------------
    # JSON 응답 형태 (API 시뮬)
    # ---------------------------
    payload: Dict[str, Any] = {
        "ingest_id": ingest_id,
        "format": "+".join(sorted(formats)) if formats else "unknown",
        "count": len(all_events),
        "sample": [e.model_dump() for e in all_events[:sample_limit]],
        "summary": {
            "by_event_type": dict(by_type),
            "by_severity": dict(by_sev),
            "by_source_type": dict(by_src),
            "top_ips": ips.most_common(10),
            "top_users": users.most_common(10),
            "time_range": {
                "min": t_min.isoformat() if t_min else None,
                "max": t_max.isoformat() if t_max else None,
                "duration_seconds": dur,
            },
            "files_scanned": {
                "total": files_seen,
                "by_ext": dict(file_counts),
            },
        },
    }
    if full:
        payload["events"] = [e.model_dump() for e in all_events]

    print("\n=== [JSON 응답 형태] ===")
    print(json.dumps(payload, indent=2, ensure_ascii=False))

    # 저장
    if save_json:
        # 디렉터리를 주면 파일명 자동 생성
        if os.path.isdir(save_json) or save_json.endswith(("\\", "/")):
            os.makedirs(save_json, exist_ok=True)
            base = _safe(os.path.basename(input_path)) or "result"
            save_path = os.path.join(save_json, f"{base}.json")
        else:
            os.makedirs(os.path.dirname(os.path.abspath(save_json)), exist_ok=True)
            save_path = save_json
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"\n-> JSON 저장: {save_path}")

    return payload

# ---------------------------
# CLI
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description="Preprocessor main (no server)")
    ap.add_argument("--input", required=True, help="ZIP / 폴더 / 단일 파일(.csv/.log/.txt)")
    ap.add_argument("--full", action="store_true", help="JSON에 events 전체 포함")
    ap.add_argument("--save-json", help="결과 JSON 저장 경로(파일 or 디렉터리)")
    ap.add_argument("--sample", type=int, default=3, help="콘솔 샘플 출력 개수 (기본 3)")
    args = ap.parse_args()

    print("=== 전처리 실행 ===\n")
    run_preprocessor(args.input, full=args.full, save_json=args.save_json, sample_limit=args.sample)
    print("\n완료!")

if __name__ == "__main__":
    # 모듈 실행 권장: python -m backend.service.preprocessor.main --input ...
    # (직접 실행도 가능하게 부트스트랩 유지)
    if __package__ is None:
        import sys
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    main()
