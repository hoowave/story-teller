import os, glob, re, json, zipfile, uuid
from collections import Counter
from typing import List, Dict, Any, Iterable, Tuple, Optional
from datetime import datetime
from fastapi import UploadFile

from facade.preprocessor.schema import Event
from facade.preprocessor.extractors import extract_entities, infer_hints
from facade.preprocessor.api import _rows_from_file, _ext, ALLOWED_EXTS

class ProcessorAgent:
    def __init__(self, output_path: Optional[str] = None, sample_limit: int = 3):
        self.output_path = output_path or os.path.join(os.path.dirname(__file__), "data", "processor_output.json")
        self.sample_limit = sample_limit

    def run_preprocessor_from_files(self, files: list[UploadFile], full: bool = False, save_json: Optional[str] = None, sample_limit: int = 3):
        ingest_id = str(uuid.uuid4())
        all_events: List[Event] = []
        formats = set()
        file_counts = Counter()

        for file in files:
            name = file.filename
            file_counts[_ext(name)] += 1
            raw_bytes = file.file.read()
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
        # 입력/출력 요약
        # ---------------------------
        self._print_summary(all_events, file_counts, formats, ingest_id)

        # ---------------------------
        # JSON payload 생성
        # ---------------------------
        payload: Dict[str, Any] = self._make_payload(all_events, formats, ingest_id, full, file_counts)

        # ---------------------------
        # JSON 저장
        # ---------------------------
        out_path = save_json or self.output_path
        input_path = os.path.join(os.path.dirname(__file__), "data", "processor_output.json")
        self._save_json(payload, out_path, input_path)

        return payload

    def run_preprocessor(self, input_path: str, full: bool = False, save_json: Optional[str] = None) -> Dict[str, Any]:
        if not input_path:
            raise ValueError("input_path를 지정해야 합니다.")
        
        ingest_id = str(uuid.uuid4())
        all_events: List[Event] = []
        formats = set()
        file_counts = Counter()
        files_seen = 0

        # ---------------------------
        # 입력 수집
        # ---------------------------
        for name, raw_bytes in self._iter_inputs(input_path):
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
        # 입력/출력 요약
        # ---------------------------
        self._print_summary(all_events, file_counts, formats, ingest_id)

        # ---------------------------
        # JSON payload 생성
        # ---------------------------
        payload: Dict[str, Any] = self._make_payload(all_events, formats, ingest_id, full, file_counts)

        # ---------------------------
        # JSON 저장
        # ---------------------------
        out_path = save_json or self.output_path
        self._save_json(payload, out_path, input_path)

        return payload

    # ---------------------------
    # 유틸
    # ---------------------------
    @staticmethod
    def _safe(name: str) -> str:
        return re.sub(r"[^-\w_.]+", "_", name)

    @staticmethod
    def _iter_inputs(input_path: str) -> Iterable[Tuple[str, bytes]]:
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
        if os.path.isfile(p) and _ext(p) in ALLOWED_EXTS:
            with open(p, "rb") as f:
                yield os.path.basename(p), f.read()
            return
        raise FileNotFoundError(f"Unsupported input: {input_path}")

    @staticmethod
    def _parse_iso(ts: str) -> Optional[datetime]:
        if not ts:
            return None
        try:
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            return datetime.fromisoformat(ts)
        except Exception:
            return None

    def _pretty_sample(self, events: List[Event], max_sample: int = 3) -> None:
        print("- sample:")
        for i, e in enumerate(events[:max_sample], 1):
            d = e.model_dump()
            ents = d.get("entities") or {}
            print(f"  [{i}] id={d.get('ingest_id')[:8]}.. ts={d.get('ts')} type={d.get('event_type_hint')} sev={d.get('severity_hint')}")
            print(f"      ips={ents.get('ips', [])[:3]} users={ents.get('users', [])[:3]} files={ents.get('files', [])[:2]} procs={ents.get('processes', [])[:2]}")
            raw = (d.get("raw") or d.get("msg") or "")[:140].replace("\n", " ")
            print(f"      raw[:140]={raw!r}")

    def _print_summary(self, events: List[Event], file_counts: Counter, formats: set, ingest_id: str):
        by_type = Counter(e.event_type_hint for e in events if e.event_type_hint)
        by_sev = Counter(e.severity_hint for e in events if e.severity_hint)
        by_src = Counter(e.source_type for e in events if e.source_type)
        ips = Counter(ip for e in events for ip in (e.entities.ips if e.entities else []))
        users = Counter(u for e in events for u in (e.entities.users if e.entities else []))
        times = [self._parse_iso(e.ts) for e in events]
        times = [t for t in times if t is not None]
        t_min, t_max = (min(times), max(times)) if times else (None, None)
        dur = (t_max - t_min).total_seconds() if t_min and t_max else 0.0

        def _top(counter: Counter, k=5):
            return ", ".join([f"{a}({b})" for a, b in counter.most_common(k)]) or "-"

        print("\n=== [입력/전처리 요약] ===")
        print(f"- 이벤트 총계: {len(events)}")
        print(f"- 포맷 추정: { '+'.join(sorted(formats)) if formats else 'unknown' }")
        print(f"- 타입 분포(top5): { _top(by_type) }")
        print(f"- 심각도 분포: { _top(by_sev) }")
        print(f"- 소스 타입 분포: { _top(by_src) }")
        print(f"- IP 상위(top5): { _top(ips) }")
        print(f"- 사용자 상위(top5): { _top(users) }")
        self._pretty_sample(events, max_sample=self.sample_limit)

    def _make_payload(self, events: List[Event], formats: set, ingest_id: str, full: bool, file_counts: Counter) -> Dict[str, Any]:
        by_type = Counter(e.event_type_hint for e in events if e.event_type_hint)
        by_sev = Counter(e.severity_hint for e in events if e.severity_hint)
        by_src = Counter(e.source_type for e in events if e.source_type)
        ips = Counter(ip for e in events for ip in (e.entities.ips if e.entities else []))
        users = Counter(u for e in events for u in (e.entities.users if e.entities else []))
        times = [self._parse_iso(e.ts) for e in events]
        times = [t for t in times if t is not None]
        t_min, t_max = (min(times), max(times)) if times else (None, None)
        dur = (t_max - t_min).total_seconds() if t_min and t_max else 0.0

        payload: Dict[str, Any] = {
            "ingest_id": ingest_id,
            "format": "+".join(sorted(formats)) if formats else "unknown",
            "count": len(events),
            "sample": [e.model_dump() for e in events[:self.sample_limit]],
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
                    "total": sum(file_counts.values()),
                    "by_ext": dict(file_counts),
                },
            },
        }
        if full:
            payload["events"] = [e.model_dump() for e in events]
        return payload

    def _save_json(self, payload: Dict[str, Any], out_path: str, input_path: str):
        if os.path.isdir(out_path) or out_path.endswith(("\\", "/")):
            os.makedirs(out_path, exist_ok=True)
            base = self._safe(os.path.basename(input_path)) or "result"
            out_path = os.path.join(out_path, f"{base}.json")
        else:
            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"\n-> JSON 저장: {out_path}")
