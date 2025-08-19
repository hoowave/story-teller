# run_risk.py
import json
from datetime import datetime, timezone
from collections import defaultdict, Counter

from risk_scorer import compute_score
from adapter import adapt_stage1_batch

def _parse_ts(ts: str) -> datetime:
    s = (ts or "").strip()
    if s.endswith("Z"):
        s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def _bucket15(t: datetime) -> datetime:
    return t.replace(minute=(t.minute // 15) * 15, second=0, microsecond=0, tzinfo=t.tzinfo)

def _build_clusters(events):
    groups = defaultdict(list)
    for ev in events:
        cid = ev.get("cluster_id")
        if not cid:
            t = _parse_ts(ev["ts"])
            cid = f"{ev.get('src_ip')}|{ev.get('target_asset')}|{ev.get('event_type')}|{_bucket15(t).isoformat()}"
        groups[cid].append(ev)

    clusters = []
    for cid, evs in groups.items():
        type_cnt = Counter(e.get("event_type", "other") for e in evs)
        asset_cnt = Counter(e.get("target_asset", "other") for e in evs)
        attack_type, _ = type_cnt.most_common(1)[0]
        target_asset, _ = asset_cnt.most_common(1)[0]

        times = sorted(_parse_ts(e["ts"]) for e in evs if e.get("ts"))
        first_seen = times[0].isoformat()
        last_seen = times[-1].isoformat()

        confs = [float(e.get("confidence")) for e in evs if e.get("confidence") is not None]
        mean_conf = sum(confs) / len(confs) if confs else 0.7

        def _is_block(e):
            act = (e.get("action") or "").lower()
            if act in {"block", "deny"}:
                return True
            meta_act = ((e.get("meta") or {}).get("Action") or "").upper()
            if meta_act in {"BLOCK", "DENY", "WAF_BLOCK"}:
                return True
            if "waf_block" in (e.get("hints") or []):
                return True
            return False

        waf_blocks = sum(1 for e in evs if _is_block(e))

        def _is_5xx(e):
            meta = e.get("meta") or {}
            st = meta.get("status") or meta.get("Status") or None
            try:
                st = int(st)
                return 500 <= st <= 599
            except Exception:
                return False

        http_5xx = sum(1 for e in evs if _is_5xx(e))

        clusters.append({
            "cluster_id": cid,
            "attack_type": attack_type,
            "events": len(evs),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "target_asset": target_asset,
            "mean_confidence": mean_conf,
            "waf_blocks": waf_blocks,
            "http_5xx": http_5xx,
        })
    return clusters

def run(payload_json: str):
    payload = json.loads(payload_json)
    events = adapt_stage1_batch(payload)
    clusters = _build_clusters(events)
    scored = [compute_score(c) for c in clusters]
    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    return scored

if __name__ == "__main__":
    # 너의 샘플 페이로드 그대로 넣어 테스트 가능
    from adapter import adapt_stage1_batch  # 이미 위에서 임포트함
    sample_payload = {
      "ingest_id": "550e8400-e29b-41d4-a716-446655440000",
      "format": "csv",
      "count": 3,
      "sample": [
        {
          "ingest_id": "550e8400-e29b-41d4-a716-446655440000",
          "ts": "2023-01-01T12:00:00+00:00",
          "source_type": "auth",
          "src_ip": "192.168.1.10",
          "dst_ip": "10.0.0.1",
          "src_port": 12345,
          "dst_port": 22,
          "proto": "tcp",
          "msg": "failed login for user admin",
          "event_type_hint": "authentication",
          "severity_hint": "warning",
          "entities": {"ips": ["192.168.1.10","10.0.0.1"],"users": ["admin"],"files": [],"processes": []},
          "raw": "2023-01-01T12:00:00Z,auth,failed login for user admin,192.168.1.10,10.0.0.1,12345,22,tcp,\"{\"\"Action\"\":\"\"AUTH_FAIL\"\"}\"",
          "meta": {"Action": "AUTH_FAIL"},
          "parsing_confidence": 0.92
        },
        {
          "ingest_id": "550e8400-e29b-41d4-a716-446655440000",
          "ts": "2023-01-01T12:01:00+00:00",
          "source_type": "web",
          "src_ip": "192.168.1.15",
          "dst_ip": "10.0.0.2",
          "src_port": 54321,
          "dst_port": 80,
          "proto": "tcp",
          "msg": "GET /login.php?user=admin&pass=' OR '1'='1",
          "event_type_hint": "web_sqli",
          "severity_hint": "high",
          "entities": {"ips": ["192.168.1.15","10.0.0.2"],"users": ["admin"],"files": ["/login.php"],"processes": []},
          "raw": "2023-01-01T12:01:00Z,web,GET /login.php?user=admin&pass=' OR '1'='1,192.168.1.15,10.0.0.2,54321,80,tcp,\"{\"\"Action\"\":\"\"DETECT_SQLI\"\"}\"",
          "meta": {"Action": "DETECT_SQLI"},
          "parsing_confidence": 0.92
        }
      ]
    }
    result = run(json.dumps(sample_payload))

    # 콘솔에도 찍고
    print(json.dumps(result, ensure_ascii=False, indent=2))

    # 파일로도 저장
    with open("stage4.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print("✅ 결과가 stage4.json 파일로 저장되었습니다.")

