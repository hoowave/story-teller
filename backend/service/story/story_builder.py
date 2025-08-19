# story_builder.py
import json
import argparse
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from collections import defaultdict

# ---------- 시간 유틸 ----------
def _parse_ts(s: str) -> datetime:
    s = (s or "").strip()
    if not s:
        return datetime.now(timezone.utc)
    if s.endswith("Z"):
        s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

# ---------- cluster_id: src|asset|event_type|bucket ----------
def _parse_cluster_id(cid: str) -> Tuple[str, str, str, str]:
    parts = (cid or "").split("|")
    src  = parts[0] if len(parts) > 0 else ""
    asset= parts[1] if len(parts) > 1 else ""
    et   = parts[2] if len(parts) > 2 else "other"
    buck = parts[3] if len(parts) > 3 else ""
    return src, asset, et, buck

# ---------- 단계/권고 ----------
STAGE_MAP = {
    "bruteforce": ("Credential Access", "mitre:T1110"),
    "sqli": ("Initial Access/Web Exploitation", "mitre:T1190"),
    "xss": ("Initial Access/Web Exploitation", "mitre:T1190"),
    "rce": ("Initial Access/Web Exploitation", "mitre:T1190"),
    "path_traversal": ("Initial Access/Web Exploitation", "mitre:T1190"),
    "file_upload": ("Initial Access/Web Exploitation", "mitre:T1190"),
    "db_sensitive_read": ("Collection", "mitre:T1005"),
    "data_exfil": ("Exfiltration", "mitre:T1041"),
    "other": ("Suspicious", "mitre:unknown"),
}

RECO_MAP = {
    "sqli": [
        "서버사이드 파라미터 바인딩 또는 ORM 적용",
        "입력 검증 및 에러 메시지 최소화(스택/쿼리 노출 금지)",
        "WAF SQLi 룰 우선순위 상향 및 튜닝",
    ],
    "bruteforce": [
        "로그인 실패 임계치 초과 시 계정 일시 잠금/캡차 적용",
        "전사 MFA 강제",
        "동일 IP 대량 실패 탐지 룰 활성화",
    ],
    "db_sensitive_read": [
        "민감 테이블 최소권한 원칙 적용 및 접근감사 로그 상시 모니터링",
        "쿼리 화이트리스트/저장 프로시저 사용 검토",
        "비정상 시간대/대량 조회 탐지 룰 추가",
    ],
    "data_exfil": [
        "Egress 통제 및 DLP 정책 적용",
        "대용량/비정상 도메인 전송 탐지 룰",
        "프록시/게이트웨이에서 데이터 전송 한도 설정",
    ],
}

def _reco_for_types(types: List[str]) -> List[str]:
    pool, out = [], []
    for t in types:
        pool += RECO_MAP.get(t, [])
    for r in pool:
        if r not in out:
            out.append(r)
    return out[:5] if out else ["추가 조사 및 룰 보강 필요"]

# ---------- Stage4 클러스터 보정 ----------
def normalize_cluster(c: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stage-4 최소 JSON에도 대응: cluster_id에서 attack_type/asset/bucket을 보완,
    first_seen/last_seen 없으면 bucket(또는 현재시각)으로 대체.
    """
    cid = c.get("cluster_id", "")
    src, asset, etype, bucket = _parse_cluster_id(cid)

    attack_type = (c.get("attack_type") or etype or "other").lower()
    target_asset = c.get("target_asset") or asset or "other"

    # 시간 보정
    first_seen = c.get("first_seen") or bucket or c.get("bucket") or ""
    last_seen  = c.get("last_seen")  or bucket or c.get("bucket") or ""
    if not first_seen and not last_seen:
        now = datetime.now(timezone.utc).isoformat()
        first_seen, last_seen = now, now

    # 기본값 보정
    events = int(c.get("events", 1))
    mean_conf = float(c.get("mean_confidence", 0.7))
    waf_blocks = int(c.get("waf_blocks", 0))
    http_5xx = int(c.get("http_5xx", 0))

    # 리스크 메타 유지
    risk_score = float(c.get("risk_score", 0.0))
    risk_level = c.get("risk_level", "Low")
    factors = c.get("factors", {})
    explain = c.get("explain", "")
    policy_version = c.get("policy_version")

    return {
        "cluster_id": cid,
        "attack_type": attack_type,
        "events": events,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "target_asset": target_asset,
        "mean_confidence": mean_conf,
        "waf_blocks": waf_blocks,
        "http_5xx": http_5xx,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "factors": factors,
        "explain": explain,
        "policy_version": policy_version,
    }

# ---------- 인시던트 묶기 (정규화된 입력 가정) ----------
def group_incidents(clusters: List[Dict[str, Any]], window_minutes: int = 60):
    def _src_of(c):
        src, _, _, _ = _parse_cluster_id(c["cluster_id"])
        return src or "unknown"

    # 안전 정렬: last_seen 없을 일이 없지만 혹시 빈 문자열이면 현재시각으로 보정
    def _key_last(c):
        try:
            return _parse_ts(c.get("last_seen") or "")
        except Exception:
            return datetime.now(timezone.utc)

    clusters_sorted = sorted(clusters, key=_key_last)
    buckets = defaultdict(list)  # src_ip -> [incident(list[cluster]), ...]

    for c in clusters_sorted:
        src_ip = _src_of(c)
        t = _parse_ts(c.get("last_seen"))
        if not buckets[src_ip]:
            buckets[src_ip].append([c])
            continue
        last_inc = buckets[src_ip][-1]
        last_t = _parse_ts(last_inc[-1].get("last_seen"))
        delta = (t - last_t).total_seconds() / 60.0
        if delta <= window_minutes:
            last_inc.append(c)
        else:
            buckets[src_ip].append([c])

    incidents, idx = [], 1
    for src_ip, incs in buckets.items():
        for group in incs:
            incidents.append({
                "incident_id": f"INC-{_parse_ts(group[0].get('first_seen')).date()}-{idx:04d}",
                "src_ip": src_ip,
                "clusters": group
            })
            idx += 1
    return incidents

# ---------- 스토리 생성 ----------
def build_story(incident: Dict[str, Any]) -> Dict[str, Any]:
    clusters = sorted(incident["clusters"], key=lambda c: _parse_ts(c.get("first_seen")))
    top = max(clusters, key=lambda c: c.get("risk_score", 0.0))
    src_ip = incident["src_ip"]

    title = f"{src_ip}의 {clusters[-1]['attack_type'].upper()} 시도"
    severity = top.get("risk_level", "Low")

    timeline, types_in_inc, assets, indicators_paths, evidence, confs = [], [], set(), set(), set(), []
    for c in clusters:
        etype = c["attack_type"]
        stage, _mitre = STAGE_MAP.get(etype, STAGE_MAP["other"])
        timeline.append({
            "t": c["first_seen"],
            "stage": stage,
            "detail": f"{etype} {c['events']}건, 대상 {c['target_asset']}, 방어지표(waf_blocks={c.get('waf_blocks',0)}, http_5xx={c.get('http_5xx',0)})"
        })
        types_in_inc.append(etype)
        assets.add(c["target_asset"])
        if etype == "sqli":
            indicators_paths.add("/login.php")  # 필요시 확장
        if c.get("waf_blocks", 0) > 0:
            evidence.add("WAF 차단/탐지 신호")
        if c.get("http_5xx", 0) > 0:
            evidence.add("HTTP 5xx 발생")
        confs.append(float(c.get("mean_confidence", 0.7)))

    summary = (
        f"동일 출처 {src_ip}에서 {', '.join(sorted(set(types_in_inc)))} 활동이 "
        f"{len(clusters)}개 클러스터로 관찰되었습니다. "
        f"주요 대상은 {', '.join(sorted(assets))} 입니다. 최고 위험도는 {severity}입니다."
    )

    recommendations = _reco_for_types(sorted(set(types_in_inc)))
    confidence = round(sum(confs)/len(confs), 2) if confs else 0.7
    tags = sorted(set(
        (["web"] if any(t in ("sqli","xss","rce","path_traversal","file_upload") for t in types_in_inc) else ["infra"])
        + types_in_inc
        + [STAGE_MAP.get(t, ("","mitre:unknown"))[1] for t in types_in_inc]
    ))

    return {
        "incident_id": incident["incident_id"],
        "title": title,
        "severity": severity,
        "summary": summary,
        "timeline": timeline,
        "clusters": [c["cluster_id"] for c in clusters],
        "attacker": {"src_ip": src_ip, "unique_assets": sorted(list(assets))},
        "indicators": {"ips": [src_ip], "paths": sorted(list(indicators_paths))},
        "evidence": sorted(list(evidence)),
        "recommendations": recommendations,
        "confidence": confidence,
        "tags": tags,
        "kpis": {
            "cluster_count": len(clusters),
            "max_risk": float(top.get("risk_score", 0.0)),
            "types": sorted(list(set(types_in_inc))),
        }
    }

# ---------- 프론트 경량 JSON ----------
def to_frontend_payload(stories: List[Dict[str, Any]]) -> Dict[str, Any]:
    incidents, timeline_flat = [], []
    for s in stories:
        incidents.append({
            "id": s["incident_id"],
            "title": s["title"],
            "severity": s["severity"],
            "summary": s["summary"],
            "max_risk": s["kpis"]["max_risk"],
            "cluster_count": s["kpis"]["cluster_count"],
            "attacker": s["attacker"],
            "tags": s["tags"],
        })
        for tl in s["timeline"]:
            timeline_flat.append({
                "incident_id": s["incident_id"],
                "timestamp": tl["t"],
                "attack_stage": tl["stage"],
                "description": tl["detail"],
                "severity": s["severity"],
                "src_ip": s["attacker"]["src_ip"]
            })
    timeline_flat.sort(key=lambda x: x["timestamp"])
    return {"incidents": incidents, "timeline": timeline_flat}

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="Stage4(JSON) → Stage5 Story(JSON)")
    ap.add_argument("--in", dest="input_path", default="stage4.json", help="stage4.json (risk 결과)")
    ap.add_argument("--out-json", dest="out_json", default="stories.json", help="스토리 JSON 저장 경로")
    ap.add_argument("--out-front", dest="out_front", default="stories.front.json", help="프론트 경량 JSON 저장 경로")
    ap.add_argument("--window-minutes", type=int, default=60, help="같은 인시던트로 묶는 시간창(분)")
    ap.add_argument("--min-score", type=float, default=None, help="이 점수 미만 클러스터 제외")
    ap.add_argument("--limit-incidents", type=int, default=None, help="상위 N개 인시던트만 출력")
    args = ap.parse_args()

    with open(args.input_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # stage4가 배열이든 객체든 방어적으로 처리
    if isinstance(raw, dict) and "results" in raw and isinstance(raw["results"], list):
        raw_clusters = raw["results"]
    elif isinstance(raw, list):
        raw_clusters = raw
    else:
        # 그 외 형식이면 배열로 가정 실패 → 에러
        raise ValueError("stage4.json 형식이 리스트(클러스터 배열)가 아닙니다.")

    # 보정 + 필터
    norm = [normalize_cluster(c) for c in raw_clusters]
    if args.min_score is not None:
        norm = [c for c in norm if float(c.get("risk_score", 0.0)) >= args.min_score]

    # 인시던트 묶기 → 스토리 생성
    incidents = group_incidents(norm, window_minutes=args.window_minutes)
    stories = [build_story(inc) for inc in incidents]

    if args.limit_incidents:
        stories.sort(key=lambda s: s["kpis"]["max_risk"], reverse=True)
        stories = stories[: args.limit_incidents]

    # 저장
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(stories, f, ensure_ascii=False, indent=2)

    with open(args.out_front, "w", encoding="utf-8") as f:
        json.dump(to_frontend_payload(stories), f, ensure_ascii=False, indent=2)

    print(f"✅ stories saved: {args.out_json}")
    print(f"✅ front payload saved: {args.out_front}")

if __name__ == "__main__":
    main()


