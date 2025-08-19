# risk_scorer.py
from __future__ import annotations
from datetime import datetime, timezone
from typing import Dict, Any

BASE_TYPE = {
    "rce": 10, "privilegeescalation": 10, "sqli": 8, "authbypass": 8,
    "sessionhijack": 8, "fileupload": 7, "pathtraversal": 7,
    "xss": 6, "csrf": 6, "scan": 4, "bruteforce": 4, "other": 3
}

ASSET_CRIT = {
    "admin": 9, "payment": 9, "auth": 9,
    "internal_api": 7, "data_access": 7,
    "public_static": 3
}

def _parse_iso(s: str):
    s = s.strip()
    if s.endswith("Z"):
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

def buck_volume(n: int) -> int:
    return 2 if n <= 5 else 5 if n <= 20 else 7 if n <= 50 else 9

def recency(first_iso: str, last_iso: str) -> int:
    t1 = _parse_iso(first_iso)
    t2 = _parse_iso(last_iso)
    dur_min = (t2 - t1).total_seconds() / 60
    now_gap_h = (datetime.now(timezone.utc) - t2.astimezone(timezone.utc)).total_seconds() / 3600
    if now_gap_h <= 1 and dur_min >= 10: return 8
    if now_gap_h <= 24: return 5
    return 3

def asset_score(asset: str) -> int:
    a = (asset or "").lower()
    if any(k in a for k in ["admin","console"]): return ASSET_CRIT["admin"]
    if any(k in a for k in ["auth","login","token"]): return ASSET_CRIT["auth"]
    if any(k in a for k in ["payment","billing"]): return ASSET_CRIT["payment"]
    if any(k in a for k in ["internal","svc","service"]): return ASSET_CRIT["internal_api"]
    if any(k in a for k in ["data","db","query"]): return ASSET_CRIT["data_access"]
    return ASSET_CRIT["public_static"]

def defense_score(waf_blocks: int, http_5xx: int) -> int:
    if http_5xx > 0: return 8
    if waf_blocks > 0: return 3
    return 1

def conf_adj(c: float) -> int:
    if c < 0.6: return -3
    if c > 0.8: return 2
    return 0

def risk_level(s: float) -> str:
    if s >= 7.5: return "High"
    if s >= 5.0: return "Medium"
    return "Low"

def compute_score(cluster: Dict[str, Any]) -> Dict[str, Any]:
    required = ["cluster_id","attack_type","events","first_seen","last_seen","target_asset"]
    missing = [k for k in required if k not in cluster]
    if missing:
        raise ValueError(f"Missing keys: {missing}")

    atk = (str(cluster["attack_type"]).strip().lower() or "other").replace(" ", "")
    t   = BASE_TYPE.get(atk, BASE_TYPE["other"])
    vol = buck_volume(int(cluster["events"]))
    rec = recency(str(cluster["first_seen"]), str(cluster["last_seen"]))
    ast = asset_score(str(cluster["target_asset"]))
    dfs = defense_score(int(cluster.get("waf_blocks", 0)), int(cluster.get("http_5xx", 0)))
    cad = conf_adj(float(cluster.get("mean_confidence", 0.5)))

    score = (0.35*t + 0.20*vol + 0.15*rec + 0.15*ast + 0.10*dfs + 0.05*cad)

    if atk in {"rce","privilegeescalation"} and ast >= 7:
        score = max(score, 5.1)
    if float(cluster.get("mean_confidence", 0)) < 0.5 and int(cluster["events"]) < 3 and int(cluster.get("waf_blocks", 0)) == 0:
        score = min(score, 4.9)

    level = risk_level(score)
    explain = (
        f"{cluster['attack_type']}가 {cluster['target_asset']}에서 {cluster['events']}건 관찰됨. "
        f"최근성{rec}/자산{ast}/방어{dfs}/확신도보정{cad} 반영 → {level}"
    )

    return {
        "cluster_id": cluster["cluster_id"],
        "risk_score": round(score, 2),
        "risk_level": level,
        "factors": {"type": t, "volume": vol, "recency": rec, "asset": ast, "defense": dfs, "confidence_adj": cad},
        "explain": explain,
        "policy_version": "v0.2"
    }






