# run_risk2.py
from adapter2 import load_preprocessed_events
from risk_scorer2 import main_from_events
import json, sys
from pathlib import Path

DEFAULT_IN = Path(__file__).with_name("sample log2.txt")
DEFAULT_OUT = Path(__file__).with_name("risk_output.json")

def run(input_path: str, out_path: str):
    events = load_preprocessed_events(input_path)
    out = main_from_events(events)
    Path(out_path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"✅ wrote {out_path} with {len(out.get('groups', []))} groups.")

if __name__ == "__main__":
    # 인자 없으면 기본값 사용
    in_path = sys.argv[1] if len(sys.argv) >= 2 else str(DEFAULT_IN)
    out_path = sys.argv[2] if len(sys.argv) >= 3 else str(DEFAULT_OUT)
    run(in_path, out_path)