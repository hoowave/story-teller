from facade.risk.adapter2 import load_preprocessed_events
from facade.risk.risk_scorer2 import main_from_events
import json, sys
from pathlib import Path

class RiskAgent:
    def __init__(self):
        pass

    def run(self):
        project_root = Path(__file__).parent.parent
        input_path = project_root / "facade" / "data" / "scenario1_only_1000_strict.json"
        out_path = project_root / "facade" / "data" / "risk_output.json"

        events = load_preprocessed_events(input_path)
        out = main_from_events(events)

        Path(out_path).write_text(
            json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"✅ wrote {out_path} with {len(out.get('groups', []))} groups.")