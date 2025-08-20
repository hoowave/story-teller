from facade.risk.adapter2 import load_preprocessed_events
from facade.risk.risk_scorer2 import main_from_events
import json, sys
from pathlib import Path

class RiskAgent:
    def __init__(self):
        project_root = Path(__file__).parent.parent
        self.__DEFAULT_IN = project_root / "facade" / "risk" / "sample_log.txt"
        self.__DEFAULT_OUT = project_root / "facade"/ "risk" / "risk_output.json"

    def run(self):
        input_path = self.__DEFAULT_IN
        out_path = self.__DEFAULT_OUT

        events = load_preprocessed_events(input_path)
        out = main_from_events(events)

        Path(out_path).write_text(
            json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"✅ wrote {out_path} with {len(out.get('groups', []))} groups.")