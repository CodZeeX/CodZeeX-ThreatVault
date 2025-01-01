import os
import json
import yaml
from .utils import log_info, log_alert, log_success

def load_sigma_rule(rule_path: str) -> dict:
    with open(rule_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def match_event(event: dict, rule: dict) -> bool:
    detection = rule.get("detection", {})
    selection = detection.get("selection", {})
    if not selection:
        return False

    for field, pattern in selection.items():
        field_clean = field.split("|")[0]
        operator = field.split("|")[1] if "|" in field else "exact"
        event_val = str(event.get(field_clean, ""))

        if operator == "contains":
            if pattern.lower() not in event_val.lower():
                return False
        elif operator == "endswith":
            if not event_val.lower().endswith(pattern.lower()):
                return False
        else:
            if event_val.lower() != str(pattern).lower():
                return False
    return True

def evaluate_events(log_file: str, rule_path: str):
    rule = load_sigma_rule(rule_path)
    log_info(f"Loaded Sigma rule: {rule.get('title', 'Unknown')} [Severity: {rule.get('level', 'info').upper()}]")
    
    with open(log_file, "r", encoding="utf-8") as f:
        events = json.load(f)
        if isinstance(events, dict):
            events = [events]

    hits = 0
    for idx, ev in enumerate(events):
        if match_event(ev, rule):
            hits += 1
            log_alert(f"Sigma Rule Match on Event #{idx+1}: {ev.get('CommandLine', ev)}")

    log_success(f"Evaluation finished: {hits} matches out of {len(events)} events.")
    return hits
