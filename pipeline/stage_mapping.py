from __future__ import annotations

import re


STAGE_ORDER = {
    "Normal": 0,
    "Reconnaissance": 1,
    "Initial Access": 2,
    "Command and Control": 3,
    "Lateral Movement": 4,
    "Exfiltration": 5,
}


# CIC-IDS2018 labels describe traffic families, not MITRE tactics. This explicit,
# reviewable mapping avoids silently pretending that the source dataset contains
# attack-stage ground truth. The rationale is exported in every build manifest.
LABEL_RULES = [
    (r"benign|normal|background|to-botnet", "Normal", "Dataset labels the flow benign/background; CTU To-Botnet is not malicious per the publisher."),
    (r"from-botnet", "Command and Control", "CTU manually labels traffic originating from the infected host as botnet activity."),
    (r"scan|infilt", "Reconnaissance", "Scanning/infiltration discovery signals exposure probing; 'Infilteration' is the publisher's CSV spelling."),
    (r"brute.?force|ftp.?brute|ssh.?brute|web.?attack|sql.?injection|xss", "Initial Access", "Credential or application exploitation targets first access."),
    (r"bot|heartbleed", "Command and Control", "Bot/Heartbleed families are treated as post-compromise control activity."),
    (r"ddos|dos|hulk|goldeneye|slowloris|slowhttptest", "Command and Control", "Availability attacks are retained as malicious activity without inventing lateral movement."),
]


def map_label(raw_label: object) -> tuple[str, str]:
    label = re.sub(r"\s+", " ", str(raw_label).strip().lower())
    for pattern, stage, rationale in LABEL_RULES:
        if re.search(pattern, label, flags=re.IGNORECASE):
            return stage, rationale
    return "Initial Access", "Unknown malicious label conservatively maps to Initial Access pending analyst review."
