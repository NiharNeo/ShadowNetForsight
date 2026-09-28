"""Versioned feature provenance; matching names alone do not imply compatibility."""
PCAP_CONTRACT = "shadownet.packet-window.v1"
TELEMETRY_CONTRACT = "shadownet.telemetry-window.v1"
CSV_CONTRACT = "shadownet.completed-flow-window.v1"


def compatibility(training_contract: str | None, input_contract: str = PCAP_CONTRACT) -> dict:
    matched = training_contract == input_contract
    return {
        "training_contract": training_contract or "legacy_unversioned",
        "input_contract": input_contract,
        "compatible": matched,
        "status": "matched" if matched else "unverified",
        "detail": (
            "Extraction contracts match; independent model validation is still required."
            if matched else
            "Checkpoint feature extraction is not verified for packet windows. Scores are exploratory; calibration cannot establish feature compatibility."
        ),
    }
