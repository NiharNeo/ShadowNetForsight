from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import random
from typing import Literal


Action = Literal["block_ip", "close_port", "isolate_host", "rate_limit"]


@dataclass(frozen=True)
class AttackEdge:
    source: str
    target: str
    service: str
    probability: float


BASE_TOPOLOGY = (
    AttackEdge("internet", "edge", "ingress", 0.78),
    AttackEdge("edge", "web", "ssh", 0.72),
    AttackEdge("web", "db", "smb", 0.63),
)


def intervene(edges: tuple[AttackEdge, ...], action: Action) -> tuple[AttackEdge, ...]:
    result = []
    for edge in edges:
        probability = edge.probability
        if action == "block_ip" and edge.source == "internet":
            probability *= 0.04
        elif action == "close_port" and edge.service == "ssh":
            probability *= 0.08
        elif action == "isolate_host" and (edge.source == "web" or edge.target == "web"):
            probability *= 0.03
        elif action == "rate_limit" and edge.service in {"ingress", "ssh"}:
            probability *= 0.48
        result.append(replace(edge, probability=probability))
    return tuple(result)


def _trial(edges: tuple[AttackEdge, ...], randomizer: random.Random) -> bool:
    reached = {"internet"}
    for edge in edges:
        if edge.source in reached and randomizer.random() < edge.probability:
            reached.add(edge.target)
    return "db" in reached


def _estimate(edges: tuple[AttackEdge, ...], trials: int, seed: int) -> tuple[float, tuple[float, float]]:
    randomizer = random.Random(seed)
    successes = sum(_trial(edges, randomizer) for _ in range(trials))
    probability = successes / trials
    radius = 1.96 * (probability * (1 - probability) / trials) ** 0.5
    return probability, (max(0.0, probability - radius), min(1.0, probability + radius))


def simulate_mitigation(action: Action, trials: int = 20_000) -> dict:
    seed = int(hashlib.sha256(action.encode()).hexdigest()[:8], 16)
    before, before_interval = _estimate(BASE_TOPOLOGY, trials, seed)
    modified = intervene(BASE_TOPOLOGY, action)
    after, after_interval = _estimate(modified, trials, seed + 1)
    changed = [
        {"edge": f"{base.source}->{base.target}:{base.service}",
         "before_probability": base.probability, "after_probability": updated.probability}
        for base, updated in zip(BASE_TOPOLOGY, modified) if base.probability != updated.probability
    ]
    return {
        "before": round(before * 100, 2), "after": round(after * 100, 2),
        "reduction": round((before - after) * 100, 2),
        "before_interval_95": [round(value * 100, 2) for value in before_interval],
        "after_interval_95": [round(value * 100, 2) for value in after_interval],
        "trials": trials, "changed_edges": changed,
        "method": "monte_carlo_structural_attack_path_intervention",
        "disclaimer": "Scenario-model estimate conditioned on the declared topology and edge probabilities; not a guaranteed causal effect.",
    }
