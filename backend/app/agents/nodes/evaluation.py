"""Node 4: Hypothesis Evaluation & Evidential Validation for Agentic SRE."""

from typing import Dict, Any, List
from app.agents.state import InvestigationState
from app.schemas.investigation import Hypothesis


def evaluate_and_rank_hypotheses(
    state: InvestigationState,
) -> Dict[str, Any]:
    """
    Evaluates candidate hypotheses against collected evidence:
    1. Validates cited evidence IDs exist (rejects hallucinated references).
    2. Checks for contradictions between claims and observations.
    3. Verifies evidential grounding for every root-cause claim.
    4. Ranks hypotheses according to evidential support score.
    """
    raw_hypotheses = state.get("hypotheses", [])
    evidence_items = state.get("evidence_items", [])

    # Index valid evidence IDs and map to observations
    valid_evidence_map: Dict[str, str] = {
        ev.get("evidence_id"): ev.get("observation", "").lower()
        for ev in evidence_items
        if ev.get("evidence_id")
    }
    valid_ids = set(valid_evidence_map.keys())

    evaluated_hypotheses: List[Dict[str, Any]] = []

    for hyp_dict in raw_hypotheses:
        hyp = Hypothesis(**hyp_dict)
        notes: List[str] = []
        is_supported = True
        adjusted_confidence = hyp.confidence

        # 1. Evidence Reference Validation
        invalid_supporting = [eid for eid in hyp.supporting_evidence_ids if eid not in valid_ids]
        invalid_contradicting = [eid for eid in hyp.contradicting_evidence_ids if eid not in valid_ids]

        if invalid_supporting:
            notes.append(f"Rejected unverified evidence references: {', '.join(invalid_supporting)}.")
            # Filter out non-existent IDs
            hyp.supporting_evidence_ids = [eid for eid in hyp.supporting_evidence_ids if eid in valid_ids]
            adjusted_confidence = max(0.1, adjusted_confidence - 0.25)
            is_supported = False

        if invalid_contradicting:
            hyp.contradicting_evidence_ids = [eid for eid in hyp.contradicting_evidence_ids if eid in valid_ids]

        # 2. Check if hypothesis has zero valid supporting evidence
        if not hyp.supporting_evidence_ids and "insufficient" not in hyp.root_cause.lower():
            notes.append("No valid supporting evidence citations found for this claim.")
            is_supported = False
            adjusted_confidence = min(adjusted_confidence, 0.3)

        # 3. Contradiction Detection
        # If any health probe returned 200 OK, a claim that the service is "unreachable" or "down" has contradiction
        has_healthy_evidence = any(
            "200 ok" in obs or "http 200" in obs
            for obs in valid_evidence_map.values()
        )
        if has_healthy_evidence and any(k in hyp.root_cause.lower() for k in ["unreachable", "down", "outage"]):
            healthy_ids = [
                eid for eid, obs in valid_evidence_map.items()
                if "200" in obs or "healthy" in obs
            ]
            for hid in healthy_ids:
                if hid not in hyp.contradicting_evidence_ids:
                    hyp.contradicting_evidence_ids.append(hid)
            notes.append("Contradicted by successful health probe returning HTTP 200.")
            adjusted_confidence = max(0.1, adjusted_confidence - 0.35)

        # 4. Evidential Grounding Check
        # Ensure at least one cited evidence observation mentions terms consistent with root cause
        claim_keywords = [
            w for w in hyp.root_cause.lower().replace("/", " ").replace("-", " ").split()
            if len(w) > 3 and w not in ["downstream", "service", "error", "cause", "issue"]
        ]
        if any(k in hyp.root_cause.lower() for k in ["unreachable", "interruption", "network"]):
            claim_keywords.extend(["connection", "refused", "unreachable", "offline", "timeout", "network"])
        if any(k in hyp.root_cause.lower() for k in ["latency", "performance", "slow"]):
            claim_keywords.extend(["latency", "duration", "delay", "threshold", "exceeded", "ms", "seconds"])
        if any(k in hyp.root_cause.lower() for k in ["500", "5xx", "degradation"]):
            claim_keywords.extend(["500", "503", "5xx", "server", "error", "degraded"])

        grounded = False
        is_normal_claim = any(k in hyp.root_cause.lower() for k in ["normal", "variance", "healthy", "transient"])
        if is_normal_claim and has_healthy_evidence:
            grounded = True
        elif not claim_keywords or "insufficient" in hyp.root_cause.lower():
            grounded = True
        else:
            for eid in hyp.supporting_evidence_ids:
                obs_text = valid_evidence_map.get(eid, "")
                if any(kw in obs_text for kw in claim_keywords):
                    grounded = True
                    break

        if not grounded and hyp.supporting_evidence_ids:
            notes.append(f"Claim keywords ({', '.join(claim_keywords[:3])}) not explicitly observed in cited evidence.")
            is_supported = False
            adjusted_confidence = max(0.2, adjusted_confidence - 0.2)



        # 5. Calibration Disclaimer
        notes.append("Confidence is an evidential heuristic score, not a calibrated statistical probability.")

        hyp.is_supported = is_supported
        hyp.confidence = round(max(0.0, min(1.0, adjusted_confidence)), 2)
        hyp.evaluation_notes = " ".join(notes)

        evaluated_hypotheses.append(hyp.model_dump())

    # 6. Rank Hypotheses by evidential support score (highest confidence first)
    evaluated_hypotheses.sort(key=lambda h: (h["is_supported"], h["confidence"]), reverse=True)
    for idx, h in enumerate(evaluated_hypotheses, start=1):
        h["rank"] = idx

    return {
        "hypotheses": evaluated_hypotheses,
    }
