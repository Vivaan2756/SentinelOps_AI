"""Canonical Execution State Machine for Phase 4.3.

Defines the 11 explicit states, legal state transitions, and validation rules
strictly adhering to docs/PHASE_4_3_EXECUTION_ARCHITECTURE.md (Section 9).
"""

from enum import Enum
from typing import Dict, Set
from app.execution.exceptions import IllegalStateTransitionError


class ExecutionState(str, Enum):
    """The 11 explicit execution states from Phase 4.3 architecture."""

    QUEUED = "queued"
    VALIDATING = "validating"
    EXECUTING = "executing"
    EXECUTION_SUCCEEDED = "execution_succeeded"
    EXECUTION_FAILED = "execution_failed"
    TIMED_OUT = "timed_out"
    EXECUTION_UNCERTAIN = "execution_uncertain"
    VERIFICATION_PENDING = "verification_pending"
    VERIFIED = "verified"
    VERIFICATION_FAILED = "verification_failed"
    CANCELLED = "cancelled"


# All valid state values as a string set
ALL_EXECUTION_STATES: Set[str] = {state.value for state in ExecutionState}

# Terminal states that cannot transition further
TERMINAL_STATES: Set[str] = {
    ExecutionState.TIMED_OUT.value,
    ExecutionState.EXECUTION_UNCERTAIN.value,
    ExecutionState.VERIFIED.value,
    ExecutionState.VERIFICATION_FAILED.value,
    ExecutionState.CANCELLED.value,
}

# Legal state transitions mapping
LEGAL_TRANSITIONS: Dict[str, Set[str]] = {
    ExecutionState.QUEUED.value: {
        ExecutionState.VALIDATING.value,
        ExecutionState.CANCELLED.value,
    },
    ExecutionState.VALIDATING.value: {
        ExecutionState.EXECUTING.value,
        ExecutionState.EXECUTION_FAILED.value,
    },
    ExecutionState.EXECUTING.value: {
        ExecutionState.EXECUTION_SUCCEEDED.value,
        ExecutionState.EXECUTION_FAILED.value,
        ExecutionState.TIMED_OUT.value,
        ExecutionState.EXECUTION_UNCERTAIN.value,
    },
    ExecutionState.EXECUTION_SUCCEEDED.value: {
        ExecutionState.VERIFICATION_PENDING.value,
        ExecutionState.VERIFIED.value,
    },
    ExecutionState.EXECUTION_FAILED.value: {
        # Retry eligible back to queued if idempotent and attempt < max_attempts
        ExecutionState.QUEUED.value,
    },
    ExecutionState.VERIFICATION_PENDING.value: {
        ExecutionState.VERIFIED.value,
        ExecutionState.VERIFICATION_FAILED.value,
    },
    # Terminal states have no valid transitions
    ExecutionState.TIMED_OUT.value: set(),
    # Operational uncertainty hold can ONLY transition via authorized operator resolution
    ExecutionState.EXECUTION_UNCERTAIN.value: {
        ExecutionState.EXECUTION_FAILED.value,        # Operator ABORT_FAILURE
        ExecutionState.VERIFICATION_PENDING.value,   # Operator CONFIRM_SUCCESS
    },
    ExecutionState.VERIFIED.value: set(),
    ExecutionState.VERIFICATION_FAILED.value: set(),
    ExecutionState.CANCELLED.value: set(),
}


def is_terminal_state(state: str) -> bool:
    """Return True if state is terminal and cannot transition further."""
    return state in TERMINAL_STATES


def validate_state_transition(current_state: str, new_state: str) -> None:
    """
    Validate that transition from current_state to new_state is allowed.
    Raises IllegalStateTransitionError if invalid.
    """
    if current_state not in ALL_EXECUTION_STATES:
        raise IllegalStateTransitionError(f"Unknown current execution state '{current_state}'.")

    if new_state not in ALL_EXECUTION_STATES:
        raise IllegalStateTransitionError(f"Unknown target execution state '{new_state}'.")

    # Idempotent re-affirmation of identical state is always a no-op
    if current_state == new_state:
        return

    allowed = LEGAL_TRANSITIONS.get(current_state, set())
    if new_state not in allowed:
        raise IllegalStateTransitionError(
            f"Illegal execution state transition from '{current_state}' to '{new_state}'. "
            f"Allowed transitions from '{current_state}': {sorted(allowed) if allowed else 'none (terminal state)'}."
        )
