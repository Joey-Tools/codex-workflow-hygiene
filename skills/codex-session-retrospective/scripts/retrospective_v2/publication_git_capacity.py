"""Capacity-ledger ownership for the local Git publication adapter."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .publication_support import (
    CapacityReservationError,
    LOCAL_GIT_CAPACITY_RESERVATION_SCHEMA,
    OperationRequest,
    PUBLICATION_CAPACITY_OVERHEAD_BYTES,
    StateCorruptionError,
    _sha256_json,
    _validate_capacity_ledger,
)


class LocalGitCapacityOperations:
    """Bind capacity reservations to one durable publication attempt."""

    def _capacity_reservation_binding_digest(
        self,
        request: OperationRequest,
        amount: int,
    ) -> str:
        return _sha256_json(
            {
                "binding": request.binding(),
                "capacity_bytes": amount,
                "destination": request.destination,
                "episode_head_update": dict(request.episode_head_update),
                "expected_target_head": request.expected_target_head,
                "host_cursor_vector": dict(request.host_cursor_vector),
                "publication_authority": dict(request.publication_authority),
                "target_ref": request.target_ref,
            }
        )

    def _capacity_reservation_record(
        self,
        request: OperationRequest,
        amount: int,
    ) -> dict[str, Any]:
        return {
            "binding_digest": self._capacity_reservation_binding_digest(
                request,
                amount,
            ),
            "capacity_bytes": amount,
            "schema": LOCAL_GIT_CAPACITY_RESERVATION_SCHEMA,
        }

    def _reserve_capacity(self, request: OperationRequest, amount: int) -> None:
        existing_amount = self._capacity_reservation_locked(request)
        if existing_amount is not None:
            if existing_amount != amount:
                raise StateCorruptionError("publication capacity reservation changed")
            return
        ledger = self._state_directory.read_json(self._capacity_path.name)
        _validate_capacity_ledger(ledger)
        reservations = dict(ledger["reservations"])
        expected = self._capacity_reservation_record(request, amount)
        used = sum(
            int(
                value
                if isinstance(value, int) and not isinstance(value, bool)
                else value["capacity_bytes"]
            )
            for value in reservations.values()
        )
        if used + amount > int(ledger["limit_bytes"]):
            raise CapacityReservationError(
                f"publication capacity exhausted: requested={amount}, available={ledger['limit_bytes'] - used}"
            )
        reservations[request.attempt_ref] = expected
        updated = dict(ledger)
        updated["reservations"] = reservations
        self._state_directory.write_json(self._capacity_path.name, updated)

    def _capacity_reservation_locked(
        self,
        request: OperationRequest,
    ) -> int | None:
        ledger = self._state_directory.read_json(self._capacity_path.name)
        _validate_capacity_ledger(ledger)
        raw = ledger["reservations"].get(request.attempt_ref)
        if raw is None:
            return None
        if isinstance(raw, int) and not isinstance(raw, bool):
            state = self._read_attempt(request.attempt_ref, missing_ok=True)
            if state is None:
                raise StateCorruptionError(
                    "legacy publication capacity lacks a durable attempt"
                )
            self._assert_attempt_binding(state, request)
            units = self._unit_plan_for_request(request)
            expected_amount = max(
                1,
                sum(int(unit["inventory"]["total_bytes"]) for unit in units)
                + PUBLICATION_CAPACITY_OVERHEAD_BYTES,
            )
            if raw != expected_amount:
                raise StateCorruptionError(
                    "legacy publication capacity cannot bind this attempt"
                )
            reservation = state["receipts"].get("reservation")
            observation = state["receipts"].get("target_observation")
            expected_observation = self._target_observation(
                request,
                target_head=request.expected_target_head,
                destination_exists=False,
            )
            expected_reservation = self._receipt(
                request,
                "reserved",
                capacity_bytes=raw,
                destination=request.destination,
                expected_target_head=request.expected_target_head,
                key_generation=state["generation_snapshot"]["key_generation"],
                policy_generation=state["generation_snapshot"]["policy_generation"],
                reservations_held=True,
                target_observation_receipt_ref=expected_observation["receipt_ref"],
                target_ref=request.target_ref,
            )
            if (
                state["capacity_held"] is not True
                or state["capacity_bytes"] != raw
                or state["unit_plan"] != units
                or not isinstance(observation, Mapping)
                or dict(observation) != expected_observation
                or not isinstance(reservation, Mapping)
                or dict(reservation) != expected_reservation
            ):
                raise StateCorruptionError(
                    "legacy publication capacity lacks a matching reservation"
                )
            reservations = dict(ledger["reservations"])
            reservations[request.attempt_ref] = self._capacity_reservation_record(
                request,
                raw,
            )
            updated = dict(ledger)
            updated["reservations"] = reservations
            self._state_directory.write_json(self._capacity_path.name, updated)
            raw = reservations[request.attempt_ref]
        record = dict(raw)
        amount = int(record["capacity_bytes"])
        if record != self._capacity_reservation_record(request, amount):
            raise StateCorruptionError(
                "publication capacity reservation binding changed"
            )
        return amount

    def _capacity_reservation(self, request: OperationRequest) -> int | None:
        with self._short_publication_lock():
            return self._capacity_reservation_locked(request)

    def _release_capacity(
        self,
        request: OperationRequest,
        expected_amount: int | None,
    ) -> None:
        with self._short_publication_lock():
            amount = self._capacity_reservation_locked(request)
            if amount is None:
                return
            if expected_amount != amount:
                raise StateCorruptionError(
                    "publication capacity release binding changed"
                )
            ledger = self._state_directory.read_json(self._capacity_path.name)
            _validate_capacity_ledger(ledger)
            reservations = dict(ledger["reservations"])
            expected = self._capacity_reservation_record(request, amount)
            if reservations.get(request.attempt_ref) != expected:
                raise StateCorruptionError(
                    "publication capacity changed before release"
                )
            del reservations[request.attempt_ref]
            updated = dict(ledger)
            updated["reservations"] = reservations
            self._state_directory.write_json(self._capacity_path.name, updated)
