"""Comprehensive unit, security, Solana wire-format, and FastAPI E2E test suite for HopPay Agentic Treasury Studio."""

from __future__ import annotations

import base64
import struct

from fastapi.testclient import TestClient
import pytest

from app import app
from solana_proof import (
    ASSOCIATED_TOKEN_PROGRAM_ID,
    MEMO_V2_PROGRAM_ID,
    SOL_WRAPPED_MINT,
    SPL_TOKEN_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
    TOKEN_2022_PROGRAM_ID,
    USDC_DEVNET_MINT,
    USDC_MAINNET_MINT,
    USDG_MAINNET_MINT,
    b58decode_pubkey,
    b58encode,
    build_unsigned_solana_audit_tx,
    is_valid_solana_pubkey,
    simulate_plan_on_solana_devnet,
)
from treasury_engine import (
    DEFAULT_TREASURY_WALLET,
    AgentPlanRequest,
    AgenticTreasuryStudio,
    CustomHopSpec,
    PayoutLineItem,
    TreasuryPolicyConfig,
    build_preset_requests,
    raw_to_tokens,
    tokens_to_raw,
)


def test_solana_pubkey_constants_and_base58_roundtrip() -> None:
    constants = [
        SYSTEM_PROGRAM_ID,
        SPL_TOKEN_PROGRAM_ID,
        TOKEN_2022_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID,
        MEMO_V2_PROGRAM_ID,
        USDG_MAINNET_MINT,
        USDC_MAINNET_MINT,
        USDC_DEVNET_MINT,
        SOL_WRAPPED_MINT,
        DEFAULT_TREASURY_WALLET,
    ]
    for pk in constants:
        raw = b58decode_pubkey(pk)
        assert len(raw) == 32
        assert b58encode(raw) == pk
        assert is_valid_solana_pubkey(pk) is True

    assert is_valid_solana_pubkey("not-a-valid-base58-key!!!") is False
    assert is_valid_solana_pubkey("11111") is False


def test_exact_decimal_token_math_no_float_drift() -> None:
    r1 = tokens_to_raw("0.1", 6)
    r2 = tokens_to_raw("0.2", 6)
    assert r1 + r2 == 300_000
    assert raw_to_tokens(r1 + r2, 6) == "0.3"

    assert tokens_to_raw("200.00", 6) == 200_000_000
    assert raw_to_tokens(200_000_000, 6) == "200"
    assert tokens_to_raw("1.234567891", 9) == 1_234_567_891

    with pytest.raises(ValueError):
        tokens_to_raw("0", 6)
    with pytest.raises(ValueError):
        tokens_to_raw("-15.5", 6)
    with pytest.raises(ValueError):
        tokens_to_raw("0.0000001", 6)


def test_split_invoice_consolidation_blocks_cap_evasion() -> None:
    studio = AgenticTreasuryStudio()
    minh_wallet = studio.contributors["@minh-svm"].wallet

    req = AgentPlanRequest(
        plan_title="Split Invoice Evasion Test",
        items=[
            PayoutLineItem(handle="@minh-svm", wallet=minh_wallet, amount_tokens="1450.25", memo="Part 1"),
            PayoutLineItem(handle="@minh-svm", wallet=minh_wallet, amount_tokens="1399.75", memo="Part 2"),
        ],
        token_symbol="USDG",
        policy=TreasuryPolicyConfig(
            max_single_recipient_usd=2_500.0,
            anomaly_spike_multiplier=5.0,
        ),
    )
    plan = studio.create_plan(req)
    assert plan["totals"]["unique_recipients"] == 1
    assert plan["totals"]["merged_duplicate_rows"] == 1
    assert plan["totals"]["total_tokens"] == "2850"
    assert plan["allowed"] is False
    assert plan["verdict"] == "POLICY_BLOCKED"
    codes = {f["code"] for f in plan["findings"]}
    assert "DUPLICATE_WALLETS_CONSOLIDATED" in codes
    assert "SINGLE_RECIPIENT_CAP_EXCEEDED" in codes


def test_velocity_spike_wallet_swap_and_denylist_trigger_anomaly_halt() -> None:
    studio = AgenticTreasuryStudio()
    presets = build_preset_requests(studio)
    plan = studio.create_plan(presets["attack_anomaly_halt"]["request"])

    assert plan["allowed"] is False
    assert plan["verdict"] == "ANOMALY_HALT"
    codes = {f["code"] for f in plan["findings"]}
    assert "SINGLE_RECIPIENT_CAP_EXCEEDED" in codes
    assert "ANOMALY_VELOCITY_SPIKE" in codes
    assert "ANOMALY_WALLET_SWAP" in codes
    assert "ANOMALY_DENYLISTED_WALLET" in codes
    assert "UNALLOWLISTED_WALLET" in codes

    with pytest.raises(PermissionError):
        studio.approve_plan(plan["plan_id"])
    with pytest.raises(PermissionError):
        studio.simulate_devnet(plan["plan_id"], allow_network=False)


def test_auto_chunking_26_recipients_into_uniform_multihopper_routes() -> None:
    studio = AgenticTreasuryStudio()
    presets = build_preset_requests(studio)
    plan = studio.create_plan(presets["scale_26_grant_wave"]["request"])

    assert plan["allowed"] is True
    assert plan["verdict"] == "AWAITING_HITL_APPROVAL"
    assert plan["totals"]["unique_recipients"] == 26
    assert plan["routing"]["chunk_count"] == 2
    chunks = plan["routing"]["chunks"]
    assert chunks[0]["destination_count"] == 20
    assert chunks[1]["destination_count"] == 6

    summed_raw = sum(int(ch["chunk_amount_raw"]) for ch in chunks)
    assert str(summed_raw) == plan["totals"]["total_raw"]


def test_custom_hop_mh018_mh019_and_mh017_sol_rent_dust_guards() -> None:
    studio = AgenticTreasuryStudio()
    hana_wallet = studio.contributors["@hana-zk"].wallet

    req = AgentPlanRequest(
        plan_title="Route Guard Verification",
        items=[
            PayoutLineItem(handle="@hana-zk", wallet=hana_wallet, amount_tokens="0.0005", memo="Tiny SOL dust"),
        ],
        token_symbol="SOL",
        custom_hops=[
            CustomHopSpec(wallet=DEFAULT_TREASURY_WALLET, waitSeconds=30),
            CustomHopSpec(wallet=hana_wallet, waitSeconds=30),
            CustomHopSpec(wallet=SYSTEM_PROGRAM_ID, waitSeconds=30),
            CustomHopSpec(bundle="contracts", waitSeconds=30),
        ],
        policy=TreasuryPolicyConfig(is_devnet=True),
    )
    plan = studio.create_plan(req)
    assert plan["allowed"] is False
    codes = {f["code"] for f in plan["findings"]}
    assert "MH_017_SOL_RENT_DUST" in codes
    assert "MH_018_SENDER_LOOP" in codes
    assert "MH_018_DESTINATION_COLLISION" in codes
    assert "MH_018_RESERVED_HOP" in codes
    assert "MH_018_CONTRACTS_FINAL_HOP" in codes
    assert "MH_019_DEVNET_BUNDLE" in codes


def test_unsigned_solana_wire_tx_layout_token2022_usdg() -> None:
    studio = AgenticTreasuryStudio()
    recipient = studio.contributors["@minh-svm"].wallet
    tx = build_unsigned_solana_audit_tx(
        fee_payer=DEFAULT_TREASURY_WALLET,
        memo_payload={"app": "HopPayAgenticStudio", "plan": "plan_unit_01"},
        token_symbol="USDG",
        mint_pubkey=USDG_MAINNET_MINT,
        token_program_id=TOKEN_2022_PROGRAM_ID,
        decimals=6,
        sample_recipient=recipient,
        sample_amount_raw=200_000_000,
    )
    assert tx["is_token_2022"] is True
    assert tx["instruction_count"] == 2
    raw_wire = base64.b64decode(tx["unsigned_tx_base64"])
    assert len(raw_wire) == tx["wire_tx_bytes_len"]
    assert raw_wire[0] == 1
    assert raw_wire[1:65] == b"\x00" * 64
    expected_ix_data = struct.pack("<BQB", 12, 200_000_000, 6)
    assert expected_ix_data in raw_wire


def test_audit_ledger_sha256_hash_chain_and_tamper_detection() -> None:
    studio = AgenticTreasuryStudio()
    presets = build_preset_requests(studio)
    p1 = studio.create_plan(presets["clean_usdg_payroll"]["request"])
    studio.approve_plan(p1["plan_id"], approver="@quangnguyen2512")
    studio.simulate_devnet(p1["plan_id"], allow_network=False)

    integrity = studio.verify_ledger_integrity()
    assert integrity["valid"] is True
    assert integrity["entry_count"] == 3
    assert studio.ledger[0].prev_hash == "0" * 64
    assert studio.ledger[1].prev_hash == studio.ledger[0].entry_hash
    assert studio.ledger[2].prev_hash == studio.ledger[1].entry_hash

    original_summary = studio.ledger[1].summary
    studio.ledger[1].summary = "TAMPERED BY ATTACKER"
    broken = studio.verify_ledger_integrity()
    assert broken["valid"] is False
    assert broken["broken_at_seq"] == 2

    studio.ledger[1].summary = original_summary
    assert studio.verify_ledger_integrity()["valid"] is True


def test_deterministic_and_live_solana_devnet_simulation() -> None:
    offline = simulate_plan_on_solana_devnet(
        plan_id="plan_offline_test",
        policy_hash="f" * 64,
        token_symbol="USDG",
        total_usd=200.0,
        recipient_count=2,
        chunk_count=1,
        allow_network=False,
    )
    assert offline["verified"] is True
    assert offline["mode"] == "DETERMINISTIC_SVM_SIMULATION"
    assert offline["units_consumed"] > 0

    live_or_fallback = simulate_plan_on_solana_devnet(
        plan_id="plan_live_probe",
        policy_hash="a" * 64,
        token_symbol="USDG",
        total_usd=200.0,
        recipient_count=2,
        chunk_count=1,
        allow_network=True,
    )
    assert live_or_fallback["verified"] is True
    assert live_or_fallback["mode"] in {"LIVE_SOLANA_DEVNET_RPC", "DETERMINISTIC_SVM_SIMULATION"}
    assert any("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr" in log for log in live_or_fallback["logs"])


def test_fastapi_e2e_dashboard_presets_hitl_approval_and_security_gates() -> None:
    client = TestClient(app)

    home = client.get("/")
    assert home.status_code == 200
    assert "HopPay Agentic Treasury Studio" in home.text

    health = client.get("/api/health").json()
    assert health["status"] == "ok"
    assert health["audit_chain"]["valid"] is True
    assert "USDG" in health["supported_tokens"]

    presets = client.get("/api/presets").json()["presets"]
    assert len(presets) == 3

    halted = client.post("/api/presets/attack_anomaly_halt/run", json={}).json()
    assert halted["verdict"] == "ANOMALY_HALT"
    res_block_approve = client.post(
        f"/api/plans/{halted['plan_id']}/approve",
        json={"approver": "@quangnguyen2512", "note": "Should fail"},
    )
    assert res_block_approve.status_code == 409

    res_block_sim = client.post(
        f"/api/plans/{halted['plan_id']}/simulate-devnet",
        json={"allow_network": False},
    )
    assert res_block_sim.status_code == 409

    clean = client.post("/api/presets/clean_usdg_payroll/run", json={}).json()
    assert clean["verdict"] == "AWAITING_HITL_APPROVAL"
    assert clean["totals"]["total_tokens"] == "3400"

    approved = client.post(
        f"/api/plans/{clean['plan_id']}/approve",
        json={"approver": "@quangnguyen2512", "note": "Milestones verified"},
    )
    assert approved.status_code == 200
    assert approved.json()["verdict"] == "APPROVED_READY"

    sim = client.post(
        f"/api/plans/{clean['plan_id']}/simulate-devnet",
        json={"allow_network": False},
    )
    assert sim.status_code == 200
    assert sim.json()["simulation"]["verified"] is True

    exported = client.get(f"/api/plans/{clean['plan_id']}/export")
    assert exported.status_code == 200
    assert exported.json()["ledger_integrity"]["valid"] is True

    ledger = client.get("/api/audit-ledger").json()
    assert ledger["integrity"]["valid"] is True
    assert len(ledger["entries"]) >= 4
