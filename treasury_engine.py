"""HopPay Agentic Treasury Studio — Autonomous AI CFO Planner, Policy Guard, Anomaly Halt & Multi-Hop Router.

Implements deterministic treasury planning for Solana DAOs, AI agents, and contributor teams:
  1. Natural-language + CSV payout intent parsing resolved against a verified contributor registry.
  2. Exact base-unit `Decimal` consolidation so split-row invoices cannot bypass per-recipient caps.
  3. Multi-layered `PolicyGuard`: Base58 validation, protocol-reserved & denylist screening,
     allowlist enforcement, wallet-swap circuit breaker, velocity spike (`>= 3.0x`) anomaly halt,
     per-recipient & batch USD caps, and MultiHopper v1 `MH_017` / `MH_018` / `MH_019` route checks.
  4. Uniform `<= 20` destination auto-chunking and Token-2022 (`USDG`) / SPL (`USDC`) fee quoting.
  5. Tamper-evident SHA-256 hash-chained `AuditLedger` with live cryptographic chain verification.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_DOWN
import hashlib
import io
import json
import re
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from solana_proof import (
    ASSOCIATED_TOKEN_PROGRAM_ID,
    MEMO_V2_PROGRAM_ID,
    SOL_WRAPPED_MINT,
    SPL_TOKEN_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
    SYSVAR_CLOCK_ID,
    SYSVAR_RENT_ID,
    TOKEN_2022_PROGRAM_ID,
    USDC_DEVNET_MINT,
    USDC_MAINNET_MINT,
    USDG_MAINNET_MINT,
    b58encode,
    build_unsigned_solana_audit_tx,
    is_valid_solana_pubkey,
    simulate_plan_on_solana_devnet,
)

MAX_DESTINATIONS_PER_ROUTE = 20
SOL_RENT_EXEMPT_MIN_LAMPORTS = 890_880
MIN_HOP_WAIT_SECONDS = 20
MAX_ROUTE_WAIT_SECONDS = 2_592_000  # 30 days
MULTIHOPPER_FEE_BPS = 50            # 0.50% dispersion routing fee

VALID_HOP_BUNDLES: frozenset[str] = frozenset(
    {"cex", "dex", "exchanges", "kol", "contracts", "mix"}
)

PROTOCOL_RESERVED_ADDRESSES: frozenset[str] = frozenset(
    {
        SYSTEM_PROGRAM_ID,
        SPL_TOKEN_PROGRAM_ID,
        TOKEN_2022_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID,
        MEMO_V2_PROGRAM_ID,
        SYSVAR_RENT_ID,
        SYSVAR_CLOCK_ID,
    }
)


def _det_wallet(seed_label: str) -> str:
    """Generate a deterministic, mathematically valid 32-byte Base58 Solana public key for fixtures."""
    return b58encode(hashlib.sha256(f"HopPayStudio:v1:{seed_label}".encode("utf-8")).digest())


DEFAULT_TREASURY_WALLET = _det_wallet("dao_treasury_multisig_vault")
QUARANTINED_SYBIL_WALLET = _det_wallet("quarantined_sybil_drain_wallet")

DENYLISTED_WALLETS: frozenset[str] = frozenset({QUARANTINED_SYBIL_WALLET})

RELAY_NODE_POOL: list[str] = [
    _det_wallet(f"multihopper_ephemeral_relay_{i}") for i in range(1, 11)
]

SUPPORTED_TOKENS: dict[str, dict[str, Any]] = {
    "USDG": {
        "symbol": "USDG",
        "name": "Global Dollar (Solana Token-2022)",
        "mint_mainnet": USDG_MAINNET_MINT,
        "mint_devnet": USDC_DEVNET_MINT,
        "token_program_id": TOKEN_2022_PROGRAM_ID,
        "standard": "Token-2022",
        "decimals": 6,
        "default_price_usd": 1.0,
    },
    "USDC": {
        "symbol": "USDC",
        "name": "USD Coin (Classic SPL)",
        "mint_mainnet": USDC_MAINNET_MINT,
        "mint_devnet": USDC_DEVNET_MINT,
        "token_program_id": SPL_TOKEN_PROGRAM_ID,
        "standard": "SPL Token",
        "decimals": 6,
        "default_price_usd": 1.0,
    },
    "SOL": {
        "symbol": "SOL",
        "name": "Wrapped / Native SOL",
        "mint_mainnet": SOL_WRAPPED_MINT,
        "mint_devnet": SOL_WRAPPED_MINT,
        "token_program_id": SPL_TOKEN_PROGRAM_ID,
        "standard": "Native / SPL",
        "decimals": 9,
        "default_price_usd": 185.0,
    },
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def tokens_to_raw(amount_tokens: str | float | Decimal, decimals: int) -> int:
    """Convert human-readable token string/number into exact integer base units via `Decimal`."""
    try:
        dec = Decimal(str(amount_tokens).strip())
    except InvalidOperation as exc:
        raise ValueError(f"Invalid numeric token amount: {amount_tokens!r}") from exc
    if dec <= 0:
        raise ValueError(f"Token amount must be strictly positive (got {amount_tokens!r})")
    scale = Decimal(10) ** decimals
    raw = int((dec * scale).to_integral_value(rounding=ROUND_DOWN))
    if raw <= 0:
        raise ValueError(f"Token amount {amount_tokens!r} rounds down to 0 base units at {decimals} decimals")
    return raw


def raw_to_tokens(amount_raw: int, decimals: int) -> str:
    """Format integer base units back to normalized decimal string without scientific notation."""
    scale = Decimal(10) ** decimals
    val = (Decimal(amount_raw) / scale).normalize()
    text = format(val, "f")
    return text if "." not in text else text.rstrip("0").rstrip(".") or "0"


class ContributorProfile(BaseModel):
    handle: str
    display_name: str
    role: str
    wallet: str
    avg_payout_usd: float = Field(..., gt=0)
    completed_bounties: int = Field(default=1, ge=0)
    allowlisted: bool = True


DEFAULT_CONTRIBUTORS: list[ContributorProfile] = [
    ContributorProfile(
        handle="@minh-svm",
        display_name="Minh Tran",
        role="Anchor & SVM Security Engineer",
        wallet=_det_wallet("contributor:minh-svm"),
        avg_payout_usd=800.0,
        completed_bounties=14,
        allowlisted=True,
    ),
    ContributorProfile(
        handle="@hana-zk",
        display_name="Hana Le",
        role="Token-2022 & SDK Architect",
        wallet=_det_wallet("contributor:hana-zk"),
        avg_payout_usd=650.0,
        completed_bounties=11,
        allowlisted=True,
    ),
    ContributorProfile(
        handle="@tuan-infra",
        display_name="Tuan Pham",
        role="Helius / Yellowstone gRPC Indexer",
        wallet=_det_wallet("contributor:tuan-infra"),
        avg_payout_usd=550.0,
        completed_bounties=9,
        allowlisted=True,
    ),
    ContributorProfile(
        handle="@linh-rust",
        display_name="Linh Nguyen",
        role="Rust Core & LiteSVM Testing",
        wallet=_det_wallet("contributor:linh-rust"),
        avg_payout_usd=500.0,
        completed_bounties=8,
        allowlisted=True,
    ),
    ContributorProfile(
        handle="@khoa-sdk",
        display_name="Khoa Vo",
        role="TypeScript @solana/kit Frontend",
        wallet=_det_wallet("contributor:khoa-sdk"),
        avg_payout_usd=480.0,
        completed_bounties=7,
        allowlisted=True,
    ),
    ContributorProfile(
        handle="@mai-ops",
        display_name="Mai Hoang",
        role="Superteam Ecosystem & Docs Lead",
        wallet=_det_wallet("contributor:mai-ops"),
        avg_payout_usd=420.0,
        completed_bounties=12,
        allowlisted=True,
    ),
]


class CustomHopSpec(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    wallet: str | None = None
    bundle: str | None = None
    wait_seconds: int = Field(default=45, alias="waitSeconds", ge=MIN_HOP_WAIT_SECONDS, le=MAX_ROUTE_WAIT_SECONDS)

    @model_validator(mode="after")
    def validate_target(self) -> "CustomHopSpec":
        has_w = bool(self.wallet and self.wallet.strip())
        has_b = bool(self.bundle and self.bundle.strip())
        if has_w == has_b:
            raise ValueError("Each hop must specify exactly one of 'wallet' or 'bundle'")
        if has_w:
            self.wallet = self.wallet.strip()
        if has_b:
            self.bundle = self.bundle.strip().lower()
            if self.bundle not in VALID_HOP_BUNDLES:
                raise ValueError(f"Unknown hop bundle {self.bundle!r}; allowed: {sorted(VALID_HOP_BUNDLES)}")
        return self


class TreasuryPolicyConfig(BaseModel):
    max_single_recipient_usd: float = Field(default=2_500.0, gt=0)
    max_batch_usd: float = Field(default=15_000.0, gt=0)
    approval_threshold_usd: float = Field(default=1_000.0, ge=0)
    require_allowlist: bool = Field(default=True)
    anomaly_spike_multiplier: float = Field(default=3.0, gt=1.0)
    halt_on_wallet_swap: bool = Field(default=True)
    is_devnet: bool = Field(default=False)


class PayoutLineItem(BaseModel):
    handle: str = Field(default="")
    wallet: str = Field(..., min_length=20, max_length=64)
    amount_tokens: str = Field(..., description="Human token amount, e.g. '750.00'")
    memo: str = Field(default="Contributor Milestone")


class AgentPlanRequest(BaseModel):
    plan_title: str = Field(default="Q4 Solana Contributor Payout Run", min_length=2, max_length=120)
    business_purpose: str = Field(default="Verified Superteam & DAO Contributor Milestones", min_length=2, max_length=240)
    agent_prompt: str = Field(default="", max_length=4000)
    csv_payload: str = Field(default="", max_length=25000)
    items: list[PayoutLineItem] = Field(default_factory=list)
    source_treasury_wallet: str = Field(default=DEFAULT_TREASURY_WALLET)
    token_symbol: Literal["USDG", "USDC", "SOL"] = "USDG"
    token_price_usd: float | None = Field(default=None, gt=0)
    hops: int = Field(default=4, ge=3, le=10)
    arrival_seconds: int = Field(default=240, ge=60, le=MAX_ROUTE_WAIT_SECONDS)
    custom_hops: list[CustomHopSpec] | None = None
    policy: TreasuryPolicyConfig = Field(default_factory=TreasuryPolicyConfig)


class PolicyFinding(BaseModel):
    code: str
    severity: Literal["CRITICAL_ANOMALY", "POLICY_VIOLATION", "WARNING"]
    subject: str
    detail: str


class AuditLedgerEntry(BaseModel):
    seq: int
    timestamp: str
    action: str
    plan_id: str
    verdict: str
    summary: str
    prev_hash: str
    entry_hash: str


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_payout_csv(csv_text: str, directory: dict[str, ContributorProfile] | None = None) -> list[PayoutLineItem]:
    """Parse `handle,wallet,amount,memo` or `wallet,amount,label` CSV into PayoutLineItems."""
    stripped = (csv_text or "").strip()
    if not stripped:
        return []
    reader = csv.DictReader(io.StringIO(stripped))
    if not reader.fieldnames:
        raise ValueError("CSV payload must include a header row (e.g., handle,wallet,amount,memo)")
    fmap = {f.strip().lower(): f for f in reader.fieldnames if f}
    handle_col = fmap.get("handle") or fmap.get("contributor")
    wallet_col = fmap.get("wallet") or fmap.get("address")
    amount_col = fmap.get("amount") or fmap.get("amount_tokens")
    memo_col = fmap.get("memo") or fmap.get("label") or fmap.get("purpose")

    if not amount_col or (not wallet_col and not handle_col):
        raise ValueError("CSV requires 'amount' and at least one of 'wallet' or 'handle'")

    dir_map = directory or {}
    items: list[PayoutLineItem] = []
    for row_idx, row in enumerate(reader, start=2):
        raw_handle = (row.get(handle_col) or "").strip() if handle_col else ""
        if raw_handle and not raw_handle.startswith("@"):
            raw_handle = f"@{raw_handle}"
        raw_wallet = (row.get(wallet_col) or "").strip() if wallet_col else ""
        raw_amount = (row.get(amount_col) or "").strip()
        if not raw_handle and not raw_wallet and not raw_amount:
            continue
        if not raw_wallet and raw_handle and raw_handle.lower() in dir_map:
            raw_wallet = dir_map[raw_handle.lower()].wallet
        if not raw_wallet:
            raise ValueError(f"CSV row {row_idx}: missing wallet address for {raw_handle or 'unnamed row'}")
        if not raw_amount:
            raise ValueError(f"CSV row {row_idx}: missing token amount")
        memo_val = (row.get(memo_col) or "").strip() if memo_col else "CSV Batch Payout"
        items.append(
            PayoutLineItem(
                handle=raw_handle,
                wallet=raw_wallet,
                amount_tokens=raw_amount,
                memo=memo_val or "CSV Batch Payout",
            )
        )
    return items


_PROMPT_ITEM_RE = re.compile(
    r"(?P<handle>@[A-Za-z0-9_-]+)\s+(?P<amount>\d+(?:\.\d+)?)\s*(?P<token>USDG|USDC|SOL)?(?:\s+for\s+(?P<memo>[^,.;\n]+))?",
    re.IGNORECASE,
)
_PROMPT_HOPS_RE = re.compile(r"(?P<hops>[3-9]|10)\s*[-\s]?hops?", re.IGNORECASE)


def parse_cfo_prompt(
    prompt_text: str, directory: dict[str, ContributorProfile]
) -> tuple[list[PayoutLineItem], str | None, int | None]:
    """Deterministically extract contributor payouts, token override, and hop count from AI CFO prompt."""
    text = (prompt_text or "").strip()
    if not text:
        return [], None, None

    extracted: list[PayoutLineItem] = []
    detected_token: str | None = None
    for match in _PROMPT_ITEM_RE.finditer(text):
        handle = match.group("handle").lower()
        amount = match.group("amount")
        tok = match.group("token")
        memo = (match.group("memo") or "AI CFO Parsed Milestone").strip()
        if tok and detected_token is None:
            detected_token = tok.upper()
        profile = directory.get(handle)
        wallet = profile.wallet if profile else _det_wallet(f"unregistered:{handle}")
        extracted.append(
            PayoutLineItem(
                handle=handle,
                wallet=wallet,
                amount_tokens=amount,
                memo=memo,
            )
        )

    hop_match = _PROMPT_HOPS_RE.search(text)
    detected_hops = int(hop_match.group("hops")) if hop_match else None
    return extracted, detected_token, detected_hops


def validate_custom_hops(
    hops: list[CustomHopSpec],
    *,
    source_wallet: str,
    destination_wallets: set[str],
    is_devnet: bool,
) -> list[PolicyFinding]:
    """Enforce MultiHopper v1 `MH_018` and `MH_019` route topology rules."""
    findings: list[PolicyFinding] = []
    n = len(hops)
    if n < 3 or n > 10:
        findings.append(
            PolicyFinding(
                code="MH_018_HOP_COUNT",
                severity="POLICY_VIOLATION",
                subject="custom_hops",
                detail=f"Multi-destination dispersion requires 3..10 hops (got {n}).",
            )
        )
    total_wait = sum(h.wait_seconds for h in hops)
    if total_wait > MAX_ROUTE_WAIT_SECONDS:
        findings.append(
            PolicyFinding(
                code="MH_018_MAX_WAIT",
                severity="POLICY_VIOLATION",
                subject="custom_hops",
                detail=f"Total hop wait ({total_wait}s) exceeds 30-day cap ({MAX_ROUTE_WAIT_SECONDS}s).",
            )
        )

    seen_hop_wallets: set[str] = set()
    for idx, hop in enumerate(hops):
        if hop.bundle:
            if is_devnet:
                findings.append(
                    PolicyFinding(
                        code="MH_019_DEVNET_BUNDLE",
                        severity="POLICY_VIOLATION",
                        subject=f"custom_hops[{idx}]",
                        detail=f"Hop bundle '{hop.bundle}' is unsupported on Solana Devnet (MH_019).",
                    )
                )
            if idx == n - 1 and hop.bundle == "contracts":
                findings.append(
                    PolicyFinding(
                        code="MH_018_CONTRACTS_FINAL_HOP",
                        severity="POLICY_VIOLATION",
                        subject=f"custom_hops[{idx}]",
                        detail="'contracts' bundle cannot be the terminal hop on multi-destination routes.",
                    )
                )
        if hop.wallet:
            w = hop.wallet
            if not is_valid_solana_pubkey(w):
                findings.append(
                    PolicyFinding(
                        code="MH_018_INVALID_HOP_PUBKEY",
                        severity="POLICY_VIOLATION",
                        subject=f"custom_hops[{idx}]",
                        detail=f"Invalid 32-byte Base58 Solana public key in hop {idx}: {w[:12]}...",
                    )
                )
                continue
            if w == source_wallet:
                findings.append(
                    PolicyFinding(
                        code="MH_018_SENDER_LOOP",
                        severity="POLICY_VIOLATION",
                        subject=f"custom_hops[{idx}]",
                        detail=f"Source treasury {w[:8]}... cannot appear as an intermediate relay hop.",
                    )
                )
            if w in destination_wallets:
                findings.append(
                    PolicyFinding(
                        code="MH_018_DESTINATION_COLLISION",
                        severity="POLICY_VIOLATION",
                        subject=f"custom_hops[{idx}]",
                        detail=f"Payout recipient {w[:8]}... cannot also act as an intermediate relay hop.",
                    )
                )
            if w in PROTOCOL_RESERVED_ADDRESSES:
                findings.append(
                    PolicyFinding(
                        code="MH_018_RESERVED_HOP",
                        severity="POLICY_VIOLATION",
                        subject=f"custom_hops[{idx}]",
                        detail=f"Address {w[:8]}... is a reserved Solana protocol program/sysvar.",
                    )
                )
            if w in seen_hop_wallets:
                findings.append(
                    PolicyFinding(
                        code="MH_018_DUPLICATE_HOP",
                        severity="POLICY_VIOLATION",
                        subject=f"custom_hops[{idx}]",
                        detail=f"Relay wallet {w[:8]}... is repeated twice in the same route.",
                    )
                )
            seen_hop_wallets.add(w)
    return findings


class AgenticTreasuryStudio:
    """Stateful in-memory Agentic CFO Studio with SHA-256 hash-chained audit ledger."""

    def __init__(self) -> None:
        self.contributors: dict[str, ContributorProfile] = {
            c.handle.lower(): c for c in DEFAULT_CONTRIBUTORS
        }
        self.wallet_to_contributor: dict[str, ContributorProfile] = {
            c.wallet: c for c in DEFAULT_CONTRIBUTORS
        }
        self.plans: dict[str, dict[str, Any]] = {}
        self.ledger: list[AuditLedgerEntry] = []

    def register_contributor(self, profile: ContributorProfile) -> None:
        key = profile.handle.lower()
        self.contributors[key] = profile
        self.wallet_to_contributor[profile.wallet] = profile

    def _append_ledger(self, *, action: str, plan_id: str, verdict: str, summary: str) -> AuditLedgerEntry:
        seq = len(self.ledger) + 1
        prev_hash = self.ledger[-1].entry_hash if self.ledger else ("0" * 64)
        timestamp = utc_now_iso()
        body = {
            "seq": seq,
            "timestamp": timestamp,
            "action": action,
            "plan_id": plan_id,
            "verdict": verdict,
            "summary": summary,
            "prev_hash": prev_hash,
        }
        entry_hash = _canonical_sha256(body)
        entry = AuditLedgerEntry(**body, entry_hash=entry_hash)
        self.ledger.append(entry)
        return entry

    def verify_ledger_integrity(self) -> dict[str, Any]:
        """Recompute every SHA-256 link from genesis (`0000...0`) to head to prove zero tampering."""
        expected_prev = "0" * 64
        for idx, item in enumerate(self.ledger, start=1):
            if item.seq != idx or item.prev_hash != expected_prev:
                return {
                    "valid": False,
                    "entry_count": len(self.ledger),
                    "broken_at_seq": idx,
                    "head_hash": self.ledger[-1].entry_hash if self.ledger else expected_prev,
                }
            recomputed = _canonical_sha256(
                {
                    "seq": item.seq,
                    "timestamp": item.timestamp,
                    "action": item.action,
                    "plan_id": item.plan_id,
                    "verdict": item.verdict,
                    "summary": item.summary,
                    "prev_hash": item.prev_hash,
                }
            )
            if recomputed != item.entry_hash:
                return {
                    "valid": False,
                    "entry_count": len(self.ledger),
                    "broken_at_seq": idx,
                    "head_hash": self.ledger[-1].entry_hash,
                }
            expected_prev = item.entry_hash
        return {
            "valid": True,
            "entry_count": len(self.ledger),
            "broken_at_seq": None,
            "genesis_prev_hash": "0" * 64,
            "head_hash": expected_prev,
        }

    def create_plan(self, req: AgentPlanRequest) -> dict[str, Any]:
        """Run the 4-stage AI CFO Planning, Policy/Anomaly Evaluation, Routing & Wire Proof pipeline."""
        # Stage 1: Merge explicit items + CSV + natural-language AI CFO prompt
        combined_items: list[PayoutLineItem] = list(req.items)
        if req.csv_payload.strip():
            combined_items.extend(parse_payout_csv(req.csv_payload, self.contributors))

        prompt_items, prompt_token, prompt_hops = parse_cfo_prompt(req.agent_prompt, self.contributors)
        if prompt_items:
            combined_items.extend(prompt_items)

        if not combined_items:
            raise ValueError("Provide at least one payout item via 'items', 'csv_payload', or 'agent_prompt'.")

        token_symbol = (prompt_token or req.token_symbol).upper()
        if token_symbol not in SUPPORTED_TOKENS:
            raise ValueError(f"Unsupported token {token_symbol!r}; choose from {list(SUPPORTED_TOKENS)}")
        token_meta = SUPPORTED_TOKENS[token_symbol]
        decimals: int = token_meta["decimals"]
        unit_price_usd = float(req.token_price_usd or token_meta["default_price_usd"])
        effective_hops = prompt_hops if prompt_hops is not None else req.hops

        findings: list[PolicyFinding] = []

        # Validate source treasury wallet
        if not is_valid_solana_pubkey(req.source_treasury_wallet):
            findings.append(
                PolicyFinding(
                    code="INVALID_TREASURY_PUBKEY",
                    severity="POLICY_VIOLATION",
                    subject=req.source_treasury_wallet,
                    detail="Source treasury wallet is not a valid 32-byte Base58 Solana public key.",
                )
            )
        elif req.source_treasury_wallet in PROTOCOL_RESERVED_ADDRESSES:
            findings.append(
                PolicyFinding(
                    code="RESERVED_TREASURY_PUBKEY",
                    severity="POLICY_VIOLATION",
                    subject=req.source_treasury_wallet,
                    detail="Source treasury wallet cannot be a reserved Solana program ID.",
                )
            )

        # Consolidate per-wallet amounts using exact base-unit Decimal arithmetic
        consolidated_raw: dict[str, int] = {}
        consolidated_handles: dict[str, set[str]] = {}
        consolidated_memos: dict[str, list[str]] = {}
        consolidated_row_counts: dict[str, int] = {}

        for idx, line in enumerate(combined_items, start=1):
            w = line.wallet.strip()
            h = line.handle.strip().lower()
            if h and not h.startswith("@"):
                h = f"@{h}"

            # Check handle -> registered wallet swap BEFORE wallet consolidation
            if h and h in self.contributors:
                expected_wallet = self.contributors[h].wallet
                if w != expected_wallet and req.policy.halt_on_wallet_swap:
                    findings.append(
                        PolicyFinding(
                            code="ANOMALY_WALLET_SWAP",
                            severity="CRITICAL_ANOMALY",
                            subject=h,
                            detail=(
                                f"Contributor {h} requested payout to unverified wallet {w[:10]}... "
                                f"(registered primary wallet is {expected_wallet[:10]}...). Automatic circuit breaker triggered."
                            ),
                        )
                    )

            if not is_valid_solana_pubkey(w):
                findings.append(
                    PolicyFinding(
                        code="INVALID_RECIPIENT_PUBKEY",
                        severity="POLICY_VIOLATION",
                        subject=f"row_{idx}",
                        detail=f"Recipient wallet '{w}' is not a valid 32-byte Base58 Solana address.",
                    )
                )
                continue

            try:
                raw_amt = tokens_to_raw(line.amount_tokens, decimals)
            except ValueError as exc:
                findings.append(
                    PolicyFinding(
                        code="INVALID_TOKEN_AMOUNT",
                        severity="POLICY_VIOLATION",
                        subject=w[:10],
                        detail=str(exc),
                    )
                )
                continue

            consolidated_raw[w] = consolidated_raw.get(w, 0) + raw_amt
            consolidated_row_counts[w] = consolidated_row_counts.get(w, 0) + 1
            if h:
                consolidated_handles.setdefault(w, set()).add(h)
            if line.memo:
                consolidated_memos.setdefault(w, []).append(line.memo)

        merged_duplicate_rows = max(0, len(combined_items) - len(consolidated_raw))
        if merged_duplicate_rows > 0:
            findings.append(
                PolicyFinding(
                    code="DUPLICATE_WALLETS_CONSOLIDATED",
                    severity="WARNING",
                    subject="consolidation",
                    detail=(
                        f"Consolidated {merged_duplicate_rows} duplicate wallet invoice row(s) across "
                        f"{len(consolidated_raw)} unique recipients before enforcing spend & velocity caps."
                    ),
                )
            )

        # Stage 2: Per-recipient Policy & Anomaly Evaluation
        recipient_breakdown: list[dict[str, Any]] = []
        total_raw = 0
        for wallet, raw_amt in consolidated_raw.items():
            total_raw += raw_amt
            tok_str = raw_to_tokens(raw_amt, decimals)
            usd_val = round(float(Decimal(raw_amt) / (Decimal(10) ** decimals)) * unit_price_usd, 2)

            profile = self.wallet_to_contributor.get(wallet)
            handles = sorted(consolidated_handles.get(wallet, set()))
            if not profile and len(handles) == 1 and handles[0] in self.contributors:
                # Wallet swap case: attach handle metadata for visibility, keep allowlisted=False for wallet
                swapped_profile = self.contributors[handles[0]]
                display_handle = swapped_profile.handle
                baseline_usd = swapped_profile.avg_payout_usd
                is_allowlisted_wallet = False
            elif profile:
                display_handle = profile.handle
                baseline_usd = profile.avg_payout_usd
                is_allowlisted_wallet = profile.allowlisted
            else:
                display_handle = handles[0] if handles else f"unregistered:{wallet[:6]}"
                baseline_usd = None
                is_allowlisted_wallet = False

            if wallet in DENYLISTED_WALLETS:
                findings.append(
                    PolicyFinding(
                        code="ANOMALY_DENYLISTED_WALLET",
                        severity="CRITICAL_ANOMALY",
                        subject=wallet[:10],
                        detail=f"Wallet {wallet[:10]}... matched quarantined sybil/sanctions denylist.",
                    )
                )

            if wallet in PROTOCOL_RESERVED_ADDRESSES:
                findings.append(
                    PolicyFinding(
                        code="RESERVED_DESTINATION_PUBKEY",
                        severity="POLICY_VIOLATION",
                        subject=wallet[:10],
                        detail=f"Destination {wallet[:10]}... is a reserved Solana program/sysvar address.",
                    )
                )

            if wallet == req.source_treasury_wallet:
                findings.append(
                    PolicyFinding(
                        code="SELF_TRANSFER_LOOP",
                        severity="POLICY_VIOLATION",
                        subject=wallet[:10],
                        detail="Source treasury wallet cannot pay itself in a contributor dispersion batch.",
                    )
                )

            if req.policy.require_allowlist and not is_allowlisted_wallet:
                findings.append(
                    PolicyFinding(
                        code="UNALLOWLISTED_WALLET",
                        severity="POLICY_VIOLATION",
                        subject=display_handle,
                        detail=f"Wallet {wallet[:10]}... ({display_handle}) is not in the approved contributor allowlist.",
                    )
                )

            if usd_val > req.policy.max_single_recipient_usd:
                split_note = (
                    f" across {consolidated_row_counts[wallet]} split rows"
                    if consolidated_row_counts[wallet] > 1
                    else ""
                )
                findings.append(
                    PolicyFinding(
                        code="SINGLE_RECIPIENT_CAP_EXCEEDED",
                        severity="POLICY_VIOLATION",
                        subject=display_handle,
                        detail=(
                            f"Consolidated payout ${usd_val:,.2f}{split_note} exceeds per-recipient cap "
                            f"(${req.policy.max_single_recipient_usd:,.2f})."
                        ),
                    )
                )

            velocity_ratio = round(usd_val / baseline_usd, 2) if baseline_usd else None
            if baseline_usd and usd_val >= baseline_usd * req.policy.anomaly_spike_multiplier:
                findings.append(
                    PolicyFinding(
                        code="ANOMALY_VELOCITY_SPIKE",
                        severity="CRITICAL_ANOMALY",
                        subject=display_handle,
                        detail=(
                            f"Payout ${usd_val:,.2f} is {velocity_ratio:.2f}x {display_handle}'s historical "
                            f"average (${baseline_usd:,.2f}), breaching {req.policy.anomaly_spike_multiplier:.1f}x anomaly circuit breaker."
                        ),
                    )
                )

            # MH_017 rent-exempt check for SOL transfers
            if token_symbol == "SOL":
                est_net_lamports = raw_amt - (raw_amt * MULTIHOPPER_FEE_BPS // 10_000)
                if est_net_lamports < SOL_RENT_EXEMPT_MIN_LAMPORTS:
                    findings.append(
                        PolicyFinding(
                            code="MH_017_SOL_RENT_DUST",
                            severity="POLICY_VIOLATION",
                            subject=display_handle,
                            detail=(
                                f"Net SOL payout ({est_net_lamports} lamports after 50 bps fee) falls below "
                                f"Solana rent-exempt minimum ({SOL_RENT_EXEMPT_MIN_LAMPORTS} lamports)."
                            ),
                        )
                    )

            recipient_breakdown.append(
                {
                    "handle": display_handle,
                    "wallet": wallet,
                    "invoice_rows_merged": consolidated_row_counts[wallet],
                    "amount_raw": str(raw_amt),
                    "amount_tokens": tok_str,
                    "usd_value": usd_val,
                    "allowlisted": is_allowlisted_wallet,
                    "baseline_avg_usd": baseline_usd,
                    "velocity_ratio": velocity_ratio,
                    "memos": consolidated_memos.get(wallet, []),
                }
            )

        total_tokens_str = raw_to_tokens(total_raw, decimals)
        total_usd = round(float(Decimal(total_raw) / (Decimal(10) ** decimals)) * unit_price_usd, 2)

        if total_usd > req.policy.max_batch_usd:
            findings.append(
                PolicyFinding(
                    code="BATCH_BUDGET_EXCEEDED",
                    severity="POLICY_VIOLATION",
                    subject="batch_total",
                    detail=(
                        f"Batch total (${total_usd:,.2f}) exceeds treasury epoch budget cap "
                        f"(${req.policy.max_batch_usd:,.2f})."
                    ),
                )
            )

        # Stage 3: Multi-Hop Route Construction & Topology Validation
        dest_wallets_set = set(consolidated_raw.keys())
        if req.custom_hops is not None:
            findings.extend(
                validate_custom_hops(
                    req.custom_hops,
                    source_wallet=req.source_treasury_wallet,
                    destination_wallets=dest_wallets_set,
                    is_devnet=req.policy.is_devnet,
                )
            )
            hop_nodes = [
                {
                    "hop_index": i + 1,
                    "target_type": "bundle" if h.bundle else "ephemeral_relay",
                    "target": h.bundle or h.wallet,
                    "wait_seconds": h.wait_seconds,
                }
                for i, h in enumerate(req.custom_hops)
            ]
            effective_arrival = sum(h.wait_seconds for h in req.custom_hops)
        else:
            per_hop_wait = max(MIN_HOP_WAIT_SECONDS, req.arrival_seconds // effective_hops)
            hop_nodes = [
                {
                    "hop_index": i + 1,
                    "target_type": "ephemeral_relay",
                    "target": RELAY_NODE_POOL[i % len(RELAY_NODE_POOL)],
                    "wait_seconds": per_hop_wait,
                }
                for i in range(effective_hops)
            ]
            effective_arrival = per_hop_wait * effective_hops

        # Chunk consolidated recipients into uniform <= 20 destination MultiHopper dispersion batches
        recipient_items = list(consolidated_raw.items())
        route_chunks: list[dict[str, Any]] = []
        for c_idx in range(0, len(recipient_items), MAX_DESTINATIONS_PER_ROUTE):
            slice_pairs = recipient_items[c_idx : c_idx + MAX_DESTINATIONS_PER_ROUTE]
            chunk_raw = sum(amt for _, amt in slice_pairs)
            route_num = (c_idx // MAX_DESTINATIONS_PER_ROUTE) + 1
            route_chunks.append(
                {
                    "route_index": route_num,
                    "idempotency_key": f"hoppay-r{route_num}-{uuid.uuid4().hex[:8]}",
                    "mode": "destinations",
                    "destination_count": len(slice_pairs),
                    "hops_count": len(hop_nodes),
                    "chunk_amount_raw": str(chunk_raw),
                    "chunk_amount_tokens": raw_to_tokens(chunk_raw, decimals),
                    "destinations": [
                        {
                            "wallet": w,
                            "amountRaw": str(amt),
                            "amountTokens": raw_to_tokens(amt, decimals),
                        }
                        for w, amt in slice_pairs
                    ],
                }
            )

        if len(route_chunks) > 1:
            findings.append(
                PolicyFinding(
                    code="AUTO_CHUNKED_MULTI_ROUTE",
                    severity="WARNING",
                    subject="router",
                    detail=(
                        f"{len(consolidated_raw)} unique recipients auto-partitioned into {len(route_chunks)} "
                        f"uniform MultiHopper dispersion routes (<= {MAX_DESTINATIONS_PER_ROUTE} wallets/route)."
                    ),
                )
            )

        # Compute Verdict
        critical_anomalies = [f for f in findings if f.severity == "CRITICAL_ANOMALY"]
        policy_violations = [f for f in findings if f.severity == "POLICY_VIOLATION"]
        warnings = [f for f in findings if f.severity == "WARNING"]

        requires_hitl = total_usd >= req.policy.approval_threshold_usd
        if critical_anomalies:
            verdict = "ANOMALY_HALT"
            allowed = False
        elif policy_violations:
            verdict = "POLICY_BLOCKED"
            allowed = False
        elif requires_hitl:
            verdict = "AWAITING_HITL_APPROVAL"
            allowed = True
        else:
            verdict = "READY_TO_ROUTE"
            allowed = True

        # Fee & Ops Comparison
        n_unique = max(1, len(consolidated_raw))
        direct_network_fee_usd = round(n_unique * 0.00095, 4)
        multihop_routing_fee_usd = round(total_usd * (MULTIHOPPER_FEE_BPS / 10_000) + len(route_chunks) * 0.04, 2)
        manual_ops_estimated_cost_usd = round(37.50 + n_unique * 2.25, 2)  # ~45m finance/multisig ops time

        plan_id = f"plan_{uuid.uuid4().hex[:10]}"
        created_at = utc_now_iso()

        policy_snapshot_for_hash = {
            "plan_id": plan_id,
            "source_treasury_wallet": req.source_treasury_wallet,
            "token_symbol": token_symbol,
            "total_raw": str(total_raw),
            "unique_recipients": len(consolidated_raw),
            "verdict": verdict,
            "findings": [f.model_dump() for f in findings],
            "policy": req.policy.model_dump(),
        }
        policy_hash = _canonical_sha256(policy_snapshot_for_hash)

        # Stage 4: Unsigned Solana Wire Transaction Proof (`Memo v2` + `TransferChecked`)
        first_recipient = recipient_items[0][0] if recipient_items else None
        first_raw = recipient_items[0][1] if recipient_items else 0
        mint_addr = token_meta["mint_devnet"] if req.policy.is_devnet else token_meta["mint_mainnet"]

        wire_preview = (
            build_unsigned_solana_audit_tx(
                fee_payer=req.source_treasury_wallet
                if is_valid_solana_pubkey(req.source_treasury_wallet)
                else DEFAULT_TREASURY_WALLET,
                memo_payload={
                    "app": "HopPayAgenticStudio",
                    "plan": plan_id,
                    "policy_sha256": policy_hash[:16],
                    "token": token_symbol,
                    "total_tokens": total_tokens_str,
                    "verdict": verdict,
                },
                token_symbol=token_symbol,
                mint_pubkey=mint_addr,
                token_program_id=token_meta["token_program_id"],
                decimals=decimals,
                sample_recipient=first_recipient,
                sample_amount_raw=first_raw,
                memo_only=first_recipient is None,
            )
            if first_recipient
            else None
        )

        reasoning_trace = [
            {
                "step": 1,
                "stage": "INTENT_CONSOLIDATION",
                "title": "Exact-Decimal Invoice Normalization",
                "detail": (
                    f"Ingested {len(combined_items)} line item(s) into {len(consolidated_raw)} unique Solana wallets "
                    f"({merged_duplicate_rows} duplicate row(s) merged) totaling {total_tokens_str} {token_symbol} (${total_usd:,.2f})."
                ),
            },
            {
                "step": 2,
                "stage": "POLICY_AND_ALLOWLIST",
                "title": "Deterministic Spend Cap & Allowlist Check",
                "detail": (
                    f"Evaluated per-recipient cap (${req.policy.max_single_recipient_usd:,.2f}), batch cap "
                    f"(${req.policy.max_batch_usd:,.2f}), and allowlist={req.policy.require_allowlist} -> "
                    f"{len(policy_violations)} policy violation(s)."
                ),
            },
            {
                "step": 3,
                "stage": "ANOMALY_CIRCUIT_BREAKER",
                "title": "Velocity Spike & Wallet-Swap Guard",
                "detail": (
                    f"Checked historical contributor baselines ({req.policy.anomaly_spike_multiplier:.1f}x threshold) "
                    f"and primary wallet bindings -> {len(critical_anomalies)} critical anomaly halt(s)."
                ),
            },
            {
                "step": 4,
                "stage": "MULTIHOP_TOPOLOGY",
                "title": "Multi-Hop Dispersion & Token-2022 Wire Proof",
                "detail": (
                    f"Assembled {len(route_chunks)} route chunk(s) across {len(hop_nodes)} relay hops "
                    f"({effective_arrival}s window) using {token_meta['standard']} ({mint_addr[:8]}...)."
                ),
            },
        ]

        ledger_entry = self._append_ledger(
            action="ANOMALY_HALTED" if verdict == "ANOMALY_HALT" else "PLAN_EVALUATED",
            plan_id=plan_id,
            verdict=verdict,
            summary=(
                f"{req.plan_title}: {total_tokens_str} {token_symbol} (${total_usd:,.2f}) across "
                f"{len(consolidated_raw)} recipient(s) -> {verdict}"
            ),
        )

        plan_doc: dict[str, Any] = {
            "plan_id": plan_id,
            "created_at": created_at,
            "plan_title": req.plan_title,
            "business_purpose": req.business_purpose,
            "source_treasury_wallet": req.source_treasury_wallet,
            "token": {
                "symbol": token_symbol,
                "name": token_meta["name"],
                "standard": token_meta["standard"],
                "mint": mint_addr,
                "token_program_id": token_meta["token_program_id"],
                "decimals": decimals,
                "unit_price_usd": unit_price_usd,
            },
            "totals": {
                "input_line_items": len(combined_items),
                "unique_recipients": len(consolidated_raw),
                "merged_duplicate_rows": merged_duplicate_rows,
                "total_raw": str(total_raw),
                "total_tokens": total_tokens_str,
                "total_usd": total_usd,
            },
            "verdict": verdict,
            "allowed": allowed,
            "requires_human_approval": requires_hitl,
            "approval": None,
            "policy_config": req.policy.model_dump(),
            "policy_hash": policy_hash,
            "counts": {
                "critical_anomalies": len(critical_anomalies),
                "policy_violations": len(policy_violations),
                "warnings": len(warnings),
            },
            "findings": [f.model_dump() for f in findings],
            "recipients": recipient_breakdown,
            "routing": {
                "hops_count": len(hop_nodes),
                "effective_arrival_seconds": effective_arrival,
                "hop_topology": hop_nodes,
                "chunk_count": len(route_chunks),
                "chunks": route_chunks,
                "cost_comparison": {
                    "direct_spl_batch_fee_usd": direct_network_fee_usd,
                    "multihop_dispersion_fee_usd": multihop_routing_fee_usd,
                    "legacy_manual_multisig_ops_usd": manual_ops_estimated_cost_usd,
                    "ops_time_saved_minutes": round(12 + n_unique * 2.5, 1),
                },
            },
            "reasoning_trace": reasoning_trace,
            "solana_wire_preview": wire_preview,
            "devnet_simulation": None,
            "latest_ledger_entry": ledger_entry.model_dump(),
        }
        self.plans[plan_id] = plan_doc
        return plan_doc

    def approve_plan(self, plan_id: str, *, approver: str = "@quangnguyen2512", note: str = "Approved after policy review") -> dict[str, Any]:
        """Record human operator sign-off; strictly blocks approving halted or policy-violating plans."""
        if plan_id not in self.plans:
            raise KeyError(f"Unknown plan_id: {plan_id}")
        plan = self.plans[plan_id]
        if not plan["allowed"]:
            raise PermissionError(
                f"Cannot approve plan {plan_id} with verdict {plan['verdict']} — resolve policy/anomaly findings first."
            )
        approval_record = {
            "approved_by": approver.strip() or "@operator",
            "approved_at": utc_now_iso(),
            "note": note.strip(),
        }
        plan["approval"] = approval_record
        plan["verdict"] = "APPROVED_READY"
        entry = self._append_ledger(
            action="HITL_APPROVED",
            plan_id=plan_id,
            verdict="APPROVED_READY",
            summary=f"Approved by {approval_record['approved_by']}: {approval_record['note']}",
        )
        plan["latest_ledger_entry"] = entry.model_dump()
        return plan

    def simulate_devnet(self, plan_id: str, *, allow_network: bool = True) -> dict[str, Any]:
        """Run Solana Devnet SVM `simulateTransaction` verification for an allowed plan."""
        if plan_id not in self.plans:
            raise KeyError(f"Unknown plan_id: {plan_id}")
        plan = self.plans[plan_id]
        if not plan["allowed"]:
            raise PermissionError(
                f"Refusing Devnet execution simulation for blocked/halted plan ({plan['verdict']})."
            )
        sim_result = simulate_plan_on_solana_devnet(
            plan_id=plan["plan_id"],
            policy_hash=plan["policy_hash"],
            token_symbol=plan["token"]["symbol"],
            total_usd=plan["totals"]["total_usd"],
            recipient_count=plan["totals"]["unique_recipients"],
            chunk_count=plan["routing"]["chunk_count"],
            allow_network=allow_network,
        )
        plan["devnet_simulation"] = sim_result
        entry = self._append_ledger(
            action="DEVNET_SIMULATED",
            plan_id=plan_id,
            verdict=plan["verdict"],
            summary=(
                f"Solana proof ({sim_result['mode']}) verified at slot {sim_result['slot']} "
                f"({sim_result['units_consumed']} CU)"
            ),
        )
        plan["latest_ledger_entry"] = entry.model_dump()
        return sim_result


def build_preset_requests(studio: AgenticTreasuryStudio) -> dict[str, dict[str, Any]]:
    """Construct the 3 interactive demo presets showcasing clean routing, anomaly halt, and >20 scale."""
    c = studio.contributors
    # Generate 26 temporary allowlisted builders for Preset 3 if requested, or run Preset 3 with require_allowlist=False
    scale_rows = ["handle,wallet,amount,memo"]
    for i in range(1, 27):
        w = _det_wallet(f"ecosystem_grant_recipient_{i:02d}")
        amt = 150 + (i % 5) * 25  # 150..250 USDC
        scale_rows.append(f"@builder-{i:02d},{w},{amt},Wave-4 Agentic Micro-Grant #{i:02d}")

    return {
        "clean_usdg_payroll": {
            "id": "clean_usdg_payroll",
            "badge": "TOKEN-2022 USDG • HITL GATE",
            "title": "Bi-Weekly Solana Core Payroll ($3,400 USDG)",
            "description": "5 allowlisted contributors paid in Global Dollar (USDG, Token-2022) via 4-hop dispersion. Passes all caps & velocity checks; triggers >= $1,000 HITL approval gate.",
            "request": AgentPlanRequest(
                plan_title="Sprint 24 Core Contributor Payroll (USDG)",
                business_purpose="Bi-weekly Superteam & SVM engineering milestones settled in USDG",
                agent_prompt=(
                    "Pay @minh-svm 920 USDG for Anchor vault audit, "
                    "@hana-zk 740 USDG for Token-2022 transfer-hook SDK, "
                    "@tuan-infra 640 USDG for gRPC webhook indexer, "
                    "@linh-rust 580 USDG for LiteSVM fuzz suite, "
                    "@khoa-sdk 520 USDG for Phantom signer UI via 4 hops"
                ),
                token_symbol="USDG",
                hops=4,
                arrival_seconds=240,
                policy=TreasuryPolicyConfig(
                    max_single_recipient_usd=2_500.0,
                    max_batch_usd=15_000.0,
                    approval_threshold_usd=1_000.0,
                    require_allowlist=True,
                    anomaly_spike_multiplier=3.0,
                    halt_on_wallet_swap=True,
                ),
            ),
        },
        "attack_anomaly_halt": {
            "id": "attack_anomaly_halt",
            "badge": "CIRCUIT BREAKER • 4 VIOLATIONS",
            "title": "Adversarial Split-Invoice + Wallet Swap + 4.4x Velocity Spike",
            "description": "Simulates a compromised invoice batch: split-row cap evasion ($1,450 + $1,400 = $2,850 > $2,500 cap), 4.4x velocity spike on @linh-rust, unverified wallet swap on @hana-zk, and a quarantined sybil wallet.",
            "request": AgentPlanRequest(
                plan_title="Suspicious Urgent Contractor Payout Batch",
                business_purpose="Unscheduled emergency contractor invoices",
                items=[
                    # Split-row cap evasion on @minh-svm ($1,450 + $1,400 = $2,850 > $2,500 cap)
                    PayoutLineItem(
                        handle="@minh-svm",
                        wallet=c["@minh-svm"].wallet,
                        amount_tokens="1450",
                        memo="Audit Invoice Part A",
                    ),
                    PayoutLineItem(
                        handle="@minh-svm",
                        wallet=c["@minh-svm"].wallet,
                        amount_tokens="1400",
                        memo="Audit Invoice Part B (split row)",
                    ),
                    # 4.4x velocity spike on @linh-rust (avg $500 -> $2,200 >= 3.0x)
                    PayoutLineItem(
                        handle="@linh-rust",
                        wallet=c["@linh-rust"].wallet,
                        amount_tokens="2200",
                        memo="Overtime Rust patch",
                    ),
                    # Sudden wallet swap on @hana-zk!
                    PayoutLineItem(
                        handle="@hana-zk",
                        wallet=_det_wallet("attacker_hijacked_hana_wallet"),
                        amount_tokens="600",
                        memo="Updated payout wallet per DM",
                    ),
                    # Quarantined sybil address
                    PayoutLineItem(
                        handle="@unknown-vendor",
                        wallet=QUARANTINED_SYBIL_WALLET,
                        amount_tokens="200",
                        memo="Advisory bounty",
                    ),
                ],
                token_symbol="USDG",
                hops=3,
                policy=TreasuryPolicyConfig(
                    max_single_recipient_usd=2_500.0,
                    max_batch_usd=15_000.0,
                    approval_threshold_usd=1_000.0,
                    require_allowlist=True,
                    anomaly_spike_multiplier=3.0,
                    halt_on_wallet_swap=True,
                ),
            ),
        },
        "scale_26_grant_wave": {
            "id": "scale_26_grant_wave",
            "badge": "AUTO-CHUNK 26 WALLETS • 2 ROUTES",
            "title": "26-Builder Agentic Grant Wave ($5,200 USDC)",
            "description": "Demonstrates high-throughput grant disbursement across 26 builders (>20 MultiHopper per-route limit), auto-chunking into 2 uniform dispersion routes (20 + 6 destinations) with exact 6-decimal math.",
            "request": AgentPlanRequest(
                plan_title="Superteam Wave-4 Micro-Grant Disbursement (26 Builders)",
                business_purpose="Cohort micro-grant tranche payouts across 26 shipped Solana MVPs",
                csv_payload="\n".join(scale_rows),
                token_symbol="USDC",
                hops=5,
                arrival_seconds=300,
                policy=TreasuryPolicyConfig(
                    max_single_recipient_usd=1_000.0,
                    max_batch_usd=20_000.0,
                    approval_threshold_usd=2_500.0,
                    require_allowlist=False,
                    anomaly_spike_multiplier=3.0,
                    halt_on_wallet_swap=True,
                ),
            ),
        },
    }
