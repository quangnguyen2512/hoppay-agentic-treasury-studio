# ARCHITECTURE — HopPay Agentic Treasury Studio (`v1.0.0`)

Autonomous AI CFO & Policy-Gated Multi-Hop Solana Treasury Router (`USDG` / `USDC` / `SOL`).

## Core Invariants
1. **Non-Custodial By Construction:** The AI CFO agent parses payout intents, consolidates duplicate wallets, enforces deterministic spend/anomaly policy, and compiles unsigned Solana wire transactions + MultiHopper dispersion routes without ever holding private keys. Signing stays strictly in Phantom/Solflare or an isolated hardware/multisig signer.
2. **Deterministic Policy Before Routing:** Natural-language and CSV payout rows are converted into exact `Decimal` integer base units (`6` decimals for `USDG`/`USDC`, `9` for `SOL`) and consolidated per recipient wallet *before* evaluating single-recipient caps, batch limits, allowlists, wallet-swap alerts, and velocity anomaly halts (`>= 3.0x` baseline spike -> automatic `ANOMALY_HALT`).
3. **Tamper-Evident Hash-Chained Audit Ledger:** Every plan evaluation, policy block, anomaly circuit-breaker halt, Human-in-the-Loop (HITL) sign-off, and Solana SVM simulation appends an immutable SHA-256 hash-chained entry (`prev_hash -> entry_hash`) exportable as JSON audit packs.
4. **Real Solana Wire & Devnet Proof:** Assembles binary-exact Solana `SPL Memo v2` + `TransferChecked` instructions (supporting Token-2022 `USDG` and classic SPL `USDC`) and verifies execution via Solana Devnet JSON-RPC (`simulateTransaction` with `sigVerify: false, replaceRecentBlockhash: true`), with deterministic offline simulation fallback.

## Directory Boundaries
```text
hoppay-treasury/
├── ARCHITECTURE.md                  # System architecture, boundaries & core invariants
├── README.md                        # 1-command quickstart, security model & deploy guide
├── pyproject.toml / requirements.txt# Zero-friction Python 3.10+ dependencies
├── vercel.json / render.yaml        # 1-minute cloud deployment manifests (Vercel & Render)
├── index.html                       # Root redirect to static Studio for GitHub Pages hosting
├── app.py                           # FastAPI REST API + static Studio server (:8090)
├── treasury_engine.py               # AI CFO parser, Decimal consolidator, PolicyGuard, MultiHopRouter
├── solana_proof.py                  # Pure-Python Base58, SPL/Token-2022 wire builder & Devnet RPC prover
├── .superstack/                     # Solana agentic idea & build context specs
├── static/
│   └── index.html                   # Interactive Agentic Treasury Studio UI + isomorphic browser engine
├── assets/
│   ├── architecture_pipeline.svg    # 4-stage policy & dispersion architecture diagram
│   ├── dashboard_preview.svg        # Studio UI & multi-hop topology preview card
│   └── audit_chain_flow.svg         # SHA-256 hash-chain & Solana SVM wire proof diagram
└── tests/
    └── test_agentic_studio.py       # End-to-end & adversarial pytest suite (10/10 tests)
```

## Execution DAG
```text
Operator Prompt / CSV Batch / Scenario Preset
   │
   ▼
treasury_engine.py (Intent Parser -> Exact Decimal Duplicate-Wallet Consolidation)
   │
   ▼
PolicyGuard (Allowlist + Reserved-Addr Block + Cap Check + 3.0x Velocity / Wallet-Swap Halt)
   │
   ├──[ANOMALY_HALT / BLOCKED]──► SHA-256 Audit Ledger (Immutable Rejection Receipt)
   │
   ▼ [READY_TO_ROUTE / HITL_APPROVED]
MultiHopRouter (Auto-Chunk <=20/route, MH_017 Rent Guard, MH_018 Loop Guard, MH_019 Bundle Check)
   │
   ▼
solana_proof.py (Compile Memo v2 + Token-2022/SPL TransferChecked -> Solana Devnet simulateTransaction)
   │
   ▼
FastAPI (`app.py`) / Static Web Studio (`static/index.html`) -> Non-Custodial Wallet Sign & Audit Export
```

## Active Solana Integrations
- **Solana Devnet JSON-RPC (`https://api.devnet.solana.com`):** Live `getLatestBlockhash` and unsigned `simulateTransaction` SVM verification (`$0` mainnet capital required).
- **Token-2022 & Classic SPL Mints:** Global Dollar `USDG` (`2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH`, `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`), `USDC` (`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`, `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`), and Devnet `USDC` (`4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`).
- **On-Chain Audit Memo & MultiHopper Topology:** `SPL Memo v2` (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`) policy-hash commitment + MultiHopper v1 route guards (`<=20` recipients/route, `3–10` hops).
