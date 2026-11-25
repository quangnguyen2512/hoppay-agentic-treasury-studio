# `.superstack/build-context.md` — HopPay Agentic Treasury Studio (`v1.0.0`)

- **Stack:** Python 3.10+ (`FastAPI`, `Pydantic v2`, `Decimal`, `httpx`) + Zero-Build Interactive Web Console (`static/index.html`) + Solana Devnet JSON-RPC (`simulateTransaction`)
- **Solana Programs Integrated:**
  - `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` (`Token-2022` for `USDG`: `2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH`)
  - `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` (`SPL Token` for `USDC`: `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`)
  - `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr` (`SPL Memo v2` on-chain policy hash commitment)
- **Automated Verification:** `10/10` tests passing via `pytest -v` (`tests/test_agentic_studio.py`).
