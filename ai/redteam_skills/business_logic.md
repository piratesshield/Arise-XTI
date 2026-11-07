---
name: business_logic
description: Business-logic flaws — race conditions, workflow/state bypass, price/quantity abuse
lanes: [business-logic, race]
cwe: [840, 841, 362, 639, 799]
capec: [26, 74, 212]
---

# Business Logic

No payload — you abuse the *intended* functionality in an unintended sequence or quantity. These are the bugs scanners miss entirely.

## Attack surface
Multi-step flows (checkout, signup, KYC, transfer, redeem, apply-coupon), anything with money/quantity/limits, state machines (draft→submit→approve), quotas/rate limits, referral/reward systems, one-time tokens.

## Key classes & proof
- **Race condition / TOCTOU (the highest-value BL bug):** fire N concurrent identical requests at a check-then-act operation (redeem coupon, withdraw, apply credit, use a one-time token, vote). Proof = the action succeeds **more times than allowed** (coupon used twice, balance goes negative, one-time token consumed N times). Use HTTP/2 single-packet or a tight async burst; measure the over-count.
- **Workflow/state bypass:** skip or reorder steps — hit `POST /checkout/complete` without `/payment`, `/approve` without `/review`, access step-3 with a step-1 token. Proof = the terminal action succeeds having skipped the gate.
- **Price/quantity manipulation:** negative quantity (`qty:-1` → credit), zero/negative price, currency swap, decimal/rounding (`0.001`), integer overflow, client-supplied price/total. Proof = the order/balance reflects the manipulated value.
- **Parameter-driven privilege/limit:** `?limit=100000`, `?role=…`, coupon stacking, reuse of single-use codes.
- **Auth flow abuse:** password-reset for another user, MFA skip, email-verification bypass, unlimited OTP attempts (no lockout).

## Safe-confirm
Demonstrate the over-count / skipped-gate / manipulated-value on your **own** test account with the smallest proof (2 concurrent, one skip). Don't drain real funds or spam real transactions.

## Tools
Python `asyncio`/`httpx` (or `aiohttp`) for the concurrency burst, the proxy to capture the flow, `Turbo Intruder`-style single-packet for tight races. Model the state machine first, then attack the gap.
