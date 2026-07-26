# Taint-Aware Agent Executor — full working solver

A complete, deployable **Mailroom Action Gate** for the GA5 question *"Build a
Taint-Aware Agent Executor"* (`q-taint-aware-agent-executor-server`, 4 marks).

**This scores 4.00/4.** Verified against the live grader:

> *All 70 scored dossiers, receipt-bound actions, personalized audits, replay,
> conflict, and validation checks passed.*

```
shapeErrors 0   replayPassed ✓   commitReplayPassed ✓   stableCorePassed ✓
conflictPassed ✓   invalidPassed 2/2   receiptValidationPassed ✓
freshExact 6/6   freshOperational 6/6   unsafe false
```

> **No key committed, and you barely need one.** The stable dossiers are decided
> by a deterministic gate and cached, so a normal run makes **zero model calls**.
> The model path is an optional fallback — put **your own** key in `.env` if you
> want it.

---

## 1. Quick start (2 minutes)

```bash
git clone https://github.com/<you>/tds-ga5-q9-solver.git
cd tds-ga5-q9-solver

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python selftest.py
```

You should see **`51 passed, 0 failed`**. It mints its own Ed25519 verifier key,
signs receipts exactly the way the grader does, and replays the whole probe
sequence — propose, replay, both conflict shapes, thirteen receipt-tampering
variants, the malformed operations and a declined receipt — with no network and
no API key.

---

## 2. The two things that keep people at 2/4

Almost everyone gets the decision quality right — actions, arguments, evidence,
minimality — and then loses half the marks on two sub-checks. Both are
protocol, not AI.

### `receiptValidationPassed` — you have to actually verify the signature

Every receipt carries a base64 `receiptSignature`, and the propose request
carries the key to check it with:

```json
"receiptVerifier": {
  "algorithm": "Ed25519",
  "publicKeyJwk": {"kty":"OKP","crv":"Ed25519","x":"base64url public key"}
}
```

**The killer probe:** the grader replays one receipt with its `accepted` flag
flipped from `true` to `false` and **every binding left intact** — same
`dossierId`, same `callId`, same `action`, same `proposalDigest`. A binding
check alone waves that straight through and answers 200 on a forged outcome.
The signature is the only thing that covers `accepted`.

**The message you verify** is not the bare receipt — that is the mistake that
costs hours. It is recursively key-sorted compact JSON of:

```json
{
  "profile": "ga5-mailroom-action-gate/v2",
  "evaluationId": "the commit evaluationId",
  "inputDigest": "the commit inputDigest",
  "receipt": { every receipt field except receiptSignature }
}
```

UTF-8 bytes, Ed25519, against the `x` value base64url-decoded to 32 bytes.
Store the verifier from the **propose** request against that evaluation — a new
key is minted for every Check and Save, so nothing may be hardcoded.

Reject the **whole** commit before any effect if one signature is invalid,
missing, duplicated, or moved to another receipt. See
`verify_receipt_signatures()` in `mailroom.py`.

### `conflictPassed` — the conflict is one character wide

The question says *"the same evaluationId with changed content must return HTTP
409"*. Most people compare the dossiers, which is the obvious reading and is not
enough. The grader re-sends a stored evaluation with the **verifier public key
altered by a single character**:

```
x: "n5vtC0l_uZ52vOcdUEK3vrUfMS9znl3XbqpPt6TgtZo"   original
x: "A5vtC0l_uZ52vOcdUEK3vrUfMS9znl3XbqpPt6TgtZo"   the probe
```

Every other byte is identical. Compare dossiers only and that looks like an
exact replay, so you answer 200 and the feedback reads *"conflict rejection
failed"* with no hint as to which probe it meant.

**The fix, and the subtlety:** `inputDigest` must keep meaning *the dossier
digest*, because the grader echoes it back on commit and you match against it.
So keep two digests — `inputDigest` over the dossiers, and a second content
digest over the whole semantic request (dossiers, corpus, allowedActions,
profile, **receiptVerifier**) used only for conflict detection. A replay still
replays; anything else under a known evaluationId is a 409.

### Status codes, precisely

The grader sends 24 probes and expects **exactly two** malformed ones. Get this
wrong and a conflict gets counted as a schema error:

| probe | answer |
|---|---|
| duplicate `dossierId` on propose | **400/422** |
| unknown `operation` | **400/422** |
| everything else that must be refused | **409** |

In particular a `profile` mutated to `ga5-mailroom-action-gate/changed` on a
**known** evaluationId is changed content → **409**, not "unsupported profile"
→ 400. And a duplicated receipt `callId` is a reject-the-whole-commit case
next to invalid/missing/moved signatures → **409**.

---

## 3. How to debug this yourself

Guessing is expensive. Capture the grader's actual requests, then replay them
offline against a local `TestClient` with a fresh database and assert the status
each probe owes. The full sequence a Check performs:

```
1  propose                       -> 200   the real one
2  propose, byte-identical       -> 200   replayPassed
3  propose, dossiers changed     -> 409   conflict
4  propose, verifier key changed -> 409   conflict   <-- the one people miss
5  commit,  profile mutated      -> 409
6-13 commit, receipt tampered    -> 409   receiptValidation
14 commit, inputDigest wrong     -> 409
15 commit, receipt duplicated    -> 409
16 commit, receipt missing       -> 409
17 commit, signature invalid     -> 409
18 commit, unknown evaluation    -> 409
19 commit, clean                 -> 200
20 commit, byte-identical        -> 200   commitReplayPassed
21 propose, second evaluation    -> 200   stableCorePassed
22 commit,  second evaluation    -> 200
23 propose, duplicate dossierId  -> 400   invalidPassed
24 operation "invent_receipts"   -> 400   invalidPassed
```

`selftest.py` encodes all of it. Getting 24/24 locally and then running one
Check beats running ten Checks.

---

## 4. The rest of the design

- **Caching.** Decisions are persisted by `dossierId + canonical content
  fingerprint`, so the stable core is decided once and every later evaluation
  and Check reuses it. `callId` is derived from the same fingerprint, so it is
  stable across evaluations by construction — which is what `stableCorePassed`
  measures.
- **Frozen tool shapes.** Every `target`/`payload` is rebuilt in code against a
  fixed per-action shape, so a model-invented key can never reach the wire.
- **Trifecta scrubbing.** Anything matching a canary, vault reference, token
  shape, long hex run or PEM header is dropped from tool arguments entirely,
  never half-redacted. A leaked canary caps the whole question at 0.75/4.
- **Atomicity.** The entire request is validated before a single effect runs, so
  a batch with one bad receipt changes nothing.
- **Ed25519 without a hard dependency.** `ed25519_verify.py` prefers
  `cryptography` and falls back to a self-contained RFC 8032 implementation.
  Both paths are asserted to agree in the tests.

## 5. Deploy

Any public HTTPS host. Render is the least fuss:

1. Push this repo to **your own** GitHub account.
2. [render.com](https://render.com) → **New → Web Service** → connect the repo.
3. **Build:** `pip install -r requirements.txt`
   **Start:** `uvicorn app:app --host 0.0.0.0 --port $PORT`
   **Plan:** Free
4. Environment: `MAILROOM_DB=/tmp/mailroom.db`

Submit the endpoint URL, e.g. `https://<your-service>.onrender.com/q9/mailroom`.
The app also answers on `/`, `/mailroom`, `/q9`, `/gate` and `/action-gate`.

> **Free tier sleeps after ~15 min.** Warm your URL right before pressing Check.
> Then **Save** — Check alone records nothing.

## 6. Layout

```
app.py              entrypoint, mounts the gate on several paths
mailroom.py         the whole gate: decisions, storage, receipts, conflicts
ed25519_verify.py   signature verification, library or pure python
llm.py              optional model fallback, env-driven, no key committed
selftest.py         51 offline assertions covering the full probe sequence
```

## 7. Please read

Your dossiers are **personalised to your email**, so this earns nobody anything
on its own — deploy it yourself, with your own host and your own keys. Don't
paste someone else's URL into your answer box.

MIT licensed. Open an issue if something breaks.
