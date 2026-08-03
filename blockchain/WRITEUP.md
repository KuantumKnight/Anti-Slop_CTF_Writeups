# Finality Cache — Writeup

**Category:** Blockchain / Reversing (anti-slop)
**Points:** 337 · 56 solves
**Service:** `nc 178.105.199.41 13357`
**Flag:** `slopped{wrapped_lane_offsets_expose_seal_keys_then_sign_recursive_checkpoints}`

> *"Yesterday's cache still whispers, but only the right sealed envelope settles the bridge."*

---

## 1. Recon

The handout `dist.zip` contained three files:

| File | What it is |
|------|------------|
| `BridgeVault.sol` | The on-chain verifier (Solidity). Decides how much credit a redeemed claim earns. |
| `guardian` | A stripped x86-64 ELF. The off-chain "relayer" that validates a receipt and emits a claim. |
| `sample.receipt` | A known-good receipt (the `FCRA` format). |

Connecting to the service shows the protocol:

```json
{"format": "FCR10", "session_id": 12249790986447752775,
 "target": "0x5938...19Ae", "goal": 80000, "route_bonus_cap": 40000,
 "trace_cap": 48, "settles_once": true,
 "route_factory": "0x5f8d...7f12", "route_init_hash": "0x8d04...1f46",
 "sample_receipt_hex": "464352410a04...",
 "commands": {
   "info": "...", "attest <receipt_hex>": "run guardian and register a staged claim hash",
   "redeem <claim_blob_hex> <sig_hex>": "redeem the current attestation",
   "balance": "...", "quit": "..."}}
```

**Goal:** get `balance >= 80000`. Each new TCP connection mints a **fresh session** with its own `session_id`, `target`, and its own `sample_receipt_hex`.

---

## 2. The contract: where does 80000 come from?

`BridgeVault.redeem()` computes credit as follows (paraphrased):

```solidity
uint64 credit = state.amount;
if (credit > committedAmount) credit = committedAmount;     // base path: capped

// route bonus path — capped at ROUTE_BONUS_CAP = 40000
if (routeSalt.len==32 && routeTicket.len==16) {
    if (computeRouteTarget(routeSalt)==target && ticket==expected) {
        routeOk = true;
        if (routeBonusAmount > credit)
            credit = min(routeBonusAmount, 40000);
    }
}

// checkpoint path — UNCAPPED
if (routeOk && checkpointSeal.len==16) {
    if (checkpointSeal==expectedSeal && checkpointBonusAmount > credit)
        credit = checkpointBonusAmount;                     // no cap!
}
balances[sessionId] += credit;
```

The signature in `redeem` is checked with `ecrecover(...) == relayer`, over an EIP-712 digest binding
`(sessionId, batchId, nullifier, committedAmount, keccak256(claimBlob))`.

So three ways to credit:
- **base:** `min(amount, committedAmount)` — need both ≥ 80000.
- **route:** capped at 40000 — useless alone.
- **checkpoint:** uncapped, but needs a valid `routeSalt` (a CREATE2 pre-image of `target`), a valid `routeTicket`, and a valid `checkpointSeal` — all of which depend on **server-only secrets**.

The checkpoint path looks "intended" but requires secrets we don't have. The interesting question becomes: **how much of the claim can we actually control**, given that only `guardian` produces the claim and only the server signs it.

---

## 3. The guardian binary

`strings` / `rabin2 -z` immediately reveal the shape:

```
ERR vm lane idx / vm lane range / vm raw idx / vm imm / vm rol imm
ERR vm xor / vm add / vm mul imm / vm empty / bad vm op / vm halt / bad vm commitment
SESSION_ROUTE_SALT_HEX   (32 bytes)
SESSION_EPOCH_SEED_HEX   (16 bytes)
SESSION_ENVELOPE_KEY_HEX (32 bytes)
ERR seal policy / ERR claim bounds / ERR lane decode / ERR trace bounds
OK %llx
usage: guardian <session_id> <receipt_hex>
```

So `guardian`:
- reads three secrets from the environment (the server sets them per session),
- contains a small **stack-machine VM** (ops: push/rol/xor/add/mul, "lanes" and "raw" operands),
- performs a "**vm commitment**" check and a "**seal policy**" check,
- on success prints `OK <preview> <claim_hex> <recipient_hex> <trace_hex>`.

The server wraps this: it parses `guardian`'s stdout into `preview=…`, `claim=…`, `trace=…`, then signs `keccak(claim)` and appends `sig=…`.

### 3.1 Running it locally — the breakthrough

The decompilation (`r2 -qc 'aaa; pdc'`) is dense, so I treated the binary as a **gray box**. Running it with **dummy** environment values:

```bash
SESSION_ROUTE_SALT_HEX=$(python3 -c "print('11'*32)") \
SESSION_EPOCH_SEED_HEX=$(python3 -c "print('22'*16)") \
SESSION_ENVELOPE_KEY_HEX=$(python3 -c "print('33'*32)") \
./guardian 12249790986447752773 <sample_hex>
```
```
OK 4e20 0a14b21c…083c2 10a09c01 1a11 6d656d6f3d726f7574652d77696e646f77 200b  b21c…083c2  74726163653a7365616c65642d77696e646f77
```

It printed **`OK`** even with completely wrong secrets! Decoding the output:

- `preview = 0x4e20 = 20000`
- `claim   = 0a14 <recipient> 10 a09c01 1a11 "memo=route-window" 20 0b`
  → protobuf-style: recipient, `amount=20000`, `memo`, `laneHint=11`
- `trace   = "trace:sealed-window"`

**Conclusion:** for this receipt the seal check that uses the secrets is *not gating*. Whatever the guardian validates here is **environment-independent**, so it is fully reproducible offline.

---

## 4. Mapping the receipt with a byte-flip scan

A single-byte mutation sweep (flip each byte, observe the error) gives the layout:

| Offset | Bytes | Meaning |
|--------|-------|---------|
| `0x00` | `46 43 52 41` | magic `FCRA` |
| `0x04` | `0a` | version (10) |
| `0x05` | `04` | lane count (`nmeb` = 4) |
| `0x06` | `19 00` | VM program length (25) |
| `0x08` | 8 bytes | `session_id` (LE) |
| `0x10` | 8 bytes | `f1` = 53 — **mode selector** |
| `0x18` | 8 bytes | `f2` = 33104 |
| `0x20` | 8 bytes | `f3` = 20000 — **committedAmount** |
| `0x28` | 20 bytes | recipient (= `target`) |
| `0x3c` | **32 bytes** | **VM commitment** (the checksum over everything else) |
| `0x5c` | 25 bytes | VM program (must equal a hardcoded constant) |
| `0x75…` | 4 records | the **lanes** (length-prefixed, RC4-encoded) |

Almost every byte is protected by the 32-byte commitment: changing `f1/f2/f3`, the recipient, or any lane byte yields `ERR bad vm commitment`.

`gdb` confirms the commitment is a self-checksum. The binary has three `memcmp` sites:

| Addr | Size | Purpose | Error |
|------|------|---------|-------|
| `0x4015fe` | 25 | VM program == constant | — |
| `0x401a7a` | 32 | **computed commitment == stored (`0x3c`)** | `ERR bad vm commitment` |
| `0x4024d4` | 16 | env-dependent **seal** | `ERR seal policy` |

Breaking at `0x401a7a` and dumping both buffers for the sample:

```
computed(rdi): ed 51 11 8d e2 7a e4 87 12 20 c6 da 16 30 73 44  af 98 a8 1c 12 70 44 40 5e 4a a1 24 30 8e b2 ee
stored(rsi):   ed 51 11 8d …                      (identical, == receipt bytes 0x3c..0x5c)
```

So **`guardian` itself is a commitment oracle.** I scripted it:

```python
GDB = "set pagination off\nset confirm off\nbreak *0x401a7a\nrun\nx/32bx $rdi\nquit\n"
def commitment(sid, hx):
    out = run_gdb(["gdb","-q","--args","./guardian",str(sid),hx], GDB)
    return parse_32_bytes_after("Breakpoint 1,", out)
```

This lets me **recompute the correct commitment for any modified receipt** — no need to fully re-implement the bespoke VM/hash (that's the "anti-slop" rabbit hole). The 16-byte seal at `0x4024d4` was *never reached* for the sample.

---

## 5. The two real bugs

### Bug 1 — `f1 == 53` skips the seal entirely
Brute-forcing `f1` (offset `0x10`): **only `f1 = 53`** returns `OK`. Every other value reaches the `0x4024d4` seal check and fails (`ERR seal policy`) because it needs the secret envelope key. With `f1 = 53` the secret-dependent seal is bypassed, so the only gate left is the env-independent commitment — which we can forge with the oracle.

### Bug 2 — the claim is just an RC4-XOR of lane 0
A differential scan over the lane region showed **lane 0 decodes byte-for-byte into the claim blob**:

```
keystream[i] = receipt[0x7a + i] XOR claim[i]
```

The keystream is **independent of the secrets and of the session**. Since I learn the plaintext claim for free (by attesting the sample), I can recover the keystream and **rewrite any claim byte** — including the `amount` varint at claim offset 23.

`varint(80000) = 80 f1 04` is the same length as `varint(20000) = a0 9c 01`, so no length changes are needed.

Setting the claim amount to 80000 locally:

```
OK preview=80000 claim=0a14…1080f1041a11…200b trace=trace:sealed-window
```

`guardian`'s `preview` is just the claim amount — not capped.

### The server's last check
First forged attempt returned **`ERR preview amount mismatch`**. The server cross-checks `preview == committedAmount`, and `committedAmount` is header field `f3` (offset `0x20`, originally 20000). Fix: set `f3 = 80000` too (it's commitment-protected, but the oracle handles that). Now `preview = 80000 = committedAmount`, and the contract credits `min(80000, 80000) = 80000`.

---

## 6. Exploit

```python
import socket, json, subprocess, re, os

HOST, PORT = "178.105.199.41", 13357
GUARD = "./guardian"
ENV = {**os.environ, "SESSION_ROUTE_SALT_HEX":"11"*32,
       "SESSION_EPOCH_SEED_HEX":"22"*16, "SESSION_ENVELOPE_KEY_HEX":"33"*32}
GDB  = "set pagination off\nset confirm off\nbreak *0x401a7a\nrun\nx/32bx $rdi\nquit\n"

def commitment(sid, hx):
    p = subprocess.run(["gdb","-q","--args",GUARD,str(sid),hx],
                       input=GDB, capture_output=True, env=ENV, text=True)
    seg = p.stdout.split("Breakpoint 1,",1)[1]
    return "".join(re.findall(r"\b0x([0-9a-f]{2})\b", seg)[:32])

def varint(n):
    o=b""
    while True:
        x=n&0x7f; n>>=7
        o+=bytes([x|0x80]) if n else bytes([x])
        if not n: return o

def recvline(s):
    d=b""; s.settimeout(8)
    while b"\n" not in d:
        c=s.recv(8192)
        if not c: break
        d+=c
    return d

s=socket.socket(); s.connect((HOST,PORT))
b=json.loads(recvline(s).strip().split(b"\n")[0])
sid, goal, sample = b["session_id"], b["goal"], b["sample_receipt_hex"]

# 1) attest the sample to learn the decoded claim (=> the RC4 keystream)
s.sendall(b"attest "+sample.encode()+b"\n")
C = bytes.fromhex(re.search(r"claim=([0-9a-f]+)", recvline(s).decode()).group(1))
S = bytearray.fromhex(sample)
BASE0 = 0x7a
KS = bytes(S[BASE0+i] ^ C[i] for i in range(len(C)))   # keystream

# 2) rewrite amount (claim offset 23, after 0x10 tag) to the goal
assert C[22] == 0x10
C2 = C[:23] + varint(goal) + C[26:]                     # 80000 == 3-byte varint

S2 = bytearray(S)
S2[0x20:0x28] = goal.to_bytes(8,"little")               # f3 = committedAmount = goal
for i in range(len(C2)):
    S2[BASE0+i] = KS[i] ^ C2[i]                          # re-encode lane 0
S2[0x3c:0x5c] = bytes.fromhex(commitment(sid, bytes(S2).hex()))  # fix commitment
forged = bytes(S2).hex()

# 3) attest forged -> server signs keccak(our claim); then redeem
s.sendall(b"attest "+forged.encode()+b"\n")
m = re.search(r"claim=([0-9a-f]+).*sig=([0-9a-f]+)", recvline(s).decode())
s.sendall(f"redeem {m.group(1)} {m.group(2)}\n".encode())
print("redeem :", recvline(s).decode().strip())
s.sendall(b"balance\n"); print("balance:", recvline(s).decode().strip())
```

Output:

```
attest(forged): preview=80000 claim=0a14…1080f1041a11…200b trace=… sig=830fe5…aece22605e…
redeem : slopped{wrapped_lane_offsets_expose_seal_keys_then_sign_recursive_checkpoints}
balance: 80000
```

---

## 7. Root cause

The flag itself summarizes it: **`wrapped_lane_offsets_expose_seal_keys_then_sign_recursive_checkpoints`**.

1. The 32-byte "VM commitment" is a **self-checksum over the receipt** computed *without* any secret. The binary is its own oracle, so any tampered receipt can be re-stamped with a valid commitment.
2. **`f1 = 53` bypasses the secret-keyed seal check** ("seal policy"), leaving the forgeable commitment as the only gate.
3. The claim is a **plain RC4-XOR of lane 0** with a key derived independently of the session secrets, so the `amount` is fully attacker-controlled.
4. The server's only sanity check (`preview == committedAmount`) is satisfied by also editing the `f3` header field.

Net: forge a receipt with `amount = committedAmount = 80000`, let the server sign it, redeem for 80000. The intricate VM/keccak/checkpoint machinery was a distraction — the trust boundary (env-independent commitment + a mode that skips the seal) was the actual break.

## 8. Tooling note
A `gdb` breakpoint at the commitment `memcmp` (`0x401a7a`, read `$rdi`) turned the target binary into a re-stamping oracle. This sidesteps reimplementing the custom VM + SipHash-style finalizer entirely — the "anti-slop" trap was getting lured into perfectly reversing that crypto rather than noticing it isn't keyed.
