> Copied from tstokenlib (commit 5be148a) on 2026-10-21. Relative links to other tstokenlib documents (`../WITNESS_LINEAGE_RESEARCH.md`, `../RUGGERBOT_TOKENS_PLAN.md`, `../lt-spiffy-plugin`) point into that repository, not this one.

# Note NFT (TSL1_LT_NOTE): wallet integration

For wallet integrators. The Note NFT is a Fuelled NFT whose terms say, for each way it can end, how much of the fuel the holder gets. The issuer (`payTo`) gets the rest. One script gives a family of instruments: vouchers, time-locked claims, callable claims, deposits, insured vouchers.

This document gives only what differs from the Fuelled NFT and the Voucher NFT. `LT_FNFT_WALLET_INTEGRATION.md` and `LT_VNFT_WALLET_INTEGRATION.md` apply otherwise. It is a new archetype: the Fuelled and the Voucher NFT are unchanged (their code is byte-identical).

Status: built and tested (`test/lt_note_test.dart`), and mined on a regtest node (`test/lt_note_localnet_test.dart`). Recorded as decision 9.12 in `WITNESS_LINEAGE_RESEARCH.md`.

## 1. The terms

Set at issuance and copied unchanged by every transfer. The script refuses a transfer that changes them (the forward check spans them).

| Field | Bytes | Meaning |
|---|---|---|
| `maxHops` | 1 | Transfers allowed. 0: no limit, and the counter stays 0. |
| `payTo` | 20 | The issuer's wallet key hash: paid the issuer's share; its key signs a call. |
| `feeCap` | 8 | The most an ending may leave for the fee. |
| `exit` | 8 | The holder's amount when the holder ends it, at any time. |
| `maturity` | 4 | A block height. |
| `mature` | 8 | The holder's amount when the holder ends it from `maturity` on. |
| `callAt` | 4 | A block height from which the issuer may end it. |
| `call` | 8 | The holder's amount when the issuer ends it. |

61 bytes. An amount of 0 gives the holder nothing on that path. An amount of at least the value less `feeCap` gives the holder everything (`NoteTerms.everything`). A height of `NoteTerms.never` (499,999,999) is never reached in practice.

Header (215 B): token id 32, issuer 20, terms 61, owner 20, counter 1, then flags, value, in 0, funding in, as for the Fuelled NFT. Records derive the terms and the counter, so growth per transfer is the Fuelled NFT's (about 153 B).

## 2. The endings

Every unlock is four pushes; the fourth selects the path.

| Fourth push | Path | Signed by | Time rule |
|---|---|---|---|
| C, the child header and record | transfer | the owner | none; the hop limit when `maxHops` is not 0 |
| `01` ‖ values (9 or 17 B) | exit | the owner | none |
| `02` ‖ values (9 or 17 B) | mature exit | the owner | nLockTime a height ≥ `maturity`; sequence not final |
| `03` ‖ owner hash ‖ values (29 or 37 B) | call | the key of `payTo` | nLockTime a height ≥ `callAt`; sequence not final |

With `a` the path's holder amount, `v` the note's value and `floor = v − feeCap`, the outputs are exactly:

| `a` | Outputs |
|---|---|
| 0 | one: `payTo`, at least `floor` |
| ≥ `floor` | one: the owner, at least `floor` |
| otherwise | two: output 0 `payTo` at least `floor − a`, output 1 the owner at least `a` |

Neither side can take the other's share: the holder's output is at least `a`, the issuer's at least `floor − a`. The slack between the fee paid and `feeCap` may go to either output. Output 0 pays `payTo` whenever the issuer is paid: it is the coin a successor's issuance spends.

There is no cheap path: a holder cannot burn the note around its terms.

## 3. The family

| Preset (`NoteTerms.`) | exit | maturity, mature | callAt, call | What the holder is exposed to |
|---|---|---|---|---|
| `voucher` | 0 | never, 0 | expiry, 0 | The issuer's word for everything |
| `zeroCoupon` | 0 | H, everything | never | Time only. Fully collateralised: it is a time-locked claim, priced at a discount for time, not a loan to the issuer. |
| `callable` | 0 | H, everything | H₀ < H, floor | The issuer ending it early at the floor |
| `deposit` | early | H, everything | never | Its own impatience: an early exit forfeits the difference |
| `insured` | 0 | never, 0 | any, floor | Being taken back, never for less than the floor |

## 4. Building

```dart
final b = FnftBuilder.note();
final i = b.issue(first, issuerPkh, owner: issuerOwnPkh,
    terms: NoteTerms.deposit(payTo: issuerPkh, feeCap: 500, at: height + 4320, early: 30000), satsPerKb: rate);
b.transfer(from, ownerKey, to, satsPerKb: rate);
b.exit(from, ownerKey, satsPerKb: rate);                 // any time
b.matureExit(from, ownerKey, satsPerKb: rate);           // nLockTime = maturity: broadcast after it
b.call(from, issuerKey, satsPerKb: rate);                // nLockTime = callAt: broadcast after it
b.reissue(ended: exitOrCall, endKey: issuerKey, issuerPkh, terms: newTerms);
```

A fee over `feeCap` is refused by the builder. `end` (the burn) is refused.

## 5. Receiving and succession

- `FnftReceive.check` with the note builder. Show the holder, before acceptance, what it gets now (`exit`), at maturity (`mature`), and if called (`call`), against the note's value: the fuel is not checked against the amounts, and each transfer pays its fee from it.
- A reissue link carries the predecessor's terms (61 bytes): `LtLink(ended, recG, terms.bytes)`. The ended transaction is an exit, a mature exit or a call that pays `payTo`. An ending that pays only the holder leaves nothing for a successor.

## 6. Measured on localnet (1 sat/kB, all mined)

| | |
|---|---|
| code | 3,479 B (the Voucher NFT's 2,726, the Fuelled NFT's 2,471) |
| issuance | 3,866 B |
| first transfer (carries the attestation) | 8,204 B; the next 8,357 B |
| exit, split in two | 3,886 B: 19,983 to the issuer, 30,000 to the holder |
| mature exit, one output | 3,845 B |
| mature exit sent 22 blocks early | taken as non-final, not mined; a transfer replaced it |
| call sent 14 blocks early | taken as non-final, not mined; the holder's exit replaced it |
| mature exit after maturity | mined at once |
| reissue from an exit | the payee followed the link |

**An early mature exit or call** waits in a node's non-final pool and is not mined when its height passes. While it waits, that node refuses a spend of the note with other inputs (a top-up) with `txn-mempool-conflict`; a one-input spend (a transfer, an exit) replaces it (decision 9.15). Send each only after its height.

## 7. Open

- The fuel is not checked against the amounts. A note whose value falls below `mature` pays the holder everything at maturity.

## 8. Selling: TSL1_LT_NOTE_S

The Note NFT's sale version, `TSL1_LT_NOTE_S` (`FnftBuilder.saleableNote()`, code 3,794 B, header 243 B), is sold in its own transfer with `FnftSwap`. `LT_FNFT_WALLET_INTEGRATION.md` section 12 describes the header, the sale and the exchange for the whole family. For a note:
- **A sale is a transfer.** With a hop limit it counts against `maxHops`; without one it does not.
- **The terms do not change.** The buyer gets the same exit, mature and call amounts and heights; price a note as what those amounts are worth at those heights.
- Exits, mature exits and calls take no pay output.
- **An issuer can hold up a sale.** A sale has two inputs, so an issuer's early call blocks it (decision 9.15): the node refuses the sale with `txn-mempool-conflict`. Clear it with a transfer to yourself, which has one input and replaces the early transaction, then sell from the new output. Send the two together. Measured on localnet for the voucher, whose forced redemption is the same case (`test/lt_fnft_sale_localnet_test.dart`).

Measured on localnet, mined: sale 9,224 B, next hop 9,365 B, the next holder's exit 4,202 B.
