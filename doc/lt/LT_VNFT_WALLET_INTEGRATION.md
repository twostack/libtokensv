> Copied from tstokenlib (commit 5be148a) on 2026-10-21. Relative links to other tstokenlib documents (`../WITNESS_LINEAGE_RESEARCH.md`, `../RUGGERBOT_TOKENS_PLAN.md`, `../lt-spiffy-plugin`) point into that repository, not this one.

# Voucher NFT (TSL1_LT_VNFT): wallet integration

For wallet integrators. The Voucher NFT is a Fuelled NFT with three more rules:
- it can be transferred at most `maxHops` times, and must then be redeemed;
- the holder can redeem it at any hop, but only to the issuer;
- after an expiry height, the issuer can force its redemption from whoever holds it.

This document gives only what differs from the Fuelled NFT. Everything else in `LT_FNFT_WALLET_INTEGRATION.md` and `LT_NFT_WALLET_INTEGRATION.md` applies.

Status: built and tested (`test/lt_vnft_test.dart`), and mined on a regtest node (`test/lt_vnft_localnet_test.dart`). Recorded as decision 9.9 in `WITNESS_LINEAGE_RESEARCH.md`.

## 1. What is different

| | Fuelled NFT | Voucher NFT |
|---|---|---|
| Transfers | unlimited | at most `maxHops` (1 to 255), then only redemption |
| The owner ends it | burn: takes the fuel | **no burn**: redeems to the issuer |
| Holder's redemption | none | any hop: the issuer is paid the fuel, less a fee of at most `feeCap` |
| Issuer's force-redemption | none | after `expiry` (a block height): the issuer takes the token and its fuel |
| Header | 153 B | 187 B: + the terms (33 B) + a counter (1 B) |
| Growth per transfer | 152 B | 152 B: terms and counter are derived, not recorded |
| Code / lock | 2,471 / 2,627 B | 2,726 / 2,916 B |

## 2. The terms

`VoucherTerms` are set at issuance and carried unchanged; the script refuses a child with other terms.

| Field | Bytes | Meaning |
|---|---|---|
| `maxHops` | 1 | Transfers allowed before the voucher must be redeemed |
| `expiry` | 4 | Block height after which the issuer can force redemption |
| `redeemTo` | 20 | The issuer's wallet key hash. Redemptions pay it, and its key signs a force-redemption. |
| `feeCap` | 8 | The most a holder's redemption may take from the token's value for the fee |

Header layout:

| Offset | Bytes | Field |
|---|---|---|
| 0 | 32 | token id |
| 32 | 20 | issuer |
| 52 | 33 | terms |
| 85 | 20 | owner |
| 105 | 1 | counter: transfers since issuance |
| 106 | 81 | flags, value, in 0, funding in, as for the Fuelled NFT |

## 3. The three spending paths

Every unlock is four pushes. The fourth push decides the path:

| Fourth push | Path | Who signs | What the script checks |
|---|---|---|---|
| C, the child header and the record (≥ 187 B) | transfer | the owner | everything the Fuelled NFT checks, plus: the counter is below `maxHops`, the child's counter is one more, the terms are unchanged |
| 8 bytes, the output's value | holder's redemption | the owner | exactly one output, P2PKH to `redeemTo`, worth at least the token's value minus `feeCap` |
| 20 bytes, the owner's key hash | issuer's force-redemption | the key of `redeemTo` | nLockTime is a height (below 500,000,000) of at least `expiry`; this input's sequence is not final; the pushed hash is the header's owner |

**Why the force-redemption is safe.** The non-final sequence makes consensus enforce the nLockTime: no node mines it before `expiry`. On the regtest node:
- An early force-redemption was taken into the non-final pool and not mined.
- The holder's own final redemption then replaced it.
- One with an nLockTime below the expiry was refused by the script.

So an issuer cannot take a voucher before its expiry, nor stop the holder's one-input spends. But while an early force-redemption waits in a node's non-final pool, that node refuses the holder's two-input spends (a top-up, a funded redemption) with `txn-mempool-conflict`, and the early force-redemption is not mined when the expiry passes (decision 9.15). The holder then uses a one-input spend; the issuer sends its force-redemption only after the expiry.

**The issuer's procedure.** Build the force-redemption with `FnftBuilder.forceRedeem`. It sets nLockTime to the expiry and the sequence to `0xfffffffe`. Broadcast it after the expiry height. On the regtest node it was mined in the first block after the expiry.

## 4. Building

```dart
final b = FnftBuilder.voucher();
final t = b.issue(first, issuerPkh, owner: issuerOwnPkh,
    terms: VoucherTerms(maxHops: 10, expiry: height + 4320, redeemTo: issuerPkh, feeCap: 1000), satsPerKb: rate);
b.transfer(from, ownerKey, to, satsPerKb: rate);          // refused past maxHops
b.redeem(from, ownerKey, satsPerKb: rate);                // `fund:` pays a fee beyond the cap
b.forceRedeem(from, issuerKey, satsPerKb: rate);          // after the expiry
b.reissue(ended: redemptionOrForced, endKey: issuerKey, issuerPkh, terms: newTerms);
```

`end` (the burn) is refused for a voucher. A holder's redemption or the issuer's force-redemption pays output 0 to the issuer: the coin a reissue spends.

## 5. Receiving and succession

- **Receiving:** `FnftReceive.check` with the voucher builder. The holding's `tx.hopsLeft` and `tx.terms` tell the payee:
  - how many transfers remain;
  - when the issuer may take the voucher back.

  Show both before a person accepts a voucher.
- **Succession:** a reissue may change the terms, and a voucher's record leaves them out. So a reissue link carries the predecessor's terms: `LtLink(ended, recG, terms)`, encoded by `LtLinks`. The ended transaction is a holder's redemption or the issuer's force-redemption. `FnftSuccession.verify` accepts either, and refuses a transfer.

## 6. Measured on localnet (1 sat/kB, all mined)

| | |
|---|---|
| Issue, 3 transfers, a 4th refused | refused by the script (`OP_VERIFY`) |
| Holder's redemption | 3,091 B; 2,975 sats of fuel → 2,971 to the issuer |
| Reissue with new terms (`maxHops` 5) | the payee followed the link to the first voucher |
| Force-redemption, nLockTime below the expiry | refused by the script |
| Force-redemption sent 19 blocks early | taken as non-final, not mined; replaced by the holder's redemption |
| Force-redemption after the expiry | 3,102 B; mined in the first block after the expiry |

## 7. libspiffy

`LtVnftPlugin` here (`doc/spiffy/VNFT.md`) gives these operations to a libspiffy wallet. Its force-redemption takes the holder's transaction as `tokenRaw`, because the issuer's wallet does not follow the voucher.

## 8. Open

- How an issuer finds a voucher's current transaction to force its redemption. One method: a "spent by" query for output 0 at each hop from the issuance, at most `maxHops` queries. This is not a scan of the chain.
- An issuer that loses the key of `redeemTo` can no longer force redemptions. Holders' redemptions still pay that key.

## 9. The payload

A Voucher NFT can carry a payload as the covenant NFT does (`LT_NFT_WALLET_INTEGRATION.md` section 11): issue it with the payload transaction's output 1 as the funding coin (`fund:`). That coin's value becomes fuel like any other. `FnftReceive.check(..., payloadTx:)` sets `holding.payload`. An issuance without a funding coin has no input 1 and carries no payload. Tested in `test/lt_payload_test.dart` (gate G3).

A Voucher NFT cannot be sold by a swap: it has no change output, and a funding coin is swept into the fuel.

## 10. Selling: TSL1_LT_VNFT_S

The Voucher NFT's sale version, `TSL1_LT_VNFT_S` (`FnftBuilder.saleableVoucher()`, code 3,039 B, header 215 B), is sold in its own transfer with `FnftSwap`. `LT_FNFT_WALLET_INTEGRATION.md` section 12 describes the header, the sale and the exchange for the whole family. For a voucher:
- **A sale is a transfer.** It counts against `maxHops`. A voucher at its limit cannot be sold; it can only be redeemed.
- **The terms do not change.** The buyer gets the same expiry, `redeemTo` and `feeCap`; after the expiry the issuer can still force a sold voucher back.
- Redemptions and forced redemptions take no pay output.
- **An issuer can hold up a sale.** A sale has two inputs, so an issuer's early forced redemption blocks it (decision 9.15): the node refuses the sale with `txn-mempool-conflict`. Clear it with a transfer to yourself, which has one input and replaces the early transaction, then sell from the new output. Send the two together. Measured on localnet for the voucher (`test/lt_fnft_sale_localnet_test.dart`).

Measured on localnet, mined: sale 7,658 B, next hop 7,800 B, the next holder's redemption 3,404 B.
