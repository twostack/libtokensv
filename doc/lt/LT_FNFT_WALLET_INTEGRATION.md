> Copied from tstokenlib (commit 5be148a) with the TSL1_LT_FT, TSL1_LT_NFT and TSL1_LT_FNFT sources on 2026-10-21. Relative links to other tstokenlib documents (`../WITNESS_LINEAGE_RESEARCH.md`, the other integration documents, `../lt-spiffy-plugin`) point into that repository, not this one.

# Fuelled NFT (TSL1_LT_FNFT): wallet integration

For wallet integrators. The Fuelled NFT is a covenant NFT whose token output carries the satoshis that pay its own fees. This document gives only what differs from the covenant NFT. For everything else, read `LT_NFT_WALLET_INTEGRATION.md`, which applies unchanged:
- BEEF is the wallet's;
- the transfer message and its links;
- the anchor;
- receiving only when the network has the transfer;
- issue to yourself, then transfer.

Status: built and tested in tstokenlib (`test/lt_fnft_test.dart`), and mined on a regtest node (`test/lt_fnft_localnet_test.dart`). Recorded as decision 9.8 in `WITNESS_LINEAGE_RESEARCH.md`.

## 1. What is different

| | Covenant NFT (`TSL1_LT_NFT`) | Fuelled NFT (`TSL1_LT_FNFT`) |
|---|---|---|
| Token output value | 1 sat | the fuel: whatever it holds |
| Who pays a transfer's fee | the sender, from a funding coin | the token, from its value |
| Inputs of a transfer | token + funding | token, or token + a top-up coin |
| Outputs of a transfer | change (0) + token (1) | token (0) only |
| The token output | output 1 | output 0 |
| Growth per transfer | 386 B | 152 B; a top-up adds 143 B once |
| Hop 20 | 13,371 B | 8,943 B (9,096 B with one top-up) |
| End (burn) | needs a funding coin; 339 B | needs none; 191 B; returns the value |
| Code / lock | 2,231 / 2,406 B | 2,471 / 2,627 B |

## 2. The token on chain

```
output 0, value = the fuel:  OP_PUSHDATA1 0x99 <header, 153 bytes> OP_CODESEPARATOR <code, 2,471 bytes>
```

The code's SHA-256 is given by `FnftScriptGen().code()`. A wallet recognises the token by the exact code bytes after the separator.

| Offset | Bytes | Field |
|---|---|---|
| 0 | 32 | Token id (zero in the issuance) |
| 32 | 20 | Issuer: HASH160 of the issuer's Rabin key |
| 52 | 20 | Owner key hash |
| 72 | 1 | Flags: 1 when input 1 funds this transaction, else 0 |
| 73 | 8 | Value of this output, little endian |
| 81 | 36 | Input 0's outpoint |
| 117 | 36 | Input 1's outpoint, or zero |

**Two ways to spend it.**
- **Normal path:** a transfer. The unlock is the preimage, the signature, the public key, and C = the child's header ‖ this transaction's record.
- **Cheap path:** `PUSH(sig) PUSH(pub)`, the owner's signature only. It ends the token and releases its value to any outputs the owner signs. A wallet must never spend a token output as an ordinary coin: doing so ends the token.

## 3. Fuel

- **Issuing:** the first coin's value, plus an optional funding coin, less the fee, is the token's starting fuel. The issuer decides how much.
- **Transfers** take their fee from the token's value: `LtBuilder.feeFor(size, satsPerKb)`. On the regtest node at 1 sat/kB that was 7 to 9 sats per transfer.
- **Topping up:** any holder may add a P2PKH coin to a transfer (`fund:`). The whole coin goes into the token; there is no change output. The coin's outpoint and signature stay in every later transaction's record: 143 B, once.
- **Running dry:** the builder refuses a transfer that would leave the token with nothing. Then a holder tops it up, or the owner burns it.
- **The burn:** `FnftBuilder.end` sends everything the token holds, less the fee, to the owner. It needs no funding coin. **The satoshis are never stranded.** Only the token, as a token, can be stranded, if nobody refuels it.
- **Reissue:** `end` pays the value to output 0, and `reissue` issues the successor on that output, so the old token's remaining fuel fuels the successor. It costs later transactions nothing.
- **Conservation:** consensus refuses a transaction whose outputs exceed its inputs. The covenant has no value rule; whatever a transfer does not keep in the token goes to the miners.

**Economics for the user interface:**
- A payee receives the token with whatever fuel the earlier transfers left. Show the fuel as part of the token, in satoshis.
- A sender pays nothing from their own coins unless they top up.

## 4. What a wallet stores

- The outpoint `(T, 0)`.
- T's raw bytes. `FnftBuilder.fromRaw` reads the header, record and fuel back from them.
- The links, if the token was reissued.
- The cached anchor.

## 5. Sending

1. Get the recipient's key hash.
2. Call `FnftBuilder.transfer(from: held.tx, ownerKey, to, satsPerKb)`. Add `fund:` only to top up.
   - The token input signs SIGHASH_ALL | FORKID.
   - The script code is the code after the separator.
   - The amount is the token's current value.
   - The key is the one whose hash is the header's owner.
3. Send the transfer message (`LT_NFT_WALLET_INTEGRATION.md` section 4). Its BEEF needs T's parent, and the top-up coin's parent if there is one. There is no other funding input.

## 6. Receiving

Use `FnftReceive.check(b, raw, ownerPkh, anchorTx, links)`. It returns an `FnftHolding` (token id, origin, value) or throws `LtRefused`. It checks:
- the bytes, as the record rebuilds them;
- the owner;
- the parent, rebuilt from the record with the derived fields spliced in, which must be the output input 0 spent;
- a run of the token's script;
- the issuer;
- each link, through `FnftSuccession.verify`.

It took 124 ms at hop 20 on the regtest node run. A transfer signed by anyone but the owner is refused without the script run: the parent rebuilt with the signer as owner is another transaction.

## 7. Redeem and reissue

As for the covenant NFT, with three differences:
- the token is output 0, so the end spends `G:0`;
- the end needs no funding coin;
- the successor's fuel is the end's output 0.

`FnftSuccession.verify` applies the same four rules, and its refusals are tested: another record, a continued token, another predecessor, a tampered record, another issuer. On the regtest node, a second issuance on the end's output 0 was refused (`Missing inputs`).

## 8. The library API

| Call | Does |
|---|---|
| `FnftBuilder.standard()` | The builder for the archetype's code |
| `issue`, `transfer` (`fund:` tops up), `end`, `reissue` | Build the transactions |
| `fromRaw`, `fromRec`, `fromRecOf` | Read and rebuild |
| `FnftReceive.check` | The payee's check |
| `FnftSuccession.verify` | One reissue link |
| `FnftIdentity.verify`, `attestationError` | The issuer |
| `LtPayload.build`, `LtPayload.of`; `FnftReceive.check(..., payloadTx:)` | The payload (section 11) |

## 9. libspiffy

`LtFnftPlugin` here moves this archetype in a libspiffy wallet. Transfers, ends and reissues take no wallet coin; libspiffy (`dc584a4`) selects and reserves none for them. Refer to `doc/spiffy/FNFT.md`.

## 10. Open

- The message envelope. It is shared with the covenant NFT and decided upstream.

## 11. The payload

A Fuelled NFT can carry a payload as the covenant NFT does (`LT_NFT_WALLET_INTEGRATION.md` section 11): issue it with the payload transaction's output 1 as the funding coin (`fund:`). That coin's value becomes fuel like any other. `FnftReceive.check(..., payloadTx:)` sets `holding.payload`. An issuance without a funding coin has no input 1 and carries no payload. Tested in `test/lt_payload_test.dart` (gate G3).

A Fuelled NFT cannot be sold by a swap: it has no change output, and a funding coin is swept into the fuel. Its sale version can (section 12).

## 12. Selling: the sale versions

The Fuelled NFT itself cannot be sold in its own transfer: it has no change output, and a funding coin is swept into the fuel. Each member of the family has a **sale version**, an archetype of its own with its own code (decision 9.13 in `WITNESS_LINEAGE_RESEARCH.md`):

| Archetype | Builder | Code | Header | Code SHA-256 |
|---|---|---|---|---|
| `TSL1_LT_FNFT_S` | `FnftBuilder.saleable()` | 2,784 B | 181 B | `0fcbc4c3b1fe514d7dc6869e00f8fcec818ab433f6f362a9f30780b361e46e6c` |
| `TSL1_LT_VNFT_S` | `FnftBuilder.saleableVoucher()` | 3,039 B | 215 B | `adc844673eaf0accebe5a6c07840bcb324a980b66b8da8380022a9fcd4d5e8ec` |
| `TSL1_LT_NOTE_S` | `FnftBuilder.saleableNote()` | 3,794 B | 243 B | `cafa8e6798ae446ca7a8e288b8cc04417ba32b39f3c70d3249e956fce4d28004` |

A token is issued as a sale version or not; it cannot change later. An issuer who wants holders to be able to sell issues the sale version.

**The header** gains `pay` after `fundIn`: amount 8 (LE), key hash 20. Flags bit 1 (paid) says the transfer has a pay output. Without the flag the pay field must be zero, and no other flag bit may be set.

**A sale** is a transfer with the buyer's coin as the funding input:

| Position | Content | Signed by |
|---|---|---|
| Input 0 | the seller's token, normal path | the seller |
| Input 1 | the buyer's P2PKH coin, exactly the price plus the fee | the buyer |
| Output 0 | the token, owned by the buyer, its fuel unchanged | |
| Output 1 | P2PKH to the seller's `payTo`, the price | |

**The exchange** is the covenant NFT's swap (`LT_NFT_WALLET_INTEGRATION.md` section 10) with `FnftSwap` in place of `LtSwap`: the same `LtSwapTerms` and version 1 encoding, `bid`, `ask`, `signing`, `readHalf`, `checkBid`, `verify`. Its warnings apply unchanged: a signed half is an open option, releasing a hold is not withdrawing, an issuance is not sold, the buyer gets no change. `FnftSwap.verify` also checks that the token keeps its fuel.

**Growth.** A plain transfer adds 152 B, as before. A sale adds 323 B: the buyer's coin (143 B) and the pay field (28 B) stay in the record.

**libspiffy:** `LtFnftSalePlugin`, `LtVnftSalePlugin` and `LtNoteSalePlugin` here have their base plugin's actions and the swap's (`doc/spiffy/SWAP.md`, section 1.8).

**Measured on localnet** (`test/lt_fnft_sale_localnet_test.dart`, all mined): FNFT_S sale 7,080 B, next hop 7,221 B; VNFT_S sale 7,658 B, next hop 7,800 B, redemption 3,404 B; NOTE_S sale 9,224 B, next hop 9,365 B, exit 4,202 B.

A Fuelled token cannot be listed for a stranger to buy (a purchase has no signer, and the family derives the parent's owner from input 0's signer). The Listed NFT (`LT_LNFT_WALLET_INTEGRATION.md`) is built on the covenant NFT for that reason.

