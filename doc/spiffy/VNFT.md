> Copied from lt-spiffy-plugin (commit 033d847) on 2026-10-22 with the lineage plugins. Here the plugins are in `lib/src/spiffy/` and their tests in `test/spiffy/`; the `test/lt_*_localnet_test.dart` suites named here are libtokensv's own regtest suites. `docs/INTEGRATION.md`, `docs/EDGE_CASES.md` and the other tstokenlib documents named here stay in those repositories.

# The Voucher NFT plugin (`LtVnftPlugin`)

This document tells how the Voucher NFT is different from the Fuelled NFT, and gives its procedures, security rules and edge cases. Read `FNFT.md` first. Its rules apply to the Voucher NFT, except where this document tells you otherwise. The language follows ASD-STE100.

The token specification for any wallet is `../lt/LT_VNFT_WALLET_INTEGRATION.md`.

## 1. What is different

The Voucher NFT (`TSL1_LT_VNFT`) is a Fuelled NFT with three more rules:

- It can be transferred at most `maxHops` times. Then it can only be redeemed.
- The holder can redeem it at any hop, but only to the issuer.
- After an expiry height, the issuer can take it back from any holder (a **force-redemption**).

| | Fuelled NFT (`LtFnftPlugin`) | Voucher NFT (`LtVnftPlugin`) |
|---|---|---|
| Plugin id / script type | `tsl1_lt_fnft` / `lt_fnft` | `tsl1_lt_vnft` / `lt_vnft` |
| Transfers | no limit | at most `maxHops` (1 to 255) |
| The owner ends it | `end`: the owner takes the fuel | **no `end`**. `redeem`: the issuer gets the fuel. |
| The issuer takes it back | not possible | `forceRedeem`, after `expiry` |
| `reissue` | from the token. The plugin ends it and issues the successor (paired). | from a redemption or a force-redemption that the issuer's wallet already has. One transaction. |
| Terms | none | `maxHops`, `expiry`, `redeemTo`, `feeCap`, set at issuance |
| Growth for each transfer | 152 B | 152 B |
| Redemption | none | 3,091 B; force-redemption 3,102 B |
| Metadata | owner, issuer, token id, `fuel` | the same, and `maxHops`, `hops`, `hopsLeft`, `expiry`, `forcedRedemptionHeight` (the expiry, from which the issuer may redeem it whoever holds it), `redeemTo`, `feeCap` |

Status: TESTED. `test/lt_vnft_plugin_test.dart` runs the plugin with stand-in wallets. In this test, the issuer's wallet does not have the holder's transactions. `test/libspiffy_vnft_wallet_test.dart` runs it in a real libspiffy wallet with ARC stubbed. tstokenlib mines the full lifecycle on a regtest node (`test/lt_vnft_localnet_test.dart`).

## 2. The terms

The issuer sets the terms at issuance. The script refuses a transfer that changes them. A reissue can set new terms.

| Param | Meaning |
|---|---|
| `maxHops` | The number of transfers before the voucher must be redeemed. The distribution from the issuer is the first transfer. |
| `expiry` | A block height. After it, the issuer can force the redemption. It must be less than 500,000,000. |
| `redeemTo` | The key hash that redemptions pay, and whose key signs a force-redemption. Default: the key of the first issuance coin, which is the issuing wallet's own key. |
| `feeCap` | The most satoshis that a holder's redemption can take from the fuel for its fee. |

**CAUTION:** `redeemTo` must be a key that the issuer's wallet holds. Use the default. If the wallet loses that key, the issuer cannot force redemptions, and holders' redemptions pay a key that nobody has.

## 3. Necessary versions

| Dependency | Necessary state | Why |
|---|---|---|
| `../tstokenlib` | `main` at `5bf749b` or later | `FnftBuilder.voucher`, `VoucherTerms`, `redeem`, `forceRedeem`, `LtLink` with terms |
| `../libspiffy` | `main` at `dc584a4` or later | As for the Fuelled NFT |

## 4. Actions

| `action` | Params | Wallet coins | Who | Result |
|---|---|---|---|---|
| `issue` | `issuer`, `maxHops`, `expiry`, `feeCap`, `redeemTo` (optional) | 1 or 2 | the issuer | The issuance, owned by the first coin's key. The coins, less the fee, are the fuel. |
| `transfer` | `token`, `to`, `attestation` (only for an issuance) | 0 | the owner | A transfer. Refused when no hops are left. |
| `topup` | `token`, `to`, `attestation` (only for an issuance) | 1 | the owner | A transfer that adds one coin to the fuel. It also uses a hop. |
| `redeem` | `token` | 0 | the owner | One P2PKH output to `redeemTo`. The fee comes from the fuel. Refused if the fee is more than `feeCap`. |
| `redeemFunded` | `token` | 1 | the owner | `redeem` with a wallet coin that pays the fee. The issuer gets the whole fuel. Use it when the fee is more than `feeCap`. |
| `forceRedeem` | `token`, `tokenRaw` (when the wallet does not have it), `lockHeight` (optional, default `expiry`) | 0 | the issuer | One P2PKH output to `redeemTo`. nLockTime is `lockHeight`. The input's sequence is `0xfffffffe`. |
| `reissue` | `ended` or `endedRaw`, `issuer`, `maxHops`, `expiry`, `feeCap`, `redeemTo` (optional) | 0 | the issuer | The successor, issued on output 0 of the redemption or force-redemption, with the new terms. Its fuel is that output's value. |

For an action with 0 wallet coins, send the payment with `amount: 0`.

## 5. Procedures

Use the procedures in `FNFT.md` and `docs/INTEGRATION.md` with these changes.

**Issue.**
1. Send `{'action': 'issue', 'issuer': issuerPkh, 'maxHops': n, 'expiry': height, 'feeCap': sats}`. Set `amount` to the fuel you want.
2. Settle it. Calculate the attestation.
3. Distribute it with `transfer`. This uses the first hop.

**Redeem (the holder).**
1. Send `{'action': 'redeem', 'token': txid}` with `amount: 0`.
2. If the plugin refuses with `takes more than the redemption fee cap`, send `redeemFunded` with an `amount` that selects one coin.
3. Settle it.
4. Tell the issuer the redemption's txid, and send it the redemption and the redeemed transaction. The issuer needs both for the reissue link.

**Force-redeem (the issuer).**
1. Find the voucher's current transaction. Refer to V-S4.
2. Wait until the chain height is at least `expiry`.
3. Send `{'action': 'forceRedeem', 'token': txid, 'tokenRaw': rawHex}` with `amount: 0`. Leave out `tokenRaw` when the issuer's wallet has the transaction.
4. Settle it.

**Reissue (the issuer).**
1. Make sure that the redemption or force-redemption is settled and that its output 0 is spendable in the issuer's wallet.
2. Send `{'action': 'reissue', 'ended': endTxid, 'issuer': issuerPkh, 'maxHops': n, 'expiry': height, 'feeCap': sats}` with `amount: 0`. Use `endedRaw` instead of `ended` when the wallet does not have the transaction.
3. Settle it. Calculate the successor's attestation.
4. Make the link with `plugin.link(endRaw, redeemedRaw)`. `redeemedRaw` is the transaction whose voucher the redemption spent. The link carries that voucher's terms.

**Receive.**
1. Call `LtVnftReceive.check(plugin, beef, ownerAddress, anchorTx, links)`.
2. It returns an `FnftHolding`. Show `holding.value` (the fuel), `holding.tx.hopsLeft` and `holding.tx.terms.expiry` before a person accepts the voucher.

## 6. Security rules

All rules in `SECURITY.md` and `FNFT.md` apply, except F-S3: a holder cannot take the fuel. These rules are added.

**V-S1: The fuel is the issuer's.**
- A holder can only move the voucher or redeem it to the issuer. Show the fuel as the voucher's value, not as the holder's.

**V-S2: The issuer cannot take a voucher before the expiry.**
- The script refuses a force-redemption whose nLockTime is less than `expiry`.
- The non-final sequence makes the network enforce the nLockTime. A node does not mine it before that height.
- The holder's own transfer or redemption replaces an early force-redemption. This was tested on a regtest node.

**V-S3: After the expiry, the holder can lose the voucher at any time.**
- A transfer after the expiry is permitted. The payee takes the risk.
- **WARNING:** Do not accept or pay for a voucher whose `expiry` has passed or is near. Show the expiry before a person accepts it.

**V-S4: The issuer's wallet does not follow the voucher.**
- Holders do not send their transfers to the issuer. To force a redemption, the issuer needs the voucher's current transaction.
- The host must get it. One method: follow the spends from the issuance outpoint with a "spent by" query for each output 0 (one query for each hop, at most `maxHops`). This is not a scan of the chain.
- The plugin checks that `tokenRaw` has the txid `token`, and runs the force-redemption through the token's script.

**V-S5: Settle a force-redemption only after the expiry.** An early one is not mined later. It waits in the node's non-final pool, and only a spend with the same inputs replaces it (tstokenlib decision 9.15).
- ARC or a node can refuse a non-final transaction, or keep it unmined. libspiffy then keeps the payment pending.

**V-S6: The redemption fee is capped.**
- A holder's redemption pays the issuer at least the fuel minus `feeCap`. A higher fee needs a wallet coin (`redeemFunded`).

## 7. How libspiffy handles a force-redemption

- The token output is not in the issuer's wallet. libspiffy does not hold it and does not refuse it: it skips a plugin input that the wallet does not have (`payment_coordinator_actor.dart`).
- The plugin signs with the key of `redeemTo`, through `keyFor`. A wallet that does not have this key gets the error `holds no key`.
- The holder's wallet sees the token spent when the network has the force-redemption.

Status: the issuer-in-another-wallet case is TESTED with stand-in wallets (`lt_vnft_plugin_test.dart`). In `libspiffy_vnft_wallet_test.dart`, one wallet is both issuer and holder.

## 8. Edge cases

| ID | Condition | What happens | Correct action | Test |
|---|---|---|---|---|
| E-V1 | A transfer when no hops are left. | `the voucher has made its <n> transfers: it can only be redeemed` | Redeem it. | `lt_vnft_plugin_test.dart` |
| E-V2 | `end` on a voucher. | `unknown action end` | Redeem it. | `lt_vnft_plugin_test.dart` |
| E-V3 | The redemption fee is more than `feeCap`. | `the fee <n> takes more than the redemption fee cap <c> from the token: add a funding coin` | Use `redeemFunded`. | `lt_vnft_plugin_test.dart` |
| E-V4 | `forceRedeem` with a `lockHeight` less than `expiry`. | `the token refuses the spend of <outpoint>` | Leave out `lockHeight`. | `lt_vnft_plugin_test.dart` |
| E-V5 | `forceRedeem` and the wallet does not have the voucher's transaction. | `the wallet does not hold transaction <txid>` | Give `tokenRaw`. Refer to V-S4. | `lt_vnft_plugin_test.dart` |
| E-V6 | `tokenRaw` is not the transaction `token`. | `tokenRaw is not transaction <txid>` | Give the correct transaction. | none |
| E-V7 | `forceRedeem` from a wallet without the `redeemTo` key. | `Wallet holds no key with public key hash <hash>` | Use the issuer's wallet. | `lt_vnft_plugin_test.dart` |
| E-V8 | `forceRedeem` settled before the expiry. | Not mined, also not after the expiry: it waits in the node's non-final pool (up to 672 hours). The holder's one-input spend (transfer, redeem) replaces it. The payment stays pending. | Settle only after the expiry (V-S5). |
| E-V12 | A holder's `topup` or `redeemFunded` refused with `txn-mempool-conflict` | An early force-redemption waits at that node. It blocks a spend with other inputs. | Use `transfer` or `redeem` (one input). | tstokenlib `lt_vnft_localnet_test.dart` |
| E-V9 | The voucher is moved after the issuer built its force-redemption. | The network refuses the force-redemption: its input is spent. | Get the new transaction and build again. | none |
| E-V10 | `maxHops` is 0 or more than 255, or `expiry` is 500,000,000 or more. | `maxHops is 1 to 255` or `expiry is a block height below 500,000,000` | Give valid terms. | `lt_vnft_plugin_test.dart` |
| E-V11 | `reissue` and output 0 of `ended` is not a key of this wallet. | `Wallet holds no key with public key hash <hash>` | Reissue from the issuer's wallet. | none |

## 9. Presets

Two uses of the terms. They need no other code.

| Preset | Terms | What it is |
|---|---|---|
| Badge | `maxHops: 1` | The issuer's distribution is the only transfer. The holder cannot pass it on. The holder can only redeem it to the issuer. Use it for a membership or a licence. The issuer can take it back after `expiry`. |
| Take-back at will | `expiry` at or below the current height | The issuer can force the redemption at any time. A non-final transaction whose nLockTime has passed is mined at once (tested on a regtest node, tstokenlib decision 9.9). The holder must trust the issuer completely. |

**CAUTION:** Show a Take-back-at-will voucher as one that the issuer can take back now. Run `CheckForeignSpendsCommand` (`SWAP.md`, section 3) before you show it as held.
