> Copied from lt-spiffy-plugin (commit 033d847) on 2026-10-22 with the lineage plugins. Here the plugins are in `lib/src/spiffy/` and their tests in `test/spiffy/`; the `test/lt_*_localnet_test.dart` suites named here are libtokensv's own regtest suites. `docs/INTEGRATION.md`, `docs/EDGE_CASES.md` and the other tstokenlib documents named here stay in those repositories.

# The Fuelled NFT plugin (`LtFnftPlugin`)

This document tells how the Fuelled NFT is different from the covenant NFT, and gives its procedures, security rules and edge cases. Read `docs/INTEGRATION.md`, `SECURITY.md` and `docs/EDGE_CASES.md` first. Their rules apply to both archetypes, except where this document tells you otherwise. The language follows ASD-STE100.

The token specification for any wallet is `../lt/LT_FNFT_WALLET_INTEGRATION.md`.

## 1. What is different

The Fuelled NFT (`TSL1_LT_FNFT`) is a covenant NFT whose token output holds the satoshis that pay its fees. This value is the **fuel**.

| | Covenant NFT (`LtNftPlugin`) | Fuelled NFT (`LtFnftPlugin`) |
|---|---|---|
| Plugin id / script type | `tsl1_lt_nft` / `lt_nft` | `tsl1_lt_fnft` / `lt_fnft` |
| Token output | output 1, 1 satoshi | output 0, holds the fuel |
| Who pays the fee of a transfer | a wallet coin | the token's fuel |
| Wallet coins for `transfer` / `end` / `reissue` | 1 / 1 / 2 | **0 / 0 / 0** |
| Wallet coins for `issue` | 2 | 1 or 2 (they become the fuel) |
| Extra action | none | `topup`: a transfer that adds one wallet coin to the fuel |
| Change output | yes | no |
| Growth for each transfer | 386 B | 152 B. A top-up adds 143 B one time. |
| Metadata | owner, issuer, token id | the same, and `fuel` (satoshis) |

Status: TESTED. `test/lt_fnft_plugin_test.dart` runs the plugin with a stand-in wallet. `test/libspiffy_fnft_wallet_test.dart` runs it in a real libspiffy wallet with ARC stubbed. tstokenlib mines the full lifecycle on a regtest node (`test/lt_fnft_localnet_test.dart`).

## 2. Necessary versions

| Dependency | Necessary state | Why |
|---|---|---|
| `../tstokenlib` | `main` at `231e3a0` or later | `FnftBuilder`, `FnftReceive`, `FnftSuccession` |
| `../libspiffy` | `main` at `dc584a4` or later | libspiffy selects and reserves no coin for an action whose `requiredFundingUtxoCount` is 0 |

## 3. Actions

| `action` | Params | Wallet coins | Result |
|---|---|---|---|
| `issue` | `issuer` | 1 or 2. The payment's `amount` selects them. | The issuance. The coins, less the fee, are the fuel. The first coin's key owns it. |
| `transfer` | `token`, `to`, `attestation` (only for an issuance) | 0 | A transfer. The fee comes from the fuel. |
| `topup` | `token`, `to`, `attestation` (only for an issuance) | 1 | A transfer that adds the whole coin to the fuel. To refuel without a transfer, give `to` = the owner's own key hash. |
| `end` | `token`, `irreversible: true` | 0 | The burn. Everything the token holds, less the fee, goes to its owner. |
| `reissue` | `token`, `issuer` | 0 | The end (primary) and the successor (paired). The successor's fuel is the ended token's value. |

For an action with 0 wallet coins, send the payment with `amount: 0`. libspiffy then selects nothing, reserves nothing and spends no wallet coin. A wallet with no coins can still transfer, end or reissue a Fuelled NFT.

## 4. Procedures

Use the procedures in `docs/INTEGRATION.md` with these changes.

**Issue (INTEGRATION section 5).**
1. Send `{'action': 'issue', 'issuer': issuerPkh}`. Set `amount` to the fuel you want. libspiffy selects coins for it, and the plugin takes one or two of them.
2. Settle it. Calculate the attestation as for the covenant NFT.

**Transfer (INTEGRATION section 6).**
1. Send `{'action': 'transfer', 'token': txid, 'to': keyHash}` with `amount: 0`. For the first transfer of an issuance, also send `'attestation'`.
2. Settle it.

The token is output 0 of the new transaction, not output 1.

**Top up.**
1. Send `{'action': 'topup', 'token': txid, 'to': keyHash}` with an `amount` that selects one coin.
2. Settle it.

The whole coin goes into the fuel. There is no change.

**End (INTEGRATION section 10).**
1. Send `{'action': 'end', 'token': txid, 'irreversible': true}` with `amount: 0`.
2. Settle it.

The owner gets the fuel, less the fee, as an ordinary P2PKH coin.

**Reissue (INTEGRATION section 9).**
1. Send `{'action': 'reissue', 'token': txid, 'issuer': issuerPkh}` with `amount: 0`.
2. Settle the end. Then settle the successor.
3. Calculate the successor's attestation.
4. Make the link with `plugin.link(endRaw, redeemedRaw)`.

**Receive (INTEGRATION section 8).**
1. Call `LtFnftReceive.check(plugin, beef, ownerAddress, anchorTx, links)`.
2. It returns an `FnftHolding`. `holding.value` is the fuel that you receive.

## 5. Security rules

All rules in `SECURITY.md` apply. These rules are added.

**F-S1: The fuel is part of the token.**
- The fuel is not spendable balance. libspiffy keeps the token output out of payments and out of the balance.
- Show the fuel (`metadata['fuel']`, `holding.value`) with the token, not with the wallet's coins.

**F-S2: A payee receives the fuel that is left.**
- Each transfer takes its fee from the fuel.
- Show the fuel before a person accepts or pays for a token.

**F-S3: The satoshis are never stranded.**
- The owner can always end the token and take its fuel. The cheap path needs only the owner's signature and accepts any value.
- What can be stranded is the token itself, when nobody refuels it. Section 7, E-F1, tells what to do.

**F-S4: Value is conserved by the network, not by the script.**
- The covenant has no value rule. A transaction whose outputs are larger than its inputs is refused by consensus (`bad-txns-in-belowout`, tested on a regtest node).
- Whatever a transfer does not keep in the token goes to the miners.
- The plugin calculates the fee from the request's fee rate. Do not give the plugin a fee rate that is much higher than ARC's policy, or the fuel goes to the miners.

**F-S5: A top-up is permanent.**
- The coin's outpoint and signature stay in every later transaction: 143 B, one time.
- A reissue refuels without that cost. Prefer a reissue when the issuer is available.

## 6. How libspiffy handles a payment that takes no coin

libspiffy asks the plugin `requiredFundingUtxoCount(action)`. When that is 0:

- It does not stop the payment when the wallet has no coins.
- It selects no coin and reserves no coin.
- It gives the plugin a request with no funding coins. The plugin gets the token's key with `keyFor`.
- It records the payment with only the token output as its spent input. The token is held until the network has the payment.

Status: TESTED in libspiffy (`coordinator_aggregate_signing_test.dart`, "a plugin action that needs no funding coin ...") and in this package (`test/libspiffy_fnft_wallet_test.dart`).

## 7. Edge cases

| ID | Condition | What happens | Correct action | Test |
|---|---|---|---|---|
| E-F1 | The fuel does not pay the fee of a transfer. | The builder refuses: `the token would hold <n> sats: the fuel does not cover the fee`. | Top up (`topup`), or ask the issuer to reissue, or end the token and take the fuel. | `lt_fnft_plugin_test.dart` |
| E-F2 | `topup` without a wallet coin. | `topup needs 1 funding coin(s), got 0` | Give an `amount` that selects one coin. | none |
| E-F3 | `issue` with more than two coins selected. | `an issuance takes one or two coins of fuel, not <n>` | Give an `amount` that one or two coins cover. | none |
| E-F4 | A token is sent with very little fuel. | The payee cannot move it without a top-up. | Show the fuel before the payee accepts (F-S2). | none |
| E-F5 | The fee rate is much higher than ARC's policy. | The extra fee comes out of the fuel and goes to the miners. | Use ARC's policy rate; libspiffy gives it in the request. | none |
| E-F6 | A token's transfer claims more value than it had. | The network refuses it (`bad-txns-in-belowout`). | Do not build transactions by hand. Use the plugin. | tstokenlib `lt_fnft_localnet_test.dart` |
| E-F7 | A second transfer of a token already sent. | `The plugin transaction spends <txid>:0, which the wallet holds as <status>` | Do not retry. | `libspiffy_fnft_wallet_test.dart` |
| E-F8 | The token's output index. | Output 0, not output 1 as for the covenant NFT. | Use `:0` in outpoints for this archetype. | all tests |
