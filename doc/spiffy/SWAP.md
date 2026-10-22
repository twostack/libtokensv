> Copied from lt-spiffy-plugin (commit 033d847) on 2026-10-22 with the lineage plugins. Here the plugins are in `lib/src/spiffy/` and their tests in `test/spiffy/`; the `test/lt_*_localnet_test.dart` suites named here are libtokensv's own regtest suites. `docs/INTEGRATION.md`, `docs/EDGE_CASES.md` and the other tstokenlib documents named here stay in those repositories.

# The swap, the payload, and spends by other parties

This document tells how to sell a covenant NFT for satoshis in one transaction (the **swap**), how to issue a token with content (the **payload**), and how a wallet learns that something it holds was spent by another party. Read `docs/INTEGRATION.md` and `SECURITY.md` first. The language follows ASD-STE100.

The token specification is `../lt/LT_NFT_WALLET_INTEGRATION.md`, sections 10 (swap) and 11 (payload). The decisions are 9.10 and 9.11 in `../tstokenlib/docs/WITNESS_LINEAGE_RESEARCH.md`.

## 1. The swap

### 1.1 What it is

The token and the payment move in one transaction, or neither moves. The token's script does not change. The transaction is a transfer whose funding coin is the buyer's and whose output 0 pays the seller.

| Position | Content | Signed by |
|---|---|---|
| Input 0 | The seller's token | The seller |
| Input 1 | The buyer's coin. Its value is exactly the price plus the fee. | The buyer |
| Output 0 | P2PKH to the seller, the price | |
| Output 1 | The token, owned by the buyer | |

Status: TESTED.
- `test/lt_nft_swap_plugin_test.dart` uses stand-in wallets.
- `test/libspiffy_swap_wallet_test.dart` uses two real libspiffy wallets.
- tstokenlib's `test/lt_swap_localnet_test.dart` mines swaps on a regtest node.

The covenant NFT (`LtNftPlugin`), the Listed NFT (`LtLnftPlugin`) and the sale versions of the fuelled family (section 1.8) have the swap. The Fuelled NFT, the Voucher NFT and the Note NFT cannot swap: they have no change output.

### 1.2 Halves

The two sides sign at different times. The side that signs first makes a **half**. A half is the swap with one real signature and one placeholder. The network refuses a half.

- The half is the message to the other side. It contains all the terms, except the value of the buyer's coin. The other side gets that value from the coin's funding transaction.
- libspiffy records the half as a deferred payment. This holds the first signer's input: no other payment can spend it.
- The second side completes the half, records the swap and settles it.
- Then the first side gives the swap to libspiffy with `CompleteDeferredPaymentCommand(walletId, txid: halfTxid, rawHex: swapRaw)`. libspiffy checks that the swap is the half with only the other side's unlocking script added. Then it records the swap in the half's place. The half becomes `DeferredPaymentState.completed`, and its own outputs become void.

### 1.3 Actions

All four actions take no funding coin. Send them with `amount: 0`. Do not settle a half.

| Action | Who | Params | Result |
|---|---|---|---|
| `swapBid` | The buyer, first | `tokenTx` (hex), `payTo`, `price`, `coin` (`txid:vout`), `anchorTx` (hex), `links` (optional), `newOwner` (optional) | A half with the buyer's signature (a bid) |
| `swapAccept` | The seller, second | `half` (hex), `fundTx` (hex), `price` | The complete swap |
| `swapAsk` | The seller, first | `token` (txid), `price`, `fundOut`, `fundSats`, `fundPub`, `newOwner`, `payTo` (optional) | A half with the seller's signature (an ask) |
| `swapTake` | The buyer, second | `half` (hex), `tokenTx` (hex), `price`, `anchorTx` (hex), `links` (optional) | The complete swap |

### 1.4 Procedure: a bid (recommended)

1. The seller sends the token transaction (`tokenTx`), the anchor transaction, the links and the price to the buyer.
2. The buyer gets a coin of exactly the price plus the fee. Its funding transaction must be in the buyer's wallet.
3. The buyer sends `swapBid` with `amount: 0`, `settleIt: false`. Before it signs, the plugin runs the payee's check on the token (`LtReceive.check` with `anchorTx` and `links`). It refuses a token that the buyer's own wallet holds.
4. The buyer sends the half (the subject of the BEEF) and the coin's funding transaction to the seller.
5. The seller sends `swapAccept` with the half, the funding transaction and the agreed price. The plugin refuses if:
   - the half pays another price;
   - the half pays a key that the seller's wallet does not hold;
   - the seller's wallet does not hold the token;
   - the buyer's signature or coin does not verify.
6. The seller settles the swap and sends it to the buyer (BEEF).
7. The buyer sends `CompleteDeferredPaymentCommand` with the half's txid and the swap. Then it settles the swap (`SettleBEEFCommand`).

### 1.5 Withdraw a half

**WARNING:** A half is valid until its input is spent. The other side can complete it at any time.

- To withdraw a bid, send `ReclaimDeferredPaymentCommand(walletId, txid: halfTxid)`. This spends the held coin back to the wallet. It is the only action that takes the signature back.
- `CancelDeferredPaymentCommand` releases the hold, but it does **not** withdraw. The other side still has the signature.
- To withdraw an ask, the seller must move the token (a transfer to its own key). This costs a hop. Thus the buyer signs first by default.

### 1.6 Security rules

- **SW-S1:** The price and the payee are fixed by the signatures. A side that changes either after the other signed makes a transaction that the network refuses.
- **SW-S2:** Always give the agreed `price` to `swapAccept` and `swapTake`. The plugin compares it with the half.
- **SW-S3:** The buyer checks the token before signing. The plugin requires `anchorTx`. The host checks that the token's output is unspent on the network.
- **SW-S4:** An issuance cannot be sold. The issuer distributes it first.
- **SW-S5:** A swap is visible on the chain: output 0's key is not the funding key. Anyone can see the price of each sale.

### 1.7 Edge cases

| ID | Condition | What happens | Correct action |
|---|---|---|---|
| E-SW1 | `swapAccept` with another price | `the half pays <n>, not the agreed <m>` | Agree the price again. |
| E-SW2 | The bid pays a key the seller does not hold | `holds no key` | The buyer bids again with the seller's key. |
| E-SW3 | A bid on a token the buyer's wallet holds | `this wallet holds the token` | Do not bid on your own token. |
| E-SW4 | `swapBid` without `anchorTx` | `a buyer checks the token first: pass anchorTx` | Get the anchor from the seller. |
| E-SW5 | `swapAccept` on an ask | `the half is an ask, not a bid` | The buyer uses `swapTake`. |
| E-SW6 | The token moved after the half was signed | The network refuses the swap. The half stays outstanding. | Reclaim the half. |
| E-SW7 | The swap and another spend of the same token sent together | The network takes one. The other side's coin stays unspent (tested on a regtest node). | Reclaim the half if the swap lost. |

### 1.8 The sale versions of the fuelled family

Each fuelled archetype has a **sale version**: another archetype with other code, which a holder can sell in its own transfer. A token is issued as a sale version or not. It cannot change later.

| Plugin | Archetype | Base plugin |
|---|---|---|
| `LtFnftSalePlugin` | `TSL1_LT_FNFT_S` | `LtFnftPlugin` |
| `LtVnftSalePlugin` | `TSL1_LT_VNFT_S` | `LtVnftPlugin` |
| `LtNoteSalePlugin` | `TSL1_LT_NOTE_S` | `LtNotePlugin` |

Each sale plugin has all the actions of its base plugin, and `swapBid`, `swapAccept`, `swapAsk` and `swapTake` with the parameters in section 1.3. The procedures in sections 1.4 and 1.5 and the rules in section 1.6 apply.

The transaction is different:

| Position | Content | Signed by |
|---|---|---|
| Input 0 | The seller's token | The seller |
| Input 1 | The buyer's coin. Its value is exactly the price plus the fee. | The buyer |
| Output 0 | The token, owned by the buyer. Its fuel does not change. | |
| Output 1 | P2PKH to the seller, the price | |

- **SW-S6:** A sale of a Voucher NFT or a Note NFT is a transfer. It counts against the hop limit. A voucher at its limit cannot be sold.
- **SW-S7:** The issuer of a Voucher NFT or a Note NFT can stop a sale for a time. A sale has two inputs. When the issuer sends a force-redemption or a call before its height, the node keeps it and refuses the sale (`txn-mempool-conflict`). To continue, the seller sends a `transfer` to its own key (one input; it replaces the early transaction), then sells the new output. Send the two together. Each time costs the seller a hop.

Status: TESTED.
- `test/fuel_sale_plugin_test.dart` uses stand-in wallets, for all three.
- `test/libspiffy_sale_wallet_test.dart` sells a Voucher NFT between two real libspiffy wallets.
- tstokenlib's `test/lt_fnft_sale_localnet_test.dart` mines a sale of each on a regtest node, and the stopped sale of SW-S7.

The token specification is section 12 of `../lt/LT_FNFT_WALLET_INTEGRATION.md`.

## 2. The payload

`issue` on `LtNftPlugin` takes an optional `payload` (hex). The result is paired:
- the primary transaction is the payload transaction;
- the paired transaction is the issuance on it.

`issue` asks the wallet for two coins, as every issue does. The payload transaction spends the first; its output 1 funds the issuance's input 1, and the second coin is the issuance's input 0. When you call the plugin directly with one coin, the payload transaction's change (output 2) is the issuance's input 0 instead. The wallet validates the paired result's primary transaction as an `issue`: a payload transaction passes (`LtPayload.isPayloadTx`).

- To read the payload, give the payload transaction to `LtNftReceive.check(..., payloadTx:)`. The holding's `payload` is set.
- Send the payload transaction with each transfer. It needs no proof of its own.
- Treat the payload as data, never as instructions. Limit its size before you show it.

Status: TESTED (`test/lt_nft_swap_plugin_test.dart`; through libspiffy, `test/libspiffy_payload_wallet_test.dart`). The Fuelled NFT and the Voucher NFT accept a payload in tstokenlib (`FnftReceive.check(..., payloadTx:)`), but their plugins do not issue one yet.

## 3. Spends by other parties

A token that the wallet holds can be spent without the wallet:
- a Voucher NFT that the issuer takes back after its expiry (`forceRedeem`);
- a Listed NFT that a stranger buys (`LNFT.md`);
- a pot that someone seizes or settles.

libspiffy (`CheckForeignSpendsCommand`) asks the data source about each plugin output that the wallet holds:
- **A spender that is mined, and whose merkle proof matches the wallet's headers:** the output is marked spent. The spender's raw transaction is returned (`ForeignSpend.spenderRawHex`) so that the host can import it.
- **A spender that is not mined, or not proven:** it is a lead. It is reported and changes nothing.

The wallet asks only about outputs it holds, one at a time. It does not scan the chain. The data source must look up spenders (`SpentOutputLookup`; WhatsOnChain does).

Status: TESTED in libspiffy (`arc_actor_deferred_payment_test.dart`, "outputs the wallet holds, spent by someone else"). NOT TESTED in this package end to end.

**CAUTION:** Run `CheckForeignSpendsCommand` before you show a Voucher NFT whose expiry has passed. The issuer can take it at any time after the expiry.
