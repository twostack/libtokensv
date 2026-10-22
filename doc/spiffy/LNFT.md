> Copied from lt-spiffy-plugin (commit 033d847) on 2026-10-22 with the lineage plugins. Here the plugins are in `lib/src/spiffy/` and their tests in `test/spiffy/`; the `test/lt_*_localnet_test.dart` suites named here are libtokensv's own regtest suites. `docs/INTEGRATION.md`, `docs/EDGE_CASES.md` and the other tstokenlib documents named here stay in those repositories.

# The Listed NFT plugin (`LtLnftPlugin`)

This document tells how to list a Listed NFT for sale, how to buy one, and what the seller's wallet must do. Read `docs/INTEGRATION.md`, `SECURITY.md` and `SWAP.md` first. The language follows ASD-STE100.

The token specification is `../lt/LT_LNFT_WALLET_INTEGRATION.md`. The decision is 9.14 in `../tstokenlib/docs/WITNESS_LINEAGE_RESEARCH.md`.

## 1. What it is

The Listed NFT (`TSL1_LT_LNFT`) is the covenant NFT with a price in its header. When the price is not zero, any person can buy the token for that price. The owner does not sign the purchase and does not know about it before it occurs.

- `LtLnftPlugin` has all the actions of `LtNftPlugin` (`issue`, `transfer`, `end`, `reissue`, the swap), and `list`, `withdraw` and `buy`.
- The code is different from the covenant NFT's code. A covenant NFT cannot become a Listed NFT. Issue a Listed NFT to sell it this way.
- Each output's metadata has `price`. Zero means not listed.

Status: TESTED.
- `test/lt_lnft_plugin_test.dart` uses stand-in wallets.
- `test/libspiffy_sale_wallet_test.dart` lists and buys between two real libspiffy wallets.
- tstokenlib's `test/lt_lnft_localnet_test.dart` mines a purchase at hop 3 and at hop 21 on a regtest node, and a purchase sent with a withdrawal.

## 2. Actions

| Action | Who | Params | Funding coins | Result |
|---|---|---|---|---|
| `list` | The owner | `token` (txid), `price` | 1 | A transfer to the owner's own key, listed at `price` |
| `withdraw` | The owner | `token` (txid) | 1 | A transfer to the owner's own key, not listed |
| `buy` | Any person | `listingTx` (hex), `coin` (`txid:vout`), `maxPrice`, `anchorTx` (hex), `links` (optional), `newOwner` (optional) | 0 | The purchase |

To change the price, send `list` again. A `transfer` also removes the listing from the new output.

## 3. Procedures

### 3.1 List a token

1. Send `list` with the token's txid and the price.
2. Settle the transfer.
3. Publish the listing transaction, the anchor transaction and the links. A buyer needs all three.

### 3.2 Buy a token

1. Get the listing transaction, the anchor transaction and the links.
2. Get a coin of exactly the price plus the fee. Its funding transaction must be in the wallet. The purchase has no change output.
3. Send `buy` with `amount: 0`. Before it signs, the plugin:
   - runs the payee's check on the token (`LtReceive.check` with `anchorTx` and `links`);
   - refuses a token that is not listed, or listed at more than `maxPrice`;
   - refuses a token that this wallet holds;
   - refuses a coin that leaves no fee over the price.
4. Settle the purchase. The token is output 1, owned by `newOwner` (the coin's key by default), and not listed.

### 3.3 Find out that a listing was bought

The seller's wallet does not sign the purchase. Thus libspiffy does not know about it.

1. Send `CheckForeignSpendsCommand` for the listed output (`SWAP.md`, section 3).
2. When the output is spent by a proven transaction, import that transaction. Its output 0 is the payment to the owner's key.

## 4. Security rules

- **LN-S1: A listing is an offer to every person.** When the listing is on the network, the owner cannot reliably withdraw it. A `withdraw` and a purchase of the same output conflict. The network keeps the one that it sees first. On a regtest node, the purchase was kept and the withdrawal refused (`txn-mempool-conflict`).
- **LN-S2: Always give `maxPrice`.** The plugin compares it with the listed price. The price in the listing transaction is the price that the buyer pays.
- **LN-S3: Check the output before you buy.** The host must check that the listed output is unspent on the network. A purchase of a spent output is refused by the network, and the coin stays unspent.
- **LN-S4: Do not list and swap the same output.** The network keeps the transaction that it sees first.
- **LN-S5: An issuance cannot be bought.** The script refuses a purchase of an issuance's output. The issuer distributes the token first.
- **LN-S6: Nobody can redirect a purchase.** The buyer's signature covers every output.

## 5. Edge cases

| ID | Condition | What happens | Correct action |
|---|---|---|---|
| E-LN1 | `buy` on a token that is not listed | `the token is not listed` | Ask the owner to list it. |
| E-LN2 | The listed price is more than `maxPrice` | `the token is listed at <n>, over the maximum <m>` | Decide again. |
| E-LN3 | `buy` on a token this wallet holds | `this wallet holds the token: withdraw the listing instead` | Use `withdraw`. |
| E-LN4 | The coin is not more than the price | `the coin (<n> sats) leaves no fee over the price <m>` | Get a coin of the price plus the fee. |
| E-LN5 | `buy` without `anchorTx` | `a buyer checks the token first: pass anchorTx` | Get the anchor from the listing's publisher. |
| E-LN6 | `list` without a price, or with zero | `list takes a price of at least 1 sat` | Give the price. Use `withdraw` to remove a listing. |
| E-LN7 | Another buyer's purchase is seen first | The network refuses this purchase. The coin stays unspent. | Do nothing. |

## 6. Sizes

On a regtest node, all mined: a listing 6,829 B, a purchase 7,118 B, the buyer's next transfer 7,617 B, a purchase at hop 21 14,209 B. The record grows 394 B for each transfer (the covenant NFT: 386 B).
