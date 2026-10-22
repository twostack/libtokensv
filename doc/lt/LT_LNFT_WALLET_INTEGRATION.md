> Copied from tstokenlib (commit 5be148a) on 2026-10-21. Relative links to other tstokenlib documents (`../WITNESS_LINEAGE_RESEARCH.md`, `../RUGGERBOT_TOKENS_PLAN.md`, `../lt-spiffy-plugin`) point into that repository, not this one.

# Listed NFT (TSL1_LT_LNFT): wallet integration

For wallet integrators. The Listed NFT is the covenant NFT with a price in its header. When the price is not zero, anyone may buy the token by paying it, without the owner's signature and without talking to the owner. This document gives only what differs from the covenant NFT. For everything else, read `LT_NFT_WALLET_INTEGRATION.md`, which applies unchanged: BEEF is the wallet's, the transfer message, the anchor, receiving, redeem and reissue, the swap, the payload.

Status: built and tested in tstokenlib (`test/lt_lnft_test.dart`), and mined on a regtest node (`test/lt_lnft_localnet_test.dart`). Proposed by ruggerbot (`TOKENS_TRADING_SET.md`, item 4). Recorded as decision 9.14 in `WITNESS_LINEAGE_RESEARCH.md`; adopted 2026-10-06.

## 1. What is different

| | Covenant NFT (`TSL1_LT_NFT`) | Listed NFT (`TSL1_LT_LNFT`) |
|---|---|---|
| Header | 172 B | 180 B: `price` after the owner |
| Who may spend the token | the owner | the owner; or anyone, by paying the price |
| Code / lock | 2,231 / 2,406 B | 2,417 / 2,600 B |
| Growth per transfer | 386 B | 394 B |
| Hop 21 (a purchase) | | 14,209 B |

The code is fixed: 2,417 bytes, SHA-256 `b43aeba4a194d9463ef6cc67c0552457c762fecbc5a838e338b2b115cccbc962`. A wallet recognises the token by those bytes after the separator. The builder is `LtBuilder(LtLayout.lnft, LtScriptGen.lnft.code().buffer)`.

Header fields (`LtLayout.lnft`):

| offset | bytes | field |
|---|---|---|
| 0 | 32 | token id: the issuance's txid; all zero in the issuance itself |
| 32 | 20 | issuer |
| 52 | 20 | owner |
| 72 | 8 | price, LE; zero: not for sale |
| 80 | 8 | change amount, LE |
| 88 | 20 | change HASH160 |
| 108 | 36 | input 0's outpoint |
| 144 | 36 | the funding input's outpoint |

`LtTx.price` reads the price of a token output; `LtTx.bought` says that a transaction is a purchase.

## 2. Listing and withdrawing

- **List:** the owner transfers the token, usually to itself, with `price:` set: `LtBuilder.transfer(from, k: 1, ownerKey, fund, outs: [LtOut(ownerPkh)], price: p)`. The new output is listed at `p`.
- **Change the price:** another transfer with another `price:`.
- **Withdraw:** a transfer with `price: 0` (the default). Any signed transfer of a listed token leaves the new output unlisted unless it sets a price.
- **An issuance cannot be listed for purchase.** The script refuses a purchase of the issuance's output; the issuer distributes it first.

Every listing, change and withdrawal is a hop: 394 B of growth and a funding coin.

## 3. Buying

A purchase spends the listed output with no signature:

| Position | Content | Signed by |
|---|---|---|
| Input 0 | the listed token, unlock `PUSH(pre) OP_0 OP_0 PUSH(C)` | nobody |
| Input 1 | the buyer's P2PKH coin | the buyer |
| Output 0 | P2PKH to the owner, at least the price | |
| Output 1 | the token, owned by the buyer, unlisted | |

Build it with `LtBuilder.buy(from: listingTx, fund: coin, newOwner: buyerPkh)`. The fee is everything the coin holds over the price. The buyer gets no change, so make a coin of exactly the price plus the fee first.

The script requires:
- the output is listed (its price is not zero) and is not the issuance's;
- output 0 pays this output's owner at least the price;
- the buyer's output is not listed.

The buyer's signature on input 1 covers every output, so nobody can redirect a purchase once it is sent. A purchase's record keeps fixed-width slots: an empty signature and a zero key, which the next transfer's rebuild writes back as `OP_0 OP_0`.

**The buyer's checks before buying:**
- `LtReceive.check` on the listing transaction for the owner's key (lineage to the anchor);
- the listed output is unspent on the network (the wallet's chain service);
- `LtTx.price` is the price the buyer agreed to pay, and is not more than the buyer's maximum.

After the purchase is mined, the buyer holds `(purchase, 1)` as for any received token.

## 4. What the seller's wallet must know

- **A listing is an open offer to everyone.** Once a listing is on the network, the owner cannot reliably withdraw it. A withdrawal and a purchase of the same output conflict, and the network keeps the one it saw first. Measured on localnet: sent together, the purchase was mined and the withdrawal refused (`txn-mempool-conflict`).
- **The token leaves without the owner signing.** The wallet learns of a sale only by watching the listed outpoint. libspiffy's outpoint watch (`CheckForeignSpendsCommand`) reports a spend by a transaction the wallet did not make, and carries that transaction. The payment is output 0 of that transaction, P2PKH to the owner's key.
- **Never list an output you also offered in a swap.** Whichever transaction the network sees first wins.
- **The swap still works.** It is the signed path, and it ignores the price. The buyer's output is unlisted unless the swap sets a price.

## 5. Measured

On localnet, all mined (`test/lt_lnft_localnet_test.dart`): list 6,829 B; purchase 7,118 B; the buyer's next transfer 7,617 B; a purchase at hop 21 14,209 B, record 8,994 B.

## 6. libspiffy

`LtLnftPlugin` here has the covenant NFT's actions, and `list`, `withdraw` and `buy` (with `maxPrice`). Refer to `doc/spiffy/LNFT.md`.

## 7. Open

- A listing on the fuelled family. A purchase has no signer, and the fuelled family derives the parent's owner from the key that signed input 0. That needs another owner derivation; nothing asks for it (decision 9.13).
