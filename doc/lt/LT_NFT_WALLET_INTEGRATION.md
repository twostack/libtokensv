> Copied from tstokenlib (commit 5be148a) on 2026-10-21. Relative links to other tstokenlib documents (`../WITNESS_LINEAGE_RESEARCH.md`, `../RUGGERBOT_TOKENS_PLAN.md`, `../lt-spiffy-plugin`) point into that repository, not this one.

# Covenant NFT (TSL1_LT_NFT): wallet integration

For wallet integrators. This document says what a wallet stores for a covenant NFT, what it sends and checks when the token changes hands, and where BEEF fits. tstokenlib does the token's part from raw transaction bytes. The wallet does the rest: BEEF, SPV against its headers, broadcasting, and following the payment to its block. tstokenlib has no BEEF code and depends on no wallet, so nothing is duplicated and nothing depends in a circle.

Status: built and tested in tstokenlib (`test/lt_nft_test.dart`), and mined on a regtest node (`test/lt_nft_localnet_test.dart`). The message fields below are a draft until a wallet carries them.

## 1. The token on chain

A token output holds 1 satoshi and is locked by

```
PUSH(header, 172 bytes) OP_CODESEPARATOR code
```

`code` is fixed for the archetype: 2,231 bytes, SHA-256 `d51ec5b4f30472584a4c39e883823e3ce6a58494ae671313e1e953ffbadec458`. A wallet recognises a token output by those bytes after the separator, and nothing else.

Header fields (`LtLayout.nft`):

| offset | bytes | field |
|---|---|---|
| 0 | 32 | token id: the issuance's txid; all zero in the issuance itself |
| 32 | 20 | issuer: HASH160 of the issuer's Rabin key |
| 52 | 20 | owner: the HASH160 a spend must be signed by |
| 72 | 8 | change amount, LE |
| 80 | 20 | change HASH160 |
| 100 | 36 | input 0's outpoint |
| 136 | 36 | the funding input's outpoint |

Every token transaction has the same shape:

- version 1 (not higher: see the header of `lt_script_gen.dart`);
- locktime 0, and every sequence `0xffffffff`;
- input 0: the token;
- input 1: funding, P2PKH;
- output 0: change, P2PKH;
- output 1: the token.

The issuance is the exception: its input 0 is an ordinary P2PKH coin.

**Two ways to spend a token output.**

- **Normal path.** The unlock is `PUSH(preimage) PUSH(sig) PUSH(pub) PUSH(C)`. The script rebuilds this transaction and its parent and fixes the outputs. That is a transfer.
- **Cheap path.** The unlock is `PUSH(sig) PUSH(pub)`, the owner's signature only. It ends the token: no later spend accepts the result as a token. A wallet must never select a token output as an ordinary coin. Signing it like P2PKH destroys the token.

## 2. What a wallet stores

A holding is one outpoint, `(T, 1)`, where T is the transaction that paid the token to the wallet. The wallet stores:

- **T's raw bytes.** Everything else derives from them. `LtBuilder.fromRaw(raw)` reads the header, signatures and record back, and the record (Rec(T)) is what the next transfer must carry.
- **The links**, if the token was ever reissued (section 6), as the bytes `LtLinks.encode` writes.
- **The identity anchor**, cached by its txid, which the record names.

The token id, issuer and owner come from the header, so a plugin can fill its UTXO metadata from the locking script alone. No other state exists. Neither the record nor any proof is kept apart from T.

## 3. Sending

1. **Get the recipient's address first.** The owner is written into the header, so the transfer cannot be built until the recipient has given a HASH160. This is the offer/accept exchange that overnode's `/overnode/token-transfer/1.0.0` already has. No witness funding is needed: the covenant NFT has no witness transaction.
2. **Build the transfer** with `LtBuilder.transfer(from: held.tx, k: 1, ownerKey, fund, outs: [LtOut(recipientPkh)], satsPerKb)`. Keys are `LtKey`s:
   - `LtPrivateKey` (or `svPrivateKey.lt`) signs in process.
   - A wallet that keeps its keys elsewhere implements `LtKey` itself. `sign(LtSigning)` gets the transaction without unlocking scripts, the input index, the script code and the amount, as a transaction signer expects. It also gets the BIP143 preimage they make. `test/lt_nft_test.dart` checks that a key signing through dartsv's own `TransactionSigner` builds byte-identical transactions.

   Input 0 is signed over:
   - SIGHASH_ALL | FORKID;
   - as scriptCode, the code after the separator (not the whole locking script);
   - an amount of 1 sat;
   - the key whose HASH160 is the header's owner.

   The owner is in the header, before the separator, so a wallet can't find the key from the script code. The integrator names it: libspiffy 4.0.0's `PluginTransactionRequest.keyFor(pubkeyHash)`.
3. **Send the transfer message (section 4).** Whether the sender broadcasts first is the wallet's ordinary rule for payments. The payee still accepts only what the network holds (section 5, step 4).

## 4. The transfer message

| field | what | when |
|---|---|---|
| `beef` | An Atomic BEEF (BRC-95) whose subject is the transfer T | always |
| `links` | `LtLinks.encode(links)`, newest first | when the token was reissued |
| `anchor` | The issuer's identity anchor transaction, as an Atomic BEEF with its merkle proof | unless the payee already holds it |
| `attestation` | The issuer's 326-byte attestation | only when T is an issuance, which issuers do not send (section 7) |

**What `beef` must hold.** It holds T, and for every input of T either the parent with a BUMP or the parent with its own ancestry, down to transactions that carry a BUMP: the usual BRC-62 rule. Either inner version works.

- V1 (BRC-62, `0100BEEF`) or V2 (BRC-96, `0200BEEF`); libspiffy reads both and writes V1.
- T must be a full transaction: format 0 or 1 in V2, never a txid-only entry (format 2). The payee's token check reads T's bytes.
- Don't send txid-only entries for ancestors either. libspiffy refuses them, and a payee that has never seen the transaction cannot use one.
- The anchor is not an ancestor of T. BRC-95 allows only the subject and its ancestors, and libspiffy's `Brc95.wrap` refuses anything else, so the anchor travels as its own Atomic BEEF.

**The links need no proofs of their own.** A link is two transactions:
- E, the end of the predecessor;
- G, the transaction whose token output E spent, given by its record.

G is E's parent, E is the parent of the reissue's issuance, and that issuance is an ancestor of T. So every link transaction is an ancestor of T. When T's ancestry is anchored in mined blocks and the network takes T, the link transactions are mined too. The payee checks them by hash: E's txid against the issuance's input, and G rebuilt from its record against E's input (section 6).

**Sizes, measured on localnet** (transactions at 1 sat/kB):

| what | bytes |
|---|---|
| T at hop n (two inputs, two outputs) | 6,038 + 386·(n−1); hop 20: 13,371 |
| one link after 20 hops and the redemption | 9,165 |
| T's parent, a token transaction | T − 386 |

The BEEF holds T, its parent (with a BUMP once mined) and the funding coin's parent. That makes it about twice T. This last figure is computed from the sizes above, not measured.

## 5. Receiving

In this order:

1. **Read the BEEF (wallet).** Take the subject's raw bytes. Check the proofs against the wallet's headers. That says the funding history is in real blocks, not that T will be mined.
2. **Check the token (tstokenlib).** Call `LtReceive.check(b, raw: T, ownerPkh: the address given at accept, anchorTx, links, runScript: true)`. It returns an `LtHolding` or throws `LtRefused` with the reason:
   - T is exactly the transaction its record rebuilds, under this code, and output 1 is paid to `ownerPkh`.
   - Input 0 spends output 1 of the transaction T's record rebuilds, on the normal path, and the parent is of the same token. With `runScript`, the token's script is run on that spend here, before the network sees it: 30 ms at hop 3, 148 ms at hop 20 on a laptop.
   - The issuer attestation that the record ends with verifies against the anchor. This uses the same checks as `LtIdentity.verify`: the anchor's AIP signature, its txid and ED25519 key, the Rabin key it names, and the Rabin signature.
   - Each link connects the token to the one before it (section 6). The holding's `originId` is the first token of the chain.
3. **Store** T's raw bytes, the links and the origin. Show the token as pending.
4. **Have the network take it (wallet).** Submit T to ARC and follow it. Count the token held when ARC reports `SEEN_ON_NETWORK` or `MINED`, as for any payment. Two transfers of the same output are a double spend that only the network settles.

What the token check needs: T's bytes only. The parent is rebuilt from the record inside T, so the payee needs no other raw transaction for the token, though the BEEF carries the parent for SPV.

## 6. Redeem and reissue

A token whose record has grown is sent back to the issuer and reissued. Recorded as decision 9.5 in `WITNESS_LINEAGE_RESEARCH.md`. The steps:

1. The holder transfers the token to the issuer's wallet key (G).
2. The issuer ends it with `LtBuilder.end`, which pays the change at output 0 (E).
3. The issuer issues the successor on that output with `LtBuilder.reissue(ended: E, …)` (R).

The chain allows at most one successor per token. The payee's check of a link (`LtSuccession.verify`) rejects any successor of a forged copy.

**Links.** Each holder of a reissued token passes `LtLink(E, Rec(G))` on with it, newest first. The payee walks them back to the origin. A transfer without links is valid; the payee then sees the current token id as the origin.

## 7. Issuers

**Issue to yourself, then transfer (decided).** Issuance and distribution are separate steps. An issuance is a supply event on the issuer's own books; distribution is a transfer like any other. So an issuer issues, and reissues, to its own key, then transfers to the holder. Every holding is then a transfer:
- the issuer's attestation travels inside it;
- miners check the attestation at the issuer's own first transfer, so a bad attestation fails with the issuer, never with a customer.

The cost is one hop: about 6 KB, 7 sats at 1 sat/kB. `LtReceive.check` still accepts an issuance with its attestation sent alongside, but issuers don't send one.

**Keep the end's output 0 for the reissue.** Spending it elsewhere leaves the token with no successor ever. Spending it into an unrelated issuance makes that issuance the successor. The chain cannot tell intent.

## 8. The library API

| call | does |
|---|---|
| `LtBuilder.transfer`, `issue`, `end`, `reissue` | build the transactions |
| `LtBuilder.fromRaw(raw)` | a token transaction from its bytes, refused unless canonical |
| `LtBuilder.fromRec(rec)` | a token transaction rebuilt from its record |
| `LtReceive.check(...)` | the payee's token check (section 5, step 2) |
| `LtSuccession.verify(...)` | one link |
| `LtIdentity.verify(t, anchorTx)` | the issuer, against the identity anchor |
| `LtLinks.encode`, `LtLinks.decode` | the links' bytes |
| `LtKey`, `LtPrivateKey`, `LtSigning` | the keys transactions are signed with, and one input to sign |
| `LtGivenSignature(pub, sig)` | a key whose signature was made elsewhere (section 10) |
| `LtSwapTerms`, `LtSwap` | the swap's terms, the digest each side signs, assembly, the checks (section 10) |
| `LtPayload.build`, `LtPayload.of` | the payload transaction, and the payload a token carries (section 11) |

## 9. Open

- **The message's envelope.** It should be independent of the transport. It will be settled upstream of tstokenlib, with spiffyvault as the first wallet.
- **Txid-only ancestors.** A token transaction's parent can be rebuilt from the record in its child, so a BEEF V2 could send token ancestors as txid only and roughly halve its size. Readers that refuse format 2, libspiffy among them, would then refuse the transfer. Not recommended unless both sides agree.

## 10. Selling: the swap

A token is sold for satoshis in its own transfer, signed by both sides. No script change is involved: the script writes output 0 from the child header's `changePkh` and `changeAmt` and never relates them to the funding input (decision 9.10 in `WITNESS_LINEAGE_RESEARCH.md`).

| Position | Content | Signed by |
|---|---|---|
| Input 0 | the seller's token, normal path | the seller |
| Input 1 | the buyer's P2PKH coin, worth exactly the price plus the fee | the buyer |
| Output 0 | P2PKH to the seller's `payTo`, the price | |
| Output 1 | the token, owned by the buyer | |

**The terms** (`LtSwapTerms`) fix every byte except the two signatures: the token transaction, `payTo`, `price`, the buyer's coin (outpoint, value, public key), and the new owner. The fee is the coin's value less the price. `encode` and `decode` give version 1 bytes; the envelope that carries them is the wallet's.

**Signing.** Each side signs `LtSwap.signing(terms, input)`: the same digest whatever the other side has done, because no preimage covers an unlocking script. Either side may sign first. `LtSwap.assemble` builds the transaction from one real key and one `LtGivenSignature`.

**The checks.**
- The buyer, before signing a bid: `LtReceive.check` on the token transaction for the seller's key, the token's output unspent on the network (the wallet's chain service), and the agreed price and payee.
- The seller, before signing: `LtSwap.checkBid(terms, buyerSig, fundTx)`: the funding transaction is the one named, its output is P2PKH to the buyer's key with the stated value, and the buyer's signature verifies.
- Either side, on the complete transaction: `LtSwap.verify(terms, raw)`: both inputs verify (the token's script on input 0), output 0 pays the price to `payTo`, and the buyer owns the token.

**What the wallet must know.**
- **A signed half is an open option.** It stays valid until its input is spent. A buyer withdraws a bid only by spending the coin it names. A seller who signed first withdraws only by moving the token, a hop. So the buyer signs first by default.
- **Releasing a hold is not withdrawing.** A wallet that stops holding the bid's coin has not taken back the signature.
- **An issuance is not sold.** Its first spend carries the issuer's attestation; the issuer distributes it first (section 7).
- **The buyer gets no change.** Make a coin of exactly the price plus the fee first.

**Measured on localnet** (`test/lt_swap_localnet_test.dart`): a swap is the size of a transfer at the same hop (6,424 B at hop 2, 13,372 B at hop 20). A swap sent after the seller's own transfer of the same token was refused (`txn-mempool-conflict`), and the buyer's coin stayed unspent.

## 11. The payload

A token can carry content without a script change and without bytes per hop (decision 9.11). The **payload transaction** of a token is the transaction whose output 1 funds input 1 of the token's issuance; its output 0 is `OP_FALSE OP_RETURN <payload>`, one push. The token id is the issuance's txid, which commits to input 1's outpoint, which names the payload transaction, which commits to its outputs.

- **Build:** `LtPayload.build(coin, payload, fundSats)` gives the payload transaction and output 1 as a coin. Issue with that coin as `fund`.
- **Read:** `LtPayload.of(issuanceRaw, payloadTx)`, or `LtReceive.check(..., payloadTx:)`, which sets `holding.payload`. Without the payload transaction a token is valid and its payload is null.
- **Send:** a transfer message may carry the payload transaction's raw bytes. It needs no proof of its own: it is an ancestor of the issuance, which is in every record.
- **Reissue:** a successor's issuance has its own input 1, so it may carry the same payload, another, or none. Showing both the origin's and the current payload when they differ is the wallet's choice.
- **Do not** add an extra output to an NFT issuance instead: its first spend rebuilds a two-output transaction, so the token is stranded (`test/lt_swap_test.dart`, gate G2).
- Treat the payload as opaque bytes, never as instructions, and bound its size before reading it (`LtPayload.maxPayload` is 100,000 B).
