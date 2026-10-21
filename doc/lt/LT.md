> Copied from tstokenlib (commit 5be148a) with the TSL1_LT_FT, TSL1_LT_NFT and TSL1_LT_FNFT sources on 2026-10-21. Relative links to other tstokenlib documents (`../WITNESS_LINEAGE_RESEARCH.md`, the other integration documents, `../lt-spiffy-plugin`) point into that repository, not this one.

# The lineage tokens (TSL1_LT_NFT, TSL1_LT_FT) and their modes

This specification covers the family; each mode's procedures for a wallet are in its own integration document (`../LT_NFT_WALLET_INTEGRATION.md`, `../LT_LNFT_WALLET_INTEGRATION.md`, `../LT_FNFT_WALLET_INTEGRATION.md`, `../LT_VNFT_WALLET_INTEGRATION.md`, `../LT_NOTE_WALLET_INTEGRATION.md`), and the plugin's guarantees, host rules, threats and known gaps in `../../../lt-spiffy-plugin/docs/SECURITY.md`. The script is `lib/src/lt/lt_script_gen.dart` and the fuelled family's `lt_fnft_script_gen.dart`; where this document and the generator differ, the generator is the authority, and `scrypt/contracts/tsl1_lt_nft.scrypt` is an annotated reading aid for the NFT.

## 1. What it is for, and its status

A token whose every hop proves, in script, the transaction it came from and the transaction that one came from, back to an issuance the issuer signed: exact, fully on chain, at one hop, with no witness transaction, no reader, and no data carried off chain beyond SPV. The family exists because the earlier archetypes' partial-SHA-256 witness check could be forged (`../WITNESS_LINEAGE_RESEARCH.md` section 2). The NFT is one indivisible unit; the fungible token adds amounts, a split into two and a merge of two. The modes are separate archetypes for new issuances: the Listed NFT (a price anyone pays), the Fuelled NFT (the token pays its own fees), the Voucher NFT (a hop limit, redemption to the issuer, forced redemption after an expiry), the Note NFT (terms that split the fuel on each ending), and the swap and the payload as transaction shapes.

Status: built in tstokenlib (`lib/src/lt/`), tested (`test/lt_nft_test.dart`, `lt_ft_test.dart`, and one test file per mode, with refusals asserted on the exact values compared and every removable check removed once), mined on a regtest node for the NFT and every mode (`test/lt_*_localnet_test.dart`; the fungible token has the interpreter's tests only), in plugins (`LtNftPlugin`, `LtLnftPlugin`, `LtFnftPlugin`, `LtVnftPlugin`, `LtNotePlugin` and their sale versions), issued from a real wallet. Not on mainnet. Transactions must stay version 1 (section 5).

## 2. The outputs

A token output holds 1 satoshi (the fungible token its amount) and is locked by `PUSH(header) OP_CODESEPARATOR code`; the code is fixed per archetype and a wallet recognises a token by those bytes and nothing else. The header holds the input side of the token's own transaction.

The NFT's header (172 bytes, `LtLayout.nft`):

| offset | bytes | field |
|---|---|---|
| 0 | 32 | token id: the issuance's txid; zero in the issuance itself |
| 32 | 20 | issuer: HASH160 of the issuer's Rabin key |
| 52 | 20 | owner |
| 72 | 8 | change amount |
| 80 | 20 | change key hash |
| 100 | 36 | input 0's outpoint |
| 136 | 36 | the funding input's outpoint |

The fungible token's header is 241 bytes: it adds the attesters' commitment (20, resettable only), a flags byte (bit 0 two token outputs, bit 1 input 0 was a reset), the passenger record's length (4), the amount (8) and the passenger's outpoint (36). The Listed NFT's is 180: a price (8) after the owner, zero when not for sale. The fuelled family's headers add their terms (the Voucher's expiry, redeemTo and hop limit; the Note's maturity, mature amount and call height).

Every token transaction has one shape: version 1; locktime 0 and every sequence final; input 0 the token (the driver), input 1 the funding coin (P2PKH); output 0 the change (P2PKH), output 1 the token. The issuance's input 0 is an ordinary coin. The fungible token's split writes two token outputs and its merge takes a passenger at input 1.

## 3. The paths

**The normal path.** Unlock `PUSH(preimage) PUSH(sig) PUSH(pub) PUSH(C)`, C the record of the parent. The script, in order: checks the preimage; rebuilds this transaction byte for byte from the header and the unlock, hashes it natively and compares with the txid in its own outpoint (step A); rebuilds the transaction it spent from the record C the same way and compares with input 0's outpoint, so that consensus ran these checks one hop earlier (step B); for an issuance's first spend, checks the issuer's Rabin signature over the identity and the token id, which closes the induction; fixes the successor outputs (the forward covenant): the change, the token to the new owner in the same code with the same token id, the amounts; checks the owner's signature. The fungible driver also rebuilds the passenger's transaction and its parent; the passenger's own script runs the cheap path.

**The cheap path.** Unlock `PUSH(sig) PUSH(pub)`, the owner's signature only. It ends the token: no later spend accepts the result as a token. A merge's passenger rides this path at input 1; at input 0 it burns.

**The reset** (fungible, resettable). Two of three attesters named at issuance sign for an outpoint and the chain restarts there, pruning the record.

**The modes.** The Listed NFT: a listing is a transfer to oneself at a price; a buy is a transfer by anyone paying at least the price to the owner, the token to the buyer; a withdraw a transfer at price zero. The Fuelled NFT: the token output holds the satoshis that pay its fees, so a transfer needs no funding input; a top-up adds fuel with a second input. The Voucher NFT: a hop limit counted in the header; a redemption only to the issuer's key; the issuer's forced redemption after the expiry height, time-locked (nLockTime a height at least the expiry, the sequence not final), its outputs the issuer's. The Note NFT: an exit, a mature exit, a call and a reissue, each splitting the fuel by the terms (`NoteMath`, `VoucherMath`). The swap: two halves, the seller's first, the buyer taking, under gates G1 to G4 of `../RUGGERBOT_TOKENS_PLAN.md`; the payload: a paired transaction riding an issuance, which a wallet validates as such (`LtPayload.isPayloadTx`).

## 4. The transactions

| | TSL1_LT_NFT | TSL1_LT_FT |
|---|---:|---:|
| code after the separator | 2,231 B | 5,343 B |
| locking script / header | 2,406 / 172 B | 5,587 / 241 B |
| issuance | 2,757 B | 5,938 B |
| hop 1 / hop 10 / hop 20 | 6,039 / 9,513 / 13,372 B | 12,470 / 16,564 / 21,114 B |
| growth per ancestor | 385 B | 455 B |
| a reset hop (a normal hop at the same depth) | | 12,728 B (17,019) |

Measured 2026-10-07 through `test/lt_nft_test.dart` and `test/lt_ft_test.dart`; the NFT has no reset.

The fuelled family's transfer is about 152 bytes of fuel a hop. Against the earlier NFT's transfer pair of about 111 KB, a lineage transfer stays smaller for a couple of hundred ancestors, and a reset brings it back to the floor.

## 5. What it guarantees and what it does not

Guaranteed by the script (the plugin's G1 to G7): only the owner transfers or ends a token; a token cannot be copied (a copy of an output has a different outpoint, and steps A and B compare txids); a token traces to an issuance the issuer signed; a token cannot be relabelled; one token output gives at most one token output (the NFT), and a token has at most one successor; nobody can change a transfer after it is signed (every input signs SIGHASH_ALL; version 1, so Chronicle's relaxed malleability rules for later versions do not apply).

Not guaranteed (the plugin's N1 to N5): that a transfer is mined (count a token as received when the network has it); that the issuer is honest or issues once; that a reissue keeps the token's identity (a new id starts; follow the links); that a token without links is the newest form of its lineage; privacy (every transfer carries the full history since issuance). Not guaranteed by anything but the attesters' honesty: two of three attesters can mint by signing for a fabricated outpoint (choose them as you would choose who may issue). And the Voucher's issuer, sending its forced redemption early, blocks the holder's two-input spends (a top-up, a funded redemption) at nodes that hold it, for as long as it waits; the holder's one-input transfer and redemption go through (9.15).

## 6. The attacks considered

| attack | stopped by | shown |
|---|---|---|
| a forged witness (the earlier archetypes) | the family has no witness: steps A and B rebuild the actual bytes | section 2's forgery is not applicable |
| a copied output; a fabricated root; a relabelled token | step A (its own outpoint), step B (its parent), the token id in every header | refused on the compared txids |
| a reset for a fabricated outpoint by two attesters | not stopped: the attesters' power, by design | demonstrated in the tests |
| a relayer re-encoding an unlock (a later transaction version) | version 1 refused by both scripts | refused |
| a cheap-path spend at input 0 of a merge | it burns the coin: a transaction's token outputs are genuine iff input 0 is a normal-path spend | refused as a token |
| a buy below the price; a listing bought from the wrong owner | the Listed NFT's forced outputs | refused |
| a forced redemption before the expiry; a redemption to anyone but the issuer; a hop past the limit | the Voucher's rules | refused |

Every removable check is removed once in the family's tests.

## 7. The parameters

The attesters (resettable tokens); the Listed NFT's price; the fuelled family's fuel and terms; the Voucher's hop limit and expiry; the Note's terms, computed with `NoteMath` and `VoucherMath` before acceptance.

## 8. The API and the plugins

`LtBuilder` (`issue`, `transfer`, `fromRaw`, the records), `LtKey` (`LtPrivateKey`, or a wallet's own signer), `LtIssuer` and the identity anchor (`IdentityAnchorBuilder`), `LtLinks`, `LtSuccession.verify`, `LtPayload`, the fuelled family's `FnftBuilder`, `NoteMath`, `VoucherMath`. The plugins and the payee's checks (`LtNftReceive.check`, `LtFnftReceive.check`, `LtVnftReceive.check`, `LtNoteReceive.check`); the host rules in `../../../lt-spiffy-plugin/docs/SECURITY.md`, `LNFT.md`, `FNFT.md`, `VNFT.md`, `NOTE.md`, `SWAP.md`.

## 9. The decisions

`../WITNESS_LINEAGE_RESEARCH.md` sections 8 and 9: the rebuild chain (8), the fungible driver and passenger (9), the reset (9.1), the promotion to the library, the Listed NFT (9.14), the swap (9.10), the payload (9.11), the Note (9.12), the fuelled and voucher archetypes; the all-on-chain rule; the verdict that the witness-rebuild in classic tokens gains nothing over single-transaction lineage.
