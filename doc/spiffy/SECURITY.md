> Copied from lt-spiffy-plugin (commit 033d847) on 2026-10-22 with the lineage plugins. Here the plugins are in `lib/src/spiffy/` and their tests in `test/spiffy/`; the `test/lt_*_localnet_test.dart` suites named here are libtokensv's own regtest suites. `docs/INTEGRATION.md`, `docs/EDGE_CASES.md` and the other tstokenlib documents named here stay in those repositories.

# Security

This document tells what the covenant NFT guarantees, what it does not guarantee, and what the host must do. The language follows ASD-STE100.

## 1. Guarantees

These properties come from the token's script. Every node checks them. No wallet can switch them off.

| ID | Guarantee | Reason |
|---|---|---|
| G1 | Only the owner can transfer or end a token. | Each spend needs a signature by the key whose hash is the header's owner. |
| G2 | A token cannot be copied. | Each spend rebuilds the token's own transaction and its parent from their bytes, and compares the txids (steps A and B). A copy of an output has a different outpoint. |
| G3 | A token traces back to its issuance. The issuer signed that issuance. | The first spend after the issuance checks the issuer's Rabin signature over the identity and the token id. Each later spend proves the step before it. |
| G4 | A token cannot be relabelled as a different token. | The token id is in every header. The rebuild compares it. |
| G5 | One token output gives at most one token output. | The NFT has no split. The script fixes the outputs of a transfer. |
| G6 | A token has at most one successor. | Only one transaction can end a token's last output. Only one transaction can spend output 0 of that end. A wallet checks a successor with `LtSuccession.verify`. |
| G7 | Nobody can change a transfer after it is signed. | Every input signs SIGHASH_ALL. The transaction is version 1, so Chronicle's relaxed rules for later versions do not apply. |

## 2. What the token does not guarantee

| ID | Not guaranteed | What to do |
|---|---|---|
| N1 | That a transfer will be mined. The payer can spend the token twice before a block. | Count a token as received only when the network has the transfer. (S08) |
| N2 | That the issuer is honest. The issuer can issue any number of tokens. | Trust the issuer as a person or company. The anchor names the issuer. |
| N3 | That a reissue keeps the token's identity. A new token id starts. | Follow the links to the origin. Show `originId` to the user. |
| N4 | That a token without links is the newest form of its lineage. A holder can omit the links. | A token without links shows its own id as the origin. That is correct but less informative. |
| N5 | Privacy. Every transfer contains the full history of the token since its issuance. The change goes to the funding coin's key. | Do not use a covenant NFT where the history must be private. |

## 3. Rules for the host

**S01: Register before use.** Register the plugin before the wallet loads or receives a transaction. If not, libspiffy does not know that a token output is the wallet's. Reason: libspiffy finds the owner of a token output only through the plugin's `ownerAddress`.

**S02: Use the correct network.** The plugin makes `ownerAddress` for its network. With the wrong network, the wallet does not find its own tokens.

**S03: Protect the Rabin key.** Anyone with the issuer's Rabin private key can issue tokens that verify as the issuer's. Keep the key in the host's secure storage. Do not put it in plugin params, logs, messages or test fixtures that leave the machine. The plugin never needs the private key. It only takes attestations.

**S04: Protect the wallet keys.** The plugin never gets a private key. It asks libspiffy's wallet aggregate for each signature through `keyFor` and the request signer. Do not give a private key to the plugin in another way.

**S05: Do not spend a token as a coin.** A token output also accepts a spend with only the owner's signature (the "cheap path"). Such a spend ends the token. libspiffy keeps token outputs out of ordinary payments only while the plugin is registered. Do not build your own transaction that spends a token output.

**S06: Issue to the issuer.** The plugin always issues to the issuing wallet's own key. The issuer then transfers. Reasons:
- Issuance and distribution are separate steps for the business.
- The first spend checks the attestation, and that is the issuer's own transfer. A bad attestation then fails with the issuer, not with a customer.

**S07: Approve irreversible operations.** `end` and `reissue` stop a token permanently. The plugin needs `irreversible: true` for `end`, and the token's issuer key hash for `reissue`. These params are a statement of intent. Give them only after a person or a policy approves the operation.

**S08: Count a token only when the network has it.**
- A valid BEEF shows that the funding history is in blocks.
- `LtNftReceive.check` shows that the bytes are a valid token for you.
- Neither shows that the network accepted this transfer.

Show "received" only after `SEEN_ON_NETWORK` or `MINED`.

**S09: Do not change the bytes.** A token transaction must keep its txid. The next spend rebuilds it byte for byte. Do not deserialize and serialize a token transaction with a library that can change the encoding. Use the raw bytes that you received. Do not make a transaction of a version other than 1.

**S10: Keep the links.** Links are not on chain in a form that a wallet can find. If a holder loses them, later holders cannot find the origin of a reissued token. The token is still valid. (N4)

**S11: Check the anchor.** `LtNftReceive.check` verifies the anchor's AIP signature, its txid, its ED25519 key, and the Rabin key that it names. Get the anchor with its merkle proof. Make sure the proof is valid against your block headers. A valid AIP signature on an anchor that is not mined does not prove that the anchor is the issuer's published identity.

**S12: Do one operation at a time on one token.** libspiffy refuses a second payment that spends a token output already held. It checks this against its read model. Two payments that start at the same time can both pass that check before the first is recorded. Use a lock for each token in the host. (EDGE_CASES E12)

## 4. Threats and how they are stopped

| Threat | Stopped by | Where |
|---|---|---|
| A stranger copies a token output into a new transaction | G2 | Script (nodes) |
| A stranger writes a token header with a real token id into an output | G2, G3. A spend on the normal path fails. The cheap path only ends it. | Script; `LtReceive.check` refuses such a transaction (not canonical) |
| The issuer makes a second successor from a forged copy | Rule 3 of `LtSuccession.verify`: the ended output must be genuine | Wallet (`LtReceive.check` with links) |
| A payee receives a transfer that spends a token twice | N1 | Network; the payee waits (S08) |
| A relayer changes a transfer | G7 | Script and signatures |
| A wallet signs the token input with the wrong key | The plugin runs the token's script before it returns the transaction | Plugin (`_checkTokenSpend`) |
| A host gives a wrong attestation | `LtIdentity.attestationError` before the build | Plugin |
| A host calls `reissue` for a token of another issuer | The `issuer` param must match the header | Plugin |
| A holder ends a token by mistake | `irreversible: true` is necessary | Plugin |
| A wallet sends the same token in two payments | Held inputs; refusal of a second payment | libspiffy coordinator (S12 for the race) |
| An ordinary payment spends a token output | Token outputs are plugin managed | libspiffy (S01, S05) |
| A funding coin smaller than the fee makes a bad header | The builder refuses | tstokenlib |

## 5. Known gaps

| ID | Gap | Effect | Status |
|---|---|---|---|
| K1 | The BEEF of a plugin payment has no ancestors and no proofs. | We expect a payee's libspiffy to refuse it. Use route A (`docs/INTEGRATION.md` section 7). | GAP (expected, NOT TESTED) |
| K2 | The hold check in the coordinator uses the read model, not the wallet aggregate. | Two concurrent payments of one token can both be built. | Mitigated by S12 |
| K3 | A token received while the plugin is not registered is not recorded. | The wallet does not show the token. Recovery (import the transaction again after registration) is NOT TESTED. | NOT TESTED |
| K4 | The issuer's identity anchor cannot rotate its Rabin key. | A new key needs a new anchor and new issuances. | Open |
| K5 | The message envelope is not decided. | Each integrator must define it for now. | Open |
