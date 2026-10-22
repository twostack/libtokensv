> Copied from lt-spiffy-plugin (commit 033d847) on 2026-10-22 with the lineage plugins. Here the plugins are in `lib/src/spiffy/` and their tests in `test/spiffy/`; the `test/lt_*_localnet_test.dart` suites named here are libtokensv's own regtest suites. `docs/INTEGRATION.md`, `docs/EDGE_CASES.md` and the other tstokenlib documents named here stay in those repositories.

# The Note NFT plugin (`LtNotePlugin`)

This document tells how the Note NFT is different from the Voucher NFT, and gives its procedures, rules and edge cases. Read `FNFT.md` and `VNFT.md` first. The language follows ASD-STE100.

The token specification for any wallet is `../lt/LT_NOTE_WALLET_INTEGRATION.md`.

## 1. What it is

The Note NFT (`TSL1_LT_NOTE`) is a fuelled token. Its terms tell, for each way it can end, how much of the fuel the holder gets. The issuer (`payTo`) gets the rest.

| | Voucher NFT | Note NFT |
|---|---|---|
| Plugin id / script type | `tsl1_lt_vnft` / `lt_vnft` | `tsl1_lt_note` / `lt_note` |
| Holder's endings | `redeem`: everything to the issuer | `exit` (any time) and `matureExit` (from `maturity`): split by the terms |
| Issuer's ending | `forceRedeem` after `expiry`: everything to the issuer | `call` from `callAt`: split by the terms |
| Transfer limit | `maxHops` 1 to 255 | `maxHops` 0 (no limit) to 255 |
| Code | 2,726 B | 3,479 B |

Status: TESTED. `test/lt_note_plugin_test.dart` uses stand-in wallets. `test/libspiffy_note_wallet_test.dart` uses a real libspiffy wallet. tstokenlib mines the endings on a regtest node.

## 2. The terms

| Param | Meaning |
|---|---|
| `maxHops` | Transfers allowed. Default 0: no limit. |
| `payTo` | The issuer's key hash. It gets the issuer's share, and its key signs a call. Default: the first issuance coin's key. |
| `feeCap` | The most an ending may leave for the fee. |
| `exit` | The holder's amount on an exit. |
| `maturity`, `mature` | From block height `maturity`, the holder's amount on a mature exit. |
| `callAt`, `call` | From block height `callAt`, the holder's amount when the issuer calls. |

An amount of 0 gives the holder nothing. `NoteTerms.everything` gives the holder everything. `NoteTerms.never` (499,999,999) is a height that is never reached.

## 3. Actions

| `action` | Who | Params | Wallet coins |
|---|---|---|---|
| `issue` | the issuer | `issuer` and the terms | 1 or 2 |
| `transfer`, `topup` | the owner | as for the Fuelled NFT | 0, 1 |
| `exit` | the owner | `token` | 0 |
| `matureExit` | the owner | `token` | 0 |
| `call` | the issuer | `token`, `tokenRaw` (when the wallet does not have it), `lockHeight` (optional) | 0 |
| `reissue` | the issuer | `ended` or `endedRaw`, `issuer`, the new terms | 0 |

An ending's outputs: one output to `payTo` when the holder's amount is 0; one output to the holder when the amount is at least the value less `feeCap`; otherwise two outputs, output 0 to `payTo` and output 1 to the holder.

## 4. Security rules

**N-S1: Show what the holder gets.** The metadata gives `holderOnExit`, `holderAtMaturity` and `holderIfCalled` (and `callableBeforeMaturity`, whether the issuer may call before the note matures) at the current fuel. Show them before a person accepts or pays for a note.

**N-S2: The fuel is not checked against the amounts.** Each transfer pays its fee from the fuel. If the fuel falls below an amount, the holder gets all that is left on that ending.

**N-S3: Neither side can take the other's share.** The holder's output is at least its amount. The issuer's output is at least the value less `feeCap` less the holder's amount.

**N-S4: The network enforces the heights.** A mature exit or a call carries its height as nLockTime with a non-final sequence. Before that height it is not mined, and any final spend of the note replaces it. Settle each one only after its height.

**N-S5: After `callAt` the issuer can end the note at any time.** Run `CheckForeignSpendsCommand` (`SWAP.md`, section 3) before you show such a note as held.

## 5. Edge cases

| ID | Condition | What happens | Correct action |
|---|---|---|---|
| E-N1 | A transfer past `maxHops` | `the note has made its <n> transfers: it can only be ended` | End it. |
| E-N2 | `end` | `unknown action end` | Use `exit`, `matureExit` or `call`. |
| E-N3 | The fee is over `feeCap` | `the fee <n> is over the note's fee cap <c>` | Use a lower fee rate. |
| E-N4 | A call with `lockHeight` below `callAt` | `the token refuses the spend` | Leave out `lockHeight`. |
| E-N5 | A call from a wallet without the `payTo` key | `holds no key` | Use the issuer's wallet. |
| E-N7 | A `topup` refused with `txn-mempool-conflict` | An early mature exit or call waits at that node. It blocks a spend with other inputs. | Use a one-input spend (`transfer`, `exit`). |
| E-N6 | A reissue from an ending that paid only the holder | `output 0 of the ended transaction is not paid to <key>` | Reissue only from an ending that paid `payTo`. |
