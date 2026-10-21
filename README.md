# libtokensv

Token scripts for [libspiffy](https://pub.dev/packages/libspiffy) wallets, as
libspiffy plugins, and a client for BSV overlay services. libspiffy itself is
not changed: the plugins go through its `ScriptPlugin` /
`TransactionBuilderPlugin` interface, as tstokenlib does.

## PushDrop

PushDrop is the token format BRC-100 overlays use (message box host
advertisements, SHIP and SLAP advertisements, and others): data fields in a
spendable output, locked to a key.

    <lockingPublicKey> OP_CHECKSIG <field 1> ... <field n> OP_2DROP ... [OP_DROP]

`PushDrop.lock` and `PushDrop.decode` write and read these scripts exactly as
`@bsv/sdk`'s `PushDrop` template does (the tests check against vectors it
wrote).

### In a wallet

Register the plugin in the isolate the libspiffy wallet runs in:

```dart
PluginRegistry().register(PushDropPlugin(network: NetworkType.MAIN));
```

and pay its output spec with the wallet's `PayInvoiceCommand`:

```dart
final spec = PushDropPlugin.outputSpec(
  outputs: [PushDropOutput(lockingScript: newToken)],          // tokens to make
  spends: [PushDropSpend(txid: ..., vout: 0, satoshis: BigInt.one,
                         lockingScript: oldToken)],             // tokens to spend
);
// PayInvoiceCommand(walletId: ..., invoiceId: ..., outputs: [spec], ...)
```

The wallet funds the fee and gets the change. Replacing a token is spending
the old one and making the new one in one transaction; withdrawing one is
spending it alone.

A token is spent with a signature by its locking key, which the wallet must
hold: one of its HD keys, or a BRC-42 (type-42) key it has recorded with the
coordinator's `RecordType42AddressesCommand` (libspiffy 5.5.0). The plugin's
`extractMetadata` names the address of the locking key as the token's owner,
so the wallet tracks a token locked to a key it holds as its own, without
counting it in the balance or spending it as change.

### Signed fields, and the key a token is locked to

BRC-100 tokens usually carry a signature over their fields, made with a
BRC-42 child of the identity key (`createSignature`), and the reference
client locks the token to that same child. A libspiffy wallet refuses to
sign data with a key it holds coins under (such a signature can be a spend
signature), so once the locking key is recorded it can no longer sign the
fields of the next token. Lock the token to a different child instead: the
overlays check the field signature, not the lock. For a message box
advertisement: fields signed with protocol `[1, 'messagebox advertisement']`,
key `1`, counterparty `anyone`, as `tm_messagebox` verifies; the token locked
to the same protocol and key with counterparty `self`, recorded as the
derivation with the wallet's anchor key as both anchor and sender and the
invoice number `1-messagebox advertisement-1`. Both derive from the identity,
so a restored wallet finds its tokens again.

## Overlay services

`OverlayClient` asks BRC-24 lookup services and submits BRC-22 transactions,
finding hosts as `@bsv/sdk`'s `LookupResolver` and `TopicBroadcaster` do: the
hosts of a lookup service through the SLAP trackers (`ls_slap`), the hosts of
a topic through its SHIP advertisements (`ls_ship`).

```dart
final overlay = OverlayClient.forNetwork(OverlayNetwork.mainnet);
final outputs = await overlay.lookup('ls_messagebox', {'identityKey': key});
final result = await overlay.submit(beef, ['tm_messagebox']);
if (!result.acknowledgedIn('tm_messagebox')) { /* not admitted */ }
```

## Lineage tokens (TSL1_LT_FT, TSL1_LT_NFT, TSL1_LT_FNFT)

Copied from [tstokenlib](../tstokenlib) as the script and builder layer, with
their interpreter tests; the libspiffy plugins that move them in a wallet are
still in `lt-spiffy-plugin`. A lineage token's script rebuilds its own
transaction and its parent's from records carried in the unlock, so one hop
at the tip proves the whole lineage back to an issuance the issuer's Rabin key
attested, on chain, with no witness transaction and no reader.
`doc/lt/LT.md` is the family specification.

- **`TSL1_LT_NFT`**: one indivisible unit. `LtBuilder.issue`, `transfer`,
  `end`; `LtReceive.check` is the payee's verification; `LtIdentity` ties the
  issuer's Rabin key to an Ed25519 identity through an anchor transaction.
  Code 2,231 B, 386 B of record per hop.
- **`TSL1_LT_FT`**: amounts, a split into two and a merge of two, with a
  2-of-3 attester reset. Code 5,343 B, 455 B per ancestor.
- **`TSL1_LT_FNFT`**: the Fuelled NFT. The token output carries the satoshis
  that pay its fees, so a transfer needs no funding input and a holder needs
  no coins; anyone may top it up; the owner may burn it to take the fuel back.
  152 B per hop (`doc/lt/LT_FNFT_WALLET_INTEGRATION.md`). The same script
  family with terms in the header gives the Voucher NFT (`FnftBuilder.voucher`:
  a hop limit, redemption only to the issuer, a forced redemption after an
  expiry) and the Note NFT (`FuelLayout.note`: the fuel split by declared
  terms at each ending).

```dart
final b = FnftBuilder.voucher();
final terms = VoucherTerms(maxHops: 3, expiry: 900000, redeemTo: hostPkh, feeCap: 2000);
final t0 = b.issue(first: coin, issuerPkh: issuer.pkh, owner: claimKeyPkh, terms: terms, fee: 300);
t0.x = issuer.attest(t0.txid);                      // the issuer's Rabin attestation, carried by the next hop
final t1 = b.transfer(from: t0, ownerKey: claimKey.lt, to: newcomerPkh, fee: 700);   // no funding input
final held = await FnftReceive.check(b: b, raw: t1.raw, ownerPkh: newcomerPkh, anchorTx: anchor);
final r = b.redeem(from: t1, ownerKey: newcomerKey.lt, fee: 300);   // one output, to redeemTo
```

Also here: the Listed NFT (`LtLayout.lnft`, a price in the header that anyone
may pay the owner), the sale versions of the fuelled family (`FuelLayout.fnftSale`,
`vnftSale`, `noteSale`: a pay output, so a token is sold inside its own
transfer), the swap (`LtSwap`, `FnftSwap`: two halves, the seller's first) and
`NoteMath` / `VoucherMath` for what an ending pays. Each archetype's wallet
procedures are in `doc/lt/LT_*_WALLET_INTEGRATION.md`.

Every hop and ending is verified through dartsv's interpreter in the tests;
`LT_LOCALNET=1 dart test test/lt_nft_localnet_test.dart` mines a lifecycle on
a regtest node.
