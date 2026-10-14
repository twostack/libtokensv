# libtoken

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
hold: one of its HD keys, or a BRC-42 (type-42) key it has recorded with
`RecordType42AddressesCommand`. For a BRC-100 token locked with counterparty
`anyone` and `forSelf`, that derivation is the wallet's anchor key as the
anchor, the public key of private key 1 (the generator point) as the sender,
and the BRC-43 invoice number (`1-messagebox advertisement-1`, say). The
plugin's `extractMetadata` names the address of the locking key as the
token's owner, so the wallet tracks a token locked to a key it holds as its
own, without counting it in the balance or spending it as change.

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
