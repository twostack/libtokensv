import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import 'package:libtoken/libtoken.dart';
import 'package:test/test.dart';

final _sighash = SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value;
final _protocol = Brc43Protocol(1, 'messagebox advertisement');

void main() {
  final funding = SVPrivateKey.fromHex('11' * 32, NetworkType.TEST);
  final fundingAddress = funding.toAddress(networkType: NetworkType.TEST);
  final fundingScript = P2PKHLockBuilder.fromAddress(fundingAddress).getScriptPubkey();
  final identity = Brc100Keys(SVPrivateKey.fromHex('22' * 32, NetworkType.TEST));
  final tokenKey = identity.derivePrivateKey(_protocol, '1', Brc100Counterparty.anyone);
  final tokenPublicKey = identity.derivePublicKey(_protocol, '1', Brc100Counterparty.anyone, forSelf: true).toHex();
  final plugin = PushDropPlugin(network: NetworkType.TEST);

  SVScript token(String host) => PushDrop.lock(lockingPublicKey: tokenPublicKey, fields: [
        hex.decode(identity.identityKey),
        host.codeUnits,
      ]);

  PluginTransactionRequest request(PluginOutputSpec spec, {int fundingSats = 10000}) {
    final utxo = BitcoinUtxo.create(
        txid: 'a' * 64, vout: 1, satoshis: BigInt.from(fundingSats), scriptPubKey: fundingScript.toHex(), address: fundingAddress.toBase58());
    return PluginTransactionRequest(
      fundingUtxos: [utxo],
      signer: DefaultTransactionSigner(_sighash, funding),
      publicKeys: [funding.publicKey],
      params: spec.params,
      fundingInputs: [
        PluginFundingInput(
            utxo: utxo, lockingScript: fundingScript, signatures: 1, newUnlocker: () => P2PKHUnlockBuilder(funding.publicKey)),
      ],
      feeRate: const FeeRate(satoshis: 100, bytes: 1000),
      keyLookup: (hash) async {
        if (hash != hex.encode(hash160(hex.decode(tokenPublicKey)))) throw StateError('no key $hash');
        return PluginKey(signer: DefaultTransactionSigner(_sighash, tokenKey), publicKey: tokenKey.publicKey);
      },
    );
  }

  void spends(Transaction tx, int index, SVScript lockingScript, int sats) => Interpreter().correctlySpends(
      tx.inputs[index].script!, lockingScript, tx, index, {VerifyFlag.SIGHASH_FORKID, VerifyFlag.UTXO_AFTER_GENESIS},
      Coin.ofSat(BigInt.from(sats)));

  test('replaces a token: spends the old one with its key, makes the new one, change back', () async {
    final old = token('https://old.example.org');
    final fresh = token('https://messagebox.bsvblockchain.tech');
    final spec = PushDropPlugin.outputSpec(
      outputs: [PushDropOutput(lockingScript: fresh)],
      spends: [PushDropSpend(txid: 'b' * 64, vout: 0, satoshis: BigInt.one, lockingScript: old)],
    );
    expect(spec.params['action'], PushDropPlugin.create);
    final result = await plugin.buildTransaction(request(spec));
    final tx = result.primaryTx;

    expect(plugin.validateTransactionStructure(tx, PushDropPlugin.create), isTrue);
    expect(tx.inputs.map((i) => i.prevTxnId), ['b' * 64, 'a' * 64]);
    spends(tx, 0, old, 1);
    spends(tx, 1, fundingScript, 10000);
    expect(tx.outputs.first.script.toHex(), fresh.toHex());
    expect(tx.outputs.first.satoshis, BigInt.one);
    expect(tx.outputs.last.satoshis, BigInt.from(10001 - 1) - result.primaryFeeSats);
    // the fee pays the rate on the signed size
    expect(result.primaryFeeSats, greaterThanOrEqualTo(const FeeRate(satoshis: 100, bytes: 1000).feeFor(tx.serialize().length ~/ 2)));
  });

  test('withdraws a token: spends it and makes none', () async {
    final old = token('https://old.example.org');
    final spec = PushDropPlugin.outputSpec(
        spends: [PushDropSpend(txid: 'b' * 64, vout: 0, satoshis: BigInt.one, lockingScript: old)]);
    expect(spec.params['action'], PushDropPlugin.spend);
    final tx = (await plugin.buildTransaction(request(spec))).primaryTx;
    expect(plugin.validateTransactionStructure(tx, PushDropPlugin.spend), isTrue);
    expect(tx.outputs, hasLength(1));
    spends(tx, 0, old, 1);
  });

  test('a token locked to a key the wallet does not hold is not spent', () async {
    final stranger = PushDrop.lock(lockingPublicKey: funding.publicKey.toHex(), fields: [
      [1]
    ]);
    final spec = PushDropPlugin.outputSpec(
        spends: [PushDropSpend(txid: 'b' * 64, vout: 0, satoshis: BigInt.one, lockingScript: stranger)]);
    expect(plugin.buildTransaction(request(spec)), throwsStateError);
  });

  test('funding short of the fee is refused', () async {
    final spec = PushDropPlugin.outputSpec(outputs: [PushDropOutput(lockingScript: token('https://a.example.org'))]);
    expect(plugin.buildTransaction(request(spec, fundingSats: 5)), throwsStateError);
  });

  test('the spec survives the isolate boundary, and covers the bytes the selection does not see', () {
    final spec = PushDropPlugin.outputSpec(outputs: [PushDropOutput(lockingScript: token('https://a.example.org'))]);
    final back = InvoiceOutputSpec.fromMap(spec.toMap()) as PluginOutputSpec;
    expect(back.params, spec.params);
    expect(back.amount, greaterThan(BigInt.one));
  });

  test('identifies its tokens and names the owner by the locking key\'s address', () {
    final script = token('https://a.example.org');
    expect(plugin.identifyScript(script), PushDropPlugin.scriptType);
    expect(plugin.identifyScript(fundingScript), isNull);
    final metadata = plugin.extractMetadata(script)!;
    expect(metadata['ownerAddress'], tokenKey.toAddress(networkType: NetworkType.TEST).toBase58());
    expect(metadata['fields'], [identity.identityKey, hex.encode('https://a.example.org'.codeUnits)]);
  });
}
