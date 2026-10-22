// The plugin against a stand-in wallet: libspiffy's request (funding coins,
// a transaction signer, a key lookup by hash, a transaction lookup) built
// from in-memory keys. Every input the plugin's transactions spend is run
// through the script interpreter, and the payee's check reads the transfer
// back from a BEEF.

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'support.dart';

List<int> dartsvSha(int i) => sha256([i]);

void main() {
  final plugin = LtNftPlugin();
  final code = plugin.builder.code;
  late RabinKeyPair rabin;
  late Transaction anchor;
  late LtIssuer issuer;

  setUpAll(() async {
    rabin = Rabin.generateKeyPair(1024);
    anchor = await anchorFor(rabin);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  final issuerKey = key(1), holder = key(2);
  final txs = <String, String>{};
  // the issuer's wallet funds from issuerKey and holds it; the holder's
  // wallet funds from key(3) and holds the holder key
  Wallet issuerWallet() => Wallet([issuerKey], issuerKey, txs);
  Wallet holderWallet() => Wallet([holder, key(3)], key(3), txs);

  test('identifies a token output and names its owner for the wallet, and nothing else', () async {
    final w = issuerWallet();
    final r = await plugin.buildTransaction(w.request({'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, coins: 2));
    final lock = r.primaryTx.outputs[1].script;
    expect(plugin.identifyScript(lock), LtNftPlugin.scriptType);
    final m = plugin.extractMetadata(lock)!;
    expect(m['ownerAddress'], addressOf(issuerKey), reason: 'issued to the issuer\'s own key');
    expect(m['tokenId'], isNull, reason: 'an issuance: its txid is the token id');
    expect(m['issuer'], hex.encode(issuer.pkh));
    expect(plugin.identifyScript(r.primaryTx.outputs[0].script), isNull);
    expect(plugin.extractMetadata(r.primaryTx.outputs[0].script), isNull);
  });

  test('issue to self, distribute, redeem, reissue, distribute again: every input verifies, the payee accepts', () async {
    final iw = issuerWallet(), hw = holderWallet();

    // issue, to the issuer's own key
    final iss = (await plugin.buildTransaction(iw.request({'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, coins: 2)))
        .primaryTx;
    expect(plugin.validateTransactionStructure(iss, 'issue'), isTrue);
    spends(iss, 0, p2pkhScript(issuerKey), 100000);
    spends(iss, 1, p2pkhScript(issuerKey), 100000);
    iw.record(iss);
    final attestation = hex.encode(issuer.attest(hex.decode(iss.id).reversed.toList()));

    // distribute: the issuer's wallet signs the token input with the owner key it looked up
    final t1 = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(holder), 'attestation': attestation})))
        .primaryTx;
    expect(plugin.validateTransactionStructure(t1, 'transfer'), isTrue);
    spends(t1, 0, iss.outputs[1].script.buffer, 1);
    spends(t1, 1, p2pkhScript(issuerKey), 100000);
    iw.record(t1);
    expect(plugin.anchorTxid(hex.decode(t1.serialize())), anchor.id, reason: 'the payee finds the anchor from the transfer');
    final held = await LtNftReceive.check(plugin: plugin, beef: beefOf(t1), ownerAddress: addressOf(holder), anchorTx: anchor);
    expect(hex.encode(held.tokenId.reversed.toList()), iss.id);
    expect(plugin.extractMetadata(t1.outputs[1].script)!['tokenId'], iss.id);

    // redeem: the holder's wallet sends it back to the issuer's key
    final g = (await plugin.buildTransaction(hw.request({'action': 'transfer', 'token': t1.id, 'to': pkhHex(issuerKey)})))
        .primaryTx;
    spends(g, 0, t1.outputs[1].script.buffer, 1);
    spends(g, 1, p2pkhScript(key(3)), 100000);
    hw.record(g);

    // reissue: the end and its successor, paired
    final rr = await plugin.buildTransaction(
        iw.request({'action': 'reissue', 'token': g.id, 'issuer': hex.encode(issuer.pkh)}, coins: 2));
    final e = rr.primaryTx, r = rr.witnessTx!;
    expect(plugin.validateTransactionStructure(e, 'reissue'), isTrue);
    expect(plugin.validateTransactionStructure(r, 'witness'), isTrue);
    spends(e, 0, g.outputs[1].script.buffer, 1);
    spends(r, 0, p2pkhScript(issuerKey), e.outputs[0].satoshis.toInt());
    spends(r, 1, p2pkhScript(issuerKey), 100000);
    expect(rr.primaryFeeSats, greaterThan(BigInt.zero));
    expect(rr.witnessFeeSats, greaterThan(BigInt.zero));
    iw.record(e);
    iw.record(r);
    final rAttest = hex.encode(issuer.attest(hex.decode(r.id).reversed.toList()));

    // distribute the successor, with the link back to the first token
    final t2 = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': r.id, 'to': pkhHex(holder), 'attestation': rAttest})))
        .primaryTx;
    spends(t2, 0, r.outputs[1].script.buffer, 1);
    final link = plugin.link(hex.decode(e.serialize()), hex.decode(g.serialize()));
    final again = await LtNftReceive.check(
        plugin: plugin, beef: beefOf(t2), ownerAddress: addressOf(holder), anchorTx: anchor, links: [link]);
    expect(hex.encode(again.originId.reversed.toList()), iss.id, reason: 'the successor traces back to the first token');

    // and the holder can end it
    hw.record(t2);
    final end = (await plugin.buildTransaction(hw.request({'action': 'end', 'token': t2.id, 'irreversible': true}))).primaryTx;
    expect(plugin.validateTransactionStructure(end, 'end'), isTrue);
    spends(end, 0, t2.outputs[1].script.buffer, 1);
  });

  test('refuses a transfer of an issuance without its attestation, and a token the wallet holds no key for', () async {
    final iw = issuerWallet();
    final iss = (await plugin.buildTransaction(iw.request({'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, coins: 2)))
        .primaryTx;
    iw.record(iss);
    expect(() => plugin.buildTransaction(iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(holder)})),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('attestation'))));
    final stranger = Wallet([key(9)], key(9), txs);
    expect(
        () => plugin.buildTransaction(stranger.request(
            {'action': 'transfer', 'token': iss.id, 'to': pkhHex(holder), 'attestation': hex.encode(issuer.attest(hex.decode(iss.id).reversed.toList()))})),
        throwsA(isA<StateError>().having((e) => e.message, 'message', contains('holds no key'))));
  });

  test('refuses a bad attestation, an end without irreversible: true, and a reissue by anyone but the issuer', () async {
    final iw = issuerWallet(), hw = holderWallet();
    final iss = (await plugin.buildTransaction(iw.request({'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, coins: 2)))
        .primaryTx;
    iw.record(iss);
    final wrong = hex.encode(issuer.attest(dartsvSha(3)));
    expect(
        () => plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(holder), 'attestation': wrong})),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('Rabin signature does not verify'))));
    final t1 = (await plugin.buildTransaction(iw.request({
      'action': 'transfer',
      'token': iss.id,
      'to': pkhHex(holder),
      'attestation': hex.encode(issuer.attest(hex.decode(iss.id).reversed.toList())),
    })))
        .primaryTx;
    hw.record(t1);
    expect(() => plugin.buildTransaction(hw.request({'action': 'end', 'token': t1.id})),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('irreversible'))));
    expect(() => plugin.buildTransaction(hw.request({'action': 'reissue', 'token': t1.id}, coins: 2)),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('issuer\'s operation'))));
  });

  test('a token spend the script refuses is never returned', () async {
    // a wallet whose key lookup answers with the wrong key for the owner
    final iw = issuerWallet();
    final iss = (await plugin.buildTransaction(iw.request({'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, coins: 2)))
        .primaryTx;
    iw.record(iss);
    final liar = Wallet([issuerKey], issuerKey, txs);
    final req = liar.request({
      'action': 'transfer',
      'token': iss.id,
      'to': pkhHex(holder),
      'attestation': hex.encode(issuer.attest(hex.decode(iss.id).reversed.toList())),
    });
    final lying = PluginTransactionRequest(
      fundingUtxos: req.fundingUtxos,
      signer: req.signer,
      publicKeys: req.publicKeys,
      params: req.params,
      transactionLookup: req.transactionLookup,
      fundingInputs: const [],
      feeRate: req.feeRate,
      keyLookup: (hash) async =>
          PluginKey(signer: DefaultTransactionSigner(sighashAllForkId, key(8)), publicKey: issuerKey.publicKey),
    );
    expect(() => plugin.buildTransaction(lying),
        throwsA(isA<StateError>().having((e) => e.message, 'message', contains('the token refuses the spend'))));
  });

  test('the payee refuses a transfer paid to someone else', () async {
    final iw = issuerWallet();
    final iss = (await plugin.buildTransaction(iw.request({'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, coins: 2)))
        .primaryTx;
    iw.record(iss);
    final t1 = (await plugin.buildTransaction(iw.request({
      'action': 'transfer',
      'token': iss.id,
      'to': pkhHex(holder),
      'attestation': hex.encode(issuer.attest(hex.decode(iss.id).reversed.toList())),
    })))
        .primaryTx;
    expect(() => LtNftReceive.check(plugin: plugin, beef: beefOf(t1), ownerAddress: addressOf(key(9)), anchorTx: anchor),
        throwsA(isA<LtRefused>().having((e) => e.reason, 'reason', contains('not paid to this key'))));
    expect(code.length, 2231);
  });
}
