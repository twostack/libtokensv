// The Fuelled NFT plugin against a stand-in wallet (support.dart): the whole
// lifecycle with every input through the script interpreter, transfers made
// from no wallet coin, the payee's check from a BEEF, and the guards.
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  final plugin = LtFnftPlugin();
  final code = plugin.builder.code;
  late RabinKeyPair rabin;
  late Transaction anchor;
  late LtIssuer issuer;

  setUpAll(() async {
    rabin = Rabin.generateKeyPair(1024);
    anchor = await anchorFor(rabin);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  final issuerKey = key(41), holder = key(42);
  final txs = <String, String>{};
  Wallet issuerWallet() => Wallet([issuerKey], issuerKey, txs);
  Wallet holderWallet() => Wallet([holder, key(43)], key(43), txs);
  String issuerHex() => hex.encode(issuer.pkh);
  String attest(Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
  int fuelOf(Transaction t) => t.outputs[0].satoshis.toInt();

  test('identifies a token output, names its owner and its fuel, and nothing else', () async {
    final r = await plugin.buildTransaction(issuerWallet().request({'action': 'issue', 'issuer': issuerHex()}));
    final lock = r.primaryTx.outputs[0].script;
    expect(plugin.identifyScript(lock), LtFnftPlugin.scriptType);
    final m = plugin.extractMetadata(lock)!;
    expect(m['ownerAddress'], addressOf(issuerKey));
    expect(m['tokenId'], isNull);
    expect(m['fuel'], fuelOf(r.primaryTx));
    expect(m['fuel'], greaterThan(99000), reason: 'the 100,000-sat coin, less the fee');
    expect(plugin.identifyScript(SVScript.fromByteArray(p2pkhScript(issuerKey))), isNull);
    expect(plugin.requiredFundingUtxoCount('transfer'), 0);
    expect(plugin.requiredFundingUtxoCount('topup'), 1);
  });

  test('issue, distribute, transfer, top up, redeem, reissue, distribute, burn: every input verifies', () async {
    final iw = issuerWallet(), hw = holderWallet();

    final iss = (await plugin.buildTransaction(iw.request({'action': 'issue', 'issuer': issuerHex()}))).primaryTx;
    expect(plugin.validateTransactionStructure(iss, 'issue'), isTrue);
    spends(iss, 0, p2pkhScript(issuerKey), 100000);
    iw.record(iss);

    // distribute: no wallet coin, the fee from the token's fuel
    final t1 = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(holder), 'attestation': attest(iss)}, coins: 0)))
        .primaryTx;
    expect(t1.inputs, hasLength(1));
    expect(plugin.validateTransactionStructure(t1, 'transfer'), isTrue);
    spends(t1, 0, iss.outputs[0].script.buffer, fuelOf(iss));
    expect(fuelOf(t1), lessThan(fuelOf(iss)));
    hw.record(t1);
    expect(plugin.anchorTxid(hex.decode(t1.serialize())), anchor.id);
    final held = await LtFnftReceive.check(plugin: plugin, beef: beefOf(t1), ownerAddress: addressOf(holder), anchorTx: anchor);
    expect(hex.encode(held.tokenId.reversed.toList()), iss.id);
    expect(held.value, fuelOf(t1));

    // top up, to the holder's own key: one coin swept into the token
    final up = (await plugin.buildTransaction(hw.request({'action': 'topup', 'token': t1.id, 'to': pkhHex(holder)})))
        .primaryTx;
    expect(plugin.validateTransactionStructure(up, 'topup'), isTrue);
    spends(up, 0, t1.outputs[0].script.buffer, fuelOf(t1));
    spends(up, 1, p2pkhScript(key(43)), 100000);
    expect(fuelOf(up), greaterThan(fuelOf(t1) + 99000));
    hw.record(up);

    // redeem to the issuer
    final g = (await plugin.buildTransaction(hw.request({'action': 'transfer', 'token': up.id, 'to': pkhHex(issuerKey)}, coins: 0)))
        .primaryTx;
    spends(g, 0, up.outputs[0].script.buffer, fuelOf(up));
    iw.record(g);

    // reissue: the end returns the fuel, the successor is fuelled by it
    final rr = await plugin.buildTransaction(iw.request({'action': 'reissue', 'token': g.id, 'issuer': issuerHex()}, coins: 0));
    final e = rr.primaryTx, r = rr.witnessTx!;
    expect(plugin.validateTransactionStructure(e, 'reissue'), isTrue);
    expect(plugin.validateTransactionStructure(r, 'witness'), isTrue);
    spends(e, 0, g.outputs[0].script.buffer, fuelOf(g));
    spends(r, 0, p2pkhScript(issuerKey), e.outputs[0].satoshis.toInt());
    expect(fuelOf(r), lessThan(fuelOf(g)));
    expect(fuelOf(r), greaterThan(fuelOf(g) - 100));
    iw.record(e);
    iw.record(r);

    // distribute the successor; the payee follows the link
    final t2 = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': r.id, 'to': pkhHex(holder), 'attestation': attest(r)}, coins: 0)))
        .primaryTx;
    spends(t2, 0, r.outputs[0].script.buffer, fuelOf(r));
    final link = plugin.link(hex.decode(e.serialize()), hex.decode(g.serialize()));
    final again = await LtFnftReceive.check(
        plugin: plugin, beef: beefOf(t2), ownerAddress: addressOf(holder), anchorTx: anchor, links: [link]);
    expect(hex.encode(again.originId.reversed.toList()), iss.id);

    // burn: the holder takes the fuel
    hw.record(t2);
    final burn =
        (await plugin.buildTransaction(hw.request({'action': 'end', 'token': t2.id, 'irreversible': true}, coins: 0))).primaryTx;
    expect(plugin.validateTransactionStructure(burn, 'end'), isTrue);
    spends(burn, 0, t2.outputs[0].script.buffer, fuelOf(t2));
    expect(burn.outputs.single.satoshis.toInt(), greaterThan(fuelOf(t2) - 100));
    expect(hex.encode(burn.outputs.single.script.buffer), hex.encode(p2pkhScript(holder)));
    expect(code.length, 2471);
  });

  test('refuses: a missing or bad attestation, an end without irreversible, a reissue by anyone but the issuer, a non-owner',
      () async {
    final iw = issuerWallet(), hw = holderWallet();
    final iss = (await plugin.buildTransaction(iw.request({'action': 'issue', 'issuer': issuerHex()}))).primaryTx;
    iw.record(iss);
    expect(() => plugin.buildTransaction(iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(holder)}, coins: 0)),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('attestation'))));
    final wrong = hex.encode(issuer.attest(sha256([3])));
    expect(
        () => plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(holder), 'attestation': wrong}, coins: 0)),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('Rabin signature does not verify'))));
    final t1 = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(holder), 'attestation': attest(iss)}, coins: 0)))
        .primaryTx;
    hw.record(t1);
    expect(() => plugin.buildTransaction(hw.request({'action': 'end', 'token': t1.id}, coins: 0)),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('irreversible'))));
    expect(() => plugin.buildTransaction(hw.request({'action': 'reissue', 'token': t1.id}, coins: 0)),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('issuer\'s operation'))));
    final stranger = Wallet([key(49)], key(49), txs);
    expect(() => stranger.request({'action': 'transfer', 'token': t1.id, 'to': pkhHex(key(49))}, coins: 0).keyFor(pkhHex(holder)),
        throwsA(isA<StateError>()));
    expect(() => plugin.buildTransaction(stranger.request({'action': 'transfer', 'token': t1.id, 'to': pkhHex(key(49))}, coins: 0)),
        throwsA(isA<StateError>().having((e) => e.message, 'message', contains('holds no key'))));
  });

  test('a transfer the fuel cannot pay is not built; a top-up still moves it', () async {
    final iw = issuerWallet();
    // a tiny issuance: 7,000 sats of fuel, priced at 1,000 sat/kB
    final small = Wallet([issuerKey], issuerKey, txs);
    final req = small.request({'action': 'issue', 'issuer': issuerHex()});
    final tiny = PluginTransactionRequest(
      fundingUtxos: [small.coin(7000)],
      signer: req.signer,
      publicKeys: req.publicKeys,
      params: req.params,
      transactionLookup: req.transactionLookup,
      fundingInputs: const [],
      feeRate: const FeeRate(satoshis: 1000, bytes: 1000),
      keyLookup: req.keyLookup,
    );
    final iss = (await plugin.buildTransaction(tiny)).primaryTx;
    iw.record(iss);
    // at 1,000 sat/kB a 6 KB transfer costs about 6,100 sats: more than is left
    PluginTransactionRequest dear(Map<String, dynamic> params, {int coins = 0}) {
      final r = iw.request(params, coins: coins);
      return PluginTransactionRequest(
        fundingUtxos: r.fundingUtxos,
        signer: r.signer,
        publicKeys: r.publicKeys,
        params: r.params,
        transactionLookup: r.transactionLookup,
        fundingInputs: const [],
        feeRate: const FeeRate(satoshis: 1000, bytes: 1000),
        keyLookup: r.keyLookup,
      );
    }

    expect(() => plugin.buildTransaction(dear({'action': 'transfer', 'token': iss.id, 'to': pkhHex(holder), 'attestation': attest(iss)})),
        throwsArgumentError);
    final up = (await plugin.buildTransaction(
            dear({'action': 'topup', 'token': iss.id, 'to': pkhHex(holder), 'attestation': attest(iss)}, coins: 1)))
        .primaryTx;
    spends(up, 0, iss.outputs[0].script.buffer, fuelOf(iss));
  });
}
