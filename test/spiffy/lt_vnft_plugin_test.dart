// The Voucher NFT plugin against a stand-in wallet (support.dart): the hop
// limit, the holder's redemption, the issuer's force-redemption from a
// transaction its wallet does not hold, a reissue with new terms, the
// payee's check, and the guards. Every token input goes through the
// script interpreter.
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  final plugin = LtVnftPlugin();
  late RabinKeyPair rabin;
  late Transaction anchor;
  late LtIssuer issuer;

  setUpAll(() async {
    rabin = Rabin.generateKeyPair(1024);
    anchor = await anchorFor(rabin);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  final issuerKey = key(61), h1 = key(62), h2 = key(63);
  final issuerTxs = <String, String>{}, holderTxs = <String, String>{};
  // separate transaction logs: the issuer's wallet does not hold the holders' transactions
  Wallet issuerWallet() => Wallet([issuerKey], issuerKey, issuerTxs);
  Wallet holderWallet() => Wallet([h1, h2, key(64)], key(64), holderTxs);
  String issuerHex() => hex.encode(issuer.pkh);
  String attest(Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
  int fuelOf(Transaction t) => t.outputs[0].satoshis.toInt();
  const expiry = 1000;
  Map<String, dynamic> issue({int maxHops = 2, int exp = expiry}) =>
      {'action': 'issue', 'issuer': issuerHex(), 'maxHops': maxHops, 'expiry': exp, 'feeCap': 500};

  /// [r] at 1,000 sat/kB.
  PluginTransactionRequest dearer(PluginTransactionRequest r) => PluginTransactionRequest(
        fundingUtxos: r.fundingUtxos,
        signer: r.signer,
        publicKeys: r.publicKeys,
        params: r.params,
        transactionLookup: r.transactionLookup,
        fundingInputs: const [],
        feeRate: const FeeRate(satoshis: 1000, bytes: 1000),
        keyLookup: r.keyLookup,
      );

  /// An issuance to the issuer, distributed to h1.
  Future<(Transaction, Transaction)> voucher({int maxHops = 2}) async {
    final iw = issuerWallet(), hw = holderWallet();
    final iss = (await plugin.buildTransaction(iw.request(issue(maxHops: maxHops)))).primaryTx;
    iw.record(iss);
    final t1 = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(h1), 'attestation': attest(iss)}, coins: 0)))
        .primaryTx;
    spends(t1, 0, iss.outputs[0].script.buffer, fuelOf(iss));
    hw.record(t1);
    return (iss, t1);
  }

  test('identifies a voucher, and names its terms, hops and fuel', () async {
    final (iss, t1) = await voucher();
    expect(plugin.identifyScript(t1.outputs[0].script), LtVnftPlugin.scriptType);
    expect(plugin.validateTransactionStructure(iss, 'issue'), isTrue);
    expect(plugin.validateTransactionStructure(t1, 'transfer'), isTrue);
    final m = plugin.extractMetadata(t1.outputs[0].script)!;
    expect(m['ownerAddress'], addressOf(h1));
    expect(m['tokenId'], iss.id);
    expect(m['issuer'], issuerHex());
    expect(m['redeemTo'], pkhHex(issuerKey), reason: 'by default the issuing wallet\'s own key');
    expect([m['maxHops'], m['hops'], m['hopsLeft'], m['expiry'], m['feeCap']], [2, 1, 1, expiry, 500]);
    expect(m['fuel'], fuelOf(t1));
    // not a Fuelled NFT, and the Fuelled NFT plugin does not take it
    expect(LtFnftPlugin().identifyScript(t1.outputs[0].script), isNull);
    expect(plugin.identifyScript(SVScript.fromByteArray(p2pkhScript(h1))), isNull);
    expect(plugin.supportedActions, isNot(contains('end')));
  });

  test('transfer to the hop limit, refused past it; the holder redeems; the issuer reissues with new terms', () async {
    final iw = issuerWallet(), hw = holderWallet();
    final (iss, t1) = await voucher();
    final t2 = (await plugin.buildTransaction(hw.request({'action': 'transfer', 'token': t1.id, 'to': pkhHex(h2)}, coins: 0)))
        .primaryTx;
    spends(t2, 0, t1.outputs[0].script.buffer, fuelOf(t1));
    hw.record(t2);
    expect(plugin.extractMetadata(t2.outputs[0].script)!['hopsLeft'], 0);
    expect(() => plugin.buildTransaction(hw.request({'action': 'transfer', 'token': t2.id, 'to': pkhHex(h1)}, coins: 0)),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('can only be redeemed'))));
    expect(() => plugin.buildTransaction(hw.request({'action': 'end', 'token': t2.id, 'irreversible': true}, coins: 0)),
        throwsArgumentError);

    final red = (await plugin.buildTransaction(hw.request({'action': 'redeem', 'token': t2.id}, coins: 0))).primaryTx;
    expect(plugin.validateTransactionStructure(red, 'redeem'), isTrue);
    spends(red, 0, t2.outputs[0].script.buffer, fuelOf(t2));
    expect(red.inputs, hasLength(1));
    expect(hex.encode(red.outputs.single.script.buffer), hex.encode(p2pkhScript(issuerKey)));
    expect(red.outputs.single.satoshis.toInt(), greaterThanOrEqualTo(fuelOf(t2) - 500));

    // the issuer's wallet sees the redemption (it pays the issuer) and reissues from it
    iw.record(red);
    final r = (await plugin.buildTransaction(
            iw.request({'action': 'reissue', 'ended': red.id, 'issuer': issuerHex(), 'maxHops': 5, 'expiry': 2000, 'feeCap': 300},
                coins: 0)))
        .primaryTx;
    expect(plugin.validateTransactionStructure(r, 'reissue'), isTrue);
    spends(r, 0, p2pkhScript(issuerKey), red.outputs.single.satoshis.toInt());
    iw.record(r);
    final d = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': r.id, 'to': pkhHex(h1), 'attestation': attest(r)}, coins: 0)))
        .primaryTx;
    spends(d, 0, r.outputs[0].script.buffer, fuelOf(r));
    final held = await LtVnftReceive.check(
        plugin: plugin,
        beef: beefOf(d),
        ownerAddress: addressOf(h1),
        anchorTx: anchor,
        links: [plugin.link(hex.decode(red.serialize()), hex.decode(t2.serialize()))]);
    expect(hex.encode(held.originId.reversed.toList()), iss.id);
    expect([held.tx.terms.maxHops, held.tx.terms.expiry, held.tx.hopsLeft], [5, 2000, 4]);
    expect(plugin.anchorTxid(hex.decode(d.serialize())), anchor.id);
  });

  test('a fee above the cap: redeem refuses, redeemFunded pays it from a coin', () async {
    final hw = holderWallet();
    final (_, t1) = await voucher();
    final atRate = dearer(hw.request({'action': 'redeem', 'token': t1.id}, coins: 0));
    expect(() => plugin.buildTransaction(atRate),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('fee cap'))));
    final paid =
        (await plugin.buildTransaction(dearer(hw.request({'action': 'redeemFunded', 'token': t1.id})))).primaryTx;
    expect(paid.inputs, hasLength(2));
    expect(plugin.validateTransactionStructure(paid, 'redeemFunded'), isTrue);
    spends(paid, 0, t1.outputs[0].script.buffer, fuelOf(t1));
    spends(paid, 1, p2pkhScript(key(64)), 100000);
    expect(paid.outputs.single.satoshis.toInt(), greaterThanOrEqualTo(fuelOf(t1)));
  });

  test('force-redeem: the issuer takes a voucher it does not hold, from the holder\'s raw transaction', () async {
    final iw = issuerWallet();
    final (_, t1) = await voucher();
    expect(issuerTxs.containsKey(t1.id), isFalse);
    expect(() => plugin.buildTransaction(iw.request({'action': 'forceRedeem', 'token': t1.id}, coins: 0)),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('does not hold'))));
    expect(
        () => plugin.buildTransaction(
            iw.request({'action': 'forceRedeem', 'token': t1.id, 'tokenRaw': hex.encode(sha256([1]))}, coins: 0)),
        throwsA(anything));

    final f = (await plugin.buildTransaction(
            iw.request({'action': 'forceRedeem', 'token': t1.id, 'tokenRaw': t1.serialize()}, coins: 0)))
        .primaryTx;
    expect(plugin.validateTransactionStructure(f, 'forceRedeem'), isTrue);
    spends(f, 0, t1.outputs[0].script.buffer, fuelOf(t1));
    expect(f.nLockTime, expiry);
    expect(f.inputs.single.sequenceNumber, 0xfffffffe);
    expect(hex.encode(f.outputs.single.script.buffer), hex.encode(p2pkhScript(issuerKey)));

    // the script refuses an nLockTime below the expiry
    expect(
        () => plugin.buildTransaction(
            iw.request({'action': 'forceRedeem', 'token': t1.id, 'tokenRaw': t1.serialize(), 'lockHeight': expiry - 1}, coins: 0)),
        throwsA(isA<StateError>().having((e) => e.message, 'message', contains('refuses'))));
    // a wallet without the redeemTo key cannot sign it
    final holder = holderWallet();
    expect(() => plugin.buildTransaction(holder.request({'action': 'forceRedeem', 'token': t1.id}, coins: 0)),
        throwsA(isA<StateError>().having((e) => e.message, 'message', contains('holds no key'))));

    // the issuer reissues from the force-redemption; the link verifies
    iw.record(f);
    final r = (await plugin.buildTransaction(
            iw.request({'action': 'reissue', 'ended': f.id, 'issuer': issuerHex(), 'maxHops': 2, 'expiry': 3000, 'feeCap': 500},
                coins: 0)))
        .primaryTx;
    iw.record(r);
    final d = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': r.id, 'to': pkhHex(h2), 'attestation': attest(r)}, coins: 0)))
        .primaryTx;
    final held = await LtVnftReceive.check(
        plugin: plugin,
        beef: beefOf(d),
        ownerAddress: addressOf(h2),
        anchorTx: anchor,
        links: [plugin.link(hex.decode(f.serialize()), hex.decode(t1.serialize()))]);
    expect(held.tx.terms.expiry, 3000);
  });

  test('refuses: a first transfer without its attestation, bad terms, a stranger\'s redemption', () async {
    final iw = issuerWallet();
    final iss = (await plugin.buildTransaction(iw.request(issue()))).primaryTx;
    iw.record(iss);
    expect(() => plugin.buildTransaction(iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(h1)}, coins: 0)),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('attestation'))));
    expect(() => plugin.buildTransaction(iw.request({...issue(), 'maxHops': 0})), throwsArgumentError);
    expect(() => plugin.buildTransaction(iw.request({...issue(), 'expiry': 500000000})), throwsArgumentError);
    final (_, t1) = await voucher();
    final stranger = Wallet([key(69)], key(69), holderTxs);
    expect(() => plugin.buildTransaction(stranger.request({'action': 'redeem', 'token': t1.id}, coins: 0)),
        throwsA(isA<StateError>().having((e) => e.message, 'message', contains('holds no key'))));
  });
}
