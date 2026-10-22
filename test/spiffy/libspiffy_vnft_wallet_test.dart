// The Voucher NFT plugin inside a real libspiffy wallet (spiffy_harness.dart).
// The wallet's root key is the issuer's redeemTo key; its second address is
// the holder. Issue to the root, distribute to the second address, redeem to
// the root, reissue from the redemption with new terms, distribute the
// successor, and force-redeem it with the root key. Only the issuance takes a
// wallet coin. Every input is run through the interpreter.
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart' as dartsv;
import 'package:libspiffy/libspiffy.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'spiffy_harness.dart';

void main() {
  final plugin = LtVnftPlugin();
  final issuer = LtIssuer(Rabin.generateKeyPair(1024), dartsv.sha256([1]), dartsv.sha256([2]));
  late SpiffyHarness h;

  setUpAll(SpiffyHarness.initIsar);
  setUp(() async {
    PluginRegistry().register(plugin);
    h = SpiffyHarness();
    await h.start();
  });
  tearDown(() async {
    PluginRegistry().unregister(LtVnftPlugin.id);
    await h.stop();
  });

  test('issue, distribute, redeem, reissue with new terms, distribute, force-redeem: one wallet coin in all', () async {
    await h.createWallet(coins: 4);
    Future<BEEFPaymentResponse> act(Map<String, dynamic> params, {int amount = 1}) async {
      final r = await h.pay(LtVnftPlugin.id, LtVnftPlugin.scriptType, params, amount: amount);
      expect(r.success, isTrue, reason: r.error);
      return r;
    }

    String attest(dartsv.Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
    int fuel(dartsv.Transaction t) => t.outputs[0].satoshis.toInt();
    Future<int> coinsAvailable() async => (await h.spiffy.walletStorage.getPaymentUTXOs(h.wallet)).where((u) => u.isAvailable).length;
    final second = SpiffyHarness.pkhOfAddress(h.second), root = SpiffyHarness.pkhOfAddress(h.root);
    final issuerHex = hex.encode(issuer.pkh);

    // issue: one coin becomes the fuel; redeemTo is the root (the first coin's key)
    final iss = h.subject((await act({'action': 'issue', 'issuer': issuerHex, 'maxHops': 2, 'expiry': 1000, 'feeCap': 500}))
        .beefBytes);
    h.checkInputs(iss);
    await h.spendable(iss.id, 0);
    final m = plugin.extractMetadata(iss.outputs[0].script)!;
    expect([m['ownerAddress'], m['redeemTo'], m['hopsLeft']], [h.root, root, 2]);
    final coinsBefore = await coinsAvailable();

    // distribute, then the holder redeems to the root
    final t1 = h.subject((await act({'action': 'transfer', 'token': iss.id, 'to': second, 'attestation': attest(iss)}, amount: 0))
        .beefBytes);
    h.checkInputs(t1);
    await h.spendable(t1.id, 0);
    final red = h.subject((await act({'action': 'redeem', 'token': t1.id}, amount: 0)).beefBytes);
    h.checkInputs(red);
    expect(red.inputs, hasLength(1));
    expect(red.outputs.single.satoshis.toInt(), greaterThanOrEqualTo(fuel(t1) - 500));
    await h.spendable(red.id, 0);

    // reissue from the redemption's output 0, with new terms
    final r = h.subject((await act(
            {'action': 'reissue', 'ended': red.id, 'issuer': issuerHex, 'maxHops': 3, 'expiry': 1200, 'feeCap': 400},
            amount: 0))
        .beefBytes);
    h.checkInputs(r);
    expect(r.inputs.single.prevTxnId, red.id);
    await h.spendable(r.id, 0);
    expect(plugin.extractMetadata(r.outputs[0].script)!['maxHops'], 3);

    // distribute the successor; the issuer (root key) forces its redemption
    final t2 = h.subject((await act({'action': 'transfer', 'token': r.id, 'to': second, 'attestation': attest(r)}, amount: 0))
        .beefBytes);
    h.checkInputs(t2);
    await h.spendable(t2.id, 0);
    final forced = h.subject((await act({'action': 'forceRedeem', 'token': t2.id}, amount: 0)).beefBytes);
    h.checkInputs(forced);
    expect(forced.nLockTime, 1200);
    expect(forced.outputs.single.script.toHex(), '76a914${root}88ac');

    expect(await coinsAvailable(), greaterThanOrEqualTo(coinsBefore), reason: 'no wallet coin after the issuance');
    for (final t in [iss, t1, r, t2]) {
      expect(await h.available(t.id, 0), isFalse, reason: '${t.id}:0 is spent');
    }
    print('fuel: issue ${fuel(iss)}, t1 ${fuel(t1)}, redeemed ${red.outputs.single.satoshis}, successor ${fuel(r)}, '
        't2 ${fuel(t2)}, forced ${forced.outputs.single.satoshis}; redeem ${red.serialize().length ~/ 2} B, '
        'force-redeem ${forced.serialize().length ~/ 2} B at 100 sat/kB');
  }, timeout: const Timeout(Duration(minutes: 8)));
}
