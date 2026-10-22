// The covenant NFT plugin inside a real libspiffy wallet (spiffy_harness.dart):
// payments go to the payment coordinator, which selects and reserves the
// funding, calls the plugin, has every input signed by the wallet aggregate
// (the token's input by the key the plugin names with keyFor), records the
// transactions and makes the BEEF. ARC is stubbed.
//
// The wallet issues to its own key, distributes to a second address of its
// own, takes it back (a redemption), reissues it, and distributes the
// successor. Every input of every transaction is run through the script
// interpreter.
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart' as dartsv;
import 'package:libspiffy/libspiffy.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'spiffy_harness.dart';

void main() {
  final plugin = LtNftPlugin();
  final issuer = LtIssuer(Rabin.generateKeyPair(1024), dartsv.sha256([1]), dartsv.sha256([2]));
  late SpiffyHarness h;

  setUpAll(SpiffyHarness.initIsar);
  setUp(() async {
    PluginRegistry().register(plugin);
    h = SpiffyHarness();
    await h.start();
  });
  tearDown(() async {
    PluginRegistry().unregister(LtNftPlugin.id);
    await h.stop();
  });

  test('a wallet issues to itself, distributes, takes back, reissues and distributes again', () async {
    await h.createWallet();
    Future<BEEFPaymentResponse> act(Map<String, dynamic> params, {int amount = 1}) async {
      final r = await h.pay(LtNftPlugin.id, LtNftPlugin.scriptType, params, amount: amount);
      expect(r.success, isTrue, reason: r.error);
      return r;
    }

    String attest(dartsv.Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
    final second = SpiffyHarness.pkhOfAddress(h.second), root = SpiffyHarness.pkhOfAddress(h.root);

    // issue to self: two funding coins (an amount above one coin makes the
    // selection take two)
    final iss = h.subject((await act({'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, amount: 70000)).beefBytes);
    h.checkInputs(iss);
    await h.spendable(iss.id, 1);
    expect(plugin.extractMetadata(iss.outputs[1].script)!['ownerAddress'], h.root);

    // distribute to the second address (the root key signs the token input)
    final t1 = h.subject((await act({'action': 'transfer', 'token': iss.id, 'to': second, 'attestation': attest(iss)})).beefBytes);
    h.checkInputs(t1);
    await h.spendable(t1.id, 1);
    expect(plugin.extractMetadata(t1.outputs[1].script)!['ownerAddress'], h.second);

    // take it back: the second address's key signs the token input
    final g = h.subject((await act({'action': 'transfer', 'token': t1.id, 'to': root})).beefBytes);
    h.checkInputs(g);
    await h.spendable(g.id, 1);

    // reissue: the end and its successor, paired
    final rr = await act({'action': 'reissue', 'token': g.id, 'issuer': hex.encode(issuer.pkh)}, amount: 70000);
    final e = h.subject(rr.beefBytes);
    final r = h.subject(rr.witnessBeefBytes!);
    h.checkInputs(e);
    h.checkInputs(r);
    expect(r.inputs[0].prevTxnId, e.id);
    expect(r.inputs[0].prevTxnOutputIndex, 0);
    await h.spendable(r.id, 1);

    // distribute the successor
    final t2 = h.subject((await act({'action': 'transfer', 'token': r.id, 'to': second, 'attestation': attest(r)})).beefBytes);
    h.checkInputs(t2);
    await h.spendable(t2.id, 1);

    // only the last token output is the wallet's to spend
    for (final t in [iss, t1, g, r]) {
      expect(await h.available(t.id, 1), isFalse, reason: '${t.id}:1 is spent by a payment');
    }
    expect(await h.available(t2.id, 1), isTrue);
    // a second transfer of a token already sent is refused
    final again = await h.pay(LtNftPlugin.id, LtNftPlugin.scriptType, {'action': 'transfer', 'token': g.id, 'to': second});
    expect(again.success, isFalse);
    expect(again.error, contains('${g.id}:1'));
    // the token outputs never funded a payment
    final tokens = await h.spiffy.walletStorage.getUTXOsByPlugin(h.wallet, LtNftPlugin.id);
    final payments = await h.spiffy.walletStorage.getPaymentUTXOs(h.wallet);
    expect(payments.where((u) => tokens.any((t) => t.key == u.key)), isEmpty);
  }, timeout: const Timeout(Duration(minutes: 6)));
}
