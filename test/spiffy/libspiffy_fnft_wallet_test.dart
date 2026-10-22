// The Fuelled NFT plugin inside a real libspiffy wallet (spiffy_harness.dart).
// The wallet issues to its own key (its coin becomes the fuel), distributes
// to a second address of its own, tops it up, takes it back, reissues it
// (fuelled by the ended token's value), distributes the successor, and burns
// it. Transfers, the reissue and the burn take no wallet coin: libspiffy
// selects and reserves none. Every input is run through the interpreter.
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart' as dartsv;
import 'package:libspiffy/libspiffy.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'spiffy_harness.dart';

void main() {
  final plugin = LtFnftPlugin();
  final issuer = LtIssuer(Rabin.generateKeyPair(1024), dartsv.sha256([1]), dartsv.sha256([2]));
  late SpiffyHarness h;

  setUpAll(SpiffyHarness.initIsar);
  setUp(() async {
    PluginRegistry().register(plugin);
    h = SpiffyHarness();
    await h.start();
  });
  tearDown(() async {
    PluginRegistry().unregister(LtFnftPlugin.id);
    await h.stop();
  });

  test('issue, distribute, top up, take back, reissue, distribute, burn: transfers take no wallet coin', () async {
    await h.createWallet(coins: 4);
    Future<BEEFPaymentResponse> act(Map<String, dynamic> params, {int amount = 1}) async {
      final r = await h.pay(LtFnftPlugin.id, LtFnftPlugin.scriptType, params, amount: amount);
      expect(r.success, isTrue, reason: r.error);
      return r;
    }

    String attest(dartsv.Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
    int fuel(dartsv.Transaction t) => t.outputs[0].satoshis.toInt();
    Future<int> coinsAvailable() async => (await h.spiffy.walletStorage.getPaymentUTXOs(h.wallet)).where((u) => u.isAvailable).length;
    final second = SpiffyHarness.pkhOfAddress(h.second), root = SpiffyHarness.pkhOfAddress(h.root);

    // issue: one 60,000-sat coin becomes the fuel
    final iss = h.subject((await act({'action': 'issue', 'issuer': hex.encode(issuer.pkh)})).beefBytes);
    h.checkInputs(iss);
    await h.spendable(iss.id, 0);
    final m = plugin.extractMetadata(iss.outputs[0].script)!;
    expect(m['ownerAddress'], h.root);
    expect(m['fuel'], fuel(iss));
    final coinsBefore = await coinsAvailable();

    // distribute: no wallet coin is selected, reserved or spent
    final t1r = await act({'action': 'transfer', 'token': iss.id, 'to': second, 'attestation': attest(iss)}, amount: 0);
    expect(t1r.spentUtxoKeys, ['${iss.id}:0'], reason: 'only the token');
    final t1 = h.subject(t1r.beefBytes);
    expect(t1.inputs, hasLength(1));
    h.checkInputs(t1);
    await h.spendable(t1.id, 0);
    expect(await coinsAvailable(), coinsBefore, reason: 'the wallet\'s coins are untouched');
    expect(fuel(t1), lessThan(fuel(iss)));

    // top up, to the same (second) address: one wallet coin swept in
    final up = h.subject((await act({'action': 'topup', 'token': t1.id, 'to': second})).beefBytes);
    expect(up.inputs, hasLength(2));
    h.checkInputs(up);
    await h.spendable(up.id, 0);
    expect(fuel(up), greaterThan(fuel(t1) + 59000));

    // take it back to the root (the second address's key signs)
    final g = h.subject((await act({'action': 'transfer', 'token': up.id, 'to': root}, amount: 0)).beefBytes);
    h.checkInputs(g);
    await h.spendable(g.id, 0);

    // reissue: no wallet coin; the successor is fuelled by the ended token
    final rr = await act({'action': 'reissue', 'token': g.id, 'issuer': hex.encode(issuer.pkh)}, amount: 0);
    final e = h.subject(rr.beefBytes);
    final r = h.subject(rr.witnessBeefBytes!);
    h.checkInputs(e);
    h.checkInputs(r);
    expect(r.inputs.single.prevTxnId, e.id);
    expect(fuel(r), greaterThan(fuel(g) - 2000));
    await h.spendable(r.id, 0);

    // distribute the successor, then burn it from the second address
    final t2 = h.subject((await act({'action': 'transfer', 'token': r.id, 'to': second, 'attestation': attest(r)}, amount: 0)).beefBytes);
    h.checkInputs(t2);
    await h.spendable(t2.id, 0);
    final burn = h.subject((await act({'action': 'end', 'token': t2.id, 'irreversible': true}, amount: 0)).beefBytes);
    expect(burn.inputs, hasLength(1));
    h.checkInputs(burn);
    expect(burn.outputs.single.satoshis.toInt(), greaterThan(fuel(t2) - 100));

    // spent tokens are not the wallet's to spend; a second transfer is refused
    for (final t in [iss, t1, up, g, r, t2]) {
      expect(await h.available(t.id, 0), isFalse, reason: '${t.id}:0 is spent');
    }
    final again = await h.pay(LtFnftPlugin.id, LtFnftPlugin.scriptType, {'action': 'transfer', 'token': g.id, 'to': second}, amount: 0);
    expect(again.success, isFalse);
    expect(again.error, contains('${g.id}:0'));
    print('fuel: issue ${fuel(iss)}, t1 ${fuel(t1)}, topped up ${fuel(up)}, g ${fuel(g)}, successor ${fuel(r)}, t2 ${fuel(t2)}, '
        'burn returned ${burn.outputs.single.satoshis}; transfer ${t1.serialize().length ~/ 2} B at 100 sat/kB');
  }, timeout: const Timeout(Duration(minutes: 8)));
}
