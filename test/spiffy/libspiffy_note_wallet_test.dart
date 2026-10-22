// The Note NFT plugin inside a real libspiffy wallet (spiffy_harness.dart).
// The wallet's root key is payTo (the issuer's); its second address is the
// holder. Issue, distribute, the holder's exit (the fuel split between the
// two), reissue from it, distribute, and the issuer's call. Only the
// issuance takes a wallet coin. Every input is run through the interpreter.
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart' as dartsv;
import 'package:libspiffy/libspiffy.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'spiffy_harness.dart';

void main() {
  final plugin = LtNotePlugin();
  final issuer = LtIssuer(Rabin.generateKeyPair(1024), dartsv.sha256([1]), dartsv.sha256([2]));
  late SpiffyHarness h;

  setUpAll(SpiffyHarness.initIsar);
  setUp(() async {
    PluginRegistry().register(plugin);
    h = SpiffyHarness();
    await h.start();
  });
  tearDown(() async {
    PluginRegistry().unregister(LtNotePlugin.id);
    await h.stop();
  });

  test('issue, distribute, exit (split), reissue, distribute, call', () async {
    await h.createWallet(coins: 4);
    Future<BEEFPaymentResponse> act(Map<String, dynamic> params, {int amount = 1}) async {
      final r = await h.pay(LtNotePlugin.id, LtNotePlugin.scriptType, params, amount: amount);
      expect(r.success, isTrue, reason: r.error);
      return r;
    }

    String attest(dartsv.Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
    final second = SpiffyHarness.pkhOfAddress(h.second), root = SpiffyHarness.pkhOfAddress(h.root);
    final terms = {
      'issuer': hex.encode(issuer.pkh),
      'feeCap': 1000,
      'exit': 20000,
      'maturity': 2000,
      'mature': NoteTerms.everything,
      'callAt': 1500,
      'call': 15000,
    };

    final iss = h.subject((await act({...terms, 'action': 'issue'})).beefBytes);
    h.checkInputs(iss);
    await h.spendable(iss.id, 0);
    final t1 = h.subject((await act({'action': 'transfer', 'token': iss.id, 'to': second, 'attestation': attest(iss)}, amount: 0))
        .beefBytes);
    h.checkInputs(t1);
    await h.spendable(t1.id, 0);

    // the holder's exit: the issuer's share at output 0, the holder's 20,000 at output 1
    final e = h.subject((await act({'action': 'exit', 'token': t1.id}, amount: 0)).beefBytes);
    h.checkInputs(e);
    expect(e.outputs.map((o) => o.script.toHex()).toList(), ['76a914${root}88ac', '76a914${second}88ac']);
    expect(e.outputs.last.satoshis.toInt(), 20000);
    await h.spendable(e.id, 0);
    await h.spendable(e.id, 1);

    // reissue from the exit's output 0, distribute, and the issuer's call
    final r = h.subject((await act({...terms, 'action': 'reissue', 'ended': e.id}, amount: 0)).beefBytes);
    h.checkInputs(r);
    await h.spendable(r.id, 0);
    final t2 = h.subject((await act({'action': 'transfer', 'token': r.id, 'to': second, 'attestation': attest(r)}, amount: 0))
        .beefBytes);
    h.checkInputs(t2);
    await h.spendable(t2.id, 0);
    final c = h.subject((await act({'action': 'call', 'token': t2.id}, amount: 0)).beefBytes);
    h.checkInputs(c);
    expect(c.nLockTime, 1500);
    expect(c.outputs.last.satoshis.toInt(), 15000);
    print('fuel: issue ${iss.outputs[0].satoshis}, exit ${e.outputs.map((o) => o.satoshis).toList()}, call ${c.outputs.map((o) => o.satoshis).toList()}; '
        'exit ${e.serialize().length ~/ 2} B, call ${c.serialize().length ~/ 2} B at 100 sat/kB');
  }, timeout: const Timeout(Duration(minutes: 8)));
}
