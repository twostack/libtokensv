// An issue with a payload inside a real libspiffy wallet (spiffy_harness.dart):
// the payment coordinator funds the issue with two coins, the plugin returns
// the payload transaction and the issuance paired, the coordinator validates
// both (the primary as an issue: a payload transaction passes), records them
// and makes the BEEF; the token then transfers. Every input is run through
// the interpreter. (The ruggerbot developers' report: libspiffy refused the
// issue, and the plugin asked for two coins and spent one.)
import 'dart:convert';
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

  test('issue with a payload through libspiffy: two coins, both spent; the token transfers', () async {
    await h.createWallet();
    final content = utf8.encode('{"name":"Wallet Payload Token"}');
    final r = await h.pay(LtNftPlugin.id, LtNftPlugin.scriptType, {'action': 'issue', 'issuer': hex.encode(issuer.pkh), 'payload': hex.encode(content)}, amount: 70000);
    expect(r.success, isTrue, reason: r.error);
    expect(r.witnessTxid, isNotNull, reason: 'the issuance is paired with the payload transaction');
    final p = h.subject(r.beefBytes);
    final iss = h.subject(r.witnessBeefBytes!);
    expect(LtPayload.isPayloadTx(hex.decode(p.serialize())), isTrue);
    expect(utf8.decode(LtPayload.of(hex.decode(iss.serialize()), hex.decode(p.serialize()))), utf8.decode(content));
    h.checkInputs(p);
    h.checkInputs(iss);
    expect(iss.inputs[1].prevTxnId, p.id, reason: 'input 1 spends the payload transaction\'s output 1');
    expect(iss.inputs[0].prevTxnId, isNot(p.id), reason: 'input 0 is the second funding coin, not the payload transaction\'s change');
    await h.spendable(iss.id, 1);
    expect(plugin.extractMetadata(iss.outputs[1].script)!['ownerAddress'], h.root);
    final attestation = hex.encode(issuer.attest(hex.decode(iss.id).reversed.toList()));
    final t1 = h.subject((await h.pay(LtNftPlugin.id, LtNftPlugin.scriptType, {'action': 'transfer', 'token': iss.id, 'to': SpiffyHarness.pkhOfAddress(h.second), 'attestation': attestation})).beefBytes);
    h.checkInputs(t1);
    await h.spendable(t1.id, 1);
    expect(plugin.extractMetadata(t1.outputs[1].script)!['ownerAddress'], h.second);
  });
}
