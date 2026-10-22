// The Note NFT plugin against stand-in wallets (support.dart): the terms in
// the metadata, a split exit, a mature exit, a call from a transaction the
// issuer's wallet does not hold, a reissue, and the guards. Every token
// input goes through the script interpreter.
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  final plugin = LtNotePlugin();
  late Transaction anchor;
  late LtIssuer issuer;

  setUpAll(() async {
    final rabin = Rabin.generateKeyPair(1024);
    anchor = await anchorFor(rabin);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  final issuerKey = key(91), h1 = key(92);
  final issuerTxs = <String, String>{}, holderTxs = <String, String>{};
  Wallet issuerWallet() => Wallet([issuerKey], issuerKey, issuerTxs);
  Wallet holderWallet() => Wallet([h1, key(93)], key(93), holderTxs);
  String attest(Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
  int fuelOf(Transaction t) => t.outputs[0].satoshis.toInt();
  Map<String, dynamic> callable() => {
        'action': 'issue',
        'issuer': hex.encode(issuer.pkh),
        'feeCap': 500,
        'exit': 30000,
        'maturity': 2000,
        'mature': NoteTerms.everything,
        'callAt': 1000,
        'call': 20000,
      };

  /// A note issued to the issuer and distributed to h1.
  Future<Transaction> distributed() async {
    final iw = issuerWallet(), hw = holderWallet();
    final iss = (await plugin.buildTransaction(iw.request(callable()))).primaryTx;
    iw.record(iss);
    final t1 = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(h1), 'attestation': attest(iss)}, coins: 0)))
        .primaryTx;
    spends(t1, 0, iss.outputs[0].script.buffer, fuelOf(iss));
    hw.record(t1);
    return t1;
  }

  test('identifies a note and names its terms and what the holder gets on each ending', () async {
    final t1 = await distributed();
    expect(plugin.identifyScript(t1.outputs[0].script), LtNotePlugin.scriptType);
    expect(LtVnftPlugin().identifyScript(t1.outputs[0].script), isNull);
    final m = plugin.extractMetadata(t1.outputs[0].script)!;
    expect(m['ownerAddress'], addressOf(h1));
    expect(m['payTo'], pkhHex(issuerKey), reason: 'by default the issuing wallet\'s own key');
    expect([m['maxHops'], m['hopsLeft'], m['exit'], m['call'], m['callAt']], [0, null, 30000, 20000, 1000]);
    expect(m['holderOnExit'], 30000);
    expect(m['holderAtMaturity'], fuelOf(t1) - 500);
    expect(m['holderIfCalled'], 20000);
  });

  test('the holder\'s exit splits the fuel; the issuer reissues from it', () async {
    final iw = issuerWallet(), hw = holderWallet();
    final t1 = await distributed();
    final e = (await plugin.buildTransaction(hw.request({'action': 'exit', 'token': t1.id}, coins: 0))).primaryTx;
    expect(plugin.validateTransactionStructure(e, 'exit'), isTrue);
    spends(e, 0, t1.outputs[0].script.buffer, fuelOf(t1));
    expect(e.outputs.last.satoshis.toInt(), 30000);
    expect(hex.encode(e.outputs.first.script.buffer), hex.encode(p2pkhScript(issuerKey)));
    iw.record(e);
    final r = (await plugin.buildTransaction(iw.request({...callable(), 'action': 'reissue', 'ended': e.id}, coins: 0))).primaryTx;
    spends(r, 0, p2pkhScript(issuerKey), e.outputs.first.satoshis.toInt());
    iw.record(r);
    final d = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': r.id, 'to': pkhHex(h1), 'attestation': attest(r)}, coins: 0)))
        .primaryTx;
    final held = await LtNoteReceive.check(
        plugin: plugin,
        beef: beefOf(d),
        ownerAddress: addressOf(h1),
        anchorTx: anchor,
        links: [plugin.link(hex.decode(e.serialize()), hex.decode(t1.serialize()))]);
    expect(held.tx.noteTerms.call, 20000);
  });

  test('the mature exit carries the maturity as nLockTime; the call is the issuer\'s, from the holder\'s raw transaction',
      () async {
    final iw = issuerWallet(), hw = holderWallet();
    final t1 = await distributed();
    final m = (await plugin.buildTransaction(hw.request({'action': 'matureExit', 'token': t1.id}, coins: 0))).primaryTx;
    spends(m, 0, t1.outputs[0].script.buffer, fuelOf(t1));
    expect(m.nLockTime, 2000);
    expect(m.outputs.single.satoshis.toInt(), greaterThanOrEqualTo(fuelOf(t1) - 500));

    expect(() => plugin.buildTransaction(iw.request({'action': 'call', 'token': t1.id}, coins: 0)),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('does not hold'))));
    final c = (await plugin.buildTransaction(iw.request({'action': 'call', 'token': t1.id, 'tokenRaw': t1.serialize()}, coins: 0)))
        .primaryTx;
    spends(c, 0, t1.outputs[0].script.buffer, fuelOf(t1));
    expect(c.nLockTime, 1000);
    expect(c.outputs.last.satoshis.toInt(), 20000);
    expect(hex.encode(c.outputs.last.script.buffer), hex.encode(p2pkhScript(h1)));
    expect(() => plugin.buildTransaction(hw.request({'action': 'call', 'token': t1.id}, coins: 0)),
        throwsA(isA<StateError>().having((e) => e.message, 'message', contains('holds no key'))));
  });

  test('refuses: end, bad terms, a stranger\'s exit, a call below callAt', () async {
    final iw = issuerWallet();
    final t1 = await distributed();
    expect(plugin.supportedActions, isNot(contains('end')));
    expect(() => plugin.buildTransaction(iw.request({...callable(), 'maturity': 600000000})), throwsArgumentError);
    final stranger = Wallet([key(99)], key(99), holderTxs);
    expect(() => plugin.buildTransaction(stranger.request({'action': 'exit', 'token': t1.id}, coins: 0)),
        throwsA(isA<StateError>().having((e) => e.message, 'message', contains('holds no key'))));
    expect(
        () => plugin.buildTransaction(
            iw.request({'action': 'call', 'token': t1.id, 'tokenRaw': t1.serialize(), 'lockHeight': 999}, coins: 0)),
        throwsA(isA<StateError>().having((e) => e.message, 'message', contains('refuses'))));
  });
}
