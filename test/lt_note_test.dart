// The Note NFT, TSL1_LT_NOTE: a fuelled token whose terms say, for each way
// it can end, how much of the fuel the holder gets; the issuer (payTo) gets
// the rest. Every preset's lifecycle through the interpreter, each refusal,
// the hop limit and no limit, and succession.
//
// Run: dart test test/lt_note_test.dart
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_fnft_builder.dart';
import 'package:libtokensv/src/lt/lt_fnft_script_gen.dart';
import 'package:libtokensv/src/lt/lt_fnft_wallet.dart';
import 'package:libtokensv/src/lt/lt_identity.dart';
import 'package:libtokensv/src/lt/lt_wallet.dart';

import 'lt_nft_test.dart' as nft show anchorFor;

final flags = {
  VerifyFlag.SIGHASH_FORKID,
  VerifyFlag.LOW_S,
  VerifyFlag.NULLFAIL,
  VerifyFlag.MINIMALDATA,
  VerifyFlag.MINIMALIF,
  VerifyFlag.SIGPUSHONLY,
  VerifyFlag.UTXO_AFTER_GENESIS,
};

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x40e70000 + i));
var _coin = 0;
LtCoin coin(SVPrivateKey k, [int sats = 100000]) => LtCoin(outpoint(sha256(le(++_coin, 4)), _coin % 3), k.lt, sats);

void spend(List<int> raw, int i, List<int> lock, int sats) {
  final tx = Transaction.fromHex(hex.encode(raw));
  Interpreter().correctlySpends(
      tx.inputs[i].script!, SVScript.fromByteArray(Uint8List.fromList(lock)), tx, i, flags, Coin.valueOf(BigInt.from(sats)));
}

Matcher refused() => throwsA(isA<ScriptException>());

void main() {
  final b = FnftBuilder.note();
  late Transaction anchor;
  late LtIssuer issuer;
  final issuerKey = key(1);
  final payTo = pkhOf(issuerKey);
  const feeCap = 500;

  setUpAll(() async {
    final rabin = Rabin.generateKeyPair(1024);
    anchor = await nft.anchorFor(rabin, seed: 31);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  /// A note under [terms] with 50,000 sats of fuel, issued to the issuer and
  /// passed on [hops] times; the last holder is key(100 + hops).
  List<FnftTx> note(NoteTerms terms, {int hops = 3}) {
    final iss = b.issue(first: coin(issuerKey, 51000), issuerPkh: issuer.pkh, owner: payTo, terms: terms);
    iss.x = issuer.attest(iss.txid);
    final c = [iss];
    for (var n = 1; n <= hops; n++) {
      final owner = n == 1 ? issuerKey : key(100 + n - 1);
      final t = b.transfer(from: c.last, ownerKey: owner.lt, to: pkhOf(key(100 + n)), fee: 100);
      spend(t.raw, 0, c.last.lock(b.code), c.last.value);
      c.add(t);
    }
    return c;
  }

  Transaction txOf(List<int> raw) => Transaction.fromHex(hex.encode(raw));
  List<(int, String)> outsOf(List<int> raw) =>
      [for (final o in txOf(raw).outputs) (o.satoshis.toInt(), hex.encode(o.script.buffer.sublist(3, 23)))];

  test('the code: Fuelled and Voucher code unchanged beside it', () {
    expect(b.code.length, 3479);
    expect(FnftBuilder.standard().code.length, 2471);
    expect(FnftBuilder.voucher().code.length, 2726);
    expect(b.L.size, 215);
  });

  group('presets: issue, three transfers, every ending each allows', () {
    test('zero-coupon: before maturity the issuer gets everything; from maturity the holder', () {
      final t = NoteTerms.zeroCoupon(payTo: payTo, feeCap: feeCap, at: 1000);
      final c = note(t);
      final holder = key(103), last = c.last;
      final early = b.exit(from: last, ownerKey: holder.lt, fee: 300);
      spend(early, 0, last.lock(b.code), last.value);
      expect(outsOf(early), [(last.value - 300, hex.encode(payTo))]);
      final late = b.matureExit(from: last, ownerKey: holder.lt, fee: 300);
      spend(late, 0, last.lock(b.code), last.value);
      expect(outsOf(late), [(last.value - 300, hex.encode(pkhOf(holder)))]);
      expect(txOf(late).nLockTime, 1000);
    });

    test('deposit: an early exit pays the holder the early amount, the issuer the rest', () {
      final t = NoteTerms.deposit(payTo: payTo, feeCap: feeCap, at: 1000, early: 30000);
      final c = note(t);
      final last = c.last;
      final e = b.exit(from: last, ownerKey: key(103).lt, fee: 300);
      spend(e, 0, last.lock(b.code), last.value);
      expect(outsOf(e), [(last.value - 300 - 30000, hex.encode(payTo)), (30000, hex.encode(pkhOf(key(103))))]);
    });

    test('callable: the issuer calls at callAt, paying the holder the floor', () {
      final t = NoteTerms.callable(payTo: payTo, feeCap: feeCap, at: 2000, callAt: 1000, floor: 20000);
      final c = note(t);
      final last = c.last;
      final x = b.call(from: last, issuerKey: issuerKey.lt, fee: 300);
      spend(x, 0, last.lock(b.code), last.value);
      expect(outsOf(x), [(last.value - 300 - 20000, hex.encode(payTo)), (20000, hex.encode(pkhOf(key(103))))]);
      expect(txOf(x).nLockTime, 1000);
      expect(txOf(x).inputs.single.sequenceNumber, FnftBuilder.nonFinal);
    });

    test('insured: a call never pays the holder less than the floor; voucher-like: nothing', () {
      final c = note(NoteTerms.insured(payTo: payTo, feeCap: feeCap, callAt: 500, floor: 10000));
      final x = b.call(from: c.last, issuerKey: issuerKey.lt, fee: 300);
      spend(x, 0, c.last.lock(b.code), c.last.value);
      expect(outsOf(x).last, (10000, hex.encode(pkhOf(key(103)))));
      final v = note(NoteTerms.voucher(payTo: payTo, feeCap: feeCap, expiry: 500));
      final y = b.call(from: v.last, issuerKey: issuerKey.lt, fee: 300);
      spend(y, 0, v.last.lock(b.code), v.last.value);
      expect(outsOf(y), [(v.last.value - 300, hex.encode(payTo))]);
      final z = b.exit(from: v.last, ownerKey: key(103).lt, fee: 300);
      spend(z, 0, v.last.lock(b.code), v.last.value);
      expect(outsOf(z), [(v.last.value - 300, hex.encode(payTo))]);
    });

    test('a note whose value fell below the mature amount pays the holder everything', () {
      final t = NoteTerms(payTo: payTo, feeCap: feeCap, exit: 0, maturity: 100, mature: 60000, callAt: NoteTerms.never, call: 0);
      final c = note(t);
      final m = b.matureExit(from: c.last, ownerKey: key(103).lt, fee: 300);
      spend(m, 0, c.last.lock(b.code), c.last.value);
      expect(outsOf(m), [(c.last.value - 300, hex.encode(pkhOf(key(103))))]);
    });
  });

  group('refusals, each on the value compared', () {
    final deposit = NoteTerms.deposit(payTo: payTo, feeCap: feeCap, at: 1000, early: 30000);

    test('an exit taking one sat of the issuer\'s share: refused; paying the issuer one under: refused', () {
      final c = note(deposit);
      final last = c.last;
      final rest = last.value - feeCap;
      List<int> body(int x0, int x1) => [...le(x0, 8), ...le(x1, 8)];
      // with the whole cap as fee, the issuer's share is exactly rest - early
      final honest = b.exit(from: last, ownerKey: key(103).lt, fee: feeCap, bodyOverride: body(rest - 30000, 30000));
      spend(honest, 0, last.lock(b.code), last.value);
      final greedy = b.exit(from: last, ownerKey: key(103).lt, fee: feeCap, bodyOverride: body(rest - 30001, 30001));
      expect(() => spend(greedy, 0, last.lock(b.code), last.value), refused());
      // with the issuer's-share clause removed, the greedy exit is accepted
      final weak = FnftBuilder(FnftScriptGen.weakened(FuelLayout.note, noteIssuerShare: false).code().buffer, FuelLayout.note);
      final wIss = weak.issue(first: coin(issuerKey, 51000), issuerPkh: issuer.pkh, owner: payTo, terms: deposit);
      wIss.x = issuer.attest(wIss.txid);
      final wt = weak.transfer(from: wIss, ownerKey: issuerKey.lt, to: pkhOf(key(103)), fee: 100);
      final wRest = wt.value - feeCap;
      final wGreedy = weak.exit(from: wt, ownerKey: key(103).lt, fee: feeCap, bodyOverride: body(wRest - 30001, 30001));
      spend(wGreedy, 0, wt.lock(weak.code), wt.value);
      final short = b.exit(from: last, ownerKey: key(103).lt, fee: feeCap, bodyOverride: body(rest - 30001, 30000));
      expect(() => spend(short, 0, last.lock(b.code), last.value), refused());
      // one output to the holder when the holder's amount is below everything
      final all = b.exit(from: last, ownerKey: key(103).lt, fee: feeCap, bodyOverride: le(rest, 8));
      expect(() => spend(all, 0, last.lock(b.code), last.value), refused());
    });

    test('a mature exit with nLockTime below maturity, a final sequence, a timestamp: refused', () {
      final c = note(deposit);
      final last = c.last;
      // with the lock-time rule removed, the early one is accepted
      final weak = FnftBuilder(FnftScriptGen.weakened(FuelLayout.note, noteLock: false).code().buffer, FuelLayout.note);
      final wIss = weak.issue(first: coin(issuerKey, 51000), issuerPkh: issuer.pkh, owner: payTo, terms: deposit);
      wIss.x = issuer.attest(wIss.txid);
      final wt = weak.transfer(from: wIss, ownerKey: issuerKey.lt, to: pkhOf(key(103)), fee: 100);
      spend(weak.matureExit(from: wt, ownerKey: key(103).lt, fee: 300, lockHeight: 999), 0, wt.lock(weak.code), wt.value);
      for (final m in [
        b.matureExit(from: last, ownerKey: key(103).lt, fee: 300, lockHeight: 999),
        b.matureExit(from: last, ownerKey: key(103).lt, fee: 300, sequence: 0xffffffff),
        b.matureExit(from: last, ownerKey: key(103).lt, fee: 300, lockHeight: 500000001),
      ]) {
        expect(() => spend(m, 0, last.lock(b.code), last.value), refused());
      }
    });

    test('a call below callAt, under the floor, by another key, naming another owner: refused', () {
      final t = NoteTerms.callable(payTo: payTo, feeCap: feeCap, at: 2000, callAt: 1000, floor: 20000);
      final c = note(t);
      final last = c.last;
      final rest = last.value - 300;
      for (final x in [
        b.call(from: last, issuerKey: issuerKey.lt, fee: 300, lockHeight: 999),
        b.call(from: last, issuerKey: issuerKey.lt, fee: 300, bodyOverride: [...le(rest - 19999, 8), ...le(19999, 8)]),
        b.call(from: last, issuerKey: key(77).lt, fee: 300),
        b.call(from: last, issuerKey: issuerKey.lt, fee: 300, ownerOverride: pkhOf(key(78))),
      ]) {
        expect(() => spend(x, 0, last.lock(b.code), last.value), refused());
      }
    });

    test('a transfer that changes a term: refused; a cheap-path spend: refused', () {
      final c = note(deposit, hops: 1);
      final patched = b.transfer(
          from: c.last, ownerKey: key(101).lt, to: pkhOf(key(102)), fee: 100,
          patchHeader: (h) => [...h]..[b.L.exit] ^= 1);
      expect(() => spend(patched.raw, 0, c.last.lock(b.code), c.last.value), refused());
      // the forward check on the header from the issuer to the owner spans
      // the terms: the comparison names them
      expect(() => spend(patched.raw, 0, c.last.lock(b.code), c.last.value),
          throwsA(isA<ScriptException>().having((e) => e.error, 'error', ScriptError.SCRIPT_ERR_EQUALVERIFY)));
      final sig = signInput(key(101).lt, prevouts: c.last.out, input: 0, scriptCode: b.code, sats: c.last.value,
          outputs: [...le(c.last.value - 100, 8), 0x19, ...p2pkh(pkhOf(key(101)))], nOut: 1);
      final cheap = cat([
        le(1, 4), [1], c.last.out, varint(sig.length + 35), push(sig), push(key(101).lt.pub), le(0xffffffff, 4), //
        [1], le(c.last.value - 100, 8), [0x19], p2pkh(pkhOf(key(101))), le(0, 4),
      ]);
      expect(() => spend(cheap, 0, c.last.lock(b.code), c.last.value), refused());
      expect(() => b.end(from: c.last, ownerKey: key(101).lt, payTo: pkhOf(key(101))), throwsArgumentError);
    });

    test('the hop limit: three transfers, a fourth refused; with no limit the counter stays 0', () {
      final limited = NoteTerms(maxHops: 3, payTo: payTo, feeCap: feeCap, exit: 0, maturity: 10, mature: NoteTerms.everything,
          callAt: NoteTerms.never, call: 0);
      final c = note(limited);
      expect(c.last.hopsLeft, 0);
      expect(() => b.transfer(from: c.last, ownerKey: key(103).lt, to: pkhOf(key(104)), fee: 100), throwsArgumentError);
      final past = b.transfer(from: c.last, ownerKey: key(103).lt, to: pkhOf(key(104)), fee: 100, counterOverride: 4);
      expect(() => spend(past.raw, 0, c.last.lock(b.code), c.last.value), refused());

      final open = note(NoteTerms.zeroCoupon(payTo: payTo, feeCap: feeCap, at: 1000), hops: 25);
      expect([for (final t in open) t.counter].toSet(), {0});
      expect(open.last.hopsLeftOrNull, isNull);
    });
  });

  group('receiving and succession', () {
    test('the payee check, and a record rebuilt from the issuer, owner and terms alone', () async {
      final t = NoteTerms.deposit(payTo: payTo, feeCap: feeCap, at: 1000, early: 30000);
      final c = note(t);
      final held = await FnftReceive.check(b: b, raw: c.last.raw, ownerPkh: pkhOf(key(103)), anchorTx: anchor);
      expect(held.tx.noteTerms.exit, 30000);
      final again = b.fromRecOf(c.last.rec, issuer: issuer.pkh, owner: pkhOf(key(103)), terms: t);
      expect(hex.encode(again.txid), hex.encode(c.last.txid));
      final counted = NoteTerms(maxHops: 5, payTo: payTo, feeCap: feeCap, exit: 0, maturity: 10, mature: NoteTerms.everything,
          callAt: NoteTerms.never, call: 0);
      final d = note(counted);
      expect(hex.encode(b.fromRecOf(d.last.rec, issuer: issuer.pkh, owner: pkhOf(key(103)), terms: counted).txid),
          hex.encode(d.last.txid));
    });

    test('a reissue from an ending that pays the issuer: the payee follows the link; from one that does not: none', () async {
      final t = NoteTerms.voucher(payTo: payTo, feeCap: feeCap, expiry: 500);
      final c = note(t);
      final ended = b.exit(from: c.last, ownerKey: key(103).lt, fee: 300);
      final r = b.reissue(ended: ended, endKey: issuerKey.lt, issuerPkh: issuer.pkh,
          terms: NoteTerms.zeroCoupon(payTo: payTo, feeCap: feeCap, at: 3000));
      r.x = issuer.attest(r.txid);
      final d = b.transfer(from: r, ownerKey: issuerKey.lt, to: pkhOf(key(200)), fee: 100);
      final held = await FnftReceive.check(
          b: b, raw: d.raw, ownerPkh: pkhOf(key(200)), anchorTx: anchor, links: [LtLink(ended, c.last.rec, t.bytes)]);
      expect(hex.encode(held.originId), hex.encode(c.first.txid));
      expect(held.tx.noteTerms.maturity, 3000);

      final allToHolder = note(NoteTerms.zeroCoupon(payTo: payTo, feeCap: feeCap, at: 10));
      final m = b.matureExit(from: allToHolder.last, ownerKey: key(103).lt, fee: 300);
      expect(() => b.reissue(ended: m, endKey: issuerKey.lt, issuerPkh: issuer.pkh, terms: t), throwsArgumentError,
          reason: 'output 0 pays the holder: there is nothing for a successor to spend');
    });
  });
}
