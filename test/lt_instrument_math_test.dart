// The Note's and the Voucher's arithmetic against the builder's own
// transactions: the amount a function gives is the amount the ending pays.
//
// Run: dart test test/lt_instrument_math_test.dart
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_fnft_builder.dart';
import 'package:libtokensv/src/lt/lt_identity.dart';
import 'package:libtokensv/src/lt/lt_instrument_math.dart';

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

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x4a7d0000 + i));
var _coin = 0;
LtCoin coin(SVPrivateKey k, [int sats = 100000]) => LtCoin(outpoint(sha256(le(++_coin, 4)), _coin % 3), k.lt, sats);

void spend(List<int> raw, int i, List<int> lock, int sats) {
  final tx = Transaction.fromHex(hex.encode(raw));
  Interpreter().correctlySpends(tx.inputs[i].script!, SVScript.fromByteArray(Uint8List.fromList(lock)), tx, i, flags, Coin.valueOf(BigInt.from(sats)));
}

List<(int, String)> outsOf(List<int> raw) =>
    [for (final o in Transaction.fromHex(hex.encode(raw)).outputs) (o.satoshis.toInt(), hex.encode(o.script.buffer.sublist(3, 23)))];

void main() {
  final issuerKey = key(1), holder = key(2);
  final payTo = pkhOf(issuerKey);
  late LtIssuer issuer;

  setUpAll(() async {
    final rabin = Rabin.generateKeyPair(1024);
    issuer = LtIdentity.issuer(rabin, await nft.anchorFor(rabin, seed: 41));
  });

  /// A note under [terms] with 50,000 sats of fuel, held by [holder] after one transfer.
  (FnftBuilder, FnftTx) note(NoteTerms terms) {
    final b = FnftBuilder.note();
    final iss = b.issue(first: coin(issuerKey, 51000), issuerPkh: issuer.pkh, owner: payTo, terms: terms);
    iss.x = issuer.attest(iss.txid);
    final t = b.transfer(from: iss, ownerKey: issuerKey.lt, to: pkhOf(holder), fee: 100);
    spend(t.raw, 0, iss.lock(b.code), iss.value);
    return (b, t);
  }

  test('a deposit: the exit before maturity and the mature exit pay what the functions say', () {
    final terms = NoteTerms.deposit(payTo: payTo, feeCap: 500, at: 300, early: 40000);
    final (b, n) = note(terms);
    final before = terms.endingsAt(height: 200, value: n.value, fee: 300);
    expect(before.map((e) => (e.name, e.available)), [('exit', true), ('mature', false), ('call', false)]);
    final x = b.exit(from: n, ownerKey: holder.lt, fee: 300);
    spend(x, 0, n.lock(b.code), n.value);
    expect(outsOf(x), [(before[0].issuer, hex.encode(payTo)), (before[0].holder, hex.encode(pkhOf(holder)))]);
    expect(terms.holderAt(height: 200, value: n.value, fee: 300), 40000);
    final after = terms.endingsAt(height: 300, value: n.value, fee: 300);
    expect(after.map((e) => (e.name, e.available)), [('exit', false), ('mature', true), ('call', false)]);
    final m = b.matureExit(from: n, ownerKey: holder.lt, fee: 300);
    spend(m, 0, n.lock(b.code), n.value);
    expect(outsOf(m), [(after[1].holder, hex.encode(pkhOf(holder)))], reason: 'everything to the holder, nothing to the issuer');
    expect(terms.holderAtMaturity(value: n.value, fee: 300), n.value - 300);
    expect(terms.blocksToMaturity(200), 100);
    expect(terms.blocksToCall(200), isNull);
    expect(terms.callCost(value: n.value, fee: 300), 0);
    expect(terms.yieldPerBlock(price: 45000, value: n.value, height: 200, fee: 300), closeTo((n.value - 300 - 45000) / 45000 / 100, 1e-12));
    expect(terms.yieldPerBlock(price: 45000, value: n.value, height: 300, fee: 300), isNull);
  });

  test('a callable: the call pays the floor and the function prices what the holder loses', () {
    final terms = NoteTerms.callable(payTo: payTo, feeCap: 500, at: 300, callAt: 150, floor: 30000);
    final (b, n) = note(terms);
    expect(terms.callableBeforeMaturity, isTrue);
    final at200 = terms.endingsAt(height: 200, value: n.value, fee: 300);
    expect(at200.map((e) => (e.name, e.available, e.by)), [('exit', true, 'holder'), ('mature', false, 'holder'), ('call', true, 'issuer')]);
    expect(at200[0].holder, 0, reason: 'a zero-coupon exit pays the holder nothing');
    final c = b.call(from: n, issuerKey: issuerKey.lt, fee: 300);
    spend(c, 0, n.lock(b.code), n.value);
    expect(outsOf(c), [(at200[2].issuer, hex.encode(payTo)), (at200[2].holder, hex.encode(pkhOf(holder)))]);
    expect(terms.holderIfCalled(value: n.value, fee: 300), 30000);
    expect(terms.callCost(value: n.value, fee: 300), n.value - 300 - 30000);
    expect(terms.blocksToCall(100), 50);
  });

  test('a voucher: blocks to expiry, the forced-redemption height, and what a redemption pays', () {
    final terms = VoucherTerms(maxHops: 5, expiry: 400, redeemTo: payTo, feeCap: 500);
    expect(terms.blocksToExpiry(350), 50);
    expect(terms.forcedRedemptionHeight, 400);
    expect(terms.redeemed(value: 50000, fee: 300), 49700);
    expect(() => terms.redeemed(value: 50000, fee: 501), throwsArgumentError);
    final b = FnftBuilder.voucher();
    final iss = b.issue(first: coin(issuerKey, 51000), issuerPkh: issuer.pkh, owner: payTo, terms: terms);
    iss.x = issuer.attest(iss.txid);
    final t = b.transfer(from: iss, ownerKey: issuerKey.lt, to: pkhOf(holder), fee: 100);
    spend(t.raw, 0, iss.lock(b.code), iss.value);
    expect(t.hopsLeft, 4);
    final r = b.redeem(from: t, ownerKey: holder.lt, fee: 300);
    spend(r, 0, t.lock(b.code), t.value);
    expect(outsOf(r).single, (terms.redeemed(value: t.value, fee: 300), hex.encode(payTo)));
  });
}
