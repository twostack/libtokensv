// The sale versions of the fuelled family (docs/RUGGERBOT_TOKENS_PLAN.md, P5,
// decision D1; WITNESS_LINEAGE_RESEARCH.md 9.13): TSL1_LT_FNFT_S, _VNFT_S and
// _NOTE_S, each with a pay output, so that it can be sold in its own transfer. A sale: input 0 the seller's token, input 1 the
// buyer's coin; output 0 the token (the buyer's), output 1 the price to the
// seller. Both sides sign SIGHASH_ALL, as in the covenant NFT's swap.
//
// Run: dart test test/lt_fnft_sale_test.dart
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

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x5a1e0000 + i));
var _coin = 0;
LtCoin coin(SVPrivateKey k, [int sats = 100000]) => LtCoin(outpoint(sha256(le(++_coin, 4)), _coin % 3), k.lt, sats);

void spend(List<int> raw, int i, List<int> lock, int sats) {
  final tx = Transaction.fromHex(hex.encode(raw));
  Interpreter().correctlySpends(
      tx.inputs[i].script!, SVScript.fromByteArray(Uint8List.fromList(lock)), tx, i, flags, Coin.valueOf(BigInt.from(sats)));
}

void main() {
  group('TSL1_LT_VNFT_S and TSL1_LT_NOTE_S', termedSales);
  final b = FnftBuilder.saleable();
  late Transaction anchor;
  late LtIssuer issuer;
  final issuerKey = key(1), seller = key(2), buyer = key(3);

  setUpAll(() async {
    final rabin = Rabin.generateKeyPair(1024);
    anchor = await nft.anchorFor(rabin, seed: 41);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  /// Issuance and [hops] transfers ending at the seller.
  List<FnftTx> chain(int hops) {
    final iss = b.issue(first: coin(issuerKey, 20000), issuerPkh: issuer.pkh, owner: pkhOf(issuerKey));
    iss.x = issuer.attest(iss.txid);
    final c = [iss];
    for (var n = 1; n <= hops; n++) {
      final owner = n == 1 ? issuerKey : key(100 + n - 1);
      final to = n == hops ? seller : key(100 + n);
      final t = b.transfer(from: c.last, ownerKey: owner.lt, to: pkhOf(to), fee: 50);
      spend(t.raw, 0, c.last.lock(b.code), c.last.value);
      c.add(t);
    }
    return c;
  }

  const price = 40000, fee = 60;
  FnftTx sell(FnftTx token, {LtKey? sellerKey, LtKey? buyerKey, int at = price}) => b.transfer(
      from: token,
      ownerKey: sellerKey ?? seller.lt,
      to: pkhOf(buyer),
      fund: LtCoin(coin(buyer).out, buyerKey ?? buyer.lt, price + fee),
      fee: fee,
      pay: (pkhOf(seller), at));

  test('the code: the Fuelled, Voucher and Note code unchanged beside it', () {
    expect(b.code.length, 2784);
    expect(FnftBuilder.standard().code.length, 2471);
    expect(b.L.size, 181);
  });

  test('a sale: both inputs verify; the seller is paid at output 1; the token keeps its fuel', () {
    final c = chain(3);
    final s = sell(c.last);
    spend(s.raw, 0, c.last.lock(b.code), c.last.value);
    spend(s.raw, 1, p2pkh(pkhOf(buyer)), price + fee);
    final tx = Transaction.fromHex(hex.encode(s.raw));
    expect(tx.outputs, hasLength(2));
    expect((tx.outputs[1].satoshis.toInt(), hex.encode(tx.outputs[1].script.buffer)), (price, hex.encode(p2pkh(pkhOf(seller)))));
    expect(s.value, c.last.value, reason: 'the buyer\'s coin pays the price and the fee');
    expect(s.paid, isTrue);
    expect(hex.encode(b.fromRaw(s.raw).raw), hex.encode(s.raw));
  });

  test('the buyer\'s next hop rebuilds the paid parent, and so does the one after', () async {
    final c = chain(2);
    final s = sell(c.last);
    final n1 = b.transfer(from: s, ownerKey: buyer.lt, to: pkhOf(key(50)), fee: 50);
    spend(n1.raw, 0, s.lock(b.code), s.value);
    final n2 = b.transfer(from: n1, ownerKey: key(50).lt, to: pkhOf(key(51)), fee: 50);
    spend(n2.raw, 0, n1.lock(b.code), n1.value);
    final held = await FnftReceive.check(b: b, raw: n2.raw, ownerPkh: pkhOf(key(51)), anchorTx: anchor);
    expect(hex.encode(held.tokenId), hex.encode(c.first.txid));
    print('levels: plain ${n1.rec.length - s.rec.length} B, after a sale ${s.rec.length - c.last.rec.length} B; '
        'sale tx ${s.raw.length} B, the next hop ${n1.raw.length} B');
  });

  test('the seller\'s signature fixes the price: the buyer cannot change it', () {
    final c = chain(1);
    final honest = sell(c.last);
    final sellerSig = Transaction.fromHex(hex.encode(honest.raw)).inputs[0].script!.chunks[1].buf!.toList();
    final cheaper = sell(c.last, sellerKey: LtGivenSignature(seller.lt.pub, sellerSig), at: price - 1);
    expect(() => spend(cheaper.raw, 0, c.last.lock(b.code), c.last.value), throwsA(isA<ScriptException>()));
  });

  test('refused: a pay field without the paid flag, and a stray flag bit', () {
    final c = chain(1);
    final hidden = b.transfer(
        from: c.last, ownerKey: seller.lt, to: pkhOf(buyer), fee: 50, patchHeader: (h) => [...h]..[b.L.pay + 9] = 7);
    expect(() => spend(hidden.raw, 0, c.last.lock(b.code), c.last.value), throwsA(isA<ScriptException>()));
    final stray = b.transfer(
        from: c.last, ownerKey: seller.lt, to: pkhOf(buyer), fee: 50, patchHeader: (h) => [...h]..[b.L.flags] |= 4);
    expect(() => spend(stray.raw, 0, c.last.lock(b.code), c.last.value), throwsA(isA<ScriptException>()));
  });

  test('removed clause: without the pay rules a hidden pay field passes, and strands the token at the next hop', () {
    final weak = FnftBuilder(const FnftScriptGen.weakened(FuelLayout.fnftSale, payRules: false).code().buffer, FuelLayout.fnftSale);
    final iss = weak.issue(first: coin(issuerKey, 20000), issuerPkh: issuer.pkh, owner: pkhOf(issuerKey));
    iss.x = issuer.attest(iss.txid);
    final t1 = weak.transfer(from: iss, ownerKey: issuerKey.lt, to: pkhOf(seller), fee: 50);
    final hidden = weak.transfer(
        from: t1, ownerKey: seller.lt, to: pkhOf(buyer), fee: 50, patchHeader: (h) => [...h]..[weak.L.pay + 9] = 7);
    spend(hidden.raw, 0, t1.lock(weak.code), t1.value);
    // its record leaves out an unpaid pay field, so no rebuild gives its txid
    final next = weak.transfer(from: hidden, ownerKey: buyer.lt, to: pkhOf(key(60)), fee: 50);
    expect(() => spend(next.raw, 0, hidden.lock(weak.code), hidden.value), throwsA(isA<ScriptException>()));
  });

  test('the other archetypes refuse a pay output in the builder', () {
    final f = FnftBuilder.standard();
    final iss = f.issue(first: coin(issuerKey, 20000), issuerPkh: issuer.pkh, owner: pkhOf(issuerKey));
    expect(() => f.transfer(from: iss, ownerKey: issuerKey.lt, to: pkhOf(buyer), pay: (pkhOf(seller), 1)), throwsArgumentError);
    expect(FuelLayout.fnft.payable, isFalse);
  });
}

/// The Voucher and Note NFT with a pay output.
void termedSales() {
  final issuerKey = key(201), seller = key(202), buyer = key(203);
  late Transaction anchor;
  late LtIssuer issuer;
  setUpAll(() async {
    final rabin = Rabin.generateKeyPair(1024);
    anchor = await nft.anchorFor(rabin, seed: 43);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  /// Issued to the issuer, passed to the seller, then sold to the buyer.
  (List<FnftTx>, FnftTx) sold(FnftBuilder b, FuelTerms terms) {
    final iss = b.issue(first: coin(issuerKey, 51000), issuerPkh: issuer.pkh, owner: pkhOf(issuerKey), terms: terms);
    iss.x = issuer.attest(iss.txid);
    final t1 = b.transfer(from: iss, ownerKey: issuerKey.lt, to: pkhOf(seller), fee: 100);
    spend(t1.raw, 0, iss.lock(b.code), iss.value);
    final s = b.transfer(
        from: t1, ownerKey: seller.lt, to: pkhOf(buyer), fund: coin(buyer, 40060), fee: 60, pay: (pkhOf(seller), 40000));
    spend(s.raw, 0, t1.lock(b.code), t1.value);
    final tx = Transaction.fromHex(hex.encode(s.raw));
    expect((tx.outputs[1].satoshis.toInt(), hex.encode(tx.outputs[1].script.buffer)), (40000, hex.encode(p2pkh(pkhOf(seller)))));
    expect(s.value, t1.value);
    return ([iss, t1], s);
  }

  List<(int, String)> outsOf(List<int> raw) => [
        for (final o in Transaction.fromHex(hex.encode(raw)).outputs) (o.satoshis.toInt(), hex.encode(o.script.buffer.sublist(3, 23)))
      ];

  test('the code: the Voucher and Note code unchanged beside their sale versions', () {
    expect(FnftBuilder.voucher().code.length, 2726);
    expect(FnftBuilder.note().code.length, 3479);
    final v = FnftBuilder.saleableVoucher(), n = FnftBuilder.saleableNote();
    expect((v.L.size, n.L.size), (215, 243));
    print('code: TSL1_LT_VNFT_S ${v.code.length} B (+${v.code.length - 2726}), '
        'TSL1_LT_NOTE_S ${n.code.length} B (+${n.code.length - 3479})');
  });

  test('voucher: a sale counts against the hop limit; the buyer redeems; the issuer forces a sold voucher back', () {
    final b = FnftBuilder.saleableVoucher();
    final terms = VoucherTerms(maxHops: 2, expiry: 1000, redeemTo: pkhOf(issuerKey), feeCap: 2000);
    final (_, s) = sold(b, terms);
    expect(s.counter, 2);
    expect(() => b.transfer(from: s, ownerKey: buyer.lt, to: pkhOf(key(60)), fee: 100), throwsArgumentError);
    final over = b.transfer(from: s, ownerKey: buyer.lt, to: pkhOf(key(60)), fee: 100, counterOverride: 3);
    expect(() => spend(over.raw, 0, s.lock(b.code), s.value), throwsA(isA<ScriptException>()));
    final r = b.redeem(from: s, ownerKey: buyer.lt, fee: 400);
    spend(r, 0, s.lock(b.code), s.value);
    expect(outsOf(r), [(s.value - 400, hex.encode(pkhOf(issuerKey)))]);
    final f = b.forceRedeem(from: s, issuerKey: issuerKey.lt, lockHeight: 1000, fee: 300);
    spend(f, 0, s.lock(b.code), s.value);
  });

  test('note: the buyer exits on the terms; the issuer calls a sold note; the next holder rebuilds the sale', () async {
    final b = FnftBuilder.saleableNote();
    final terms = NoteTerms.callable(payTo: pkhOf(issuerKey), feeCap: 500, at: 2000, callAt: 1000, floor: 20000);
    final (_, s) = sold(b, terms);
    final x = b.call(from: s, issuerKey: issuerKey.lt, fee: 300);
    spend(x, 0, s.lock(b.code), s.value);
    expect(outsOf(x).last, (20000, hex.encode(pkhOf(buyer))));
    final n1 = b.transfer(from: s, ownerKey: buyer.lt, to: pkhOf(key(61)), fee: 100);
    spend(n1.raw, 0, s.lock(b.code), s.value);
    final m = b.matureExit(from: n1, ownerKey: key(61).lt, fee: 300);
    spend(m, 0, n1.lock(b.code), n1.value);
    final held = await FnftReceive.check(b: b, raw: n1.raw, ownerPkh: pkhOf(key(61)), anchorTx: anchor);
    expect(hex.encode(held.tokenId), hex.encode(s.tokenId));
    print('note sale ${s.raw.length} B, the next hop ${n1.raw.length} B; level after a sale ${s.rec.length - s.x.length} B');
  });

  test('voucher and note: a pay field without the flag, and a stray flag bit, are refused', () {
    for (final (b, terms) in [
      (FnftBuilder.saleableVoucher(), VoucherTerms(maxHops: 5, expiry: 1000, redeemTo: pkhOf(issuerKey), feeCap: 2000) as FuelTerms),
      (FnftBuilder.saleableNote(), NoteTerms.zeroCoupon(payTo: pkhOf(issuerKey), feeCap: 500, at: 1000)),
    ]) {
      final iss = b.issue(first: coin(issuerKey, 51000), issuerPkh: issuer.pkh, owner: pkhOf(issuerKey), terms: terms);
      iss.x = issuer.attest(iss.txid);
      final hidden = b.transfer(
          from: iss, ownerKey: issuerKey.lt, to: pkhOf(buyer), fee: 50, patchHeader: (h) => [...h]..[b.L.pay + 9] = 7);
      expect(() => spend(hidden.raw, 0, iss.lock(b.code), iss.value), throwsA(isA<ScriptException>()), reason: b.L.name);
      final stray = b.transfer(
          from: iss, ownerKey: issuerKey.lt, to: pkhOf(buyer), fee: 50, patchHeader: (h) => [...h]..[b.L.flags] |= 4);
      expect(() => spend(stray.raw, 0, iss.lock(b.code), iss.value), throwsA(isA<ScriptException>()), reason: b.L.name);
    }
  });
}
