// The swap (WITNESS_LINEAGE_RESEARCH.md 9.10): a covenant NFT sold for
// satoshis in its own transfer, signed by both sides, with no script change.
// Also gate G2 of docs/RUGGERBOT_TOKENS_PLAN.md: an NFT issuance with an
// extra output strands its token.
//
// Run: dart test test/lt_swap_test.dart
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_identity.dart';
import 'package:libtokensv/src/lt/lt_layout.dart';
import 'package:libtokensv/src/lt/lt_script_gen.dart';
import 'package:libtokensv/src/lt/lt_swap.dart';
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

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x5a9b0000 + i));
var _coin = 0;
LtCoin coin(SVPrivateKey k, [int sats = 100000]) => LtCoin(outpoint(sha256(le(++_coin, 4)), _coin % 3), k.lt, sats);

void spend(List<int> raw, int i, List<int> lock, int sats) {
  final tx = Transaction.fromHex(hex.encode(raw));
  Interpreter().correctlySpends(
      tx.inputs[i].script!, SVScript.fromByteArray(Uint8List.fromList(lock)), tx, i, flags, Coin.valueOf(BigInt.from(sats)));
}

/// A funding transaction paying [sats] to [k] at output [vout], so the
/// seller can check the buyer's coin.
(List<int>, LtCoin) fundingTx(SVPrivateKey k, int sats, {int vout = 0}) {
  final outs = [
    for (var i = 0; i < vout; i++) [...le(1000, 8), 0x19, ...p2pkh(pkhOf(key(999)))],
    [...le(sats, 8), 0x19, ...p2pkh(pkhOf(k))],
  ];
  final raw = cat([
    le(1, 4), [1], sha256(le(++_coin, 4)), le(0, 4), [0], le(0xffffffff, 4), //
    [outs.length], ...outs, le(0, 4),
  ]);
  return (raw, LtCoin(outpoint(h256(raw), vout), k.lt, sats));
}

void main() {
  final code = LtScriptGen.nft.code().buffer;
  final b = LtBuilder(LtLayout.nft, code);
  final swap = LtSwap(b);
  late RabinKeyPair rabin;
  late Transaction anchor;
  late LtIssuer issuer;
  final seller = key(1), buyer = key(2), sellerPayee = key(3), funder = key(9);

  setUpAll(() async {
    rabin = Rabin.generateKeyPair(1024);
    anchor = await nft.anchorFor(rabin, seed: 11);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  /// An issuance and [hops] transfers ending at [seller].
  List<LtTx> chainTo(int hops) {
    final iss = b.issue(first: coin(key(0)), fund: coin(funder), issuerPkh: issuer.pkh, owner: pkhOf(key(0)));
    iss.x = issuer.attest(iss.txid);
    final c = [iss];
    for (var n = 1; n <= hops; n++) {
      final to = n == hops ? seller : key(100 + n);
      final owner = n == 1 ? key(0) : key(100 + n - 1);
      c.add(b.transfer(from: c.last, k: 1, ownerKey: owner.lt, fund: coin(funder), outs: [LtOut(pkhOf(to))]));
    }
    return c;
  }

  LtSwapTerms termsFor(LtTx token, LtCoin fund, {int price = 50000, List<int>? payTo, List<int>? newOwner}) => LtSwapTerms(
        tokenTx: token.raw,
        payTo: payTo ?? pkhOf(sellerPayee),
        price: price,
        fundOut: fund.out,
        fundSats: fund.sats,
        fundPub: fund.pub,
        newOwner: newOwner ?? pkhOf(buyer),
      );

  /// Each side signs its own input from the terms alone.
  List<int> sellerSigns(LtSwapTerms t) => seller.lt.sign(swap.signing(t, 0, sellerPub: seller.lt.pub));
  List<int> buyerSigns(LtSwapTerms t, LtKey k) => k.sign(swap.signing(t, 1));

  group('gate G1: a buyer-funded transfer that pays the seller', () {
    test('signed in either order, it verifies on both inputs, with one txid', () {
      final c = chainTo(3);
      final (fundRaw, fund) = fundingTx(buyer, 50300);
      final t = termsFor(c.last, fund);
      // buyer first: the bid
      final bSig = buyerSigns(t, buyer.lt);
      swap.checkBid(t, bSig, fundRaw);
      final a = swap.assemble(t, seller: seller.lt, buyer: LtGivenSignature(buyer.lt.pub, bSig));
      // seller first: the ask
      final sSig = sellerSigns(t);
      final z = swap.assemble(t, seller: LtGivenSignature(seller.lt.pub, sSig), buyer: buyer.lt);
      expect(hex.encode(a.txid), hex.encode(z.txid));
      expect(hex.encode(a.raw), hex.encode(z.raw), reason: 'RFC 6979 signatures: the same bytes either way');
      swap.verify(t, a.raw);
      spend(a.raw, 0, c.last.lock(1, code), 1);
      spend(a.raw, 1, p2pkh(pkhOf(buyer)), 50300);
      final tx = Transaction.fromHex(hex.encode(a.raw));
      expect(tx.outputs[0].satoshis.toInt(), 50000);
      expect(hex.encode(tx.outputs[0].script.buffer), hex.encode(p2pkh(pkhOf(sellerPayee))));
    });

    test('the buyer\'s next hop rebuilds the swap, and so does the one after', () {
      final c = chainTo(2);
      final (_, fund) = fundingTx(buyer, 50300);
      final t = termsFor(c.last, fund);
      final s = swap.assemble(t, seller: seller.lt, buyer: buyer.lt);
      final read = b.fromRaw(s.raw);
      expect(hex.encode(read.rec), hex.encode(s.rec), reason: 'a swap reads back like any transfer');
      final n1 = b.transfer(from: read, k: 1, ownerKey: buyer.lt, fund: coin(funder), outs: [LtOut(pkhOf(key(50)))]);
      spend(n1.raw, 0, s.lock(1, code), 1);
      final n2 = b.transfer(from: n1, k: 1, ownerKey: key(50).lt, fund: coin(funder), outs: [LtOut(pkhOf(key(51)))]);
      spend(n2.raw, 0, n1.lock(1, code), 1);
    });

    test('the payee check passes for the new owner and refuses any other key', () async {
      final c = chainTo(1);
      final (_, fund) = fundingTx(buyer, 50300);
      final t = termsFor(c.last, fund);
      final s = swap.assemble(t, seller: seller.lt, buyer: buyer.lt);
      final held = await LtReceive.check(b: b, raw: s.raw, ownerPkh: pkhOf(buyer), anchorTx: anchor);
      expect(hex.encode(held.tokenId), hex.encode(c.first.txid));
      expect(() => LtReceive.check(b: b, raw: s.raw, ownerPkh: pkhOf(seller), anchorTx: anchor),
          throwsA(isA<LtRefused>().having((e) => e.reason, 'reason', contains('not paid to this key'))));
    });
  });

  group('what neither side can change after the other signed', () {
    test('the seller changes payTo, price or newOwner: the buyer\'s signature fails', () {
      final c = chainTo(1);
      final (_, fund) = fundingTx(buyer, 50300);
      final t = termsFor(c.last, fund);
      final bSig = buyerSigns(t, buyer.lt);
      for (final changed in [
        termsFor(c.last, fund, payTo: pkhOf(key(66))),
        termsFor(c.last, fund, price: 50100),
        termsFor(c.last, fund, newOwner: pkhOf(key(67))),
      ]) {
        final s = swap.assemble(changed, seller: seller.lt, buyer: LtGivenSignature(buyer.lt.pub, bSig));
        expect(() => spend(s.raw, 1, p2pkh(pkhOf(buyer)), 50300),
            throwsA(isA<ScriptException>().having((e) => e.error, 'error', ScriptError.SCRIPT_ERR_SIG_NULLFAIL)));
        expect(() => swap.verify(changed, s.raw), throwsA(isA<LtRefused>()));
      }
    });

    test('the buyer\'s signature replayed on another token fails', () {
      final c1 = chainTo(1), c2 = chainTo(1);
      final (_, fund) = fundingTx(buyer, 50300);
      final bSig = buyerSigns(termsFor(c1.last, fund), buyer.lt);
      final other = termsFor(c2.last, fund);
      final s = swap.assemble(other, seller: seller.lt, buyer: LtGivenSignature(buyer.lt.pub, bSig));
      expect(() => spend(s.raw, 1, p2pkh(pkhOf(buyer)), 50300), throwsA(isA<ScriptException>()));
    });

    test('a misstated coin value: the bid check refuses it, and the signature fails under the true value', () {
      final c = chainTo(1);
      final (fundRaw, fund) = fundingTx(buyer, 50300);
      final lie = termsFor(c.last, LtCoin(fund.out, fund.key, 60000));
      final bSig = buyerSigns(lie, buyer.lt);
      expect(() => swap.checkBid(lie, bSig, fundRaw),
          throwsA(isA<LtRefused>().having((e) => e.reason, 'reason', contains('holds 50300, not 60000'))));
      final s = swap.assemble(lie, seller: seller.lt, buyer: LtGivenSignature(buyer.lt.pub, bSig));
      expect(() => spend(s.raw, 1, p2pkh(pkhOf(buyer)), 50300), throwsA(isA<ScriptException>()));
    });

    test('the bid check refuses another funding transaction, another key, a garbage signature', () {
      final c = chainTo(1);
      final (fundRaw, fund) = fundingTx(buyer, 50300);
      final (otherRaw, _) = fundingTx(buyer, 50300);
      final t = termsFor(c.last, fund);
      final bSig = buyerSigns(t, buyer.lt);
      expect(() => swap.checkBid(t, bSig, otherRaw),
          throwsA(isA<LtRefused>().having((e) => e.reason, 'reason', contains('not the one the bid names'))));
      final wrongKey = LtSwapTerms(
          tokenTx: t.tokenTx, payTo: t.payTo, price: t.price, fundOut: t.fundOut, fundSats: t.fundSats, fundPub: key(77).lt.pub,
          newOwner: t.newOwner);
      expect(() => swap.checkBid(wrongKey, bSig, fundRaw),
          throwsA(isA<LtRefused>().having((e) => e.reason, 'reason', contains('not P2PKH to the key'))));
      final garbage = [...bSig]..[10] ^= 1;
      expect(() => swap.checkBid(t, garbage, fundRaw),
          throwsA(isA<LtRefused>().having((e) => e.reason, 'reason', contains('the buyer\'s signature does not verify'))));
    });

    test('the terms round-trip, and refuse a bad version, trailing bytes and a short encoding', () {
      final c = chainTo(1);
      final (_, fund) = fundingTx(buyer, 50300);
      final t = termsFor(c.last, fund);
      final e = t.encode();
      expect(hex.encode(LtSwapTerms.decode(e).encode()), hex.encode(e));
      expect(() => LtSwapTerms.decode([2, ...e.sublist(1)]), throwsArgumentError);
      expect(() => LtSwapTerms.decode([...e, 0]), throwsArgumentError);
      expect(() => LtSwapTerms.decode(e.sublist(0, e.length - 1)), throwsArgumentError);
      expect(() => LtSwapTerms.decode(e, maxTokenTx: 100), throwsArgumentError);
    });

    test('the builder refuses a sale with a rate-priced fee, and a swap of an issuance', () {
      final c = chainTo(1);
      expect(
          () => b.transfer(
              from: c.last, k: 1, ownerKey: seller.lt, fund: coin(buyer), outs: [LtOut(pkhOf(buyer))], satsPerKb: 1,
              changePkh: pkhOf(seller)),
          throwsArgumentError);
      final (_, fund) = fundingTx(buyer, 50300);
      expect(() => swap.assemble(termsFor(c.first, fund), seller: key(0).lt, buyer: buyer.lt), throwsArgumentError);
    });
  });

  group('halves: a bid and an ask read back into their terms', () {
    test('a bid reads back, and the seller completes it from the bytes alone', () {
      final c = chainTo(1);
      final (fundRaw, fund) = fundingTx(buyer, 50300);
      final t = termsFor(c.last, fund);
      final half = swap.bid(t, buyer.lt);
      final read = swap.readHalf(half.raw, tokenTx: c.last.raw, fundSats: 50300);
      expect(read.isBid, isTrue);
      expect(hex.encode(read.terms.encode()), hex.encode(t.encode()));
      swap.checkBid(read.terms, read.buyerSig!, fundRaw);
      final done = swap.assemble(read.terms, seller: seller.lt, buyer: LtGivenSignature(read.terms.fundPub, read.buyerSig!));
      swap.verify(t, done.raw);
      // the half and the swap differ only in input 0's unlocking script
      final h = Transaction.fromHex(hex.encode(half.raw)), d = Transaction.fromHex(hex.encode(done.raw));
      expect(h.inputs[1].script!.toHex(), d.inputs[1].script!.toHex());
      expect([for (final o in h.outputs) o.serialize()], [for (final o in d.outputs) o.serialize()]);
    });

    test('an ask reads back, and the buyer completes it', () {
      final c = chainTo(1);
      final (_, fund) = fundingTx(buyer, 50300);
      final t = termsFor(c.last, fund);
      final half = swap.ask(t, seller.lt);
      final read = swap.readHalf(half.raw, tokenTx: c.last.raw, fundSats: 50300);
      expect(read.isBid, isFalse);
      final done = swap.assemble(read.terms, seller: LtGivenSignature(read.sellerPub!, read.sellerSig!), buyer: buyer.lt);
      swap.verify(t, done.raw);
    });

    test('refused: a half with both or neither signature, another token, a stated value that is not the coin\'s', () {
      final c = chainTo(1), other = chainTo(1);
      final (fundRaw, fund) = fundingTx(buyer, 50300);
      final t = termsFor(c.last, fund);
      final full = swap.assemble(t, seller: seller.lt, buyer: buyer.lt);
      expect(() => swap.readHalf(full.raw, tokenTx: c.last.raw, fundSats: 50300), throwsA(isA<LtRefused>()));
      final half = swap.bid(t, buyer.lt);
      expect(() => swap.readHalf(half.raw, tokenTx: other.last.raw, fundSats: 50300), throwsA(isA<LtRefused>()));
      // a misstated value is in no byte of the swap: the buyer's signature
      // commits to the coin's true value, and the bid check catches the lie
      final lie = swap.readHalf(half.raw, tokenTx: c.last.raw, fundSats: 60000);
      expect(() => swap.checkBid(lie.terms, lie.buyerSig!, fundRaw),
          throwsA(isA<LtRefused>().having((e) => e.reason, 'reason', contains('holds 50300, not 60000'))));
    });
  });

  test('gate G2: an NFT issuance with an extra output strands its token', () {
    final extra = [...le(0, 8), 3, OpCodes.OP_FALSE, OpCodes.OP_RETURN, 0];
    final iss = b.issue(first: coin(key(0)), fund: coin(funder), issuerPkh: issuer.pkh, owner: pkhOf(key(0)), extraOutputs: extra);
    iss.x = issuer.attest(iss.txid);
    final t1 = b.transfer(from: iss, k: 1, ownerKey: key(0).lt, fund: coin(funder), outs: [LtOut(pkhOf(key(1)))]);
    expect(() => spend(t1.raw, 0, iss.lock(1, code), 1), throwsA(isA<ScriptException>()),
        reason: 'the rebuild writes two outputs: the txid it computes is not the issuance\'s');
  });
}
