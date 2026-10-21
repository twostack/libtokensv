// FnftSwap: the swap's exchange (terms, bid, ask, halves) for the fuelled
// sale versions (WITNESS_LINEAGE_RESEARCH.md 9.13). The token is output 0,
// the price output 1, and the token keeps its fuel.
//
// Run: dart test test/lt_fnft_swap_test.dart
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_fnft_builder.dart';
import 'package:libtokensv/src/lt/lt_identity.dart';
import 'package:libtokensv/src/lt/lt_swap.dart';
import 'package:libtokensv/src/lt/lt_wallet.dart' show LtRefused;

import 'lt_nft_test.dart' as nft show anchorFor;

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x5a2e0000 + i));
var _n = 0;

/// A funding transaction paying [sats] to [k] at output 0.
List<int> fundTx(SVPrivateKey k, int sats) =>
    cat([le(1, 4), [1], sha256(le(++_n, 4)), le(0, 4), [0], le(0xffffffff, 4), [1], le(sats, 8), [25], p2pkh(pkhOf(k)), le(0, 4)]);

void main() {
  late LtIssuer issuer;
  final issuerKey = key(1), seller = key(2), buyer = key(3);
  setUpAll(() async {
    final rabin = Rabin.generateKeyPair(1024);
    issuer = LtIdentity.issuer(rabin, await nft.anchorFor(rabin, seed: 47));
  });

  for (final (name, b, terms) in [
    ('TSL1_LT_FNFT_S', FnftBuilder.saleable(), null),
    ('TSL1_LT_VNFT_S', FnftBuilder.saleableVoucher(), VoucherTerms(maxHops: 5, expiry: 1000, redeemTo: List.filled(20, 9), feeCap: 2000)),
    ('TSL1_LT_NOTE_S', FnftBuilder.saleableNote(), NoteTerms.zeroCoupon(payTo: List.filled(20, 9), feeCap: 500, at: 1000)),
  ]) {
    group(name, () {
      final swap = FnftSwap(b);
      late FnftTx held;
      late List<int> fTx;
      late LtSwapTerms t;
      setUp(() {
        final iss = b.issue(
            first: LtCoin(outpoint(sha256(le(++_n, 4)), 0), issuerKey.lt, 30000), issuerPkh: issuer.pkh, owner: pkhOf(issuerKey), terms: terms);
        iss.x = issuer.attest(iss.txid);
        held = b.transfer(from: iss, ownerKey: issuerKey.lt, to: pkhOf(seller), fee: 100);
        fTx = fundTx(buyer, 25060);
        t = LtSwapTerms(
            tokenTx: held.raw, payTo: pkhOf(seller), price: 25000, fundOut: outpoint(h256(fTx), 0), fundSats: 25060,
            fundPub: buyer.lt.pub, newOwner: pkhOf(buyer));
      });

      test('a bid read back, checked and completed by the seller; the token keeps its fuel', () {
        final bid = swap.bid(t, buyer.lt);
        final half = swap.readHalf(bid.raw, tokenTx: held.raw, fundSats: 25060);
        expect(half.buyerSig, isNotNull);
        expect(hex.encode(half.terms.encode()), hex.encode(t.encode()));
        swap.checkBid(half.terms, half.buyerSig!, fTx);
        final done = swap.assemble(half.terms, seller: seller.lt, buyer: LtGivenSignature(buyer.lt.pub, half.buyerSig!));
        final s = swap.verify(t, done.raw);
        expect(s.value, held.value);
      });

      test('an ask read back and completed by the buyer', () {
        final ask = swap.ask(t, seller.lt);
        final half = swap.readHalf(ask.raw, tokenTx: held.raw, fundSats: 25060);
        final done = swap.assemble(half.terms, seller: LtGivenSignature(half.sellerPub!, half.sellerSig!), buyer: buyer.lt);
        swap.verify(t, done.raw);
      });

      test('refused: a lower price with the seller\'s signature, a coin that is not the bid\'s, another new owner', () {
        final ask = swap.half(t, seller.lt);
        final cheaper = LtSwapTerms(
            tokenTx: t.tokenTx, payTo: t.payTo, price: 24000, fundOut: t.fundOut, fundSats: t.fundSats, fundPub: t.fundPub, newOwner: t.newOwner);
        final cut = swap.assemble(cheaper, seller: LtGivenSignature(ask.$1, ask.$2), buyer: buyer.lt);
        expect(() => swap.verify(cheaper, cut.raw), throwsA(isA<LtRefused>()));
        final bid = swap.readHalf(swap.bid(t, buyer.lt).raw, tokenTx: held.raw, fundSats: 25060);
        expect(() => swap.checkBid(bid.terms, bid.buyerSig!, fundTx(buyer, 25060)), throwsA(isA<LtRefused>()));
        final done = swap.assemble(t, seller: seller.lt, buyer: buyer.lt);
        final other = LtSwapTerms(
            tokenTx: t.tokenTx, payTo: t.payTo, price: t.price, fundOut: t.fundOut, fundSats: t.fundSats, fundPub: t.fundPub, newOwner: pkhOf(key(9)));
        expect(() => swap.verify(other, done.raw), throwsA(isA<LtRefused>()));
      });
    });
  }

  test('only a sale version is sold this way', () {
    expect(() => FnftSwap(FnftBuilder.standard()), throwsArgumentError);
    expect(() => FnftSwap(FnftBuilder.voucher()), throwsArgumentError);
  });
}

extension on FnftSwap {
  /// The seller's public key and signature from an ask.
  (List<int>, List<int>) half(LtSwapTerms t, LtKey seller) {
    final h = readHalf(ask(t, seller).raw, tokenTx: t.tokenTx, fundSats: t.fundSats);
    return (h.sellerPub!, h.sellerSig!);
  }
}

