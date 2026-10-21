// The swap: a covenant NFT (TSL1_LT_NFT) sold for satoshis in its own
// transfer, signed by both sides. No script change: the token's script
// writes output 0 from the child header's changePkh and changeAmt and never
// relates them to the funding input, so a transfer funded by the buyer's
// coin may pay output 0 to the seller (WITNESS_LINEAGE_RESEARCH.md 9.10).
//
//   in 0  the seller's token, normal path      signed by the seller
//   in 1  the buyer's P2PKH coin               signed by the buyer
//   out 0 P2PKH to payTo, price
//   out 1 the token, owner newOwner
//
// Every input signs SIGHASH_ALL, and no preimage covers an unlocking script,
// so each side signs the same digest whatever the other has done. The first
// signer's signature is an open option until its input is spent elsewhere.
//
// FnftSwap is the same exchange for the sale versions of the fuelled family
// (TSL1_LT_FNFT_S, _VNFT_S, _NOTE_S; 9.13), whose script writes the pay
// output from the child header's pay field:
//
//   in 0  the seller's token, normal path      signed by the seller
//   in 1  the buyer's P2PKH coin               signed by the buyer
//   out 0 the token, owner newOwner, its fuel unchanged
//   out 1 P2PKH to payTo, price
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'lt_builder.dart';
import 'lt_fnft_builder.dart';
import 'lt_wallet.dart' show LtRefused;

/// Everything that fixes a swap's bytes except the two signatures.
class LtSwapTerms {
  /// The raw transaction whose token output is sold (output 1 for the
  /// covenant NFT, output 0 for a fuelled sale version).
  final List<int> tokenTx;

  /// The key hash the price is paid to.
  final List<int> payTo;

  /// The satoshis paid to [payTo].
  final int price;

  /// The buyer's coin (36-byte outpoint), its value, and the key that signs it.
  final List<int> fundOut;
  final int fundSats;
  final List<int> fundPub;

  /// The token's owner after the swap.
  final List<int> newOwner;

  LtSwapTerms({
    required this.tokenTx,
    required this.payTo,
    required this.price,
    required this.fundOut,
    required this.fundSats,
    required this.fundPub,
    required this.newOwner,
  }) {
    if (payTo.length != 20) throw ArgumentError('payTo is a 20-byte key hash');
    if (newOwner.length != 20) throw ArgumentError('newOwner is a 20-byte key hash');
    if (fundOut.length != 36) throw ArgumentError('fundOut is a 36-byte outpoint');
    if (fundPub.length != 33) throw ArgumentError('fundPub is a 33-byte compressed public key');
    if (price < 1) throw ArgumentError('the price is at least 1 sat');
    if (fundSats - price < 1) throw ArgumentError('the buyer\'s coin ($fundSats sats) leaves no fee over the price $price');
  }

  /// The fee: everything the buyer's coin holds over the price. (A fuelled
  /// token keeps its fuel: the buyer's coin pays the price and the fee.)
  int get fee => fundSats - price;

  static const version = 1;

  /// Version 1: `[1] ‖ varint ‖ tokenTx ‖ payTo 20 ‖ price 8 ‖ fundOut 36 ‖
  /// fundSats 8 ‖ fundPub 33 ‖ newOwner 20`.
  Uint8List encode() => cat([
        [version], varint(tokenTx.length), tokenTx, payTo, le(price, 8), fundOut, le(fundSats, 8), fundPub, newOwner,
      ]);

  /// The terms [encode] wrote. Refuses an unknown version, a short or long
  /// encoding, and a token transaction over [maxTokenTx] bytes.
  static LtSwapTerms decode(List<int> b, {int maxTokenTx = 10000000}) {
    var at = 0;
    List<int> take(int n) {
      if (n < 0 || at + n > b.length) throw ArgumentError('swap terms cut short');
      return b.sublist(at, at += n);
    }

    int uint(int n) {
      final x = take(n);
      var v = 0;
      for (var i = n - 1; i >= 0; i--) {
        v = (v << 8) | x[i];
      }
      return v;
    }

    final v = uint(1);
    if (v != version) throw ArgumentError('swap terms version $v is not known');
    final f = uint(1);
    final n = f < 253 ? f : f == 0xfd ? uint(2) : f == 0xfe ? uint(4) : throw ArgumentError('token transaction too large');
    if (n > maxTokenTx) throw ArgumentError('the token transaction is $n bytes, over $maxTokenTx');
    final t = LtSwapTerms(
      tokenTx: take(n),
      payTo: take(20),
      price: uint(8),
      fundOut: take(36),
      fundSats: uint(8),
      fundPub: take(33),
      newOwner: take(20),
    );
    if (at != b.length) throw ArgumentError('${b.length - at} trailing bytes after the swap terms');
    return t;
  }
}

/// A swap signed by one side only, read back ([LtSwap.readHalf]): the terms
/// it fixes and the signature it carries. A bid carries [buyerSig] (the
/// buyer signed first), an ask [sellerSig] and [sellerPub].
class LtSwapHalf {
  final LtSwapTerms terms;
  final List<int>? buyerSig;
  final List<int>? sellerSig;
  final List<int>? sellerPub;
  LtSwapHalf(this.terms, {this.buyerSig, this.sellerSig, this.sellerPub});
  bool get isBid => buyerSig != null;
}

/// Builds and checks swaps of one covenant NFT code.
class LtSwap {
  static final _flags = {
    VerifyFlag.SIGHASH_FORKID,
    VerifyFlag.LOW_S,
    VerifyFlag.NULLFAIL,
    VerifyFlag.MINIMALDATA,
    VerifyFlag.MINIMALIF,
    VerifyFlag.SIGPUSHONLY,
    VerifyFlag.UTXO_AFTER_GENESIS,
  };

  static final _nobody = List<int>.filled(33, 2);

  final LtBuilder b;
  LtSwap(this.b) {
    if (b.L.fungible) throw ArgumentError('a swap sells an NFT; ${b.L.name} is fungible');
  }

  /// The swap of [t], with [seller] signing input 0 and [buyer] input 1.
  /// Either may be an [LtGivenSignature] carrying the other side's signature.
  LtTx assemble(LtSwapTerms t, {required LtKey seller, required LtKey buyer}) {
    final from = b.fromRaw(t.tokenTx);
    if (from.isIssuance) throw ArgumentError('an issuance is distributed by its issuer, not sold: its first spend carries the attestation');
    if (buyer.pub.length != 33 || hex.encode(buyer.pub) != hex.encode(t.fundPub)) {
      throw ArgumentError('input 1 is signed by the key the terms name');
    }
    return b.transfer(
      from: from,
      k: 1,
      ownerKey: seller,
      fund: LtCoin(t.fundOut, buyer, t.fundSats),
      outs: [LtOut(t.newOwner)],
      fee: t.fee,
      changePkh: t.payTo,
    );
  }

  /// What the signer of [input] (0 the seller, 1 the buyer) signs: the
  /// same for every order of signing. [sellerPub] is the key that signs
  /// input 0; its signature is in no preimage, so the buyer may pass any.
  LtSigning signing(LtSwapTerms t, int input, {List<int>? sellerPub}) {
    if (input != 0 && input != 1) throw ArgumentError('a swap has inputs 0 and 1');
    LtSigning? got;
    final capture = _Capture((s) => got = s);
    final pub0 = sellerPub ?? _nobody;
    assemble(t,
        seller: input == 0 ? (capture..pubKey = pub0) : LtGivenSignature(pub0, const [0x30]),
        buyer: input == 1 ? (capture..pubKey = t.fundPub) : LtGivenSignature(t.fundPub, const [0x30]));
    return got!;
  }

  /// The half [half] built: a bid (the buyer's input signed, the seller's a
  /// placeholder) or an ask (the reverse), as [half]'s other side needs it
  /// to sign. [tokenTx] is the token transaction its input 0 spends and
  /// [fundSats] the value of the buyer's coin (from its funding
  /// transaction), which no transaction states. The terms are rebuilt from
  /// the bytes, and the half is refused unless [assemble] gives the same
  /// transaction with that signature.
  LtSwapHalf readHalf(List<int> half, {required List<int> tokenTx, required int fundSats}) {
    final Transaction tx;
    try {
      tx = Transaction.fromHex(hex.encode(half));
    } catch (e) {
      throw LtRefused('the half does not parse: $e');
    }
    if (tx.inputs.length != 2 || tx.outputs.length != 2) throw LtRefused('a swap has two inputs and two outputs');
    final from = b.fromRaw(tokenTx);
    if (hex.encode(_outOf(tx, 0)) != hex.encode(outpoint(from.txid, 1))) throw LtRefused('input 0 does not spend the token');
    final LtTx s;
    try {
      s = b.fromRaw(half);
    } on ArgumentError catch (e) {
      throw LtRefused('the half is not a transfer of this token\'s code: ${e.message}');
    }
    final L = b.L;
    final o0 = tx.outputs[0].script.buffer;
    if (o0.length != 25 || o0[0] != OpCodes.OP_DUP) throw LtRefused('output 0 is not P2PKH');
    List<List<int>> pushes(int i) => [for (final c in tx.inputs[i].script?.chunks ?? const <ScriptChunk>[]) c.buf?.toList() ?? const <int>[]];
    final in0 = pushes(0), in1 = pushes(1);
    if (in0.length != 4 || in1.length != 2) throw LtRefused('the half\'s unlocks are not a transfer\'s');
    final terms = LtSwapTerms(
      tokenTx: tokenTx,
      payTo: o0.sublist(3, 23),
      price: tx.outputs[0].satoshis.toInt(),
      fundOut: _outOf(tx, 1),
      fundSats: fundSats,
      fundPub: in1[1],
      newOwner: s.h1.sublist(L.owner, L.owner + 20),
    );
    final buyerSigned = in1[0].length > 8, sellerSigned = in0[1].length > 8;
    if (buyerSigned == sellerSigned) throw LtRefused('a half carries exactly one side\'s signature');
    final again = buyerSigned
        ? assemble(terms, seller: LtGivenSignature(in0[2], in0[1]), buyer: LtGivenSignature(terms.fundPub, in1[0]))
        : assemble(terms, seller: LtGivenSignature(in0[2], in0[1]), buyer: LtGivenSignature(terms.fundPub, in1[0]));
    if (hex.encode(again.raw) != hex.encode(half)) throw LtRefused('the half is not the swap its own terms build');
    return buyerSigned
        ? LtSwapHalf(terms, buyerSig: in1[0])
        : LtSwapHalf(terms, sellerSig: in0[1], sellerPub: in0[2]);
  }

  /// A bid: the swap of [t] with the buyer's input signed by [buyer] and a
  /// placeholder for the seller's. Not a valid transaction: the seller
  /// completes it ([assemble] with an [LtGivenSignature]).
  LtTx bid(LtSwapTerms t, LtKey buyer) => assemble(t, seller: LtGivenSignature(_nobody, const [0x30]), buyer: buyer);

  /// An ask: the swap of [t] with the seller's input signed by [seller] and
  /// a placeholder for the buyer's.
  LtTx ask(LtSwapTerms t, LtKey seller) => assemble(t, seller: seller, buyer: LtGivenSignature(t.fundPub, const [0x30]));

  /// The seller's checks on a bid before signing: [fundTx] is the buyer's
  /// coin as the terms describe it, and [buyerSig] is a valid signature of
  /// input 1. Throws [LtRefused] with the reason.
  void checkBid(LtSwapTerms t, List<int> buyerSig, List<int> fundTx) {
    if (hex.encode(h256(fundTx)) != hex.encode(t.fundOut.sublist(0, 32))) {
      throw LtRefused('the funding transaction is not the one the bid names');
    }
    final Transaction f;
    try {
      f = Transaction.fromHex(hex.encode(fundTx));
    } catch (e) {
      throw LtRefused('the funding transaction does not parse: $e');
    }
    final vout = _vout(t.fundOut);
    if (vout >= f.outputs.length) throw LtRefused('the funding transaction has no output $vout');
    final o = f.outputs[vout];
    if (hex.encode(o.script.buffer) != hex.encode(p2pkh(hash160(t.fundPub)))) {
      throw LtRefused('the buyer\'s coin is not P2PKH to the key the bid names');
    }
    if (o.satoshis.toInt() != t.fundSats) throw LtRefused('the buyer\'s coin holds ${o.satoshis}, not ${t.fundSats}');
    final s = assemble(t, seller: LtGivenSignature(_nobody, const [0x30]), buyer: LtGivenSignature(t.fundPub, buyerSig));
    _run(s.raw, 1, p2pkh(hash160(t.fundPub)), t.fundSats, 'the buyer\'s signature');
  }

  /// The checks either side makes on the complete swap [raw]: both inputs
  /// verify (the token's script on input 0), output 0 pays [t.payTo] the
  /// price, and the token's new owner is [t.newOwner]. Returns the swap.
  LtTx verify(LtSwapTerms t, List<int> raw) {
    final from = b.fromRaw(t.tokenTx);
    final s = b.fromRaw(raw);
    final tx = Transaction.fromHex(hex.encode(raw));
    if (tx.inputs.length != 2 || tx.outputs.length != 2) throw LtRefused('a swap has two inputs and two outputs');
    final L = b.L;
    if (hex.encode(s.h1.sublist(L.in0, L.in0 + 36)) != hex.encode(outpoint(from.txid, 1)) ||
        hex.encode(_outOf(tx, 0)) != hex.encode(outpoint(from.txid, 1))) {
      throw LtRefused('input 0 is not the token the terms sell');
    }
    if (hex.encode(_outOf(tx, 1)) != hex.encode(t.fundOut)) {
      throw LtRefused('input 1 is not the buyer\'s coin');
    }
    if (hex.encode(tx.outputs[0].script.buffer) != hex.encode(p2pkh(t.payTo)) || tx.outputs[0].satoshis.toInt() != t.price) {
      throw LtRefused('output 0 does not pay the price to the seller');
    }
    if (hex.encode(s.h1.sublist(L.owner, L.owner + 20)) != hex.encode(t.newOwner)) throw LtRefused('the token does not go to the buyer');
    _run(raw, 0, from.lock(1, b.code), 1, 'the token');
    _run(raw, 1, p2pkh(hash160(t.fundPub)), t.fundSats, 'the buyer\'s coin');
    return s;
  }

  static int _vout(List<int> out) {
    var v = 0;
    for (var i = 3; i >= 0; i--) {
      v = (v << 8) | out[32 + i];
    }
    return v;
  }

  static List<int> _outOf(Transaction tx, int i) =>
      [...hex.decode(tx.inputs[i].prevTxnId).reversed, ...le(tx.inputs[i].prevTxnOutputIndex, 4)];

  static void _run(List<int> raw, int i, List<int> lock, int sats, String what) {
    final tx = Transaction.fromHex(hex.encode(raw));
    try {
      Interpreter().correctlySpends(
          tx.inputs[i].script!, SVScript.fromByteArray(Uint8List.fromList(lock)), tx, i, _flags, Coin.valueOf(BigInt.from(sats)));
    } catch (e) {
      throw LtRefused('$what does not verify: $e');
    }
  }
}

class _Capture extends LtKey {
  final void Function(LtSigning) onSign;
  List<int> pubKey = const [];
  _Capture(this.onSign);
  @override
  List<int> get pub => pubKey;
  @override
  List<int> sign(LtSigning s) {
    onSign(s);
    return const [0x30];
  }
}

/// Builds and checks sales of one fuelled sale version (TSL1_LT_FNFT_S,
/// _VNFT_S or _NOTE_S): the same terms, halves and checks as [LtSwap], with
/// the token at output 0 and the price at output 1.
class FnftSwap {
  final FnftBuilder b;
  FnftSwap(this.b) {
    if (!b.L.payable) throw ArgumentError('${b.L.name} has no pay output: only a sale version is sold in its own transfer');
  }

  /// The sale of [t], with [seller] signing input 0 and [buyer] input 1.
  /// Either may be an [LtGivenSignature] carrying the other side's signature.
  FnftTx assemble(LtSwapTerms t, {required LtKey seller, required LtKey buyer}) {
    final from = b.fromRaw(t.tokenTx);
    if (from.isIssuance) throw ArgumentError('an issuance is distributed by its issuer, not sold: its first spend carries the attestation');
    if (buyer.pub.length != 33 || hex.encode(buyer.pub) != hex.encode(t.fundPub)) {
      throw ArgumentError('input 1 is signed by the key the terms name');
    }
    return b.transfer(
      from: from,
      ownerKey: seller,
      to: t.newOwner,
      fund: LtCoin(t.fundOut, buyer, t.fundSats),
      fee: t.fee,
      pay: (t.payTo, t.price),
    );
  }

  /// What the signer of [input] (0 the seller, 1 the buyer) signs.
  LtSigning signing(LtSwapTerms t, int input, {List<int>? sellerPub}) {
    if (input != 0 && input != 1) throw ArgumentError('a sale has inputs 0 and 1');
    LtSigning? got;
    final capture = _Capture((s) => got = s);
    final pub0 = sellerPub ?? LtSwap._nobody;
    assemble(t,
        seller: input == 0 ? (capture..pubKey = pub0) : LtGivenSignature(pub0, const [0x30]),
        buyer: input == 1 ? (capture..pubKey = t.fundPub) : LtGivenSignature(t.fundPub, const [0x30]));
    return got!;
  }

  /// A bid: the buyer's input signed, a placeholder for the seller's.
  FnftTx bid(LtSwapTerms t, LtKey buyer) => assemble(t, seller: LtGivenSignature(LtSwap._nobody, const [0x30]), buyer: buyer);

  /// An ask: the seller's input signed, a placeholder for the buyer's.
  FnftTx ask(LtSwapTerms t, LtKey seller) => assemble(t, seller: seller, buyer: LtGivenSignature(t.fundPub, const [0x30]));

  /// The half [half] built, read back as for [LtSwap.readHalf].
  LtSwapHalf readHalf(List<int> half, {required List<int> tokenTx, required int fundSats}) {
    final Transaction tx;
    try {
      tx = Transaction.fromHex(hex.encode(half));
    } catch (e) {
      throw LtRefused('the half does not parse: $e');
    }
    if (tx.inputs.length != 2 || tx.outputs.length != 2) throw LtRefused('a sale has two inputs and two outputs');
    final from = b.fromRaw(tokenTx);
    if (hex.encode(LtSwap._outOf(tx, 0)) != hex.encode(outpoint(from.txid, 0))) throw LtRefused('input 0 does not spend the token');
    final FnftTx s;
    try {
      s = b.fromRaw(half);
    } on ArgumentError catch (e) {
      throw LtRefused('the half is not a transfer of this token\'s code: ${e.message}');
    }
    if (!s.paid) throw LtRefused('the half has no pay output');
    final L = b.L;
    List<List<int>> pushes(int i) => [for (final c in tx.inputs[i].script?.chunks ?? const <ScriptChunk>[]) c.buf?.toList() ?? const <int>[]];
    final in0 = pushes(0), in1 = pushes(1);
    if (in0.length != 4 || in1.length != 2) throw LtRefused('the half\'s unlocks are not a transfer\'s');
    var price = 0;
    for (var i = 7; i >= 0; i--) {
      price = (price << 8) | s.h[L.pay + i];
    }
    final terms = LtSwapTerms(
      tokenTx: tokenTx,
      payTo: s.h.sublist(L.pay + 8, L.pay + 28),
      price: price,
      fundOut: LtSwap._outOf(tx, 1),
      fundSats: fundSats,
      fundPub: in1[1],
      newOwner: s.owner,
    );
    final buyerSigned = in1[0].length > 8, sellerSigned = in0[1].length > 8;
    if (buyerSigned == sellerSigned) throw LtRefused('a half carries exactly one side\'s signature');
    final again = assemble(terms, seller: LtGivenSignature(in0[2], in0[1]), buyer: LtGivenSignature(terms.fundPub, in1[0]));
    if (hex.encode(again.raw) != hex.encode(half)) throw LtRefused('the half is not the sale its own terms build');
    return buyerSigned ? LtSwapHalf(terms, buyerSig: in1[0]) : LtSwapHalf(terms, sellerSig: in0[1], sellerPub: in0[2]);
  }

  /// The seller's checks on a bid before signing, as for [LtSwap.checkBid].
  void checkBid(LtSwapTerms t, List<int> buyerSig, List<int> fundTx) {
    if (hex.encode(h256(fundTx)) != hex.encode(t.fundOut.sublist(0, 32))) {
      throw LtRefused('the funding transaction is not the one the bid names');
    }
    final Transaction f;
    try {
      f = Transaction.fromHex(hex.encode(fundTx));
    } catch (e) {
      throw LtRefused('the funding transaction does not parse: $e');
    }
    final vout = LtSwap._vout(t.fundOut);
    if (vout >= f.outputs.length) throw LtRefused('the funding transaction has no output $vout');
    final o = f.outputs[vout];
    if (hex.encode(o.script.buffer) != hex.encode(p2pkh(hash160(t.fundPub)))) {
      throw LtRefused('the buyer\'s coin is not P2PKH to the key the bid names');
    }
    if (o.satoshis.toInt() != t.fundSats) throw LtRefused('the buyer\'s coin holds ${o.satoshis}, not ${t.fundSats}');
    final s = assemble(t, seller: LtGivenSignature(LtSwap._nobody, const [0x30]), buyer: LtGivenSignature(t.fundPub, buyerSig));
    LtSwap._run(s.raw, 1, p2pkh(hash160(t.fundPub)), t.fundSats, 'the buyer\'s signature');
  }

  /// The checks either side makes on the complete sale [raw]: both inputs
  /// verify, output 1 pays [t.payTo] the price, the token's new owner is
  /// [t.newOwner], and it keeps its fuel. Returns the sale.
  FnftTx verify(LtSwapTerms t, List<int> raw) {
    final from = b.fromRaw(t.tokenTx);
    final s = b.fromRaw(raw);
    final tx = Transaction.fromHex(hex.encode(raw));
    if (tx.inputs.length != 2 || tx.outputs.length != 2) throw LtRefused('a sale has two inputs and two outputs');
    if (hex.encode(s.in0) != hex.encode(outpoint(from.txid, 0)) || hex.encode(LtSwap._outOf(tx, 0)) != hex.encode(outpoint(from.txid, 0))) {
      throw LtRefused('input 0 is not the token the terms sell');
    }
    if (hex.encode(LtSwap._outOf(tx, 1)) != hex.encode(t.fundOut)) throw LtRefused('input 1 is not the buyer\'s coin');
    if (hex.encode(tx.outputs[1].script.buffer) != hex.encode(p2pkh(t.payTo)) || tx.outputs[1].satoshis.toInt() != t.price) {
      throw LtRefused('output 1 does not pay the price to the seller');
    }
    if (hex.encode(s.owner) != hex.encode(t.newOwner)) throw LtRefused('the token does not go to the buyer');
    if (s.value != from.value) throw LtRefused('the token holds ${s.value} sats, not its ${from.value}');
    LtSwap._run(raw, 0, from.lock(b.code), from.value, 'the token');
    LtSwap._run(raw, 1, p2pkh(hash160(t.fundPub)), t.fundSats, 'the buyer\'s coin');
    return s;
  }
}
