// The wallet side of the lineage tokens: builds the transactions the script
// in lt_script_gen.dart rebuilds. Every serialisation here is written out by
// hand, as an independent statement of the format the script assumes; the
// two are tested against each other through the interpreter.
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import '../crypto/rabin.dart';
import 'lt_layout.dart';
import 'lt_script_gen.dart';

const _seq = [0xff, 0xff, 0xff, 0xff];
const sighashAllForkId = 0x41;

Uint8List cat(List<List<int>> parts) => Uint8List.fromList([for (final p in parts) ...p]);
List<int> le(int v, int k) => [for (var i = 0; i < k; i++) (v >> (8 * i)) & 0xff];
List<int> h256(List<int> b) => sha256Twice(b);

List<int> varint(int n) => n < 253
    ? [n]
    : n < 0x10000
    ? [0xfd, ...le(n, 2)]
    : [0xfe, ...le(n, 4)];

/// A minimal data push.
List<int> push(List<int> d) {
  final n = d.length;
  final prefix = n < 76
      ? [n]
      : n < 256
      ? [0x4c, n]
      : n < 0x10000
      ? [0x4d, ...le(n, 2)]
      : [0x4e, ...le(n, 4)];
  return [...prefix, ...d];
}

List<int> p2pkh(List<int> pkh) => [0x76, 0xa9, 0x14, ...pkh, 0x88, 0xac];
List<int> outpoint(List<int> txid, int index) => [...txid, ...le(index, 4)];

/// A signature's 74-byte slot: length, signature, zero padding.
List<int> slot(List<int> sig) {
  if (sig.length > 73) throw ArgumentError('signature is ${sig.length} bytes');
  return [sig.length, ...sig, ...List<int>.filled(73 - sig.length, 0)];
}

List<int> leBig(BigInt v, int k) {
  final out = List<int>.filled(k, 0);
  var x = v;
  for (var i = 0; i < k && x > BigInt.zero; i++) {
    out[i] = (x & BigInt.from(0xff)).toInt();
    x >>= 8;
  }
  if (x > BigInt.zero) throw ArgumentError('does not fit in $k bytes');
  return out;
}

List<int> pubOf(SVPrivateKey k) => hex.decode(k.publicKey.toHex());
List<int> pkhOf(SVPrivateKey k) => hash160(pubOf(k));

/// [key]'s signature over the preimage [pre], DER with the sighash byte.
List<int> signPreimage(SVPrivateKey key, List<int> pre) => hex.decode(
  DefaultTransactionSigner.signPreimageWithKey(key, Uint8List.fromList(pre), sighashAllForkId).toTxFormat(),
);

/// [signPreimage], for the research models that sign their own preimages.
List<int> sign(SVPrivateKey key, List<int> pre) => signPreimage(key, pre);

/// [key]'s signature for input [input] of the transaction with [prevouts]
/// (36 bytes each, every sequence 0xffffffff, locktime 0) and [nOut]
/// [outputs], spending [sats] under [scriptCode].
List<int> signInput(LtKey key, {
  required List<int> prevouts,
  required int input,
  required List<int> scriptCode,
  required int sats,
  required List<int> outputs,
  required int nOut,
  int version = 1,
  int sequence = 0xffffffff,
  int lockTime = 0,
}) {
  final nIn = prevouts.length ~/ 36;
  final pre = preimageAll(
    prevouts: prevouts,
    nIn: nIn,
    spent: prevouts.sublist(36 * input, 36 * input + 36),
    scriptCode: scriptCode,
    sats: sats,
    hashOutputs: h256(outputs),
    version: version,
    sequence: sequence,
    lockTime: lockTime,
  );
  final unsigned = cat([
    le(version, 4), varint(nIn),
    for (var i = 0; i < nIn; i++) ...[prevouts.sublist(36 * i, 36 * i + 36), [0], le(sequence, 4)],
    varint(nOut), outputs, le(lockTime, 4),
  ]);
  return key.sign(LtSigning(unsigned, input, scriptCode, sats, pre));
}

/// A key token transactions are signed with: its public key, and its
/// signature over one input. [LtPrivateKey] signs in this process; a wallet
/// that keeps its keys elsewhere implements this over its own signer.
abstract class LtKey {
  /// The compressed public key.
  List<int> get pub;

  /// HASH160 of [pub].
  List<int> get pkh => hash160(pub);

  /// The signature, DER with the sighash byte (SIGHASH_ALL | FORKID), for
  /// the input [s] describes.
  List<int> sign(LtSigning s);
}

/// One input to sign. [unsigned] is the whole transaction with empty
/// unlocking scripts, [input] the input's index, [scriptCode] the script the
/// signature covers (for a token input, the code after the separator), and
/// [sats] the value of the output it spends; [preimage] is the BIP143
/// preimage those make. A signer may sign [preimage] directly or rebuild it
/// from the rest, as a wallet that signs transactions does.
class LtSigning {
  final Uint8List unsigned;
  final int input;
  final List<int> scriptCode;
  final int sats;
  final List<int> preimage;
  LtSigning(this.unsigned, this.input, this.scriptCode, this.sats, this.preimage);
}

/// An [LtKey] held in this process.
class LtPrivateKey extends LtKey {
  final SVPrivateKey key;
  LtPrivateKey(this.key);
  @override
  List<int> get pub => pubOf(key);
  @override
  List<int> sign(LtSigning s) => signPreimage(key, s.preimage);
}

/// A signature made elsewhere: [sign] returns [sig] whatever it is asked to
/// sign. With it, a transaction whose inputs are signed on two machines is
/// assembled by the ordinary builder ([LtSwap]).
class LtGivenSignature extends LtKey {
  @override
  final List<int> pub;
  final List<int> sig;
  LtGivenSignature(this.pub, this.sig);
  @override
  List<int> sign(LtSigning s) => sig;
}

/// The private key of [k], an [LtPrivateKey]; for code that signs its own
/// preimages. Throws for a key held elsewhere.
SVPrivateKey privateKeyOf(LtKey k) =>
    k is LtPrivateKey ? k.key : throw ArgumentError('the key is not held in this process');

extension LtKeyOf on SVPrivateKey {
  /// This key as an [LtKey].
  LtKey get lt => LtPrivateKey(this);
}

/// A P2PKH coin: outpoint, key, value.
class LtCoin {
  final List<int> out;
  final LtKey key;
  final int sats;
  LtCoin(this.out, this.key, this.sats);
  List<int> get pub => key.pub;
  List<int> get pkh => key.pkh;
}

/// A BIP143 preimage, SIGHASH_ALL|FORKID, for a transaction with [nIn]
/// inputs all carrying [sequence] (0xffffffff by default) and [lockTime]
/// (0 by default).
List<int> preimageAll({
  required List<int> prevouts,
  required int nIn,
  required List<int> spent,
  required List<int> scriptCode,
  required int sats,
  required List<int> hashOutputs,
  int version = 1,
  int sequence = 0xffffffff,
  int lockTime = 0,
}) => cat([
  le(version, 4),
  h256(prevouts),
  h256([for (var i = 0; i < nIn; i++) ...le(sequence, 4)]),
  spent,
  varint(scriptCode.length),
  scriptCode,
  le(sats, 8),
  le(sequence, 4),
  hashOutputs,
  le(lockTime, 4),
  le(sighashAllForkId, 4),
]);

/// The issuer: TSL1's identity (a Rabin key, the identity transaction and the
/// ed25519 key it names).
class LtIssuer {
  final RabinKeyPair key;
  final List<int> identityTxId;
  final List<int> ed25519PubKey;
  LtIssuer(this.key, this.identityTxId, this.ed25519PubKey);

  List<int> get nSlot => leBig(key.n, LtResetEvidence.numLen);
  List<int> get pkh => hash160(nSlot);

  /// The attestation the first spend of the issuance carries: the issuer's
  /// signature over SHA256(identityTxId ‖ ed25519PubKey ‖ tokenId).
  List<int> attest(List<int> tokenId, {bool corrupt = false}) {
    final h = Rabin.sha256ToScriptInt([...identityTxId, ...ed25519PubKey, ...tokenId]);
    final sig = Rabin.sign(h, key.p, key.q);
    final s = corrupt ? sig.s + BigInt.one : sig.s;
    final blob = cat([identityTxId, ed25519PubKey, le(sig.padding, 4), leBig(s, LtResetEvidence.numLen), nSlot]);
    if (blob.length != LtIssuerBlob.size) throw StateError('blob is ${blob.length} bytes');
    return blob;
  }
}

/// A reset attester: a Rabin key.
class LtAttester {
  final RabinKeyPair key;
  LtAttester(this.key);
  List<int> get nSlot => leBig(key.n, LtResetEvidence.numLen);
  List<int> get pkh => hash160(nSlot);

  /// padding ‖ s ‖ n over SHA256(tag ‖ tokenId ‖ outpoint).
  List<int> attest(List<int> tokenId, List<int> outpoint, {bool corrupt = false}) {
    final h = Rabin.sha256ToScriptInt([...LtResetEvidence.tag, ...tokenId, ...outpoint]);
    final sig = Rabin.sign(h, key.p, key.q);
    final blob = cat([le(sig.padding, 4), leBig(corrupt ? sig.s + BigInt.one : sig.s, LtResetEvidence.numLen), nSlot]);
    if (blob.length != LtResetEvidence.blob) throw StateError('blob is ${blob.length} bytes');
    return blob;
  }
}

/// The three attesters' key hashes, as the evidence carries them.
List<int> attesterList(List<LtAttester> a) {
  if (a.length != 3) throw ArgumentError('three attesters, not ${a.length}');
  return cat([for (final x in a) x.pkh]);
}

/// The header's commitment to the three attesters.
List<int> attestersOf(List<LtAttester> a) => hash160(attesterList(a));

/// The evidence a reset carries: the issuance's record, the list and two blobs.
List<int> resetEvidence(LtTx issuance, List<LtAttester> all, List<int> blob1, List<int> blob2) {
  if (!issuance.isIssuance) throw ArgumentError('not an issuance');
  final e = cat([issuance.headersAndSigs, attesterList(all), blob1, blob2]);
  if (e.length != issuance.L.resetEvidence) throw StateError('evidence is ${e.length} bytes');
  return e;
}

/// A token output to create: its owner and, for the fungible archetype, its amount.
class LtOut {
  final List<int> owner;
  final int amount;
  LtOut(this.owner, [this.amount = 1]);
}

/// A token output offered as the passenger of a merge, with its owner's key.
class LtPassenger {
  final LtTx tx;
  final int k;
  final LtKey key;
  LtPassenger(this.tx, this.k, this.key);
}

/// A lineage-token transaction as built here, with what its children need.
class LtTx {
  final LtLayout L;
  final List<int> h1;
  final List<int>? h2;

  /// sender slot, pub, [passenger slot, pub], funding slot, pub.
  final List<int> sigs;

  /// X(T). For the issuance it is the issuer's attestation, set once known.
  List<int> x;
  final Uint8List raw;
  LtTx(this.L, this.h1, this.h2, this.sigs, this.x, this.raw);

  List<int> get txid => h256(raw);
  bool get isIssuance => h1.sublist(0, 32).every((b) => b == 0);
  List<int> get tokenId => h1.sublist(L.tokenId, L.issuer);
  List<int> hdr(int k) => k == 1 ? h1 : h2!;
  List<int> get hdrs => [...h1, ...?h2];

  int amount(int k) {
    if (!L.fungible) return 1;
    final a = hdr(k).sublist(L.amount, L.amount + 8);
    var v = 0;
    for (var i = 7; i >= 0; i--) {
      v = (v << 8) | a[i];
    }
    return v;
  }

  /// Rec(T): everything a script needs to rebuild this transaction.
  List<int> get rec => [...hdrs, ...sigs, ...x];

  /// Rec(T) without X: for an issuance, all a rebuild needs.
  List<int> get headersAndSigs => [...hdrs, ...sigs];

  List<int> lock(int k, List<int> code) => LtScriptGen(L).lock(hdr(k), code);

  /// TSL1_LT_LNFT: the price output 1 is listed at (0: not for sale).
  int get price {
    if (!L.listed) return 0;
    var v = 0;
    for (var i = 7; i >= 0; i--) {
      v = (v << 8) | h1[L.price + i];
    }
    return v;
  }

  /// TSL1_LT_LNFT: this transaction is a purchase (nobody signed input 0).
  bool get bought => L.listed && !isIssuance && sigs.sublist(LtLayout.slot, LtLayout.sigPair).every((b) => b == 0);
}

/// Builds the transactions of one archetype against one script.
class LtBuilder {
  final LtLayout L;
  final List<int> code;
  LtBuilder(this.L, this.code);

  static final zero32 = List<int>.filled(32, 0);
  static final zero36 = List<int>.filled(36, 0);

  List<int> header({
    required List<int> tokenId,
    required List<int> issuer,
    List<int> attesters = const [],
    bool split = false,
    bool reset = false,
    int passLen = 0,
    required List<int> owner,
    int amount = 1,
    int price = 0,
    required int changeAmt,
    required List<int> changePkh,
    required List<int> in0,
    List<int>? passIn,
    required List<int> fundIn,
  }) {
    if (price != 0 && !L.listed) throw ArgumentError('${L.name} has no price');
    if (!L.fungible && (split || passLen != 0 || amount != 1)) {
      throw ArgumentError('${L.name} has one indivisible unit and no passenger');
    }
    if (attesters.length != (L.resettable ? 20 : 0)) {
      throw ArgumentError('${L.name} ${L.resettable ? 'commits to its three attesters' : 'has no attesters'}');
    }
    if (reset && !L.resettable) throw ArgumentError('${L.name} cannot be reset: redeem and reissue it');
    final h = cat([
      tokenId, issuer, attesters, //
      if (L.hasFlags) [(split ? LtLayout.flagSplit : 0) | (reset ? LtLayout.flagReset : 0)],
      if (L.fungible) le(passLen, 4),
      owner,
      if (L.fungible) le(amount, 8),
      if (L.listed) le(price, 8),
      le(changeAmt, 8), changePkh, in0,
      if (L.fungible) passIn ?? zero36,
      fundIn,
    ]);
    if (h.length != L.size) throw StateError('header is ${h.length} bytes');
    return h;
  }

  List<int> tokenOut(List<int> h) {
    final lock = LtScriptGen(L).lock(h, code);
    return [...le(1, 8), ...varint(lock.length), ...lock];
  }

  List<int> changeOut(List<int> h) => [
    ...h.sublist(L.changeAmt, L.changePkh),
    0x19,
    ...p2pkh(h.sublist(L.changePkh, L.in0)),
  ];

  List<int> outputsOf(List<int> h1, List<int>? h2) => cat([changeOut(h1), tokenOut(h1), if (h2 != null) tokenOut(h2)]);

  /// The issuance: an ordinary transaction, in 0 a P2PKH coin, in 1 funding,
  /// out 0 the change of both, out 1 the token. Set the result's `x` to the
  /// issuer's attestation over its txid before spending it.
  ///
  /// The fee is [fee] sats, or with [satsPerKb] the transaction's size at
  /// that rate (at least [minFee]).
  LtTx issue({
    required LtCoin first,
    required LtCoin fund,
    required List<int> issuerPkh,
    List<int> attesters = const [],
    required List<int> owner,
    int amount = 1,
    int fee = 1000,
    int? satsPerKb,
    List<int> extraOutputs = const [],
  }) {
    LtTx at(int f) => _issue(first, fund, issuerPkh, attesters, owner, amount, f, extraOutputs);
    return satsPerKb == null ? at(fee) : at(feeFor(at(minFee).raw.length, satsPerKb));
  }

  /// Fees below this are not offered, whatever the rate.
  static const minFee = 1;

  /// The fee for a transaction of [size] bytes at [satsPerKb], with room for
  /// the few bytes a re-signed transaction can differ by (a DER signature is
  /// 70 to 72 bytes).
  static int feeFor(int size, int satsPerKb) {
    final f = ((size + 8) * satsPerKb + 999) ~/ 1000;
    return f < minFee ? minFee : f;
  }

  LtTx _issue(LtCoin first, LtCoin fund, List<int> issuerPkh, List<int> attesters, List<int> owner, int amount, int fee,
      List<int> extraOutputs) {
    if (first.sats + fund.sats - 1 - fee < 1) throw ArgumentError('the coins do not cover the token\'s 1 sat and the fee $fee');
    final h1 = header(
      tokenId: zero32,
      issuer: issuerPkh,
      attesters: attesters,
      owner: owner,
      amount: amount,
      changeAmt: first.sats + fund.sats - 1 - fee,
      changePkh: fund.pkh,
      in0: first.out,
      fundIn: fund.out,
    );
    final outs = [...outputsOf(h1, null), ...extraOutputs];
    final prevouts = [...first.out, ...fund.out];
    final s0 = signInput(first.key, prevouts: prevouts, input: 0, scriptCode: p2pkh(first.pkh), sats: first.sats, outputs: outs, nOut: 2 + (extraOutputs.isEmpty ? 0 : 1));
    final s1 = signInput(fund.key, prevouts: prevouts, input: 1, scriptCode: p2pkh(fund.pkh), sats: fund.sats, outputs: outs, nOut: 2 + (extraOutputs.isEmpty ? 0 : 1));
    final ss0 = [...push(s0), ...push(first.pub)];
    final ss1 = [...push(s1), ...push(fund.pub)];
    final raw = cat([
      le(1, 4), [2], //
      first.out, varint(ss0.length), ss0, _seq,
      fund.out, varint(ss1.length), ss1, _seq,
      [2 + (extraOutputs.isEmpty ? 0 : 1)], outs, le(0, 4),
    ]);
    return LtTx(L, h1, null, [...slot(s0), ...first.pub, ...slot(s1), ...fund.pub], const [], raw);
  }

  /// A transfer: spends ([from], [k]) as the driver, optionally a
  /// [passenger] (FT), and creates one or two (FT) token outputs. With
  /// [reset], the evidence replaces the parent's record and the child is
  /// flagged as a reset. With [cheap] the driver input is a cheap-path spend
  /// (signature only), which no later script accepts as a token.
  ///
  /// With [changePkh], output 0 pays that key instead of the funding coin's:
  /// a sale, where the buyer's coin funds the transfer and output 0 pays the
  /// seller `fund.sats - fee` ([LtSwap]). The script does not relate output 0
  /// to the funding input. The fee must then be fixed ([satsPerKb] is
  /// refused): it sets the price.
  ///
  /// The overrides build transactions an honest wallet never would; they are
  /// for tests.
  LtTx transfer({
    required LtTx from,
    required int k,
    required LtKey ownerKey,
    required LtCoin fund,
    required List<LtOut> outs,
    LtPassenger? passenger,
    List<int>? reset,
    int fee = 1000,
    int? satsPerKb,
    List<int>? changePkh,
    int price = 0,
    bool cheap = false,
    int version = 1,
    List<int>? in0Override,
    List<int>? tokenIdOverride,
    List<int>? recPOverride,
    List<int>? passRecOverride,
    List<int> Function(List<int>)? patchH2,
  }) {
    if (changePkh != null && satsPerKb != null) {
      throw ArgumentError('a transfer that pays output 0 to another key takes a fixed fee: the fee sets what that key is paid');
    }
    if (changePkh != null && changePkh.length != 20) throw ArgumentError('changePkh is a 20-byte key hash');
    if (satsPerKb != null) {
      LtTx at(int f) => transfer(from: from, k: k, ownerKey: ownerKey, fund: fund, outs: outs, passenger: passenger,
          reset: reset, fee: f, cheap: cheap, version: version, in0Override: in0Override, price: price,
          tokenIdOverride: tokenIdOverride, recPOverride: recPOverride, passRecOverride: passRecOverride, patchH2: patchH2);
      return at(feeFor(at(minFee).raw.length, satsPerKb));
    }
    if (outs.isEmpty || outs.length > 2) throw ArgumentError('one or two token outputs');
    if (fund.sats - fee < 1) throw ArgumentError('the funding (${fund.sats} sats) does not cover the fee $fee');
    final tokenId = tokenIdOverride ?? (from.isIssuance ? from.txid : from.tokenId);
    final passRec = passRecOverride ?? (passenger == null ? const <int>[] : passenger.tx.rec);
    final in0 = in0Override ?? outpoint(from.txid, k);
    final passIn = passenger == null ? zero36 : outpoint(passenger.tx.txid, passenger.k);
    List<int> h(LtOut o) => header(
      tokenId: tokenId,
      issuer: from.h1.sublist(L.issuer, L.attesters),
      attesters: from.h1.sublist(L.attesters, L.flags),
      split: outs.length == 2,
      reset: reset != null,
      passLen: passRec.length,
      owner: o.owner,
      amount: o.amount,
      price: price,
      changeAmt: fund.sats - fee,
      changePkh: changePkh ?? fund.pkh,
      in0: in0,
      passIn: passIn,
      fundIn: fund.out,
    );
    final h1 = h(outs[0]);
    final h2 = outs.length == 2 ? (patchH2 ?? (x) => x)(h(outs[1])) : null;
    final x = [...passRec, ...(reset ?? recPOverride ?? from.rec)];
    final c = [...h1, ...?h2, ...x];
    final outputs = outputsOf(h1, h2);
    final ho = h256(outputs);
    final nIn = passenger == null ? 2 : 3;
    final prevouts = [...in0, if (passenger != null) ...passIn, ...fund.out];
    final pre = preimageAll(
      prevouts: prevouts,
      nIn: nIn,
      spent: in0,
      scriptCode: code,
      sats: 1,
      hashOutputs: ho,
      version: version,
    );
    final sSig = signInput(ownerKey, prevouts: prevouts, input: 0, scriptCode: code, sats: 1, outputs: outputs, nOut: outs.length + 1, version: version);
    final sPub = ownerKey.pub;
    final ss0 = cheap ? [...push(sSig), ...push(sPub)] : [...push(pre), ...push(sSig), ...push(sPub), ...push(c)];
    List<int> pSig = const [], pPub = const [], ss1 = const [];
    if (passenger != null) {
      pSig = signInput(passenger.key, prevouts: prevouts, input: 1, scriptCode: code, sats: 1, outputs: outputs, nOut: outs.length + 1, version: version);
      pPub = passenger.key.pub;
      ss1 = [...push(pSig), ...push(pPub)];
    }
    final fSig = signInput(fund.key, prevouts: prevouts, input: nIn - 1, scriptCode: p2pkh(fund.pkh), sats: fund.sats, outputs: outputs, nOut: outs.length + 1, version: version);
    final ssF = [...push(fSig), ...push(fund.pub)];
    final raw = cat([
      le(version, 4), [nIn], //
      in0, varint(ss0.length), ss0, _seq,
      if (passenger != null) ...[passIn, varint(ss1.length), ss1, _seq],
      fund.out, varint(ssF.length), ssF, _seq,
      [outs.length + 1], outputs, le(0, 4),
    ]);
    final sigs = [
      ...slot(sSig), ...sPub, //
      if (passenger != null) ...[...slot(pSig), ...pPub],
      ...slot(fSig), ...fund.pub,
    ];
    return LtTx(L, h1, h2, sigs, x, raw);
  }

  /// TSL1_LT_LNFT: anyone buys the listed token at ([from], 1) with [fund],
  /// paying its owner [pay] (default the listed price) at output 0; the
  /// token goes to [newOwner], unlisted. No signature on input 0: the
  /// unlock is PUSH(pre) OP_0 OP_0 PUSH(C). The fee is what [fund] holds
  /// over [pay]. [childPrice] builds what an honest buyer never would (tests).
  LtTx buy({required LtTx from, required LtCoin fund, required List<int> newOwner, int? pay, int childPrice = 0, List<int>? payToOverride}) {
    if (!L.listed) throw ArgumentError('${L.name} cannot be bought: it has no price');
    final amount = pay ?? from.price;
    if (fund.sats - amount < 1) throw ArgumentError('the coin (${fund.sats} sats) does not cover the price $amount and a fee');
    final in0 = outpoint(from.txid, 1);
    final h1 = header(
      tokenId: from.isIssuance ? from.txid : from.tokenId,
      issuer: from.h1.sublist(L.issuer, L.issuer + 20),
      owner: newOwner,
      price: childPrice,
      changeAmt: amount,
      changePkh: payToOverride ?? from.h1.sublist(L.owner, L.owner + 20),
      in0: in0,
      fundIn: fund.out,
    );
    final x = from.rec;
    final outputs = outputsOf(h1, null);
    final prevouts = [...in0, ...fund.out];
    final pre = preimageAll(prevouts: prevouts, nIn: 2, spent: in0, scriptCode: code, sats: 1, hashOutputs: h256(outputs));
    final fSig = signInput(fund.key, prevouts: prevouts, input: 1, scriptCode: p2pkh(fund.pkh), sats: fund.sats, outputs: outputs, nOut: 2);
    final ss0 = [...push(pre), 0x00, 0x00, ...push([...h1, ...x])];
    final ssF = [...push(fSig), ...push(fund.pub)];
    final raw = cat([
      le(1, 4), [2], //
      in0, varint(ss0.length), ss0, _seq,
      fund.out, varint(ssF.length), ssF, _seq,
      [2], outputs, le(0, 4),
    ]);
    final sigs = [...slot(const []), ...List<int>.filled(33, 0), ...slot(fSig), ...fund.pub];
    return LtTx(L, h1, null, sigs, x, raw);
  }

  /// Ends the token at ([from], [k]): its owner spends it on the cheap path
  /// (their signature only), which no script accepts as a token afterwards,
  /// with [fund] as input 1, and the transaction pays plain P2PKH outputs:
  /// the rest, less the fee, to [changePkh] at output 0, then [pay] (pkh,
  /// sats). This is how an issuer retires a redeemed token before reissuing
  /// it: output 0 is the coin a successor's issuance spends ([reissue]), so
  /// it goes to [changePkh], never to a payee. Returns the raw transaction;
  /// it is not a token transaction.
  Uint8List end({
    required LtTx from,
    required int k,
    required LtKey ownerKey,
    required LtCoin fund,
    required List<int> changePkh,
    List<(List<int>, int)> pay = const [],
    int fee = 1000,
    int? satsPerKb,
  }) {
    Uint8List at(int f) {
      final token = outpoint(from.txid, k);
      final rest = 1 + fund.sats - f - pay.fold<int>(0, (a, p) => a + p.$2);
      if (rest < 1) throw ArgumentError('the funding does not cover the payments and the fee');
      final outputs = cat([
        [...le(rest, 8), 0x19, ...p2pkh(changePkh)],
        for (final (pkh, sats) in pay) [...le(sats, 8), 0x19, ...p2pkh(pkh)],
      ]);
      final prevouts = [...token, ...fund.out];
      final s0 = signInput(ownerKey, prevouts: prevouts, input: 0, scriptCode: code, sats: 1, outputs: outputs, nOut: pay.length + 1);
      final s1 = signInput(fund.key, prevouts: prevouts, input: 1, scriptCode: p2pkh(fund.pkh), sats: fund.sats, outputs: outputs, nOut: pay.length + 1);
      final ss0 = [...push(s0), ...push(ownerKey.pub)];
      final ss1 = [...push(s1), ...push(fund.pub)];
      return cat([
        le(1, 4), [2], //
        token, varint(ss0.length), ss0, _seq,
        fund.out, varint(ss1.length), ss1, _seq,
        [pay.length + 1], outputs, le(0, 4),
      ]);
    }

    return satsPerKb == null ? at(fee) : at(feeFor(at(minFee).length, satsPerKb));
  }

  /// The successor of the token that [ended] ended ([end]): an issuance
  /// whose first coin is output 0 of [ended], which [endKey] owns. Only one
  /// transaction can spend that output, so a token has at most one
  /// successor; [LtSuccession.verify] is the wallet's check. Set the
  /// result's `x` to the issuer's attestation, as for [issue].
  LtTx reissue({
    required List<int> ended,
    required LtKey endKey,
    required LtCoin fund,
    required List<int> issuerPkh,
    required List<int> owner,
    int fee = 1000,
    int? satsPerKb,
  }) {
    final e = Transaction.fromHex(hex.encode(ended));
    final o = e.outputs.first;
    if (hex.encode(o.script.buffer) != hex.encode(p2pkh(endKey.pkh))) {
      throw ArgumentError('output 0 of the ended transaction is not paid to ${hex.encode(endKey.pkh)}');
    }
    return issue(
      first: LtCoin(outpoint(h256(ended), 0), endKey, o.satoshis.toInt()),
      fund: fund,
      issuerPkh: issuerPkh,
      owner: owner,
      fee: fee,
      satsPerKb: satsPerKb,
    );
  }

  /// The transaction whose record is [rec], rebuilt byte for byte as the
  /// script rebuilds it: a record holds everything but its own token
  /// outputs' code, which is [code]. An issuance rebuilds only without extra
  /// outputs. A transaction that is not what the record describes (a
  /// cheap-path spend, a forgery) has another txid, so a caller who knows
  /// the txid checks the result's against it.
  LtTx fromRec(List<int> rec) {
    if (rec.length < L.size) throw ArgumentError('a record is at least a header');
    final h1 = rec.sublist(0, L.size);
    var at = L.size;
    List<int>? h2;
    if (L.fungible && h1[L.flags] & LtLayout.flagSplit != 0) {
      h2 = rec.sublist(at, at += L.size);
    }
    int leAt(List<int> b, int i, int n) {
      var v = 0;
      for (var j = n - 1; j >= 0; j--) {
        v = (v << 8) | b[i + j];
      }
      return v;
    }

    final issuance = h1.sublist(L.tokenId, L.issuer).every((b) => b == 0);
    final passenger = L.fungible && leAt(h1, L.passLen, 4) != 0;
    final pairs = passenger ? 3 : 2;
    if (rec.length < at + pairs * LtLayout.sigPair) throw ArgumentError('the record is cut short');
    final sigs = rec.sublist(at, at += pairs * LtLayout.sigPair);
    final x = rec.sublist(at);
    List<int> sigIn(int i) {
      final s = sigs.sublist(i * LtLayout.sigPair, i * LtLayout.sigPair + LtLayout.slot);
      if (s[0] > 73) throw ArgumentError('signature slot $i is malformed');
      return s.sublist(1, 1 + s[0]);
    }

    List<int> pubIn(int i) => sigs.sublist(i * LtLayout.sigPair + LtLayout.slot, (i + 1) * LtLayout.sigPair);
    List<int> p2pkhUnlock(int i) => [...push(sigIn(i)), ...push(pubIn(i))];

    final in0 = h1.sublist(L.in0, L.in0 + 36);
    final fundIn = h1.sublist(L.fundIn, L.fundIn + 36);
    final outputs = outputsOf(h1, h2);
    final List<int> ss0;
    List<int> ss1 = const [];
    final passIn = passenger ? h1.sublist(L.passIn, L.passIn + 36) : const <int>[];
    if (issuance) {
      ss0 = p2pkhUnlock(0);
    } else {
      final pre = preimageAll(
        prevouts: [...in0, ...passIn, ...fundIn],
        nIn: passenger ? 3 : 2,
        spent: in0,
        scriptCode: code,
        sats: 1,
        hashOutputs: h256(outputs),
      );
      final bought = L.listed && pubIn(0).every((b) => b == 0);
      ss0 = [...push(pre), ...push(sigIn(0)), ...push(bought ? const [] : pubIn(0)), ...push([...h1, ...?h2, ...x])];
      if (passenger) ss1 = p2pkhUnlock(1);
    }
    final ssF = p2pkhUnlock(pairs - 1);
    final raw = cat([
      le(1, 4), [pairs], //
      in0, varint(ss0.length), ss0, _seq,
      if (passenger) ...[passIn, varint(ss1.length), ss1, _seq],
      fundIn, varint(ssF.length), ssF, _seq,
      [h2 == null ? 2 : 3], outputs, le(0, 4),
    ]);
    return LtTx(L, h1, h2, sigs, x, raw);
  }

  /// [raw] as a lineage-token transaction of this archetype and code: its
  /// header(s) read from its token output(s), its signatures and X from its
  /// unlocks. Throws unless [raw] is exactly the transaction its record
  /// rebuilds, so a cheap-path spend, another code or any other shape is
  /// refused. An issuance comes back with an empty `x`: the issuer's
  /// attestation is not in it.
  LtTx fromRaw(List<int> raw) {
    final Transaction tx;
    try {
      tx = Transaction.fromHex(hex.encode(raw));
    } catch (e) {
      throw ArgumentError('not a transaction: $e');
    }
    if (tx.outputs.length < 2 || tx.inputs.length < 2) throw ArgumentError('not a lineage-token transaction');
    List<int> headerOf(int k) {
      final c = tx.outputs[k].script.chunks;
      if (c.isEmpty || c.first.buf == null || c.first.buf!.length != L.size) throw ArgumentError('output $k is not a token output');
      return c.first.buf!.toList();
    }

    List<List<int>> pushes(int i) {
      final c = tx.inputs[i].script?.chunks ?? const [];
      if (c.any((x) => x.buf == null && !(L.listed && x.opcodenum == OpCodes.OP_0))) {
        throw ArgumentError('input $i\'s unlock is not pushes only');
      }
      return [for (final x in c) x.buf?.toList() ?? const <int>[]];
    }

    final h1 = headerOf(1);
    final h2 = L.fungible && h1[L.flags] & LtLayout.flagSplit != 0 ? headerOf(2) : null;
    final issuance = h1.sublist(L.tokenId, L.issuer).every((b) => b == 0);
    final in0 = pushes(0);
    if (in0.length != (issuance ? 2 : 4)) throw ArgumentError('input 0 is not a ${issuance ? 'P2PKH' : 'normal-path'} spend');
    final (sig0, pub0) = issuance ? (in0[0], in0[1]) : (in0[1], in0[2]);
    final pairs = <int>[...slot(sig0), ...(L.listed && pub0.isEmpty ? List<int>.filled(33, 0) : pub0)];
    for (var i = 1; i < tx.inputs.length; i++) {
      final p = pushes(i);
      if (p.length != 2) throw ArgumentError('input $i is not a signature and a key');
      pairs.addAll([...slot(p[0]), ...p[1]]);
    }
    final hdrs = [...h1, ...?h2];
    List<int> x = const [];
    if (!issuance) {
      final c = in0[3];
      if (c.length < hdrs.length) throw ArgumentError('input 0 carries no record');
      x = c.sublist(hdrs.length);
    }
    final t = fromRec([...hdrs, ...pairs, ...x]);
    if (hex.encode(t.raw) != hex.encode(raw)) throw ArgumentError('not the transaction its record rebuilds');
    return t;
  }

  /// The evidence for resetting ([t], [k]): two of the three attesters sign,
  /// and the evidence carries the token's [issuance].
  List<int> reset(LtTx issuance, LtTx t, int k, List<LtAttester> all, int i, int j) {
    final o = outpoint(t.txid, k);
    return resetEvidence(issuance, all, all[i].attest(t.tokenId, o), all[j].attest(t.tokenId, o));
  }
}
