// The wallet side of the Fuelled NFT (TSL1_LT_FNFT): builds the transactions
// lt_fnft_script_gen.dart rebuilds, and rebuilds them from their records as
// the script does. Serialisations are written out by hand, as an independent
// statement of the format the script assumes; the two are tested against each
// other through the interpreter.
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'lt_builder.dart';
import 'lt_fnft_script_gen.dart';
import 'lt_layout.dart';

const _seq = [0xff, 0xff, 0xff, 0xff];

/// The terms a fuelled token's header carries after its issuer, fixed at
/// issuance and carried unchanged: [VoucherTerms] or [NoteTerms].
abstract class FuelTerms {
  /// Transfers allowed; for a Note NFT 0 is no limit.
  int get maxHops;

  /// The header bytes.
  List<int> get bytes;
}

/// The Voucher NFT's terms, fixed at issuance and carried unchanged: at most
/// [maxHops] transfers (1..255) before it must be redeemed; after block
/// height [expiry] the issuer may force its redemption; redemptions pay
/// [redeemTo] (the issuer's wallet key hash); a holder's redemption may
/// leave at most [feeCap] sats of the token's value for the fee.
class VoucherTerms implements FuelTerms {
  @override
  final int maxHops;
  final int expiry;
  final List<int> redeemTo;
  final int feeCap;
  VoucherTerms({required this.maxHops, required this.expiry, required this.redeemTo, required this.feeCap}) {
    if (maxHops < 1 || maxHops > 255) throw ArgumentError('maxHops is 1 to 255, not $maxHops');
    if (expiry < 0 || expiry >= 500000000) throw ArgumentError('expiry is a block height below 500,000,000, not $expiry');
    if (redeemTo.length != 20) throw ArgumentError('redeemTo is a 20-byte key hash');
    if (feeCap < 0) throw ArgumentError('feeCap is not negative');
  }

  /// The 33 header bytes: maxHops 1, expiry 4, redeemTo 20, feeCap 8, LE.
  @override
  List<int> get bytes => [maxHops, ...le(expiry, 4), ...redeemTo, ...le(feeCap, 8)];

  static VoucherTerms of(List<int> b) {
    int leAt(int at, int n) {
      var v = 0;
      for (var i = n - 1; i >= 0; i--) {
        v = (v << 8) | b[at + i];
      }
      return v;
    }

    return VoucherTerms(maxHops: b[0], expiry: leAt(1, 4), redeemTo: b.sublist(5, 25), feeCap: leAt(25, 8));
  }
}

int _leAt(List<int> b, int at, int n) {
  var v = 0;
  for (var i = n - 1; i >= 0; i--) {
    v = (v << 8) | b[at + i];
  }
  return v;
}

/// The Note NFT's terms (TSL1_LT_NOTE): for each way the note can end, how
/// much of the fuel the holder gets; the issuer ([payTo]) gets the rest.
///  * [exit]: the holder ends it before [maturity];
///  * [mature]: the holder ends it from block height [maturity] on;
///  * [call]: the issuer ends it from block height [callAt] on.
/// An amount of 0 gives the holder nothing on that path; an amount of at
/// least the value less [feeCap] gives the holder everything ([everything]).
/// A height of [never] is never reached. [maxHops] 0 is no limit on
/// transfers. A holder's ending, or a call, may leave at most [feeCap] for
/// the fee.
class NoteTerms implements FuelTerms {
  @override
  final int maxHops;
  final List<int> payTo;
  final int feeCap;
  final int exit;
  final int maturity;
  final int mature;
  final int callAt;
  final int call;

  /// The holder gets everything the note holds (less the fee).
  static const everything = 0x7fffffffffffffff;

  /// A height no chain reaches in practice.
  static const never = 499999999;

  NoteTerms({
    this.maxHops = 0,
    required this.payTo,
    required this.feeCap,
    required this.exit,
    required this.maturity,
    required this.mature,
    required this.callAt,
    required this.call,
  }) {
    if (maxHops < 0 || maxHops > 255) throw ArgumentError('maxHops is 0 to 255, not $maxHops');
    if (payTo.length != 20) throw ArgumentError('payTo is a 20-byte key hash');
    for (final (n, v) in [('feeCap', feeCap), ('exit', exit), ('mature', mature), ('call', call)]) {
      if (v < 0) throw ArgumentError('$n is not negative');
    }
    for (final (n, v) in [('maturity', maturity), ('callAt', callAt)]) {
      if (v < 0 || v > never) throw ArgumentError('$n is a block height up to $never, not $v');
    }
  }

  /// The Voucher NFT as a note: the holder gets nothing on any ending, the
  /// issuer may call it from [expiry].
  factory NoteTerms.voucher({required List<int> payTo, required int feeCap, required int expiry, int maxHops = 0}) =>
      NoteTerms(maxHops: maxHops, payTo: payTo, feeCap: feeCap, exit: 0, maturity: never, mature: 0, callAt: expiry, call: 0);

  /// A time-locked claim on the fuel: nothing before [at], everything from
  /// it; the issuer can never call it. Its price before [at] is a discount
  /// for time. It is fully collateralised: no one owes anything.
  factory NoteTerms.zeroCoupon({required List<int> payTo, required int feeCap, required int at, int maxHops = 0}) =>
      NoteTerms(maxHops: maxHops, payTo: payTo, feeCap: feeCap, exit: 0, maturity: at, mature: everything, callAt: never, call: 0);

  /// [NoteTerms.zeroCoupon], which the issuer may end from [callAt] (before
  /// [at]) by paying the holder [floor].
  factory NoteTerms.callable(
          {required List<int> payTo, required int feeCap, required int at, required int callAt, required int floor, int maxHops = 0}) =>
      NoteTerms(maxHops: maxHops, payTo: payTo, feeCap: feeCap, exit: 0, maturity: at, mature: everything, callAt: callAt, call: floor);

  /// A deposit: the holder may leave at any time with [early], everything
  /// from [at]; the issuer keeps the difference of an early exit.
  factory NoteTerms.deposit({required List<int> payTo, required int feeCap, required int at, required int early, int maxHops = 0}) =>
      NoteTerms(maxHops: maxHops, payTo: payTo, feeCap: feeCap, exit: early, maturity: at, mature: everything, callAt: never, call: 0);

  /// A voucher the issuer may take back from [callAt], but never for less
  /// than [floor] to the holder.
  factory NoteTerms.insured(
          {required List<int> payTo, required int feeCap, required int callAt, required int floor, int maxHops = 0}) =>
      NoteTerms(maxHops: maxHops, payTo: payTo, feeCap: feeCap, exit: 0, maturity: never, mature: 0, callAt: callAt, call: floor);

  /// The 61 header bytes: maxHops 1, payTo 20, feeCap 8, exit 8, maturity 4,
  /// mature 8, callAt 4, call 8, LE.
  @override
  List<int> get bytes => [
        maxHops, ...payTo, ...le(feeCap, 8), ...le(exit, 8), ...le(maturity, 4), ...le(mature, 8), //
        ...le(callAt, 4), ...le(call, 8),
      ];

  static NoteTerms of(List<int> b) => NoteTerms(
        maxHops: b[0],
        payTo: b.sublist(1, 21),
        feeCap: _leAt(b, 21, 8),
        exit: _leAt(b, 29, 8),
        maturity: _leAt(b, 37, 4),
        mature: _leAt(b, 41, 8),
        callAt: _leAt(b, 49, 4),
        call: _leAt(b, 53, 8),
      );

  /// What the holder gets of a note holding [value] when ending with the
  /// holder amount [a] and a fee of [fee]: (to payTo, to the holder).
  static (int, int) split(int a, int value, int fee) {
    final rest = value - fee;
    if (a == 0) return (rest, 0);
    if (a >= rest) return (0, rest);
    return (rest - a, a);
  }
}

/// A Fuelled NFT transaction: its token output's header, the signatures its
/// record carries, and X (its parent's record, or for the issuance the
/// issuer's attestation once known).
class FnftTx {
  final List<int> h;

  /// sender slot, pub, [funding slot, pub]
  final List<int> sigs;
  List<int> x;
  final Uint8List raw;

  /// The archetype: the Fuelled NFT or the Voucher NFT.
  final FuelLayout L;
  FnftTx(this.h, this.sigs, this.x, this.raw, [this.L = FuelLayout.fnft]);

  List<int> get txid => h256(raw);
  bool get isIssuance => h.sublist(0, 32).every((b) => b == 0);

  /// The token id: this txid for the issuance, the header's otherwise.
  List<int> get tokenId => isIssuance ? txid : h.sublist(L.tokenId, L.issuer);
  List<int> get issuer => h.sublist(L.issuer, L.issuer + 20);
  List<int> get owner => h.sublist(L.owner, L.owner + 20);
  bool get funded => h[L.flags] & FnftLayout.flagFunded != 0;

  /// TSL1_LT_FNFT_S: this transaction has a pay output (output 1).
  bool get paid => L.payable && h[L.flags] & FuelLayout.flagPaid != 0;
  List<int> get in0 => h.sublist(L.in0, L.fundIn);

  /// The satoshis the token output holds: its fuel.
  int get value {
    var v = 0;
    for (var i = 7; i >= 0; i--) {
      v = (v << 8) | h[L.value + i];
    }
    return v;
  }

  /// Voucher or Note NFT: the hops since issuance, and the terms.
  int get counter => L.termed ? h[L.counter] : 0;
  VoucherTerms get terms => VoucherTerms.of(h.sublist(L.maxHops, L.maxHops + L.terms));
  NoteTerms get noteTerms => NoteTerms.of(h.sublist(L.maxHops, L.maxHops + L.terms));

  /// The terms' header bytes (empty for the Fuelled NFT).
  List<int> get termBytes => L.termed ? h.sublist(L.maxHops, L.maxHops + L.terms) : const [];

  /// The terms' transfer limit, 0 for none.
  int get maxHops => L.termed ? h[L.maxHops] : 0;

  /// Voucher or Note NFT: the transfers left before it must be ended; null
  /// for a note with no limit.
  int? get hopsLeftOrNull => maxHops == 0 ? null : maxHops - counter;

  /// Voucher NFT: the transfers left before it must be redeemed.
  int get hopsLeft => maxHops - counter;

  /// The token output: always output 0.
  List<int> get out => outpoint(txid, 0);

  /// The record header: flags, value, in0, [fundIn], [pay].
  List<int> get recHeader => [
        ...h.sublist(L.derived, L.fundIn),
        if (funded) ...h.sublist(L.fundIn, L.fundIn + 36),
        if (paid) ...h.sublist(L.pay, L.pay + 28),
      ];

  /// Rec(T): the compact header, the signatures, X.
  List<int> get rec => [...recHeader, ...sigs, ...x];

  /// Rec(T) without X: for the issuance, all a rebuild needs.
  List<int> get headerAndSigs => [...recHeader, ...sigs];

  /// The derived header bytes: token id field, issuer, (a voucher's terms,)
  /// owner (and a voucher's counter).
  List<int> get prefix => h.sublist(0, L.derived);

  /// The derived bytes of the parent's header, as the script splices them
  /// in: its token id (zero when the parent is the issuance), the issuer,
  /// and as owner HASH160 of the key that signed input 0 here.
  List<int> get parentPrefix {
    final tid = tokenId;
    final parentIsIssuance = hex.encode(h.sublist(L.in0, L.in0 + 32)) == hex.encode(tid);
    return [
      ...(parentIsIssuance ? List<int>.filled(32, 0) : tid),
      ...h.sublist(L.issuer, L.owner), // the issuer, and a voucher's terms
      ...hash160(sigs.sublist(FnftLayout.slot, LtLayout.sigPair)),
      if (L.termed) maxHops == 0 ? counter : counter - 1,
    ];
  }

  List<int> lock(List<int> code) => FnftScriptGen(L).lock(h, code);
}


class FnftBuilder {
  final List<int> code;
  final FuelLayout L;
  FnftBuilder(this.code, [this.L = FuelLayout.fnft]);

  /// The builder for the Fuelled NFT's own code.
  factory FnftBuilder.standard() => FnftBuilder(const FnftScriptGen().code().buffer);

  /// The builder for the Voucher NFT's own code.
  factory FnftBuilder.voucher() => FnftBuilder(const FnftScriptGen(FuelLayout.vnft).code().buffer, FuelLayout.vnft);

  /// The builder for the Fuelled NFT with a pay output, TSL1_LT_FNFT_S.
  factory FnftBuilder.saleable() => FnftBuilder(const FnftScriptGen(FuelLayout.fnftSale).code().buffer, FuelLayout.fnftSale);

  /// The builder for the Voucher NFT with a pay output, TSL1_LT_VNFT_S.
  factory FnftBuilder.saleableVoucher() =>
      FnftBuilder(const FnftScriptGen(FuelLayout.vnftSale).code().buffer, FuelLayout.vnftSale);

  /// The builder for the Note NFT with a pay output, TSL1_LT_NOTE_S.
  factory FnftBuilder.saleableNote() => FnftBuilder(const FnftScriptGen(FuelLayout.noteSale).code().buffer, FuelLayout.noteSale);

  /// The builder for the Note NFT's own code.
  factory FnftBuilder.note() => FnftBuilder(const FnftScriptGen(FuelLayout.note).code().buffer, FuelLayout.note);

  static final zero32 = List<int>.filled(32, 0);
  static final zero36 = List<int>.filled(36, 0);

  List<int> header({
    required List<int> tokenId,
    required List<int> issuer,
    required List<int> owner,
    required int value,
    required List<int> in0,
    List<int>? fundIn,
    FuelTerms? terms,
    int counter = 0,
    List<int>? pay,
  }) {
    if (value < 1) throw ArgumentError('the token would hold $value sats: the fuel does not cover the fee');
    if (pay != null && !L.payable) throw ArgumentError('${L.name} has no pay output');
    if (pay != null && pay.length != 28) throw ArgumentError('the pay field is 28 bytes');
    if (L.termed != (terms != null)) throw ArgumentError(L.termed ? 'a ${L.name} has terms' : '${L.name} has no terms');
    if (L.voucher && terms is! VoucherTerms) throw ArgumentError('a Voucher NFT takes VoucherTerms');
    if (L.isNote && terms is! NoteTerms) throw ArgumentError('a Note NFT takes NoteTerms');
    final h = cat([
      tokenId, issuer, if (terms != null) terms.bytes, owner, if (L.termed) [counter], //
      [(fundIn == null ? 0 : FnftLayout.flagFunded) | (pay == null ? 0 : FuelLayout.flagPaid)], le(value, 8), in0,
      fundIn ?? zero36,
      if (L.payable) pay ?? List<int>.filled(28, 0),
    ]);
    if (h.length != L.size) throw StateError('header is ${h.length} bytes');
    return h;
  }

  /// The serialised token output holding [h]: value ‖ varint ‖ lock.
  List<int> tokenOut(List<int> h) {
    final lock = FnftScriptGen(L).lock(h, code);
    return [...h.sublist(L.value, L.in0), ...varint(lock.length), ...lock];
  }

  /// The outputs of the transaction whose header is [h]: the token, and
  /// for a paid TSL1_LT_FNFT_S transfer the pay output.
  List<int> outputsOf(List<int> h) => [
        ...tokenOut(h),
        if (L.payable && h[L.flags] & FuelLayout.flagPaid != 0) ...[...h.sublist(L.pay, L.pay + 8), 0x19, ...p2pkh(h.sublist(L.pay + 8, L.pay + 28))],
      ];

  int _nOut(List<int> h) => L.payable && h[L.flags] & FuelLayout.flagPaid != 0 ? 2 : 1;

  static List<int> _fundPart(LtCoin fund, List<int> sig) {
    final ss = [...push(sig), ...push(fund.pub)];
    return [...fund.out, ...varint(ss.length), ...ss, ..._seq];
  }

  /// [build] at [fee], or with [satsPerKb] at the rate on its own size.
  static T _priced<T>(T Function(int fee) build, int Function(T) size, int fee, int? satsPerKb) =>
      satsPerKb == null ? build(fee) : build(LtBuilder.feeFor(size(build(LtBuilder.minFee)), satsPerKb));

  /// The issuance: in 0 [first] (P2PKH), in 1 [fund] if given, out 0 the
  /// token holding both less the fee. Issue to the issuer's own key, then
  /// transfer. Set the result's `x` to the issuer's attestation.
  FnftTx issue({
    required LtCoin first,
    LtCoin? fund,
    required List<int> issuerPkh,
    required List<int> owner,
    FuelTerms? terms,
    int fee = 1000,
    int? satsPerKb,
  }) =>
      _priced((f) => _issue(first, fund, issuerPkh, owner, terms, f), (t) => t.raw.length, fee, satsPerKb);

  FnftTx _issue(LtCoin first, LtCoin? fund, List<int> issuerPkh, List<int> owner, FuelTerms? terms, int fee) {
    final h = header(
      tokenId: zero32,
      issuer: issuerPkh,
      owner: owner,
      terms: terms,
      value: first.sats + (fund?.sats ?? 0) - fee,
      in0: first.out,
      fundIn: fund?.out,
    );
    final outs = tokenOut(h);
    final prevouts = [...first.out, ...?fund?.out];
    final s0 = signInput(first.key, prevouts: prevouts, input: 0, scriptCode: p2pkh(first.pkh), sats: first.sats, outputs: outs, nOut: 1);
    final ss0 = [...push(s0), ...push(first.pub)];
    final sigs = [...slot(s0), ...first.pub];
    var fundPart = <int>[];
    if (fund != null) {
      final s1 = signInput(fund.key, prevouts: prevouts, input: 1, scriptCode: p2pkh(fund.pkh), sats: fund.sats, outputs: outs, nOut: 1);
      fundPart = _fundPart(fund, s1);
      sigs.addAll([...slot(s1), ...fund.pub]);
    }
    final raw = cat([
      le(1, 4), [fund == null ? 1 : 2], //
      first.out, varint(ss0.length), ss0, _seq,
      fundPart,
      [1], outs, le(0, 4),
    ]);
    return FnftTx(h, sigs, const [], raw, L);
  }

  /// A transfer of [from]'s token to [to], paid from its fuel, topped up
  /// with [fund] (swept whole into the token) if given. The overrides build
  /// what an honest wallet never would; they are for tests.
  FnftTx transfer({
    required FnftTx from,
    required LtKey ownerKey,
    required List<int> to,
    LtCoin? fund,
    int fee = 1000,
    int? satsPerKb,
    List<int>? tokenIdOverride,
    List<int>? recOverride,
    List<int>? in0Override,
    List<int> Function(List<int>)? patchHeader,
    int? counterOverride,
    (List<int>, int)? pay,
  }) =>
      _priced(
          (f) => _transfer(from, ownerKey, to, fund, f, tokenIdOverride, recOverride, in0Override, patchHeader, counterOverride, pay),
          (t) => t.raw.length,
          fee,
          satsPerKb);

  FnftTx _transfer(FnftTx from, LtKey ownerKey, List<int> to, LtCoin? fund, int fee, List<int>? tokenIdOverride,
      List<int>? recOverride, List<int>? in0Override, List<int> Function(List<int>)? patchHeader, int? counterOverride,
      (List<int>, int)? pay) {
    if (pay != null && pay.$1.length != 20) throw ArgumentError('the pay key hash is 20 bytes');
    if (L.termed && counterOverride == null && from.maxHops != 0 && from.counter >= from.maxHops) {
      throw ArgumentError(L.voucher
          ? 'the voucher has made its ${from.maxHops} transfers: it can only be redeemed'
          : 'the note has made its ${from.maxHops} transfers: it can only be ended');
    }
    final in0 = in0Override ?? from.out;
    var h = header(
      tokenId: tokenIdOverride ?? from.tokenId,
      issuer: from.issuer,
      owner: to,
      terms: L.voucher ? from.terms : L.isNote ? from.noteTerms : null,
      counter: counterOverride ?? (L.termed && from.maxHops != 0 ? from.counter + 1 : 0),
      value: from.value + (fund?.sats ?? 0) - fee - (pay?.$2 ?? 0),
      in0: in0,
      fundIn: fund?.out,
      pay: pay == null ? null : [...le(pay.$2, 8), ...pay.$1],
    );
    if (patchHeader != null) h = patchHeader(h);
    final outs = outputsOf(h);
    final nOut = _nOut(h);
    final prevouts = [...in0, ...?fund?.out];
    final nIn = fund == null ? 1 : 2;
    final pre = preimageAll(prevouts: prevouts, nIn: nIn, spent: in0, scriptCode: code, sats: from.value, hashOutputs: h256(outs));
    final sSig = signInput(ownerKey, prevouts: prevouts, input: 0, scriptCode: code, sats: from.value, outputs: outs, nOut: nOut);
    final x = recOverride ?? from.rec;
    final ss0 = [...push(pre), ...push(sSig), ...push(ownerKey.pub), ...push([...h, ...x])];
    final sigs = [...slot(sSig), ...ownerKey.pub];
    var fundPart = <int>[];
    if (fund != null) {
      final s1 = signInput(fund.key, prevouts: prevouts, input: 1, scriptCode: p2pkh(fund.pkh), sats: fund.sats, outputs: outs, nOut: nOut);
      fundPart = _fundPart(fund, s1);
      sigs.addAll([...slot(s1), ...fund.pub]);
    }
    final raw = cat([
      le(1, 4), [nIn], //
      in0, varint(ss0.length), ss0, _seq,
      fundPart,
      [nOut], outs, le(0, 4),
    ]);
    return FnftTx(h, sigs, x, raw, L);
  }

  /// Ends [from]'s token on the cheap path (the owner's signature only):
  /// everything it holds, with [fund] if given, less the fee, to [payTo] at
  /// output 0, P2PKH. No script accepts the result as a token. Output 0 is
  /// the coin a successor's issuance spends ([reissue]).
  Uint8List end({
    required FnftTx from,
    required LtKey ownerKey,
    LtCoin? fund,
    required List<int> payTo,
    int fee = 1000,
    int? satsPerKb,
  }) =>
      _priced((f) => _end(from, ownerKey, fund, payTo, f), (r) => r.length, fee, satsPerKb);

  Uint8List _end(FnftTx from, LtKey ownerKey, LtCoin? fund, List<int> payTo, int fee) {
    if (L.voucher) throw ArgumentError('a Voucher NFT has no burn: it is redeemed to the issuer (redeem, forceRedeem)');
    if (L.isNote) throw ArgumentError('a Note NFT has no burn: it ends by its terms (exit, matureExit, call)');
    final rest = from.value + (fund?.sats ?? 0) - fee;
    if (rest < 1) throw ArgumentError('the token and the funding do not cover the fee $fee');
    final token = from.out;
    final outs = [...le(rest, 8), 0x19, ...p2pkh(payTo)];
    final prevouts = [...token, ...?fund?.out];
    final s0 = signInput(ownerKey, prevouts: prevouts, input: 0, scriptCode: code, sats: from.value, outputs: outs, nOut: 1);
    final ss0 = [...push(s0), ...push(ownerKey.pub)];
    var fundPart = <int>[];
    if (fund != null) {
      final s1 = signInput(fund.key, prevouts: prevouts, input: 1, scriptCode: p2pkh(fund.pkh), sats: fund.sats, outputs: outs, nOut: 1);
      fundPart = _fundPart(fund, s1);
    }
    return cat([
      le(1, 4), [fund == null ? 1 : 2], //
      token, varint(ss0.length), ss0, _seq,
      fundPart,
      [1], outs, le(0, 4),
    ]);
  }

  /// The successor of the token that [ended] ended: an issuance whose first
  /// coin is output 0 of [ended] (the ended token's value, which fuels the
  /// successor), owned by [endKey], who owns that output; [fund] adds fuel.
  /// Only one transaction can spend that output, so a token has at most one
  /// successor. Set the result's `x` to the issuer's attestation.
  FnftTx reissue({
    required List<int> ended,
    required LtKey endKey,
    LtCoin? fund,
    required List<int> issuerPkh,
    FuelTerms? terms,
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
      owner: endKey.pkh,
      terms: terms,
      fee: fee,
      satsPerKb: satsPerKb,
    );
  }

  /// Voucher NFT: the holder redeems [from]'s token to the issuer. The one
  /// output pays the terms' redeemTo everything the token holds (with [fund]
  /// if given) less the fee; the fee taken from the token may not exceed the
  /// terms' feeCap. Output 0 is the coin the successor's issuance spends.
  /// [payToOverride] and [checkCap] false build what an honest wallet never
  /// would (tests).
  Uint8List redeem({
    required FnftTx from,
    required LtKey ownerKey,
    LtCoin? fund,
    int fee = 1000,
    int? satsPerKb,
    List<int>? payToOverride,
    bool checkCap = true,
  }) =>
      _priced((f) => _redeem(from, ownerKey, fund, f, payToOverride, checkCap), (r) => r.length, fee, satsPerKb);

  Uint8List _redeem(FnftTx from, LtKey ownerKey, LtCoin? fund, int fee, List<int>? payToOverride, bool checkCap) {
    if (!L.voucher) throw ArgumentError('${L.name} has no redemption path: use end');
    final out = from.value + (fund?.sats ?? 0) - fee;
    if (checkCap && out < from.value - from.terms.feeCap) {
      throw ArgumentError('the fee $fee takes more than the redemption fee cap ${from.terms.feeCap} from the token: add a funding coin');
    }
    final outs = [...le(out, 8), 0x19, ...p2pkh(payToOverride ?? from.terms.redeemTo)];
    final prevouts = [...from.out, ...?fund?.out];
    final nIn = fund == null ? 1 : 2;
    final pre = preimageAll(prevouts: prevouts, nIn: nIn, spent: from.out, scriptCode: code, sats: from.value, hashOutputs: h256(outs));
    final s0 = signInput(ownerKey, prevouts: prevouts, input: 0, scriptCode: code, sats: from.value, outputs: outs, nOut: 1);
    final ss0 = [...push(pre), ...push(s0), ...push(ownerKey.pub), ...push(le(out, 8))];
    var fundPart = <int>[];
    if (fund != null) {
      final s1 = signInput(fund.key, prevouts: prevouts, input: 1, scriptCode: p2pkh(fund.pkh), sats: fund.sats, outputs: outs, nOut: 1);
      fundPart = _fundPart(fund, s1);
    }
    return cat([
      le(1, 4), [nIn], //
      from.out, varint(ss0.length), ss0, _seq,
      fundPart,
      [1], outs, le(0, 4),
    ]);
  }

  /// Voucher NFT: the issuer forces the redemption of [from]'s token after
  /// its expiry, whoever holds it. [issuerKey] is the key whose hash is the
  /// terms' redeemTo; everything the token holds less the fee goes to
  /// [payTo] (default redeemTo) at output 0. The transaction carries
  /// nLockTime [lockHeight] (default the expiry) and a non-final sequence, so
  /// no node mines it before that height; broadcast it after.
  Uint8List forceRedeem({
    required FnftTx from,
    required LtKey issuerKey,
    List<int>? payTo,
    int? lockHeight,
    int fee = 1000,
    int? satsPerKb,
    int sequence = nonFinal,
    List<int>? ownerOverride,
  }) =>
      _priced((f) => _forceRedeem(from, issuerKey, payTo, lockHeight, f, sequence, ownerOverride), (r) => r.length, fee,
          satsPerKb);

  static const nonFinal = 0xfffffffe;

  Uint8List _forceRedeem(FnftTx from, LtKey issuerKey, List<int>? payTo, int? lockHeight, int fee, int sequence,
      List<int>? ownerOverride) {
    if (!L.voucher) throw ArgumentError('${L.name} has no forced redemption');
    final lock = lockHeight ?? from.terms.expiry;
    final out = from.value - fee;
    if (out < 1) throw ArgumentError('the token does not cover the fee $fee');
    final outs = [...le(out, 8), 0x19, ...p2pkh(payTo ?? from.terms.redeemTo)];
    final prevouts = from.out;
    final pre = preimageAll(
        prevouts: prevouts, nIn: 1, spent: from.out, scriptCode: code, sats: from.value, hashOutputs: h256(outs),
        sequence: sequence, lockTime: lock);
    final s0 = signInput(issuerKey, prevouts: prevouts, input: 0, scriptCode: code, sats: from.value, outputs: outs, nOut: 1,
        sequence: sequence, lockTime: lock);
    final ss0 = [...push(pre), ...push(s0), ...push(issuerKey.pub), ...push(ownerOverride ?? from.owner)];
    return cat([
      le(1, 4), [1], //
      from.out, varint(ss0.length), ss0, le(sequence, 4),
      [1], outs, le(lock, 4),
    ]);
  }

  /// Note NFT: the holder ends [from]'s note before its maturity; the split
  /// is the terms' `exit`.
  Uint8List exit({required FnftTx from, required LtKey ownerKey, int fee = 1000, int? satsPerKb, List<int>? bodyOverride}) =>
      _priced((f) => _noteEnd(from, ownerKey, 1, f, null, bodyOverride: bodyOverride), (r) => r.length, fee, satsPerKb);

  /// Note NFT: the holder ends [from]'s note from its maturity on; the split
  /// is the terms' `mature`. nLockTime is [lockHeight] (default the
  /// maturity) with a non-final sequence: no node mines it before then.
  Uint8List matureExit(
          {required FnftTx from, required LtKey ownerKey, int? lockHeight, int fee = 1000, int? satsPerKb, int sequence = nonFinal}) =>
      _priced((f) => _noteEnd(from, ownerKey, 2, f, lockHeight ?? from.noteTerms.maturity, sequence: sequence), (r) => r.length,
          fee, satsPerKb);

  /// Note NFT: the issuer ([issuerKey], the key of the terms' payTo) ends
  /// [from]'s note from callAt on, whoever holds it; the split is the terms'
  /// `call`. nLockTime is [lockHeight] (default callAt).
  Uint8List call(
          {required FnftTx from,
          required LtKey issuerKey,
          int? lockHeight,
          int fee = 1000,
          int? satsPerKb,
          int sequence = nonFinal,
          List<int>? ownerOverride,
          List<int>? bodyOverride}) =>
      _priced(
          (f) => _noteEnd(from, issuerKey, 3, f, lockHeight ?? from.noteTerms.callAt,
              sequence: sequence, ownerOverride: ownerOverride, bodyOverride: bodyOverride),
          (r) => r.length,
          fee,
          satsPerKb);

  Uint8List _noteEnd(FnftTx from, LtKey key, int path, int fee, int? lock,
      {int sequence = 0xffffffff, List<int>? ownerOverride, List<int>? bodyOverride}) {
    if (!L.isNote) throw ArgumentError('${L.name} has no note endings');
    final t = from.noteTerms;
    if (fee > t.feeCap) throw ArgumentError('the fee $fee is over the note\'s fee cap ${t.feeCap}');
    final a = switch (path) { 1 => t.exit, 2 => t.mature, _ => t.call };
    final (toIssuer, toHolder) = NoteTerms.split(a, from.value, fee);
    final values = toIssuer == 0
        ? [toHolder]
        : toHolder == 0
            ? [toIssuer]
            : [toIssuer, toHolder];
    final payees = toIssuer == 0
        ? [from.owner]
        : toHolder == 0
            ? [t.payTo]
            : [t.payTo, from.owner];
    final body = bodyOverride ?? [for (final v in values) ...le(v, 8)];
    final outs = cat([
      for (var i = 0; i < body.length ~/ 8; i++) [...body.sublist(8 * i, 8 * i + 8), 0x19, ...p2pkh(payees[i.clamp(0, payees.length - 1)])],
    ]);
    final lockTime = lock ?? 0;
    final seq = lock == null ? 0xffffffff : sequence;
    final pre = preimageAll(
        prevouts: from.out, nIn: 1, spent: from.out, scriptCode: code, sats: from.value, hashOutputs: h256(outs),
        sequence: seq, lockTime: lockTime);
    final sig = signInput(key, prevouts: from.out, input: 0, scriptCode: code, sats: from.value, outputs: outs,
        nOut: body.length ~/ 8, sequence: seq, lockTime: lockTime);
    final c = [path, if (path == 3) ...(ownerOverride ?? from.owner), ...body];
    final ss0 = [...push(pre), ...push(sig), ...push(key.pub), ...push(c)];
    return cat([
      le(1, 4), [1], //
      from.out, varint(ss0.length), ss0, le(seq, 4),
      [body.length ~/ 8], outs, le(lockTime, 4),
    ]);
  }

  /// The levels of [rec] as (start, length, funded), outermost first, up to
  /// and including the issuance's (the level after which 326 bytes, the
  /// attestation, remain), or with no attestation the level the record ends
  /// with. Throws when the record does not divide into levels.
  static List<(int, int, bool)> levels(List<int> rec) {
    final out = <(int, int, bool)>[];
    var at = 0;
    while (true) {
      if (at >= rec.length) throw ArgumentError('the record is cut short');
      final f = rec[at];
      if (f & ~(FnftLayout.flagFunded | FuelLayout.flagPaid) != 0) throw ArgumentError('level ${out.length} has flags $f');
      final n = FnftLayout.level(f & FnftLayout.flagFunded != 0) + (f & FuelLayout.flagPaid != 0 ? 28 : 0);
      if (at + n > rec.length) throw ArgumentError('the record is cut short');
      out.add((at, n, f & FnftLayout.flagFunded != 0));
      at += n;
      final left = rec.length - at;
      if (left == FnftLayout.attestation || left == 0) return out;
    }
  }

  /// The transaction whose record is [rec], rebuilt byte for byte as the
  /// script rebuilds it, with [prefix] as the derived 72 header bytes. A
  /// transaction that is not what its record describes has another txid,
  /// so a caller who knows the txid compares.
  FnftTx fromRec(List<int> rec, {required List<int> prefix}) {
    if (prefix.length != L.derived) throw ArgumentError('the prefix is ${prefix.length} bytes, not 72');
    if (rec.isEmpty) throw ArgumentError('an empty record');
    final f = rec[0];
    final paid = L.payable && f & FuelLayout.flagPaid != 0;
    if (f & ~(FnftLayout.flagFunded | (L.payable ? FuelLayout.flagPaid : 0)) != 0) throw ArgumentError('flags $f');
    final funded = f & FnftLayout.flagFunded != 0;
    final hc = FnftLayout.recHeader(funded) + (paid ? 28 : 0);
    final sl = funded ? 2 * LtLayout.sigPair : LtLayout.sigPair;
    if (rec.length < hc + sl) throw ArgumentError('the record is cut short');
    final r = rec.sublist(0, hc);
    final h = [
      ...prefix, ...r.sublist(0, 45), //
      ...(funded ? r.sublist(45, 81) : zero36),
      if (L.payable) ...(paid ? r.sublist(hc - 28, hc) : List<int>.filled(28, 0)),
    ];
    final sigs = rec.sublist(hc, hc + sl);
    final x = rec.sublist(hc + sl);
    List<int> sigIn(int i) {
      final s = sigs.sublist(i * LtLayout.sigPair, i * LtLayout.sigPair + LtLayout.slot);
      if (s[0] > 73) throw ArgumentError('signature slot $i is malformed');
      return s.sublist(1, 1 + s[0]);
    }

    List<int> pubIn(int i) => sigs.sublist(i * LtLayout.sigPair + LtLayout.slot, (i + 1) * LtLayout.sigPair);
    final t = FnftTx(h, sigs, x, Uint8List(0), L);
    final outs = outputsOf(h);
    final in0 = t.in0;
    final List<int> ss0;
    if (t.isIssuance) {
      ss0 = [...push(sigIn(0)), ...push(pubIn(0))];
    } else {
      if (x.length < 9) throw ArgumentError('the parent record is cut short');
      var spent = 0;
      for (var i = 8; i >= 1; i--) {
        spent = (spent << 8) | x[i];
      }
      final pre = preimageAll(
        prevouts: [...in0, if (funded) ...h.sublist(L.fundIn, L.fundIn + 36)],
        nIn: funded ? 2 : 1,
        spent: in0,
        scriptCode: code,
        sats: spent,
        hashOutputs: h256(outs),
      );
      ss0 = [...push(pre), ...push(sigIn(0)), ...push(pubIn(0)), ...push([...h, ...x])];
    }
    List<int> fundPart = const [];
    if (funded) {
      final ss1 = [...push(sigIn(1)), ...push(pubIn(1))];
      fundPart = [...h.sublist(L.fundIn, L.fundIn + 36), ...varint(ss1.length), ...ss1, ..._seq];
    }
    final raw = cat([
      le(1, 4), [funded ? 2 : 1], //
      in0, varint(ss0.length), ss0, _seq,
      fundPart,
      [_nOut(h)], outs, le(0, 4),
    ]);
    return FnftTx(h, sigs, x, raw, L);
  }

  /// The transaction whose record is [rec] when only its [issuer] and
  /// [owner] (HASH160 of the key that spent its token output) are known: the
  /// token id comes from the record, by rebuilding the issuance at its tail,
  /// whose txid it is, and whose owner signed the level before it.
  ///
  /// A Voucher NFT's record also leaves out its [terms] (given) and its
  /// counter (the number of levels above the issuance's).
  FnftTx fromRecOf(List<int> rec, {required List<int> issuer, required List<int> owner, FuelTerms? terms}) {
    if (L.termed != (terms != null)) throw ArgumentError(L.termed ? 'a ${L.name} record needs its terms' : '${L.name} has no terms');
    final lv = levels(rec);
    final (iStart, _, _) = lv.last;
    final counted = terms != null && terms.maxHops != 0;
    List<int> pfx(List<int> tid, List<int> own, int counter) =>
        [...tid, ...issuer, ...?terms?.bytes, ...own, if (L.termed) counted ? counter : 0];
    if (lv.length == 1) return fromRec(rec, prefix: pfx(zero32, owner, 0));
    final (hStart, _, hFunded) = lv[lv.length - 2];
    final hop1Pub = rec.sublist(hStart + FnftLayout.recHeader(hFunded) + LtLayout.slot,
        hStart + FnftLayout.recHeader(hFunded) + LtLayout.sigPair);
    final issuance = fromRec(rec.sublist(iStart), prefix: pfx(zero32, hash160(hop1Pub), 0));
    return fromRec(rec, prefix: pfx(issuance.txid, owner, lv.length - 1));
  }

  /// [raw] as a Fuelled NFT transaction of this code: its header from its
  /// token output, its signatures and X from its unlocks. Throws unless [raw]
  /// is exactly the transaction its record rebuilds. An issuance comes back
  /// with an empty `x`: the attestation is not in it.
  FnftTx fromRaw(List<int> raw) {
    final Transaction tx;
    try {
      tx = Transaction.fromHex(hex.encode(raw));
    } catch (e) {
      throw ArgumentError('not a transaction: $e');
    }
    if (tx.outputs.isEmpty || tx.outputs.length > (L.payable ? 2 : 1) || tx.inputs.isEmpty || tx.inputs.length > 2) {
      throw ArgumentError('not a Fuelled NFT transaction: ${tx.inputs.length} inputs, ${tx.outputs.length} outputs');
    }
    final c = tx.outputs[0].script.chunks;
    if (c.isEmpty || c.first.buf == null || c.first.buf!.length != L.size) {
      throw ArgumentError('output 0 is not a token output');
    }
    final h = c.first.buf!.toList();
    List<List<int>> pushes(int i) {
      final ch = tx.inputs[i].script?.chunks ?? const [];
      if (ch.any((x) => x.buf == null)) throw ArgumentError('input $i\'s unlock is not pushes only');
      return [for (final x in ch) x.buf!.toList()];
    }

    final issuance = h.sublist(0, 32).every((b) => b == 0);
    final in0 = pushes(0);
    if (in0.length != (issuance ? 2 : 4)) throw ArgumentError('input 0 is not a ${issuance ? 'P2PKH' : 'normal-path'} spend');
    final (s0, p0) = issuance ? (in0[0], in0[1]) : (in0[1], in0[2]);
    final sigs = <int>[...slot(s0), ...p0];
    if (tx.inputs.length == 2) {
      final p = pushes(1);
      if (p.length != 2) throw ArgumentError('input 1 is not a signature and a key');
      sigs.addAll([...slot(p[0]), ...p[1]]);
    }
    List<int> x = const [];
    if (!issuance) {
      if (in0[3].length < L.size) throw ArgumentError('input 0 carries no record');
      x = in0[3].sublist(L.size);
    }
    final probe = FnftTx(h, const [], const [], Uint8List(0), L);
    final t = fromRec([...probe.recHeader, ...sigs, ...x], prefix: h.sublist(0, L.derived));
    if (hex.encode(t.raw) != hex.encode(raw)) throw ArgumentError('not the transaction its record rebuilds');
    return t;
  }
}
