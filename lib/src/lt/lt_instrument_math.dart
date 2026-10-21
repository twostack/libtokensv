// The numbers an agent prices a Note or a Voucher with
// (AGENT_ECONOMY_PLAN.md item C): pure functions of the terms, a value and a
// height, next to the builder whose transactions they describe. Each number
// is checked against the builder's own transaction in
// test/lt_instrument_math_test.dart.
import 'lt_fnft_builder.dart';

/// One way a note can end at a height: whether it is open, who may send it,
/// and what each side gets.
class NoteEnding {
  final String name;
  final bool available;
  final String by;
  final int holder, issuer;
  const NoteEnding(this.name, this.available, this.by, this.holder, this.issuer);
  @override
  String toString() => '$name (${available ? 'open' : 'closed'}, by the $by): holder $holder, issuer $issuer';
}

extension NoteMath on NoteTerms {
  /// The three endings of a note holding [value], at [height], with a fee of
  /// [fee] taken from the note: exit (the holder, before maturity), mature
  /// (the holder, from maturity), call (the issuer, from callAt). The
  /// amounts are the builder's: `NoteTerms.split`.
  List<NoteEnding> endingsAt({required int height, required int value, int fee = 1000}) {
    NoteEnding e(String name, bool open, String by, int amount) {
      final (toIssuer, toHolder) = NoteTerms.split(amount, value, fee);
      return NoteEnding(name, open, by, toHolder, toIssuer);
    }

    return [
      e('exit', height < maturity, 'holder', exit),
      e('mature', height >= maturity, 'holder', mature),
      e('call', height >= callAt, 'issuer', call),
    ];
  }

  /// What the holder can take at [height] by its own hand: the mature
  /// amount from maturity, the exit before it.
  int holderAt({required int height, required int value, int fee = 1000}) =>
      endingsAt(height: height, value: value, fee: fee)[height >= maturity ? 1 : 0].holder;

  /// What the holder gets at maturity.
  int holderAtMaturity({required int value, int fee = 1000}) => NoteTerms.split(mature, value, fee).$2;

  /// What the holder gets if the issuer calls.
  int holderIfCalled({required int value, int fee = 1000}) => NoteTerms.split(call, value, fee).$2;

  /// Blocks from [height] to maturity, and to the first call; null when
  /// never.
  int? blocksToMaturity(int height) => maturity >= NoteTerms.never ? null : maturity - height;
  int? blocksToCall(int height) => callAt >= NoteTerms.never ? null : callAt - height;

  /// The simple yield per block of paying [price] now for a note holding
  /// [value], held to maturity from [height]: (mature payout − price) /
  /// price / blocks. Null when the note never matures or is already mature.
  double? yieldPerBlock({required int price, required int value, required int height, int fee = 1000}) {
    final blocks = blocksToMaturity(height);
    if (blocks == null || blocks <= 0 || price <= 0) return null;
    return (holderAtMaturity(value: value, fee: fee) - price) / price / blocks;
  }

  /// What the holder loses if the issuer calls instead of letting the note
  /// mature: the mature payout less the call payout (0 when a call pays as
  /// much, or the note cannot be called).
  int callCost({required int value, int fee = 1000}) {
    if (callAt >= NoteTerms.never) return 0;
    final d = holderAtMaturity(value: value, fee: fee) - holderIfCalled(value: value, fee: fee);
    return d > 0 ? d : 0;
  }

  /// Whether the issuer may call before the note matures.
  bool get callableBeforeMaturity => callAt < maturity;
}

extension VoucherMath on VoucherTerms {
  /// Blocks from [height] to the expiry, from which the issuer may force
  /// the redemption; 0 or less once it may.
  int blocksToExpiry(int height) => expiry - height;

  /// The height from which the issuer may redeem it whoever holds it.
  int get forcedRedemptionHeight => expiry;

  /// What the redemption pays redeemTo from a voucher holding [value] at a
  /// fee of [fee], which may not exceed feeCap.
  int redeemed({required int value, int fee = 1000}) {
    if (fee > feeCap) throw ArgumentError('the fee $fee exceeds feeCap $feeCap');
    return value - fee;
  }
}
