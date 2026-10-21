// The payload transaction (WITNESS_LINEAGE_RESEARCH.md 9.11): content
// bound to a lineage token with no script change and no bytes per hop.
//
// The payload transaction of a token is the transaction whose output funds
// input 1 of the token's issuance. Its output 0 is OP_FALSE OP_RETURN
// <payload>, one push. The token id is the issuance's txid, which commits
// to input 1's outpoint, which names the payload transaction by its txid,
// which commits to its outputs. So the token id commits to the payload for
// the token's life, in every archetype whose issuance has an input 1 (the
// covenant NFT always; the Fuelled and Voucher NFT when funded).
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'lt_builder.dart';
import 'lt_wallet.dart' show LtRefused;

class LtPayload {
  /// The largest payload [build] writes and [of] reads.
  static const maxPayload = 100000;

  /// The payload transaction: [coin] in, output 0 the data, output 1 a
  /// P2PKH coin of [fundSats] to [coin]'s key (the issuance's input 1),
  /// output 2 the change when there is any. Returns the raw transaction and
  /// output 1 as a coin.
  static (Uint8List, LtCoin) build({
    required LtCoin coin,
    required List<int> payload,
    required int fundSats,
    int fee = 1000,
    int? satsPerKb,
  }) {
    if (payload.isEmpty || payload.length > maxPayload) throw ArgumentError('a payload is 1 to $maxPayload bytes');
    if (fundSats < 1) throw ArgumentError('the issuance\'s coin holds at least 1 sat');
    (Uint8List, LtCoin) at(int f) {
      final change = coin.sats - fundSats - f;
      if (change < 0) throw ArgumentError('the coin (${coin.sats} sats) does not cover $fundSats and the fee $f');
      final data = [OpCodes.OP_FALSE, OpCodes.OP_RETURN, ...push(payload)];
      final outputs = cat([
        [...le(0, 8), ...varint(data.length), ...data],
        [...le(fundSats, 8), 0x19, ...p2pkh(coin.pkh)],
        if (change > 0) [...le(change, 8), 0x19, ...p2pkh(coin.pkh)],
      ]);
      final nOut = change > 0 ? 3 : 2;
      final sig = signInput(coin.key, prevouts: coin.out, input: 0, scriptCode: p2pkh(coin.pkh), sats: coin.sats, outputs: outputs, nOut: nOut);
      final ss = [...push(sig), ...push(coin.pub)];
      final raw = cat([
        le(1, 4), [1], coin.out, varint(ss.length), ss, le(0xffffffff, 4), //
        [nOut], outputs, le(0, 4),
      ]);
      return (raw, LtCoin(outpoint(h256(raw), 1), coin.key, fundSats));
    }

    return satsPerKb == null ? at(fee) : at(LtBuilder.feeFor(at(LtBuilder.minFee).$1.length, satsPerKb));
  }

  /// Whether [raw] has a payload transaction's shape: output 0 OP_FALSE
  /// OP_RETURN with one minimal push of 1 to [maxPayload] bytes, output 1 a
  /// P2PKH (the issuance's input 1). What a wallet checks on the primary
  /// transaction of a paired issue.
  static bool isPayloadTx(List<int> raw) {
    try {
      final p = Transaction.fromHex(hex.encode(raw));
      if (p.outputs.length < 2) return false;
      final s = p.outputs.first.script.buffer;
      if (s.length < 3 || s[0] != OpCodes.OP_FALSE || s[1] != OpCodes.OP_RETURN) return false;
      final chunks = SVScript.fromByteArray(Uint8List.fromList(s.sublist(2))).chunks;
      if (chunks.length != 1 || chunks.first.buf == null) return false;
      final payload = chunks.first.buf!.toList();
      if (payload.isEmpty || payload.length > maxPayload || hex.encode(push(payload)) != hex.encode(s.sublist(2))) return false;
      final f = p.outputs[1].script.buffer;
      return f.length == 25 && f[0] == OpCodes.OP_DUP && f[1] == OpCodes.OP_HASH160 && f[24] == OpCodes.OP_CHECKSIG;
    } catch (_) {
      return false;
    }
  }

  /// The payload of the token issued by [issuanceRaw] (any archetype),
  /// given its payload transaction [payloadTx]. Throws [LtRefused] unless
  /// [payloadTx] is the transaction input 1 of the issuance spends, at its
  /// output 1, and its output 0 is OP_FALSE OP_RETURN with one push.
  static List<int> of(List<int> issuanceRaw, List<int> payloadTx) {
    final Transaction iss;
    try {
      iss = Transaction.fromHex(hex.encode(issuanceRaw));
    } catch (e) {
      throw LtRefused('the issuance does not parse: $e');
    }
    if (iss.inputs.length < 2) throw LtRefused('the issuance has no input 1: the token carries no payload');
    final in1 = iss.inputs[1];
    if (in1.prevTxnId != hex.encode(h256(payloadTx).reversed.toList())) {
      throw LtRefused('the payload transaction is not the one the issuance\'s input 1 spends');
    }
    if (in1.prevTxnOutputIndex != 1) throw LtRefused('the issuance spends output ${in1.prevTxnOutputIndex}, not output 1');
    final Transaction p;
    try {
      p = Transaction.fromHex(hex.encode(payloadTx));
    } catch (e) {
      throw LtRefused('the payload transaction does not parse: $e');
    }
    final s = p.outputs.first.script.buffer;
    if (s.length < 3 || s[0] != OpCodes.OP_FALSE || s[1] != OpCodes.OP_RETURN) {
      throw LtRefused('output 0 of the payload transaction is not OP_FALSE OP_RETURN');
    }
    final chunks = SVScript.fromByteArray(Uint8List.fromList(s.sublist(2))).chunks;
    if (chunks.length != 1 || chunks.first.buf == null) throw LtRefused('the payload is not one push');
    final payload = chunks.first.buf!.toList();
    if (payload.isEmpty || payload.length > maxPayload) throw LtRefused('the payload is ${payload.length} bytes');
    if (hex.encode(push(payload)) != hex.encode(s.sublist(2))) throw LtRefused('the payload push is not minimal');
    return payload;
  }
}
