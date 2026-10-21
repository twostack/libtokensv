// What a wallet holds of a covenant NFT and how it checks one it is paid,
// from raw transaction bytes. BEEF is the wallet's: the wallet proves that
// the transaction's ancestry is mined and has the network take it; this
// file says whether the bytes are a genuine token of the issuer, owned by
// the wallet's key. docs/LT_NFT_WALLET_INTEGRATION.md is the integrator's
// side of the same contract.
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'lt_builder.dart';
import 'lt_identity.dart';
import 'lt_layout.dart';
import 'lt_payload.dart';
import 'lt_succession.dart';

/// One reissue in a token's history: [ended], the raw transaction that
/// ended the predecessor, and [recG], the record of the transaction whose
/// token output it spent ([LtSuccession.verify]). For a Voucher NFT,
/// [terms] are the predecessor's terms (33 bytes, 61 for a Note NFT), which its record leaves
/// out and a reissue may change; empty otherwise.
class LtLink {
  final List<int> ended;
  final List<int> recG;
  final List<int> terms;
  LtLink(this.ended, this.recG, [this.terms = const []]);
}

/// The links a transfer carries, newest first, as bytes: a varint count,
/// then per link a varint length and [LtLink.ended], a varint length and
/// [LtLink.recG], a varint length and [LtLink.terms] (0 when none).
class LtLinks {
  static Uint8List encode(List<LtLink> links) => cat([
        varint(links.length),
        for (final l in links) ...[varint(l.ended.length), l.ended, varint(l.recG.length), l.recG, varint(l.terms.length), l.terms],
      ]);

  static List<LtLink> decode(List<int> b) {
    var at = 0;
    int vi() {
      if (at >= b.length) throw ArgumentError('links cut short');
      final f = b[at++];
      if (f < 253) return f;
      final n = f == 0xfd ? 2 : f == 0xfe ? 4 : throw ArgumentError('link length too large');
      if (at + n > b.length) throw ArgumentError('links cut short');
      var v = 0;
      for (var i = n - 1; i >= 0; i--) {
        v = (v << 8) | b[at + i];
      }
      at += n;
      return v;
    }

    List<int> bytes() {
      final n = vi();
      if (at + n > b.length) throw ArgumentError('links cut short');
      return b.sublist(at, at += n);
    }

    final count = vi();
    final out = [for (var i = 0; i < count; i++) LtLink(bytes(), bytes(), bytes())];
    if (at != b.length) throw ArgumentError('${b.length - at} trailing bytes after the links');
    return out;
  }
}

/// A covenant NFT a wallet holds: output [k] of [tx], the token [tokenId],
/// whose lineage through [links] starts at [originId] (the same id when it
/// was never reissued). Rec([tx]) is what the next transfer carries; the
/// wallet keeps [tx]'s raw bytes and the links, and nothing else.
class LtHolding {
  final LtTx tx;
  final int k;
  final List<int> tokenId;
  final List<int> originId;
  final List<LtLink> links;

  /// The payload bound to the token's issuance ([LtPayload]), when the check
  /// was given its payload transaction; null otherwise.
  final List<int>? payload;
  LtHolding(this.tx, this.k, this.tokenId, this.originId, this.links, [this.payload]);

  /// The outpoint the wallet holds: ([tx], [k]).
  List<int> get out => outpoint(tx.txid, k);
}

/// The payee's check refused the token; [reason] says which check.
class LtRefused implements Exception {
  final String reason;
  LtRefused(this.reason);
  @override
  String toString() => 'LtRefused: $reason';
}

class LtReceive {
  static final _flags = {
    VerifyFlag.SIGHASH_FORKID,
    VerifyFlag.LOW_S,
    VerifyFlag.NULLFAIL,
    VerifyFlag.MINIMALDATA,
    VerifyFlag.MINIMALIF,
    VerifyFlag.SIGPUSHONLY,
    VerifyFlag.UTXO_AFTER_GENESIS,
  };

  /// The payee's check of the covenant NFT at output 1 of [raw], paid to
  /// [ownerPkh]. Returns the holding, or throws [LtRefused] at the first
  /// check that fails:
  ///  1. [raw] is a token transaction of [b]'s code, exactly as its record
  ///     rebuilds it, and output 1 is owned by [ownerPkh];
  ///  2. an issuance carries [attestation]; any other transaction spends,
  ///     at input 0 on the normal path, output 1 of the transaction its
  ///     record rebuilds, so its output is the one the token's code forces;
  ///     with [runScript] that spend is also run here, so that a token not
  ///     yet mined is checked before the network sees it;
  ///  3. the issuer attestation the record ends with verifies against
  ///     [anchorTx];
  ///  4. each of [links] (newest first) shows the token's issuance
  ///     succeeding the token before it ([LtSuccession.verify]);
  ///  5. with [payloadTx], it is the payload transaction of the token's
  ///     issuance ([LtPayload.of]), and the holding carries the payload.
  /// What it does not check is the wallet's: that the transaction's
  /// ancestry is mined (its BEEF) and that the network takes it.
  static Future<LtHolding> check({
    required LtBuilder b,
    required List<int> raw,
    required List<int> ownerPkh,
    required Transaction anchorTx,
    List<int>? attestation,
    List<LtLink> links = const [],
    bool runScript = true,
    List<int>? payloadTx,
  }) async {
    final L = b.L;
    if (L.fungible) throw LtRefused('the payee check is defined for the NFT');

    // 1. the bytes, and the owner
    final LtTx t;
    try {
      t = b.fromRaw(raw);
    } on ArgumentError catch (e) {
      throw LtRefused('not a token transaction of this code: ${e.message}');
    }
    if (hex.encode(t.h1.sublist(L.owner, L.owner + 20)) != hex.encode(ownerPkh)) {
      throw LtRefused('the token is not paid to this key');
    }

    // 2. the input side
    if (t.isIssuance) {
      if (attestation == null) throw LtRefused('an issuance comes with its issuer attestation');
      t.x = attestation;
    } else {
      final LtTx p;
      try {
        p = b.fromRec(t.x);
      } on ArgumentError catch (e) {
        throw LtRefused('the parent record does not parse: ${e.message}');
      }
      final in0 = t.h1.sublist(L.in0, L.in0 + 36);
      if (hex.encode(in0) != hex.encode(outpoint(p.txid, 1))) {
        throw LtRefused('input 0 does not spend the token output of the transaction its record rebuilds');
      }
      if (hex.encode(p.isIssuance ? p.txid : p.tokenId) != hex.encode(t.tokenId)) {
        throw LtRefused('the parent is of another token');
      }
      if (runScript) {
        final tx = Transaction.fromHex(hex.encode(raw));
        try {
          Interpreter().correctlySpends(tx.inputs[0].script!, SVScript.fromByteArray(Uint8List.fromList(p.lock(1, b.code))),
              tx, 0, _flags, Coin.valueOf(BigInt.one));
        } catch (e) {
          throw LtRefused('the token\'s script refuses the spend: $e');
        }
      }
    }

    // 3. the issuer
    final who = await LtIdentity.verify(t, anchorTx);
    if (who != null) throw LtRefused('issuer: $who');

    // 4. the reissues
    final tokenId = t.isIssuance ? t.txid : t.tokenId;
    var issuance = issuanceOf(b, t);
    final payload = payloadTx == null ? null : LtPayload.of(issuance.raw, payloadTx);
    var origin = tokenId;
    for (var i = 0; i < links.length; i++) {
      final LtTx g;
      try {
        g = b.fromRec(links[i].recG);
      } on ArgumentError catch (e) {
        throw LtRefused('link $i: the record does not parse: ${e.message}');
      }
      final predecessor = g.isIssuance ? g.txid : g.tokenId;
      final why = await LtSuccession.verify(
          b: b, r: issuance, predecessor: predecessor, ended: links[i].ended, recG: links[i].recG, anchorTx: anchorTx);
      if (why != null) throw LtRefused('link $i: $why');
      issuance = issuanceOf(b, g);
      origin = predecessor;
    }
    return LtHolding(t, 1, tokenId, origin, links, payload);
  }

  /// The issuance of [t]'s token, with its attestation: [t] itself when it
  /// is the issuance, otherwise rebuilt from the end of [t]'s record, where
  /// the issuance's record sits, and refused unless its txid is [t]'s token
  /// id.
  static LtTx issuanceOf(LtBuilder b, LtTx t) {
    if (t.isIssuance) return t;
    final rec = t.rec;
    final n = b.L.issuanceRec + LtIssuerBlob.size;
    if (rec.length < n) throw LtRefused('the record is too short to hold the issuance');
    final r = b.fromRec(rec.sublist(rec.length - n));
    if (!r.isIssuance) throw LtRefused('the record does not end with the issuance');
    if (hex.encode(r.txid) != hex.encode(t.tokenId)) throw LtRefused('the record ends with another token\'s issuance');
    return r;
  }
}
