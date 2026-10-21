// What a wallet checks of a Fuelled NFT (TSL1_LT_FNFT), from raw transaction
// bytes: the payee's check, the issuer, and reissue succession. BEEF, SPV and
// broadcasting are the wallet's (docs/LT_FNFT_WALLET_INTEGRATION.md).
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'lt_builder.dart' show h256, outpoint;
import 'lt_fnft_builder.dart';
import 'lt_fnft_script_gen.dart';
import 'lt_identity.dart';
import 'lt_layout.dart';
import 'lt_payload.dart';
import 'lt_wallet.dart' show LtLink, LtRefused;

/// A Fuelled NFT a wallet holds: output 0 of [tx], the token [tokenId],
/// whose lineage through [links] starts at [originId], holding [value] sats
/// of fuel.
class FnftHolding {
  final FnftTx tx;
  final List<int> tokenId;
  final List<int> originId;
  final List<LtLink> links;

  /// The payload bound to the token's issuance ([LtPayload]), when the check
  /// was given its payload transaction; null otherwise.
  final List<int>? payload;
  FnftHolding(this.tx, this.tokenId, this.originId, this.links, [this.payload]);

  List<int> get out => tx.out;
  int get value => tx.value;
}

class FnftIdentity {
  /// The attestation [t]'s record ends with (the issuance's own `x`), or null.
  static List<int>? blobOf(FnftTx t) {
    if (t.isIssuance) return t.x.length == FnftLayout.attestation ? t.x : null;
    final rec = t.rec;
    return rec.length < FnftLayout.attestation ? null : rec.sublist(rec.length - FnftLayout.attestation);
  }

  /// [LtIdentity.attestationError] for a Fuelled NFT.
  static String? attestationError(FnftTx t) {
    final blob = blobOf(t);
    if (blob == null) return 'the record has no issuer attestation';
    return LtIdentity.attestationErrorOf(blob: blob, issuerPkh: t.issuer, tokenId: t.tokenId);
  }

  /// [LtIdentity.verify] for a Fuelled NFT.
  static Future<String?> verify(FnftTx t, Transaction anchorTx) =>
      LtIdentity.verifyOf(blob: blobOf(t), issuerPkh: t.issuer, tokenId: t.tokenId, anchorTx: anchorTx);
}

class FnftReceive {
  static final _flags = {
    VerifyFlag.SIGHASH_FORKID,
    VerifyFlag.LOW_S,
    VerifyFlag.NULLFAIL,
    VerifyFlag.MINIMALDATA,
    VerifyFlag.MINIMALIF,
    VerifyFlag.SIGPUSHONLY,
    VerifyFlag.UTXO_AFTER_GENESIS,
  };

  /// The payee's check of the Fuelled NFT at output 0 of [raw], paid to
  /// [ownerPkh]. Returns the holding or throws [LtRefused] at the first check
  /// that fails:
  ///  1. [raw] is a transaction of [b]'s code, exactly as its record rebuilds
  ///     it, and its token is owned by [ownerPkh];
  ///  2. an issuance carries [attestation]; any other transaction spends,
  ///     at input 0, output 0 of the transaction its record rebuilds (with
  ///     the derived bytes the script would splice in) and is of the same
  ///     token; with [runScript] that spend is run here too;
  ///  3. the issuer attestation verifies against [anchorTx];
  ///  4. each of [links] (newest first) shows the token's issuance succeeding
  ///     the token before it ([FnftSuccession.verify]);
  ///  5. with [payloadTx], it is the payload transaction of the token's
  ///     issuance ([LtPayload.of]), and the holding carries the payload.
  static Future<FnftHolding> check({
    required FnftBuilder b,
    required List<int> raw,
    required List<int> ownerPkh,
    required Transaction anchorTx,
    List<int>? attestation,
    List<LtLink> links = const [],
    bool runScript = true,
    List<int>? payloadTx,
  }) async {
    final FnftTx t;
    try {
      t = b.fromRaw(raw);
    } on ArgumentError catch (e) {
      throw LtRefused('not a Fuelled NFT transaction of this code: ${e.message}');
    }
    if (hex.encode(t.owner) != hex.encode(ownerPkh)) throw LtRefused('the token is not paid to this key');

    if (t.isIssuance) {
      if (attestation == null) throw LtRefused('an issuance comes with its issuer attestation');
      t.x = attestation;
    } else {
      final FnftTx p;
      try {
        p = b.fromRec(t.x, prefix: t.parentPrefix);
      } on ArgumentError catch (e) {
        throw LtRefused('the parent record does not parse: ${e.message}');
      }
      if (hex.encode(t.in0) != hex.encode(p.out)) {
        throw LtRefused('input 0 does not spend the token output of the transaction its record rebuilds');
      }
      if (hex.encode(p.tokenId) != hex.encode(t.tokenId)) throw LtRefused('the parent is of another token');
      if (runScript) {
        final tx = Transaction.fromHex(hex.encode(raw));
        try {
          Interpreter().correctlySpends(tx.inputs[0].script!, SVScript.fromByteArray(Uint8List.fromList(p.lock(b.code))), tx, 0,
              _flags, Coin.valueOf(BigInt.from(p.value)));
        } catch (e) {
          throw LtRefused('the token\'s script refuses the spend: $e');
        }
      }
    }

    final who = await FnftIdentity.verify(t, anchorTx);
    if (who != null) throw LtRefused('issuer: $who');

    var issuance = issuanceOf(b, t);
    final payload = payloadTx == null ? null : LtPayload.of(issuance.raw, payloadTx);
    var origin = t.tokenId;
    for (var i = 0; i < links.length; i++) {
      final FnftTx g;
      try {
        g = FnftSuccession.ended(b, links[i].ended, links[i].recG, issuance.issuer, terms: links[i].terms);
      } on ArgumentError catch (e) {
        throw LtRefused('link $i: the record does not parse: ${e.message}');
      }
      final why = await FnftSuccession.verify(
          b: b,
          r: issuance,
          predecessor: g.tokenId,
          ended: links[i].ended,
          recG: links[i].recG,
          anchorTx: anchorTx,
          terms: links[i].terms);
      if (why != null) throw LtRefused('link $i: $why');
      issuance = issuanceOf(b, g);
      origin = g.tokenId;
    }
    return FnftHolding(t, t.tokenId, origin, links, payload);
  }

  /// The issuance of [t]'s token with its attestation: [t] itself, or
  /// rebuilt from the last level of [t]'s record (its owner signed the level
  /// before it), refused unless its txid is [t]'s token id.
  static FnftTx issuanceOf(FnftBuilder b, FnftTx t) {
    if (t.isIssuance) return t;
    final rec = t.rec;
    final List<(int, int, bool)> lv;
    try {
      lv = FnftBuilder.levels(rec);
    } on ArgumentError catch (e) {
      throw LtRefused('the record does not divide into levels: ${e.message}');
    }
    if (rec.length - (lv.last.$1 + lv.last.$2) != FnftLayout.attestation || lv.length < 2) {
      throw LtRefused('the record does not end with the issuance');
    }
    final (hStart, _, hFunded) = lv[lv.length - 2];
    final hop1Pub = rec.sublist(hStart + FnftLayout.recHeader(hFunded) + LtLayout.slot,
        hStart + FnftLayout.recHeader(hFunded) + LtLayout.sigPair);
    final r = b.fromRec(rec.sublist(lv.last.$1), prefix: [
      ...FnftBuilder.zero32,
      ...t.h.sublist(t.L.issuer, t.L.owner), // the issuer, and a voucher's terms
      ...hash160(hop1Pub),
      if (t.L.termed) 0,
    ]);
    if (hex.encode(r.txid) != hex.encode(t.tokenId)) throw LtRefused('the record ends with another token\'s issuance');
    return r;
  }
}

class FnftSuccession {
  /// G, the transaction whose token output [ended]'s input 0 spent, rebuilt
  /// from its record [recG]: its owner is the key that signed that input,
  /// its issuer [issuer] (the successor's, which the txid then confirms).
  static FnftTx ended(FnftBuilder b, List<int> ended, List<int> recG, List<int> issuer, {List<int> terms = const []}) {
    final e = Transaction.fromHex(hex.encode(ended));
    final owner = endedOwner(b, e) ?? (throw ArgumentError('the ended transaction\'s input 0 does not end a token'));
    return b.fromRecOf(recG,
        issuer: issuer,
        owner: owner,
        terms: b.L.voucher
            ? VoucherTerms.of(terms)
            : b.L.isNote
                ? NoteTerms.of(terms)
                : null);
  }

  /// The owner of the token output [e]'s input 0 ended, or null when that
  /// input is no ending spend: for the Fuelled NFT the cheap path
  /// (PUSH(sig) PUSH(pub), the owner's key); for the Voucher NFT a holder's
  /// redemption (pre, sig, the owner's key, an 8-byte value) or the issuer's
  /// force-redemption (pre, sig, the issuer's key, the owner's 20-byte hash);
  /// for the Note NFT the holder's exit (the last push 9 or 17 bytes: the
  /// signer is the owner) or the issuer's call (29 or 37 bytes, the owner's
  /// hash at bytes 1..21).
  static List<int>? endedOwner(FnftBuilder b, Transaction e) {
    if (e.inputs.isEmpty) return null;
    final chunks = e.inputs.first.script?.chunks ?? const [];
    if (chunks.any((c) => c.buf == null)) return null;
    if (!b.L.termed) return chunks.length == 2 ? hash160(chunks[1].buf!) : null;
    if (chunks.length != 4) return null;
    final last = chunks[3].buf!;
    if (b.L.isNote) {
      if (last.length == 9 || last.length == 17) return hash160(chunks[2].buf!);
      if (last.length == 29 || last.length == 37) return last.sublist(1, 21);
      return null;
    }
    if (last.length == 8) return hash160(chunks[2].buf!);
    if (last.length == 20) return last;
    return null;
  }

  /// The wallet's check that the issuance [r] succeeds the token
  /// [predecessor], given [ended], the transaction that ended it, and [recG],
  /// the record of the transaction whose token output [ended] spent. Null
  /// when:
  ///  1. [r] is an issuance whose first input spends output 0 of [ended];
  ///  2. [ended]'s input 0 spends output 0 of G on the cheap path (two pushes);
  ///  3. G is [recG] rebuilt and its output 0 is a genuine output of
  ///     [predecessor]: G is its issuance, or G's input 0 spends output 0 of
  ///     the transaction the record in G's unlock rebuilds;
  ///  4. [r] and G name the same issuer (the rebuild with [r]'s issuer
  ///     matches), and [r] (and G when G is the issuance) verify against
  ///     [anchorTx].
  /// Otherwise the first that fails. [ended] being mined is the caller's
  /// check (a BEEF).
  static Future<String?> verify({
    required FnftBuilder b,
    required FnftTx r,
    required List<int> predecessor,
    required List<int> ended,
    required List<int> recG,
    required Transaction anchorTx,
    List<int> terms = const [],
  }) async {
    String hx(List<int> v) => hex.encode(v);
    final eid = h256(ended);

    // 1. R spends E:0
    if (!r.isIssuance) return 'the successor is not an issuance';
    if (hx(b.fromRec(r.headerAndSigs, prefix: r.prefix).raw) != hx(r.raw)) return 'the successor is not the issuance its record describes';
    if (hx(r.in0) != hx(outpoint(eid, 0))) return 'the successor does not spend output 0 of the ended transaction';

    // 2. E spends G:0 on the cheap path
    final Transaction e;
    try {
      e = Transaction.fromHex(hex.encode(ended));
    } catch (_) {
      return 'the ended transaction does not parse';
    }
    if (e.inputs.isEmpty) return 'the ended transaction has no inputs';
    final i0 = e.inputs.first;
    if (endedOwner(b, e) == null) return 'the ended transaction\'s input 0 is not a cheap-path spend';
    if (i0.prevTxnOutputIndex != 0) return 'the ended transaction\'s input 0 does not spend a token output';
    final gid = hex.decode(i0.prevTxnId).reversed.toList();

    // 3. G is the record rebuilt, and its output 0 is genuine
    final FnftTx g;
    try {
      g = FnftSuccession.ended(b, ended, recG, r.issuer, terms: terms);
    } catch (err) {
      return 'the record of the ended token does not parse: $err';
    }
    if (hx(g.txid) != hx(gid)) return 'the record is not of the transaction the ended transaction spent';
    if (hx(g.tokenId) != hx(predecessor)) return 'the ended token is not the predecessor';
    if (!g.isIssuance) {
      final FnftTx p;
      try {
        p = b.fromRec(g.x, prefix: g.parentPrefix);
      } catch (err) {
        return 'the parent record does not parse: $err';
      }
      if (hx(g.in0) != hx(p.out)) return 'the ended token\'s input 0 is not a spend of a token output';
      if (hx(p.tokenId) != hx(predecessor)) return 'the ended token\'s parent is of another token';
    }

    // 4. the attestations
    if (g.isIssuance) {
      final why = await FnftIdentity.verify(g, anchorTx);
      if (why != null) return 'the ended issuance: $why';
    }
    final why = await FnftIdentity.verify(r, anchorTx);
    if (why != null) return 'the successor: $why';
    return null;
  }
}
