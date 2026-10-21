// Who issued a lineage token: the issuer's identity anchor transaction
// (IdentityAnchorBuilder: MAP metadata at output 1, an AIP signature by the
// issuer's ED25519 key at output 2) tied to the token by the Rabin
// attestation every token record ends with.
//
// The script checks, at the first spend after the issuance, that the Rabin
// key whose HASH160 is in the header signed SHA256(identityTxId ‖
// ed25519PubKey ‖ tokenId). It does not read the anchor: what the anchor says
// is checked here, by the wallet, from the anchor transaction (fetched by its
// txid, with a BEEF proof that it is mined) and the token's record.
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import '../builder/identity_anchor_builder.dart';
import '../crypto/rabin.dart';
import '../transaction/identity_verification.dart';
import 'lt_builder.dart';
import 'lt_layout.dart';

/// An issuer's identity, as the anchor publishes it and a token names it.
class LtIdentity {
  /// The MAP key under which the anchor names the issuer's Rabin key: the
  /// hex HASH160 of its 129-byte modulus slot, the value token headers carry.
  static const rabinKeyField = 'rabinPKH';

  /// The anchor's metadata for an issuer of lineage tokens: [extra] (name,
  /// domain, ...) and the Rabin key hash, for [IdentityAnchorBuilder].
  static Map<String, String> anchorMetadata(RabinKeyPair rabin, [Map<String, String> extra = const {}]) =>
      {...extra, rabinKeyField: hex.encode(hash160(leBig(rabin.n, LtResetEvidence.numLen)))};

  /// The issuer of tokens under the anchor [anchorTx]: its Rabin key and the
  /// anchor's txid (byte order as in transactions, the order token ids use)
  /// and ED25519 key. Throws when the anchor does not name this Rabin key.
  static LtIssuer issuer(RabinKeyPair rabin, Transaction anchorTx) {
    final meta = IdentityAnchorBuilder.extractMetadata(anchorTx);
    final want = anchorMetadata(rabin)[rabinKeyField];
    if (meta[rabinKeyField] != want) throw ArgumentError('the anchor names Rabin key ${meta[rabinKeyField]}, not $want');
    final ed = IdentityAnchorBuilder.extractPublicKey(anchorTx);
    if (ed.length != 64) throw ArgumentError('the anchor has no ED25519 key');
    return LtIssuer(rabin, h256(hex.decode(anchorTx.serialize())), hex.decode(ed));
  }

  /// The part of [verify] that needs no anchor: null when the record of [t]
  /// ends with an attestation by the Rabin key whose hash is the issuer in
  /// [t]'s header, over the identity it names and [t]'s token id. That is
  /// what the script checks at the issuance's first spend, so a transfer
  /// built on an attestation that fails here is refused by every node.
  static String? attestationError(LtTx t) {
    final blob = _blobOf(t);
    if (blob == null) return 'the record has no issuer attestation';
    return attestationErrorOf(blob: blob, issuerPkh: t.h1.sublist(t.L.issuer, t.L.issuer + 20), tokenId: t.isIssuance ? t.txid : t.tokenId);
  }

  /// The wallet's check of who issued the token [t] belongs to, given the
  /// identity anchor [anchorTx]: null when
  ///  * the anchor's AIP signature, by its ED25519 key, covers the anchor;
  ///  * the attestation at the end of [t]'s record names this anchor's txid
  ///    and ED25519 key;
  ///  * the anchor names the Rabin key whose hash is the issuer in [t]'s
  ///    header, and the attestation's modulus is that key;
  ///  * that key signed SHA256(anchor txid ‖ ED25519 key ‖ token id).
  /// Otherwise the first that fails. [t] is any transaction of the token,
  /// the issuance included: its record ends with the attestation (the
  /// issuance's once its `x` is set).
  static Future<String?> verify(LtTx t, Transaction anchorTx) => verifyOf(
        blob: _blobOf(t),
        issuerPkh: t.h1.sublist(t.L.issuer, t.L.issuer + 20),
        tokenId: t.isIssuance ? t.txid : t.tokenId,
        anchorTx: anchorTx,
      );

  static List<int>? _blobOf(LtTx t) {
    final rec = t.rec;
    if (rec.length < LtIssuerBlob.size || (t.isIssuance && t.x.length != LtIssuerBlob.size)) return null;
    return rec.sublist(rec.length - LtIssuerBlob.size);
  }

  /// [attestationError] for any archetype: the attestation [blob], the
  /// issuer key hash [issuerPkh] the token's header names, its [tokenId].
  static String? attestationErrorOf({required List<int> blob, required List<int> issuerPkh, required List<int> tokenId}) {
    if (blob.length != LtIssuerBlob.size) return 'the record has no issuer attestation';
    final idTx = blob.sublist(LtIssuerBlob.identityTxId, LtIssuerBlob.ed25519PubKey);
    final ed = blob.sublist(LtIssuerBlob.ed25519PubKey, LtIssuerBlob.padding);
    final pad = ByteData.sublistView(Uint8List.fromList(blob.sublist(LtIssuerBlob.padding, LtIssuerBlob.s))).getUint32(0, Endian.little);
    final s = _le(blob.sublist(LtIssuerBlob.s, LtIssuerBlob.n));
    final nSlot = blob.sublist(LtIssuerBlob.n, LtIssuerBlob.size);
    if (!_eq(hash160(nSlot), issuerPkh)) return 'the attestation is by another Rabin key';
    final m = Rabin.sha256ToScriptInt([...idTx, ...ed, ...tokenId]);
    if (!Rabin.verify(m, RabinSignature(s, pad), _le(nSlot))) return 'the issuer\'s Rabin signature does not verify';
    return null;
  }

  /// [verify] for any archetype; [blob] null means the record has none.
  static Future<String?> verifyOf({
    required List<int>? blob,
    required List<int> issuerPkh,
    required List<int> tokenId,
    required Transaction anchorTx,
  }) async {
    if (blob == null || blob.length != LtIssuerBlob.size) return 'the record has no issuer attestation';
    final idTx = blob.sublist(LtIssuerBlob.identityTxId, LtIssuerBlob.ed25519PubKey);
    final ed = blob.sublist(LtIssuerBlob.ed25519PubKey, LtIssuerBlob.padding);
    if (!await IdentityVerification.verifyIdentityAnchor(anchorTx)) return 'the anchor\'s AIP signature does not verify';
    if (!_eq(h256(hex.decode(anchorTx.serialize())), idTx)) return 'the attestation names another anchor';
    if (IdentityAnchorBuilder.extractPublicKey(anchorTx) != hex.encode(ed)) return 'the attestation names another ED25519 key';
    final meta = IdentityAnchorBuilder.extractMetadata(anchorTx);
    if (meta[rabinKeyField] != hex.encode(issuerPkh)) return 'the anchor does not name the token\'s issuer key';
    return attestationErrorOf(blob: blob, issuerPkh: issuerPkh, tokenId: tokenId);
  }

  static BigInt _le(List<int> b) {
    var v = BigInt.zero;
    for (var i = b.length - 1; i >= 0; i--) {
      v = (v << 8) | BigInt.from(b[i]);
    }
    return v;
  }

  static bool _eq(List<int> a, List<int> b) => a.length == b.length && hex.encode(a) == hex.encode(b);
}
