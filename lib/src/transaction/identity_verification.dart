import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';

import '../builder/identity_anchor_builder.dart';
import '../builder/map_lockbuilder.dart';

/// Utilities for verifying the link between a token issuance and its issuer identity.
class IdentityVerification {

  /// Extracts the identity anchor txid and signature from an issuance transaction's
  /// metadata output (output[4]).
  ///
  /// Returns a record with identityTxId and identitySig, or nulls if not present.
  static ({String? identityTxId, String? identitySig}) extractIdentityFromMetadata(SVScript metadataScript) {
    try {
      var mapLocker = MapLockBuilder.fromScript(metadataScript);
      return (
        identityTxId: mapLocker.map['identityTxId']?.toString(),
        identitySig: mapLocker.map['identitySig']?.toString(),
      );
    } catch (_) {
      return (identityTxId: null, identitySig: null);
    }
  }

  /// Verifies that the issuance transaction's metadata correctly links to the
  /// identity anchor transaction.
  ///
  /// Verification steps:
  /// 1. Extract identityTxId and identitySig from issuance metadata (output[4])
  /// 2. Extract ED25519 public key from identity anchor's AIP output (output[2])
  /// 3. Verify identitySig is a valid signature over identityTxId using that pubkey
  static Future<bool> verifyIssuanceIdentity(Transaction issuanceTx, Transaction identityAnchorTx) async {
    var metadataScript = issuanceTx.outputs[4].script;
    var identity = extractIdentityFromMetadata(metadataScript);

    if (identity.identityTxId == null || identity.identitySig == null) {
      return false;
    }

    var pubkeyHex = IdentityAnchorBuilder.extractPublicKey(identityAnchorTx);
    if (pubkeyHex.isEmpty) return false;

    var algorithm = Ed25519();
    var publicKey = SimplePublicKey(hex.decode(pubkeyHex), type: KeyPairType.ed25519);
    var signatureBytes = base64Decode(identity.identitySig!);
    var messageBytes = hex.decode(identity.identityTxId!);

    var signature = Signature(signatureBytes, publicKey: publicKey);

    try {
      return await algorithm.verify(messageBytes, signature: signature);
    } catch (_) {
      return false;
    }
  }

  /// Verifies the identity anchor transaction's self-signature: the AIP
  /// output (output[2]) holds an ED25519 signature, by the key it names, over
  /// [IdentityAnchorBuilder.signedMessage] of the MAP output (output[1]) and
  /// the outputs after the AIP output.
  static Future<bool> verifyIdentityAnchor(Transaction identityAnchorTx) async {
    if (identityAnchorTx.outputs.length < 3) return false;
    var pubkeyHex = IdentityAnchorBuilder.extractPublicKey(identityAnchorTx);
    // parsed back from the script, the AIP signature is hex (it is built from base64)
    var signatureHex = IdentityAnchorBuilder.extractSignature(identityAnchorTx);
    if (pubkeyHex.isEmpty || signatureHex.isEmpty) return false;

    try {
      var message = await IdentityAnchorBuilder.signedMessage(
          identityAnchorTx.outputs[1].script, [for (final o in identityAnchorTx.outputs.skip(3)) o.script]);
      var publicKey = SimplePublicKey(hex.decode(pubkeyHex), type: KeyPairType.ed25519);
      var signature = Signature(hex.decode(signatureHex), publicKey: publicKey);
      return await Ed25519().verify(message, signature: signature);
    } catch (_) {
      return false;
    }
  }
}
