import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';

import 'aip_lockbuilder.dart';
import 'b_lockbuilder.dart';
import 'map_lockbuilder.dart';

/// Builds an identity anchor transaction for token issuers.
///
/// The identity anchor transaction is a standalone on-chain record that
/// establishes an issuer's identity. Output layout:
///   - Output 0: Change (added by TransactionBuilder)
///   - Output 1: OP_RETURN with MAP-formatted identity metadata
///   - Output 2: OP_RETURN with AIP signature + ED25519 pubkey over
///               [signedMessage]: SHA256 of the identity content, the MAP
///               output's script followed by every output script after the AIP
///   - Output 3: (optional) B:// artwork data
///
/// When artwork is provided, a SHA-256 hash of the artwork bytes is included
/// in the MAP metadata (key: `artworkHash`), and the artwork output itself is
/// part of what the AIP signature covers.
///
/// The signed message is content only: no input, signature, fee or change
/// enters it, so anyone can recompute it from the published transaction
/// ([IdentityVerification.verifyIdentityAnchor]). (Until 2026-10 the AIP
/// signed the serialised transaction without the AIP output, with that
/// draft's own input signature and change, which nobody could rebuild from
/// the published transaction; anchors made that way do not verify.)
class IdentityAnchorBuilder {

  /// Key-value pairs of issuer identity metadata to store on-chain.
  final Map<String, String> identityMetadata;

  /// Optional artwork image bytes to embed via B:// protocol.
  final List<int>? artworkBytes;

  /// MIME type of the artwork (e.g. 'image/png'). Required when [artworkBytes] is provided.
  final String? artworkMimeType;

  /// Creates an identity anchor builder with the given [identityMetadata]
  /// and optional artwork to embed as a B:// output.
  IdentityAnchorBuilder(this.identityMetadata, {this.artworkBytes, this.artworkMimeType});

  /// The message the AIP signature covers: SHA256 of the MAP output's script
  /// followed by the scripts of the outputs after the AIP output.
  static Future<List<int>> signedMessage(SVScript mapScript, List<SVScript> after) async =>
      (await Sha256().hash([...mapScript.buffer, for (final s in after) ...s.buffer])).bytes;

  /// The anchor's outputs as lock builders, in order: the MAP metadata, the
  /// AIP signature over it (and the artwork), the B:// artwork when given.
  /// A wallet that funds the anchor its own way places these behind any
  /// coin, every one at zero satoshis, after its change output: the
  /// verifier reads the MAP at output 1, the AIP at output 2 and the
  /// artwork at output 3 ([extractMetadata], [extractPublicKey],
  /// [extractArtwork]).
  Future<List<LockingScriptBuilder>> anchorOutputs(SignatureWand wand) async {
    // Build the MAP metadata output with app and type prefixed
    var mapData = <String, String>{
      'app': 'tsl1',
      'type': 'issuer_identity',
    };
    mapData.addAll(identityMetadata);

    // If artwork is provided, include its SHA-256 hash in MAP so AIP covers it
    if (artworkBytes != null && artworkBytes!.isNotEmpty) {
      var artworkHash = await Sha256().hash(artworkBytes!);
      mapData['artworkHash'] = hex.encode(artworkHash.bytes);
      if (artworkMimeType != null) {
        mapData['artworkMimeType'] = artworkMimeType!;
      }
    }

    var mapLocker = MapLockBuilder.fromMap(mapData);

    // Optional B:// locker for artwork data
    BLockBuilder? artworkLocker;
    if (artworkBytes != null && artworkBytes!.isNotEmpty) {
      artworkLocker = BLockBuilder(
        artworkBytes!,
        artworkMimeType ?? 'application/octet-stream',
        'binary',
      );
    }

    // Sign the identity content with ED25519
    var message = await signedMessage(
        mapLocker.getScriptPubkey(), [if (artworkLocker != null) artworkLocker.getScriptPubkey()]);
    var signature = await wand.sign(message);
    SimplePublicKey pubkey = (await wand.extractPublicKeyUsedForSignatures() as SimplePublicKey);
    var aipLocker = AIPLockBuilder(hex.encode(pubkey.bytes), base64Encode(signature.bytes));
    return [mapLocker, aipLocker, if (artworkLocker != null) artworkLocker];
  }

  /// Builds the identity anchor transaction.
  ///
  /// [fundingTx] - Transaction holding the funding coin, a P2PKH to
  /// [fundingPubKey], at output [fundingOutput] (1 by default; any output
  /// of a wallet's may fund an anchor)
  /// [signer] - TransactionSigner for the funding input
  /// [fundingPubKey] - Public key for the funding UTXO
  /// [changeAddress] - Address to send change to
  /// [wand] - ED25519 SignatureWand for signing the identity anchor
  Future<Transaction> buildTransaction(
    Transaction fundingTx,
    TransactionSigner signer,
    SVPublicKey fundingPubKey,
    Address changeAddress,
    SignatureWand wand, {
    int fundingOutput = 1,
  }) async {
    if (fundingOutput < 0 || fundingOutput >= fundingTx.outputs.length) {
      throw ArgumentError('the funding transaction has ${fundingTx.outputs.length} outputs, not an output $fundingOutput');
    }
    // One build. Layout: [0]=change, [1]=MAP, [2]=AIP, [3]=B:// artwork (optional)
    var builder = TransactionBuilder().spendFromTxnWithSigner(signer, fundingTx, fundingOutput, TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(fundingPubKey));
    for (final locker in await anchorOutputs(wand)) {
      builder.spendToLockBuilder(locker, BigInt.zero);
    }
    return builder.sendChangeToPKH(changeAddress).withFeePerKb(100).build(false);
  }

  /// Extracts identity metadata from an identity anchor transaction's MAP output (output[1]).
  static Map<String, String> extractMetadata(Transaction identityAnchorTx) {
    var mapScript = identityAnchorTx.outputs[1].script;
    var mapLocker = MapLockBuilder.fromScript(mapScript);
    return mapLocker.map.map((k, v) => MapEntry(k, v.toString()));
  }

  /// Extracts the AIP public key from an identity anchor transaction's AIP output (output[2]).
  static String extractPublicKey(Transaction identityAnchorTx) {
    var aipScript = identityAnchorTx.outputs[2].script;
    var aipLocker = AIPLockBuilder.fromScript(aipScript);
    return aipLocker.publicKey ?? '';
  }

  /// Extracts the AIP signature from an identity anchor transaction's AIP output (output[2]).
  static String extractSignature(Transaction identityAnchorTx) {
    var aipScript = identityAnchorTx.outputs[2].script;
    var aipLocker = AIPLockBuilder.fromScript(aipScript);
    return aipLocker.signature ?? '';
  }

  /// Extracts artwork data from an identity anchor transaction's B:// output (output[3]).
  ///
  /// Returns null if no artwork output is present.
  static ({List<int> data, String mediaType})? extractArtwork(Transaction identityAnchorTx) {
    if (identityAnchorTx.outputs.length < 4) return null;
    try {
      var bLocker = BLockBuilder.fromScript(identityAnchorTx.outputs[3].script);
      if (bLocker.data == null || bLocker.data!.isEmpty) return null;
      return (data: bLocker.data!, mediaType: bLocker.mediaType ?? 'application/octet-stream');
    } catch (_) {
      return null;
    }
  }
}
