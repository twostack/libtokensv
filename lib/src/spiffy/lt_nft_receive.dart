import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import '../../libtokensv.dart';

import 'lt_fnft_plugin.dart';
import 'lt_nft_plugin.dart';
import 'lt_note_plugin.dart';
import 'lt_vnft_plugin.dart';

/// The payee's side: the token check of a transfer as it arrives, a BEEF
/// (V1, V2 or Atomic, as libspiffy's [Brc95] reads them).
///
/// This is tstokenlib's token check on the BEEF's subject. libspiffy does
/// the rest of the payee's part (docs/LT_NFT_WALLET_INTEGRATION.md in
/// tstokenlib, section 5): `ValidateBEEFCommand` checks the proofs against
/// the wallet's headers and has the network take the transfer, and the
/// token is the wallet's once the network holds it.
class LtNftReceive {
  /// The subject of [beef] (V1, V2 or Atomic): the Atomic BEEF's named
  /// transaction, or a bare BEEF's last. Throws [LtRefused] for a BEEF that
  /// does not read.
  static Uint8List subject(List<int> beef) {
    final ReadBeef read;
    try {
      read = Brc95.read(beef);
    } on BEEFException catch (e) {
      throw LtRefused('the BEEF does not read: ${e.message}');
    }
    final txs = read.beef.txs;
    if (txs.isEmpty) throw LtRefused('the BEEF holds no transaction');
    return read.subjectTxid == null
        ? txs.last
        : read.beef.findTransactionByTxid(Uint8List.fromList(hex.decode(read.subjectTxid!)))!['txData'] as Uint8List;
  }

  /// The holding the BEEF [beef] pays to [ownerAddress], or [LtRefused].
  /// [anchorTx] is the issuer's identity anchor; [links] the reissue links
  /// that travelled with the transfer, newest first; [payloadTx] the
  /// token's payload transaction, when it has one (`holding.payload`).
  static Future<LtHolding> check({
    required LtNftPlugin plugin,
    required List<int> beef,
    required String ownerAddress,
    required Transaction anchorTx,
    List<LtLink> links = const [],
    List<int>? payloadTx,
  }) async {
    final raw = subject(beef);
    return LtReceive.check(
      b: plugin.builder,
      raw: raw,
      ownerPkh: hex.decode(Address.fromBase58(ownerAddress).pubkeyHash160),
      anchorTx: anchorTx,
      links: links,
      payloadTx: payloadTx,
    );
  }
}

/// [LtNftReceive] for the Fuelled NFT: the payee's token check of a
/// transfer as it arrives, a BEEF.
class LtFnftReceive {
  /// The holding the BEEF [beef] pays to [ownerAddress], or [LtRefused].
  static Future<FnftHolding> check({
    required LtFnftPlugin plugin,
    required List<int> beef,
    required String ownerAddress,
    required Transaction anchorTx,
    List<LtLink> links = const [],
    List<int>? payloadTx,
  }) =>
      FnftReceive.check(
        b: plugin.builder,
        raw: LtNftReceive.subject(beef),
        ownerPkh: hex.decode(Address.fromBase58(ownerAddress).pubkeyHash160),
        anchorTx: anchorTx,
        links: links,
        payloadTx: payloadTx,
      );
}

/// [LtNftReceive] for the Voucher NFT. The holding's `tx.hopsLeft` and
/// `tx.terms.expiry` say how many transfers remain and when the issuer may
/// take the voucher back.
class LtVnftReceive {
  static Future<FnftHolding> check({
    required LtVnftPlugin plugin,
    required List<int> beef,
    required String ownerAddress,
    required Transaction anchorTx,
    List<LtLink> links = const [],
    List<int>? payloadTx,
  }) =>
      FnftReceive.check(
        b: plugin.builder,
        raw: LtNftReceive.subject(beef),
        ownerPkh: hex.decode(Address.fromBase58(ownerAddress).pubkeyHash160),
        anchorTx: anchorTx,
        links: links,
        payloadTx: payloadTx,
      );
}

/// [LtNftReceive] for the Note NFT. The holding's `tx.noteTerms` and value
/// say what the holder gets on each ending; show them before acceptance.
class LtNoteReceive {
  static Future<FnftHolding> check({
    required LtNotePlugin plugin,
    required List<int> beef,
    required String ownerAddress,
    required Transaction anchorTx,
    List<LtLink> links = const [],
    List<int>? payloadTx,
  }) =>
      FnftReceive.check(
        b: plugin.builder,
        raw: LtNftReceive.subject(beef),
        ownerPkh: hex.decode(Address.fromBase58(ownerAddress).pubkeyHash160),
        anchorTx: anchorTx,
        links: links,
        payloadTx: payloadTx,
      );
}
