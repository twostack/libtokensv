// Which token a reissued covenant NFT succeeds.
//
// The NFT has no reset: a token whose record has grown is redeemed to its
// issuer, who ends it (LtBuilder.end: its last genuine output spent on the
// cheap path) and reissues it (LtBuilder.reissue: an issuance whose first
// coin is output 0 of that end transaction E). Nothing in the script or the
// header is added for this. Uniqueness comes from the chain:
//  * an NFT's genuine outputs form one chain, each spent once; a normal-path
//    spend continues it and a cheap-path spend ends it, so at most one
//    transaction E ever ends a token;
//  * E has one output 0, and one transaction at most spends it.
// So a token has at most one successor, whoever builds it. What the chain
// does not say is that E's input was a genuine output of the token (the cheap
// path takes any owner's signature, and anyone can write a token's code and
// header into an output): the wallet checks that from the record of the
// transaction E spent, which rebuilds it and its parent.
//
// The successor's issuer attestation signs its txid, which commits to its
// first input, so the issuer has attested the succession too.
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'lt_builder.dart';
import 'lt_identity.dart';

class LtSuccession {
  /// The wallet's check that the issuance [r] succeeds the token
  /// [predecessor] (its id), given [ended], the raw transaction that ended
  /// it, and [recG], the record of the transaction whose output [ended]
  /// spent. Null when
  ///  1. [r] is an issuance whose first input is output 0 of [ended];
  ///  2. [ended]'s input 0 spends output 1 of a transaction G on the cheap
  ///     path: its unlock is two pushes, a signature and a public key;
  ///  3. G is [recG] rebuilt, and G's output 1 is a genuine output of
  ///     [predecessor]: G is its issuance, or G's input 0 spends output 1 of
  ///     a transaction P, rebuilt from the record in G's unlock, so that
  ///     miners ran the token's code on it;
  ///  4. [r] names G's issuer, and [r] (and G, when G is an issuance, whose
  ///     attestation no spend has checked) verifies against [anchorTx].
  /// Otherwise the first that fails. [ended] being mined is the caller's
  /// check (a BEEF): this one reads the bytes.
  static Future<String?> verify({
    required LtBuilder b,
    required LtTx r,
    required List<int> predecessor,
    required List<int> ended,
    required List<int> recG,
    required Transaction anchorTx,
  }) async {
    if (b.L.fungible) return 'succession is defined for the NFT, which cannot be reset';
    final L = b.L;
    final eid = h256(ended);

    // 1. R spends E:0, and its header says so
    if (!r.isIssuance) return 'the successor is not an issuance';
    if (!_eq(b.fromRec(r.headersAndSigs).raw, r.raw)) return 'the successor is not the issuance its record describes';
    if (!_eq(r.h1.sublist(L.in0, L.in0 + 36), outpoint(eid, 0))) return 'the successor does not spend output 0 of the ended transaction';

    // 2. E spends G:1 on the cheap path
    final Transaction e;
    try {
      e = Transaction.fromHex(hex.encode(ended));
    } catch (_) {
      return 'the ended transaction does not parse';
    }
    if (e.inputs.isEmpty) return 'the ended transaction has no inputs';
    final i0 = e.inputs.first;
    final chunks = i0.script?.chunks ?? const [];
    if (chunks.length != 2 || chunks.any((c) => c.opcodenum > OpCodes.OP_PUSHDATA4 || c.buf == null)) {
      return 'the ended transaction\'s input 0 is not a cheap-path spend';
    }
    if (i0.prevTxnOutputIndex != 1) return 'the ended transaction\'s input 0 does not spend a token output';
    final gid = hex.decode(i0.prevTxnId).reversed.toList();

    // 3. G is the record rebuilt, and its output 1 is genuine
    final LtTx g;
    try {
      g = b.fromRec(recG);
    } catch (e) {
      return 'the record of the ended token does not parse: $e';
    }
    if (!_eq(g.txid, gid)) return 'the record is not of the transaction the ended transaction spent';
    if (g.isIssuance) {
      if (!_eq(g.txid, predecessor)) return 'the ended token is not the predecessor';
    } else {
      if (!_eq(g.tokenId, predecessor)) return 'the ended token is not the predecessor';
      final pOut = g.h1.sublist(L.in0, L.in0 + 36);
      if (pOut[32] != 1 || pOut.sublist(33).any((x) => x != 0)) return 'the ended token\'s parent output is not a token output';
      final LtTx p;
      try {
        p = b.fromRec(g.x);
      } catch (e) {
        return 'the parent record does not parse: $e';
      }
      if (!_eq(p.txid, pOut.sublist(0, 32))) return 'the ended token\'s input 0 is not a spend of a token output';
      if (!_eq(p.isIssuance ? p.txid : p.tokenId, predecessor)) return 'the ended token\'s parent is of another token';
    }

    // 4. the same issuer, and the attestations verify
    if (!_eq(r.h1.sublist(L.issuer, L.issuer + 20), g.h1.sublist(L.issuer, L.issuer + 20))) {
      return 'the successor names another issuer';
    }
    if (g.isIssuance) {
      final why = await LtIdentity.verify(g, anchorTx);
      if (why != null) return 'the ended issuance: $why';
    }
    final why = await LtIdentity.verify(r, anchorTx);
    if (why != null) return 'the successor: $why';
    return null;
  }

  static bool _eq(List<int> a, List<int> b) => a.length == b.length && hex.encode(a) == hex.encode(b);
}
