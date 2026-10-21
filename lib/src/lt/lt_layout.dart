// Byte layouts of the lineage-token (TSL1_LT) headers and reset evidence.

/// The fixed-width header a lineage-token output carries in front of its
/// code. The two archetypes share the prefix (token id, issuer, and for a
/// token that can be reset the attesters and a flags byte); the fungible one
/// adds the passenger record length, an amount and the passenger input's
/// outpoint.
class LtLayout {
  final bool fungible;

  /// Whether the token can be reset (two of three attesters fixed at
  /// issuance vouch for an outpoint and the record restarts there). A token
  /// that cannot is redeemed and reissued instead; its header has no
  /// attesters, and the NFT's no flags byte either.
  final bool resettable;

  /// TSL1_LT_LNFT (WITNESS_LINEAGE_RESEARCH.md 9.14): a price in the header
  /// after the owner, and a path anyone may take by paying it.
  final bool listed;
  const LtLayout._(this.fungible, this.resettable, [this.listed = false]);

  /// TSL1_LT_FT: amounts, splits into two outputs, merges with one passenger.
  static const ft = LtLayout._(true, true);

  /// TSL1_LT_NFT: one indivisible unit, one output, no passenger, no reset.
  static const nft = LtLayout._(false, false);

  /// TSL1_LT_LNFT: the NFT with a price anyone may pay.
  static const lnft = LtLayout._(false, false, true);

  String get name => fungible ? 'TSL1_LT_FT' : listed ? 'TSL1_LT_LNFT' : 'TSL1_LT_NFT';

  int get tokenId => 0; // 32, the issuance txid; zero in the issuance itself
  int get issuer => 32; // 20, HASH160 of the issuer's Rabin modulus slot
  int get attesters => 52; // resettable only: 20, HASH160 of the three reset attesters' key hashes
  int get flags => resettable ? 72 : 52; // FT or resettable: 1, bit 0: two token outputs (FT); bit 1: input 0 was a reset
  bool get hasFlags => fungible || resettable;
  int get passLen => flags + 1; // FT only: 4, LE, |Rec(passenger)|; zero: no passenger input
  int get owner => fungible ? passLen + 4 : flags + (hasFlags ? 1 : 0); // 20
  int get amount => 97; // FT only: 8, LE
  int get price => owner + 20; // listed only: 8, LE; zero: not for sale
  int get changeAmt => owner + (fungible || listed ? 28 : 20); // 8
  int get changePkh => changeAmt + 8; // 20
  int get in0 => changePkh + 20; // 36, the driver input's outpoint (issuance: the first coin)
  int get passIn => in0 + 36; // FT only: 36, zero if none
  int get fundIn => fungible ? passIn + 36 : in0 + 36; // 36
  int get size => fundIn + 36; // 241 (FT), 172 (NFT), 180 (LNFT)

  /// Rec(issuance) without the issuer's attestation: the header and the two
  /// P2PKH signature pairs, which is all rebuilding the issuance needs.
  int get issuanceRec => size + sigsTwo; // 455 (FT), 386 (NFT)

  /// A reset's evidence: Rec(issuance), then [LtResetEvidence.sigs].
  int get resetEvidence => issuanceRec + LtResetEvidence.sigs; // 1,039 (FT)

  /// The part of a header the two outputs of a split must share: everything
  /// but owner and amount.
  int get shared1 => owner;
  int get shared2 => changeAmt;

  static const slot = 74; // a signature slot: length, signature, zero padding
  static const sigPair = 107; // slot + 33-byte public key
  static const sigsTwo = 214; // sender + funding
  static const sigsThree = 321; // sender + passenger + funding

  static const flagSplit = 1;
  static const flagReset = 2;
}

/// A reset's evidence: the issuance's record ([LtLayout.issuanceRec] bytes,
/// so that the script can rebuild the issuance the token id names and take
/// the attesters from it), then the attester list, then two of the three
/// attesters' Rabin signatures over SHA256(tag ‖ tokenId ‖ attested outpoint).
class LtResetEvidence {
  static const list = 0; // 60: three HASH160s of 129-byte modulus slots, after the issuance record
  static const numLen = 129; // Rabin numbers, LE, zero-padded
  static const blob = 4 + 2 * numLen; // 262: padding 4, s 129, n 129
  static const sigs = 60 + 2 * blob; // 584: the list and two blobs
  static const tag = [0x52, 0x45, 0x53, 0x45, 0x54, 0x2d, 0x30, 0x31]; // "RESET-01"
}

/// The issuer's attestation the first spend of an issuance carries, TSL1's
/// identity message with the issuance txid as the token id.
class LtIssuerBlob {
  static const identityTxId = 0; // 32
  static const ed25519PubKey = 32; // 32
  static const padding = 64; // 4, LE
  static const s = 68; // 129
  static const n = 197; // 129
  static const size = 326;
}
