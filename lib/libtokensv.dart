/// BSV token scripts for libspiffy wallets, and a client for BSV overlay
/// services.
library;

export 'src/overlay/overlay_admin_token.dart';
export 'src/overlay/overlay_client.dart';
export 'src/pushdrop/pushdrop.dart';
export 'src/pushdrop/pushdrop_plugin.dart';

// The lineage tokens, TSL1_LT_FT and TSL1_LT_NFT: a token whose script
// rebuilds its own transaction and its parent's from records carried in
// the unlock, so that one hop at the tip verifies the whole lineage on
// chain, with no witness transaction and no reader (doc/lt/LT.md).
export 'src/lt/lt_layout.dart' show LtLayout, LtResetEvidence, LtIssuerBlob;
export 'src/lt/lt_script_gen.dart' show LtScriptGen;
export 'src/lt/lt_builder.dart'
    show LtBuilder, LtTx, LtOut, LtPassenger, LtCoin, LtIssuer, LtAttester, attesterList, attestersOf, resetEvidence,
        LtKey, LtPrivateKey, LtSigning, LtKeyOf, LtGivenSignature, sighashAllForkId, outpoint;
export 'src/lt/lt_identity.dart' show LtIdentity;
export 'src/lt/lt_succession.dart' show LtSuccession;
export 'src/lt/lt_wallet.dart' show LtLink, LtLinks, LtHolding, LtRefused, LtReceive;
export 'src/lt/lt_payload.dart' show LtPayload;

// The Fuelled NFT, TSL1_LT_FNFT: the token output carries the satoshis that
// pay its own fees (doc/lt/LT_FNFT_WALLET_INTEGRATION.md). The Voucher NFT
// (FuelLayout.vnft, FnftBuilder.voucher) and the Note NFT (FuelLayout.note)
// are the same script family with terms in the header.
export 'src/lt/lt_fnft_script_gen.dart' show FnftLayout, FnftScriptGen, FuelLayout;
export 'src/lt/lt_fnft_builder.dart' show FnftBuilder, FnftTx, VoucherTerms, NoteTerms, FuelTerms;
export 'src/lt/lt_fnft_wallet.dart' show FnftHolding, FnftIdentity, FnftReceive, FnftSuccession;

// The issuer's identity: a Rabin key anchored to an Ed25519 identity by an
// anchor transaction (MAP + AIP), which LtIdentity verifies.
export 'src/crypto/rabin.dart';
export 'src/builder/identity_anchor_builder.dart';
export 'src/transaction/identity_verification.dart';
