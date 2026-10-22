import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import '../../libtokensv.dart';

/// A wallet key as tstokenlib signs with it: [signer] signs transaction
/// inputs (it never hands over a key or signs a bare digest), [publicKey] goes
/// in the unlocking script.
///
/// Each signature is asked for as a wallet signs: over the transaction with
/// empty unlocking scripts, the input, the script the signature covers and
/// the amount, which make the same digest as the preimage tstokenlib computes.
class WalletKey extends LtKey {
  final TransactionSigner signer;
  final SVPublicKey publicKey;
  WalletKey(this.signer, this.publicKey);

  @override
  List<int> get pub => hex.decode(publicKey.toHex());

  @override
  List<int> sign(LtSigning s) {
    final tx = Transaction.fromHex(hex.encode(s.unsigned));
    final input = tx.inputs[s.input];
    final unlock = P2PKHUnlockBuilder(publicKey);
    tx.inputs[s.input] =
        TransactionInput(input.prevTxnId, input.prevTxnOutputIndex, input.sequenceNumber, scriptBuilder: unlock);
    signer.sign(tx, TransactionOutput(BigInt.from(s.sats), SVScript.fromByteArray(Uint8List.fromList(s.scriptCode))),
        s.input);
    if (unlock.signatures.isEmpty) throw StateError('the wallet returned no signature for input ${s.input}');
    return hex.decode(unlock.signatures.last.toTxFormat());
  }
}
