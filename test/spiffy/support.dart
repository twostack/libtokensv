// Shared by the plugin tests: a stand-in for the wallet libspiffy is (funding
// coins, a transaction signer, a key lookup by hash, a transaction lookup)
// built from in-memory keys; an identity anchor; a BEEF of one transaction.
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import 'package:libtokensv/libtokensv.dart';

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x70a00000 + i));
List<int> pkh(SVPrivateKey k) => hash160(hex.decode(k.publicKey.toHex()));
String pkhHex(SVPrivateKey k) => hex.encode(pkh(k));
String addressOf(SVPrivateKey k) => Address.fromPublicKey(k.publicKey, NetworkType.TEST).toBase58();
List<int> p2pkhScript(SVPrivateKey k) => [0x76, 0xa9, 0x14, ...pkh(k), 0x88, 0xac];

final flags = {
  VerifyFlag.SIGHASH_FORKID,
  VerifyFlag.LOW_S,
  VerifyFlag.NULLFAIL,
  VerifyFlag.MINIMALDATA,
  VerifyFlag.MINIMALIF,
  VerifyFlag.SIGPUSHONLY,
  VerifyFlag.UTXO_AFTER_GENESIS,
};

void spends(Transaction tx, int i, List<int> lock, int sats) => Interpreter().correctlySpends(
    tx.inputs[i].script!, SVScript.fromByteArray(Uint8List.fromList(lock)), tx, i, flags, Coin.valueOf(BigInt.from(sats)));

/// A wallet as the plugin sees it: [keys] by key hash, funding coins at
/// [funder], and the raw transactions it has recorded.
class Wallet {
  final List<SVPrivateKey> keys;
  final SVPrivateKey funder;
  final Map<String, String> txs;
  var _coin = 0;
  Wallet(this.keys, this.funder, this.txs);

  BitcoinUtxo coin(int sats) {
    final txid = hex.encode(sha256([++_coin, ...pkh(funder)]));
    return BitcoinUtxo.create(
        txid: txid, vout: 0, satoshis: BigInt.from(sats), scriptPubKey: hex.encode(p2pkhScript(funder)), address: addressOf(funder));
  }

  PluginTransactionRequest request(Map<String, dynamic> params, {int coins = 1, Transaction? coinTx}) {
    final funding = coinTx != null
        ? [
            BitcoinUtxo.create(
                txid: coinTx.id,
                vout: 0,
                satoshis: coinTx.outputs[0].satoshis,
                scriptPubKey: coinTx.outputs[0].script.toHex(),
                address: addressOf(funder))
          ]
        : [for (var i = 0; i < coins; i++) coin(100000)];
    final signer = DefaultTransactionSigner(sighashAllForkId, funder);
    return PluginTransactionRequest(
      fundingUtxos: funding,
      signer: signer,
      publicKeys: [for (final _ in funding) funder.publicKey],
      params: params,
      transactionLookup: (txid) async => txs[txid],
      fundingInputs: const [],
      feeRate: const FeeRate(satoshis: 1, bytes: 1000),
      keyLookup: (hash) async {
        final k = keys.where((k) => pkhHex(k) == hash).firstOrNull ??
            (throw StateError('Wallet holds no key with public key hash $hash'));
        return PluginKey(signer: DefaultTransactionSigner(sighashAllForkId, k), publicKey: k.publicKey);
      },
    );
  }

  void record(Transaction tx) => txs[tx.id] = tx.serialize();
}

Future<Transaction> anchorFor(RabinKeyPair rabin) async {
  final k = key(7000);
  final address = Address.fromPublicKey(k.publicKey, NetworkType.TEST);
  final funding = (TransactionBuilder()
        .spendFromOutpoint(
            TransactionOutpoint(hex.encode(List<int>.generate(32, (i) => i)), 0, BigInt.from(200000),
                P2PKHLockBuilder.fromAddress(address).getScriptPubkey()),
            TransactionInput.MAX_SEQ_NUMBER,
            P2PKHUnlockBuilder(k.publicKey))
        .spendToLockBuilder(P2PKHLockBuilder.fromAddress(address), BigInt.from(546))
        .spendToLockBuilder(P2PKHLockBuilder.fromAddress(address), BigInt.from(199000))
        ..withOption(TransactionOption.DISABLE_DUST_OUTPUTS))
      .build(false);
  final ed = Ed25519();
  final wand = await ed.newSignatureWandFromKeyPair(await ed.newKeyPairFromSeed(List<int>.generate(32, (i) => i)));
  return IdentityAnchorBuilder(LtIdentity.anchorMetadata(rabin, {'name': 'Plugin Test Issuer'})).buildTransaction(
      funding, DefaultTransactionSigner(sighashAllForkId, k), k.publicKey, address, wand);
}

/// [t] alone as an Atomic BEEF, as a payer would hand it over (no proofs:
/// the token check reads only the subject).
List<int> beefOf(Transaction t) {
  final raw = Uint8List.fromList(hex.decode(t.serialize()));
  return Brc95.wrap(BEEF.create(bumps: const [], txs: [raw], hasMerkle: const [false], bumpIndex: const []), t.id);
}

