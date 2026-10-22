import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import '../../libtokensv.dart';

import 'wallet_key.dart';

/// What both lineage-token plugins share.
class PluginSupport {
  static final _flags = {
    VerifyFlag.SIGHASH_FORKID,
    VerifyFlag.LOW_S,
    VerifyFlag.NULLFAIL,
    VerifyFlag.MINIMALDATA,
    VerifyFlag.MINIMALIF,
    VerifyFlag.SIGPUSHONLY,
    VerifyFlag.UTXO_AFTER_GENESIS,
  };

  /// A display-order txid as transaction bytes (internal order).
  static Uint8List internal(String displayTxid) => Uint8List.fromList(hex.decode(displayTxid).reversed.toList());

  /// A 20-byte key hash from hex.
  static List<int> keyHash(Object? hexHash) {
    final h = hex.decode(hexHash as String);
    if (h.length != 20) throw ArgumentError('a key hash is 20 bytes, not ${h.length}');
    return h;
  }

  /// [tx]'s fee, given the values of the outputs its inputs spend.
  static BigInt fee(Transaction tx, List<int> inputSats) =>
      BigInt.from(inputSats.fold<int>(0, (a, s) => a + s)) - tx.outputs.fold<BigInt>(BigInt.zero, (a, o) => a + o.satoshis);

  /// The request's fee rate in whole satoshis per kB, rounded up.
  static int rate(PluginTransactionRequest r) => r.feeRate.satoshisPerKb.ceil();

  /// The request's funding coins as tstokenlib coins, signed by the wallet.
  static List<LtCoin> funds(PluginTransactionRequest r) => [
        for (var i = 0; i < r.fundingUtxos.length; i++)
          LtCoin(outpoint(internal(r.fundingUtxos[i].txid), r.fundingUtxos[i].vout), WalletKey(r.signer, r.publicKeys[i]),
              r.fundingUtxos[i].satoshis.toInt()),
      ];

  /// The raw bytes of [txid] from the wallet's transaction log.
  static Future<List<int>> lookup(PluginTransactionRequest r, String txid) async {
    final lookup = r.transactionLookup ?? (throw ArgumentError('the wallet offers no transaction lookup'));
    final rawHex = await lookup(txid) ?? (throw ArgumentError('the wallet does not hold transaction $txid'));
    return hex.decode(rawHex);
  }

  /// The wallet key whose hash is [owner], as a tstokenlib key.
  static Future<LtKey> ownerKey(PluginTransactionRequest r, List<int> owner) async {
    final k = await r.keyFor(hex.encode(owner));
    return WalletKey(k.signer, k.publicKey);
  }

  /// Runs [lock]'s script on input 0 of [raw], which spends [sats]: a
  /// transaction the token refuses is never handed to the wallet. (libspiffy
  /// builds in passes, the first with stand-in signatures; this throws on
  /// those, and libspiffy builds again once it has the real ones.)
  static void checkTokenSpend(List<int> raw, List<int> lock, int sats, String what) {
    final tx = Transaction.fromHex(hex.encode(raw));
    try {
      Interpreter().correctlySpends(
          tx.inputs[0].script!, SVScript.fromByteArray(Uint8List.fromList(lock)), tx, 0, _flags, Coin.valueOf(BigInt.from(sats)));
    } catch (e) {
      throw StateError('the token refuses the spend of $what: $e');
    }
  }

  /// The header of a fuelled token output's [script] under [b]'s layout and
  /// code, or null when [script] is not `PUSH(header) OP_CODESEPARATOR code`
  /// with exactly that code.
  static List<int>? fuelHeaderOf(SVScript script, FnftBuilder b) {
    final bytes = script.buffer;
    final size = b.L.size;
    const lead = 2;
    if (bytes.length != lead + size + 1 + b.code.length) return null;
    if (bytes[0] != OpCodes.OP_PUSHDATA1 || bytes[1] != size || bytes[lead + size] != OpCodes.OP_CODESEPARATOR) return null;
    for (var i = 0; i < b.code.length; i++) {
      if (bytes[lead + size + 1 + i] != b.code[i]) return null;
    }
    return bytes.sublist(lead, lead + size);
  }

  /// A little-endian unsigned number from [b][at:at+n].
  static int leInt(List<int> b, int at, int n) {
    var v = 0;
    for (var i = n - 1; i >= 0; i--) {
      v = (v << 8) | b[at + i];
    }
    return v;
  }

  /// [outpoint]'s display form, txid:vout.
  static String show(List<int> outpoint) {
    var vout = 0;
    for (var i = 3; i >= 0; i--) {
      vout = (vout << 8) | outpoint[32 + i];
    }
    return '${hex.encode(outpoint.sublist(0, 32).reversed.toList())}:$vout';
  }
}
