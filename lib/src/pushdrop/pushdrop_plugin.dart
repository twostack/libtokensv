import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';

import 'pushdrop.dart';

/// PushDrop tokens in a libspiffy wallet: register it with
/// `PluginRegistry().register(PushDropPlugin(network: ...))` in the isolate
/// the wallet runs in, then pay [PushDropPlugin.outputSpec] with the wallet's
/// `PayInvoiceCommand`.
///
/// One transaction can make tokens and spend tokens: replacing a token is
/// spending the old one and making the new one, withdrawing it is spending
/// it alone. The wallet funds the fee and gets the change.
///
/// A token is locked to a key, and the wallet signs a spend with it when
/// the key is one of its own: an HD key, or a type-42 key it has recorded
/// (`RecordType42AddressesCommand`). Its tokens are then the wallet's: the
/// wallet tracks them (with this plugin's [extractMetadata]) but never
/// counts them in the balance or spends them as change.
class PushDropPlugin extends TransactionBuilderPlugin {
  static const String id = 'pushdrop';
  static const String scriptType = 'pushdrop';

  /// Makes the [outputSpec] outputs (and spends its tokens).
  static const String create = 'create';

  /// Spends tokens, making none.
  static const String spend = 'spend';

  /// The network of the wallet's addresses: a token's owner is the address
  /// of its locking key.
  final NetworkType network;

  PushDropPlugin({required this.network});

  /// What to pay with `PayInvoiceCommand(outputs: [...])` for a transaction
  /// that makes [outputs] and spends [spends].
  ///
  /// Its amount is the tokens' satoshis and an allowance for the fee of the
  /// bytes the wallet's selection does not see (the selection sizes the
  /// funding inputs only): the tokens, the inputs spending tokens and the
  /// change. The allowance covers up to 100 satoshis per 1000 bytes; what the
  /// transaction does not pay comes back as change.
  static PluginOutputSpec outputSpec({
    List<PushDropOutput> outputs = const [],
    List<PushDropSpend> spends = const [],
    String? label,
  }) {
    if (outputs.isEmpty && spends.isEmpty) {
      throw ArgumentError('A PushDrop transaction makes or spends at least one token');
    }
    final extraBytes = [
      for (final o in outputs) _outputSize(o.lockingScript.buffer.length),
      for (final _ in spends) _pushDropInputSize,
      _outputSize(_p2pkhScriptBytes),
    ].fold(0, (a, b) => a + b);
    final tokens = outputs.fold<BigInt>(BigInt.zero, (sum, o) => sum + o.satoshis);
    return PluginOutputSpec(
      pluginId: id,
      pluginScriptType: scriptType,
      params: {
        'action': outputs.isEmpty ? spend : create,
        'outputs': [for (final o in outputs) o.toMap()],
        'spends': [for (final s in spends) s.toMap()],
      },
      amount: tokens + BigInt.from(extraBytes ~/ 10 + 1),
      label: label,
    );
  }

  @override
  String get pluginId => id;

  @override
  String get displayName => 'PushDrop tokens';

  @override
  List<String> get scriptTypes => const [scriptType];

  @override
  List<String> get supportedActions => const [create, spend];

  @override
  bool get spendsAnyWalletOutput => true;

  @override
  String? identifyScript(SVScript script) => PushDrop.decode(script) == null ? null : scriptType;

  /// The token's owner (the address of its locking key, which the wallet
  /// attributes it by), its locking key and its fields.
  @override
  Map<String, dynamic>? extractMetadata(SVScript script) {
    final token = PushDrop.decode(script);
    if (token == null) return null;
    return {
      'ownerAddress': Address.fromPublicKey(SVPublicKey.fromHex(token.lockingPublicKey), network).toBase58(),
      'lockingPublicKey': token.lockingPublicKey,
      'fields': [for (final f in token.fields) hex.encode(f)],
    };
  }

  @override
  LockingScriptBuilder? createLockBuilder(PluginOutputSpec spec) {
    final outputs = _outputs(spec.params);
    if (outputs.isEmpty) return null;
    final token = PushDrop.decode(outputs.first.lockingScript)!;
    return PushDropLockBuilder(lockingPublicKey: token.lockingPublicKey, fields: token.fields);
  }

  @override
  UnlockingScriptBuilder? createUnlockBuilder(PluginUnlockSpec spec) =>
      spec.scriptType == scriptType ? PushDropUnlockBuilder() : null;

  @override
  bool validateTransactionStructure(Transaction tx, String action) {
    final tokens = tx.outputs.where((o) => PushDrop.decode(o.script) != null).length;
    return action == spend ? tokens == 0 : tokens > 0;
  }

  @override
  Future<TransactionBuilderResult> buildTransaction(PluginTransactionRequest request) async {
    final outputs = _outputs(request.params);
    final spends = [
      for (final s in (request.params['spends'] as List? ?? const [])) PushDropSpend.fromMap(Map<String, dynamic>.from(s as Map))
    ];
    if (request.fundingInputs.isEmpty) throw StateError('A PushDrop transaction needs a funding input for its fee');

    final builder = TransactionBuilder();
    var total = BigInt.zero;
    for (final s in spends) {
      final token = PushDrop.decode(s.lockingScript) ??
          (throw ArgumentError('${s.txid}:${s.vout} is not a PushDrop token'));
      final keyHash = hex.encode(hash160(hex.decode(token.lockingPublicKey)));
      final owner = await request.keyFor(keyHash);
      builder.spendFromOutpointWithSigner(
        owner.signer,
        TransactionOutpoint(s.txid, s.vout, s.satoshis, s.lockingScript),
        TransactionInput.MAX_SEQ_NUMBER,
        PushDropUnlockBuilder(),
      );
      total += s.satoshis;
    }
    for (final input in request.fundingInputs) {
      builder.spendFromOutpointWithSigner(
          request.signer, input.outpoint, TransactionInput.MAX_SEQ_NUMBER, input.newUnlocker());
      total += input.utxo.satoshis;
    }
    var paid = BigInt.zero;
    for (final o in outputs) {
      final token = PushDrop.decode(o.lockingScript)!;
      builder.spendToLockBuilder(PushDropLockBuilder(lockingPublicKey: token.lockingPublicKey, fields: token.fields), o.satoshis);
      paid += o.satoshis;
    }

    final size = 4 + 4 + 1 + 1 +
        spends.length * _pushDropInputSize +
        request.fundingInputs.fold<int>(0, (sum, i) => sum + _fundingInputSize(i)) +
        outputs.fold<int>(0, (sum, o) => sum + _outputSize(o.lockingScript.buffer.length)) +
        _outputSize(_p2pkhScriptBytes);
    final fee = request.feeRate.feeFor(size);
    final change = total - paid - fee;
    if (change < BigInt.zero) {
      throw StateError('The funding ($total satoshis) does not cover $paid satoshis of tokens and the $fee fee');
    }
    if (change > BigInt.zero) {
      builder.spendToLockBuilder(P2PKHLockBuilder.fromAddress(Address.fromBase58(request.fundingInputs.first.utxo.address)), change);
    }
    return TransactionBuilderResult(primaryTx: builder.build(false), primaryFeeSats: fee);
  }

  static List<PushDropOutput> _outputs(Map<String, dynamic> params) => [
        for (final o in (params['outputs'] as List? ?? const [])) PushDropOutput.fromMap(Map<String, dynamic>.from(o as Map))
      ];

  static const _p2pkhScriptBytes = 25;

  /// Outpoint, sequence, and a one-signature unlocking script.
  static const _pushDropInputSize = 36 + 4 + 1 + 73;

  static int _outputSize(int scriptBytes) => 8 + _varIntSize(scriptBytes) + scriptBytes;

  /// A funding input with its unlocking script: a signature each, and the
  /// public key a P2PKH input pushes.
  static int _fundingInputSize(PluginFundingInput input) {
    final script = input.lockingScript.buffer;
    final p2pkh = script.length == 25 && script[0] == OpCodes.OP_DUP;
    final unlocking = input.signatures * 73 + (p2pkh ? 34 : 0) + (input.signatures > 1 ? 1 : 0);
    return 36 + 4 + _varIntSize(unlocking) + unlocking;
  }

  static int _varIntSize(int n) => n < 0xfd ? 1 : (n <= 0xffff ? 3 : 5);
}

/// A token a PushDrop transaction makes.
class PushDropOutput {
  final SVScript lockingScript;
  final BigInt satoshis;

  PushDropOutput({required this.lockingScript, BigInt? satoshis}) : satoshis = satoshis ?? BigInt.one {
    if (PushDrop.decode(lockingScript) == null) throw ArgumentError('Not a PushDrop locking script');
  }

  Map<String, dynamic> toMap() => {'lockingScript': lockingScript.toHex(), 'satoshis': satoshis.toString()};

  factory PushDropOutput.fromMap(Map<String, dynamic> map) => PushDropOutput(
      lockingScript: SVScript.fromHex(map['lockingScript'] as String), satoshis: BigInt.parse(map['satoshis'] as String));
}

/// A token a PushDrop transaction spends.
class PushDropSpend {
  final String txid;
  final int vout;
  final BigInt satoshis;
  final SVScript lockingScript;

  PushDropSpend({required this.txid, required this.vout, required this.satoshis, required this.lockingScript});

  Map<String, dynamic> toMap() =>
      {'txid': txid, 'vout': vout, 'satoshis': satoshis.toString(), 'lockingScript': lockingScript.toHex()};

  factory PushDropSpend.fromMap(Map<String, dynamic> map) => PushDropSpend(
        txid: map['txid'] as String,
        vout: map['vout'] as int,
        satoshis: BigInt.parse(map['satoshis'] as String),
        lockingScript: SVScript.fromHex(map['lockingScript'] as String),
      );
}
