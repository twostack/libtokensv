import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import '../../libtokensv.dart';

import 'fuel_sale.dart';
import 'plugin_support.dart';

/// The Fuelled NFT (TSL1_LT_FNFT) as a libspiffy plugin: a covenant NFT
/// whose token output carries the satoshis that pay its own fees.
///
/// libspiffy selects funding coins only for the actions that take some
/// (`issue`, `topup`); the others are paid from the token's fuel, and the
/// wallet's coins are not touched. The token's own input is signed with the
/// key its header names as owner, through [PluginTransactionRequest.keyFor].
///
/// Actions (`params['action']`; key hashes and txids as hex, txids in
/// display order). Issuance and distribution are separate steps: `issue` and
/// `reissue` make the token the issuing wallet's own.
///  * `issue`: an issuance under `params['issuer']`, fuelled by the funding
///    coins libspiffy selected for the payment's amount (one or two), owned
///    by the first coin's key.
///  * `transfer`: the token at output 0 of `params['token']` to
///    `params['to']`, its fee from the token's fuel. When that transaction
///    is the issuance, `params['attestation']` is the issuer's attestation
///    over its txid, checked before anything is built.
///  * `topup`: `transfer` with one funding coin swept whole into the token.
///    To refuel without giving the token away, `to` is the owner's own key
///    hash.
///  * `end`: the token spent on the cheap path; everything it holds, less
///    the fee, to its owner. It cannot be undone: `params['irreversible']`
///    must be `true`.
///  * `reissue`: `end`, and its successor issued on the end's output 0 to the
///    ended token's owner, fuelled by the ended token's value; paired, from
///    one reservation. Only the issuer can attest the successor, so
///    `params['issuer']` must be the token's issuer key hash.
///
/// Every token spend is run through the token's script before the
/// transaction is returned. Fees are the request's rate.
class LtFnftPlugin extends TransactionBuilderPlugin {
  static const id = 'tsl1_lt_fnft';
  static const scriptType = 'lt_fnft';

  final NetworkType network;
  final FnftBuilder _b;
  final String _id, _scriptType, _name;
  final FuelSale? _sale;
  LtFnftPlugin({this.network = NetworkType.TEST})
      : _b = FnftBuilder.standard(),
        _id = id,
        _scriptType = scriptType,
        _name = 'Fuelled NFT (TSL1_LT_FNFT)',
        _sale = null;

  /// The sale version ([LtFnftSalePlugin]): this plugin's actions, and the swap's.
  LtFnftPlugin.archetype(this._b, this._id, this._scriptType, this._name, {this.network = NetworkType.TEST})
      : _sale = _b.L.payable ? FuelSale(_b) : null;

  /// The builder this plugin builds with.
  FnftBuilder get builder => _b;

  @override
  String get pluginId => _id;
  @override
  String get displayName => _name;
  @override
  List<String> get scriptTypes => [_scriptType];
  @override
  List<String> get supportedActions => [...const ['issue', 'transfer', 'topup', 'end', 'reissue'], if (_sale != null) ...FuelSale.actions];
  @override
  int requiredFundingUtxoCount(String action) => FuelSale.actions.contains(action) ? 0 : (action == 'issue' || action == 'topup' ? 1 : 0);

  /// The header of a token output's [script], or null when [script] is not
  /// `PUSH(header) OP_CODESEPARATOR code` with this archetype's code.
  List<int>? headerOf(SVScript script) => PluginSupport.fuelHeaderOf(script, _b);

  @override
  String? identifyScript(SVScript script) => headerOf(script) == null ? null : _scriptType;

  /// What libspiffy keeps of a token output: `ownerAddress` makes it the
  /// wallet's and keeps it out of payments; `fuel` is the satoshis it holds
  /// (the output's own value; shown so that a user sees the fuel as part of
  /// the token, not as spendable balance).
  @override
  Map<String, dynamic>? extractMetadata(SVScript script) {
    final h = headerOf(script);
    if (h == null) return null;
    final tokenId = h.sublist(FnftLayout.tokenId, FnftLayout.issuer);
    final owner = hex.encode(h.sublist(FnftLayout.owner, FnftLayout.flags));
    var fuel = 0;
    for (var i = 7; i >= 0; i--) {
      fuel = (fuel << 8) | h[FnftLayout.value + i];
    }
    return {
      'pluginId': _id,
      'scriptType': _scriptType,
      'tokenId': tokenId.every((x) => x == 0) ? null : hex.encode(tokenId.reversed.toList()),
      'issuer': hex.encode(h.sublist(FnftLayout.issuer, FnftLayout.owner)),
      'ownerPKH': owner,
      'ownerAddress': Address.fromPubkeyHash(owner, network).toBase58(),
      'fuel': fuel,
    };
  }

  @override
  LockingScriptBuilder? createLockBuilder(PluginOutputSpec spec) => null;
  @override
  UnlockingScriptBuilder? createUnlockBuilder(PluginUnlockSpec spec) => null;

  @override
  bool validateTransactionStructure(Transaction tx, String action) {
    final raw = hex.decode(tx.serialize());
    if (_sale != null && FuelSale.actions.contains(action)) return _sale.validate(tx);
    switch (action) {
      case 'issue':
      case 'transfer':
      case 'topup':
      case 'witness': // the reissue's paired successor, an issuance
        try {
          final t = _b.fromRaw(raw);
          return switch (action) {
            'transfer' => !t.isIssuance && !t.funded,
            'topup' => !t.isIssuance && t.funded,
            _ => t.isIssuance,
          };
        } on ArgumentError {
          return false;
        }
      case 'end':
      case 'reissue': // the primary of a reissue is the end
        return tx.inputs.length == 1 &&
            tx.outputs.length == 1 &&
            tx.outputs.single.script.buffer.length == 25 &&
            tx.outputs.single.script.buffer[0] == OpCodes.OP_DUP;
      default:
        return false;
    }
  }

  @override
  Future<TransactionBuilderResult> buildTransaction(PluginTransactionRequest request) async {
    final p = request.params;
    final action = p['action'] as String;
    final rate = PluginSupport.rate(request);
    final funds = PluginSupport.funds(request);
    if (funds.length < requiredFundingUtxoCount(action)) {
      throw ArgumentError('$action needs ${requiredFundingUtxoCount(action)} funding coin(s), got ${funds.length}');
    }

    if (_sale != null && FuelSale.actions.contains(action)) return _sale.build(request, action, () => _held(request));
    switch (action) {
      case 'issue':
        if (funds.length > 2) throw ArgumentError('an issuance takes one or two coins of fuel, not ${funds.length}');
        final t = _b.issue(
          first: funds[0],
          fund: funds.length == 2 ? funds[1] : null,
          issuerPkh: PluginSupport.keyHash(p['issuer']),
          owner: funds[0].pkh,
          satsPerKb: rate,
        );
        return _result(t.raw, [for (final f in funds) f.sats]);

      case 'transfer':
      case 'topup':
        final (from, owner) = await _held(request);
        final fund = action == 'topup' ? funds[0] : null;
        final t = _b.transfer(from: from, ownerKey: owner, to: PluginSupport.keyHash(p['to']), fund: fund, satsPerKb: rate);
        PluginSupport.checkTokenSpend(t.raw, from.lock(_b.code), from.value, PluginSupport.show(from.out));
        return _result(t.raw, [from.value, if (fund != null) fund.sats]);

      case 'end':
        if (p['irreversible'] != true) {
          throw ArgumentError('end destroys the token for good: pass irreversible: true');
        }
        final (from, owner) = await _held(request);
        final e = _b.end(from: from, ownerKey: owner, payTo: owner.pkh, satsPerKb: rate);
        PluginSupport.checkTokenSpend(e, from.lock(_b.code), from.value, PluginSupport.show(from.out));
        return _result(e, [from.value]);

      case 'reissue':
        final (from, owner) = await _held(request);
        final issuer = hex.encode(from.issuer);
        if (p['issuer'] != issuer) {
          throw ArgumentError('reissue is the issuer\'s operation: params[\'issuer\'] must be the token\'s issuer $issuer; '
              'a successor no one can attest is a token ended for nothing');
        }
        final e = _b.end(from: from, ownerKey: owner, payTo: owner.pkh, satsPerKb: rate);
        PluginSupport.checkTokenSpend(e, from.lock(_b.code), from.value, PluginSupport.show(from.out));
        final r = _b.reissue(ended: e, endKey: owner, issuerPkh: from.issuer, satsPerKb: rate);
        final eTx = Transaction.fromHex(hex.encode(e));
        final rTx = Transaction.fromHex(hex.encode(r.raw));
        return TransactionBuilderResult.paired(
          primaryTx: eTx,
          primaryFeeSats: PluginSupport.fee(eTx, [from.value]),
          witnessTx: rTx,
          witnessFeeSats: PluginSupport.fee(rTx, [eTx.outputs[0].satoshis.toInt()]),
        );

      default:
        throw ArgumentError('unknown action $action');
    }
  }

  /// The txid (display order) of the issuer's identity anchor that the
  /// transfer [transferRaw] names; the payee fetches it, with its proof.
  String anchorTxid(List<int> transferRaw) {
    final t = _b.fromRaw(transferRaw);
    if (t.isIssuance) throw ArgumentError('an issuance carries no attestation: a holder is paid by a transfer');
    final rec = t.rec;
    return hex.encode(rec.sublist(rec.length - FnftLayout.attestation, rec.length - FnftLayout.attestation + 32).reversed.toList());
  }

  /// The reissue link a holder of the successor passes on: [endRaw], the
  /// primary transaction of a `reissue`, and [redeemedRaw], the transaction
  /// whose token output it ended. The issuer's wallet holds both.
  LtLink link(List<int> endRaw, List<int> redeemedRaw) => LtLink(endRaw, _b.fromRaw(redeemedRaw).rec);

  /// The token the request spends, read back from the wallet's copy of its
  /// transaction, and the wallet key its header names as owner.
  Future<(FnftTx, LtKey)> _held(PluginTransactionRequest request) async {
    final txid = request.params['token'] as String;
    final t = _b.fromRaw(await PluginSupport.lookup(request, txid));
    if (t.isIssuance) {
      final a = request.params['attestation'] as String?;
      if (a == null) throw ArgumentError('$txid is an issuance: the transfer carries the issuer\'s attestation');
      t.x = hex.decode(a);
      final why = FnftIdentity.attestationError(t);
      if (why != null) throw ArgumentError('the attestation for $txid: $why');
    }
    return (t, await PluginSupport.ownerKey(request, t.owner));
  }

  TransactionBuilderResult _result(List<int> raw, List<int> inputSats) {
    final tx = Transaction.fromHex(hex.encode(raw));
    return TransactionBuilderResult(primaryTx: tx, primaryFeeSats: PluginSupport.fee(tx, inputSats));
  }
}

/// The Fuelled NFT's sale version (TSL1_LT_FNFT_S) as a libspiffy plugin: the actions
/// of [LtFnftPlugin], and the swap's ([FuelSale]).
class LtFnftSalePlugin extends LtFnftPlugin {
  static const id = 'tsl1_lt_fnft_s';
  static const scriptType = 'lt_fnft_s';

  LtFnftSalePlugin({NetworkType network = NetworkType.TEST})
      : super.archetype(FnftBuilder.saleable(), id, scriptType, 'Fuelled NFT, sale version (TSL1_LT_FNFT_S)', network: network);
}
