import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import '../../libtokensv.dart';

import 'fuel_sale.dart';
import 'plugin_support.dart';

/// The Voucher NFT (TSL1_LT_VNFT) as a libspiffy plugin: a Fuelled NFT that
/// can be transferred at most `maxHops` times, is redeemed only to the
/// issuer, and after its expiry height can be force-redeemed by the issuer.
///
/// Actions (`params['action']`; key hashes and txids as hex, txids in
/// display order):
///  * `issue`: under `params['issuer']` with the terms `params['maxHops']`,
///    `params['expiry']` (a block height), `params['feeCap']` (sats) and
///    `params['redeemTo']` (default: the first funding coin's key hash, the
///    issuing wallet's own). The selected coins (one or two) are the fuel.
///  * `transfer`: the voucher at output 0 of `params['token']` to
///    `params['to']`, paid from its fuel; `params['attestation']` for the
///    first transfer of an issuance. Refused past `maxHops`.
///  * `topup`: `transfer` with one funding coin swept into the fuel.
///  * `redeem`: the holder redeems to the issuer; the fee comes from the
///    fuel and may not exceed `feeCap`.
///  * `redeemFunded`: `redeem` with one funding coin paying the fee, for a
///    fee above the cap; the issuer is paid the voucher's whole value.
///  * `forceRedeem`: the issuer, after the expiry, takes the voucher and its
///    fuel from whoever holds it. Signed by the wallet key of `redeemTo`.
///    The voucher's transaction comes from the wallet or, when the wallet
///    does not hold it, from `params['tokenRaw']`. `params['lockHeight']`
///    (default the expiry) is the nLockTime. Settle it after that height.
///  * `reissue`: the issuer issues the successor on output 0 of the
///    redemption or force-redemption `params['ended']` (or
///    `params['endedRaw']`), with new terms (as for `issue`), fuelled by the
///    ended voucher's value.
///
/// Every token spend is run through the token's script before the
/// transaction is returned. Fees are the request's rate.
class LtVnftPlugin extends TransactionBuilderPlugin {
  static const id = 'tsl1_lt_vnft';
  static const scriptType = 'lt_vnft';

  final NetworkType network;
  final FnftBuilder _b;
  final String _id, _scriptType, _name;
  final FuelSale? _sale;
  LtVnftPlugin({this.network = NetworkType.TEST})
      : _b = FnftBuilder.voucher(),
        _id = id,
        _scriptType = scriptType,
        _name = 'Voucher NFT (TSL1_LT_VNFT)',
        _sale = null;

  /// The sale version ([LtVnftSalePlugin]): this plugin's actions, and the swap's.
  LtVnftPlugin.archetype(this._b, this._id, this._scriptType, this._name, {this.network = NetworkType.TEST})
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
  List<String> get supportedActions => [...const ['issue', 'transfer', 'topup', 'redeem', 'redeemFunded', 'forceRedeem', 'reissue'], if (_sale != null) ...FuelSale.actions];
  @override
  int requiredFundingUtxoCount(String action) => FuelSale.actions.contains(action) ? 0 : (const {'issue', 'topup', 'redeemFunded'}.contains(action) ? 1 : 0);

  List<int>? headerOf(SVScript script) => PluginSupport.fuelHeaderOf(script, _b);

  @override
  String? identifyScript(SVScript script) => headerOf(script) == null ? null : _scriptType;

  /// What libspiffy keeps of a voucher output: `ownerAddress` makes it the
  /// wallet's and keeps it out of payments; `fuel` is its value; the terms
  /// and `hopsLeft` tell the holder when it must be redeemed, and `expiry`
  /// when the issuer may take it back.
  @override
  Map<String, dynamic>? extractMetadata(SVScript script) {
    final h = headerOf(script);
    if (h == null) return null;
    final L = _b.L;
    final tokenId = h.sublist(L.tokenId, L.issuer);
    final owner = hex.encode(h.sublist(L.owner, L.owner + 20));
    final maxHops = h[L.maxHops], counter = h[L.counter];
    return {
      'pluginId': _id,
      'scriptType': _scriptType,
      'tokenId': tokenId.every((x) => x == 0) ? null : hex.encode(tokenId.reversed.toList()),
      'issuer': hex.encode(h.sublist(L.issuer, L.issuer + 20)),
      'ownerPKH': owner,
      'ownerAddress': Address.fromPubkeyHash(owner, network).toBase58(),
      'fuel': PluginSupport.leInt(h, L.value, 8),
      'maxHops': maxHops,
      'hops': counter,
      'hopsLeft': maxHops - counter,
      'expiry': PluginSupport.leInt(h, L.expiry, 4),
      'forcedRedemptionHeight': PluginSupport.leInt(h, L.expiry, 4),
      'redeemTo': hex.encode(h.sublist(L.redeemTo, L.redeemTo + 20)),
      'feeCap': PluginSupport.leInt(h, L.feeCap, 8),
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
      case 'reissue':
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
      case 'redeem':
      case 'redeemFunded':
      case 'forceRedeem':
        return tx.inputs.isNotEmpty &&
            tx.inputs.length <= 2 &&
            tx.outputs.length == 1 &&
            tx.outputs.single.script.buffer.length == 25 &&
            tx.outputs.single.script.buffer[0] == OpCodes.OP_DUP;
      default:
        return false;
    }
  }

  VoucherTerms _terms(Map<String, dynamic> p, List<int> defaultRedeemTo) => VoucherTerms(
        maxHops: p['maxHops'] as int,
        expiry: p['expiry'] as int,
        feeCap: p['feeCap'] as int,
        redeemTo: p['redeemTo'] == null ? defaultRedeemTo : PluginSupport.keyHash(p['redeemTo']),
      );

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
          terms: _terms(p, funds[0].pkh),
          satsPerKb: rate,
        );
        return _result(t.raw, [for (final f in funds) f.sats]);

      case 'transfer':
      case 'topup':
        final (from, owner) = await _held(request);
        final fund = action == 'topup' ? funds[0] : null;
        final t = _b.transfer(from: from, ownerKey: owner, to: PluginSupport.keyHash(p['to']), fund: fund, satsPerKb: rate);
        _check(t.raw, from);
        return _result(t.raw, [from.value, if (fund != null) fund.sats]);

      case 'redeem':
      case 'redeemFunded':
        final (from, owner) = await _held(request);
        final fund = action == 'redeemFunded' ? funds[0] : null;
        final r = _b.redeem(from: from, ownerKey: owner, fund: fund, satsPerKb: rate);
        _check(r, from);
        return _result(r, [from.value, if (fund != null) fund.sats]);

      case 'forceRedeem':
        final from = await _token(request);
        final issuerKey = await PluginSupport.ownerKey(request, from.terms.redeemTo);
        final f = _b.forceRedeem(from: from, issuerKey: issuerKey, lockHeight: p['lockHeight'] as int?, satsPerKb: rate);
        _check(f, from);
        return _result(f, [from.value]);

      case 'reissue':
        final ended = p['endedRaw'] != null
            ? hex.decode(p['endedRaw'] as String)
            : await PluginSupport.lookup(request, p['ended'] as String);
        final e = Transaction.fromHex(hex.encode(ended));
        final e0 = e.outputs.first.script.buffer;
        if (e0.length != 25) throw ArgumentError('output 0 of the ended transaction is not P2PKH');
        final endKey = await PluginSupport.ownerKey(request, e0.sublist(3, 23));
        final r = _b.reissue(
          ended: ended,
          endKey: endKey,
          issuerPkh: PluginSupport.keyHash(p['issuer']),
          terms: _terms(p, endKey.pkh),
          satsPerKb: rate,
        );
        return _result(r.raw, [e.outputs.first.satoshis.toInt()]);

      default:
        throw ArgumentError('unknown action $action');
    }
  }

  /// The txid (display order) of the issuer's identity anchor that the
  /// transfer [transferRaw] names.
  String anchorTxid(List<int> transferRaw) {
    final t = _b.fromRaw(transferRaw);
    if (t.isIssuance) throw ArgumentError('an issuance carries no attestation: a holder is paid by a transfer');
    final rec = t.rec;
    return hex.encode(rec.sublist(rec.length - FnftLayout.attestation, rec.length - FnftLayout.attestation + 32).reversed.toList());
  }

  /// The reissue link a holder of the successor passes on: [endRaw], the
  /// redemption or force-redemption, and [redeemedRaw], the transaction
  /// whose voucher it ended. The link carries the ended voucher's terms.
  LtLink link(List<int> endRaw, List<int> redeemedRaw) {
    final g = _b.fromRaw(redeemedRaw);
    return LtLink(endRaw, g.rec, g.terms.bytes);
  }

  /// The voucher the request spends, from the wallet or `params['tokenRaw']`.
  Future<FnftTx> _token(PluginTransactionRequest request) async {
    final txid = request.params['token'] as String;
    final List<int> raw;
    if (request.params['tokenRaw'] != null) {
      raw = hex.decode(request.params['tokenRaw'] as String);
      if (Transaction.fromHex(hex.encode(raw)).id != txid) throw ArgumentError('tokenRaw is not transaction $txid');
    } else {
      raw = await PluginSupport.lookup(request, txid);
    }
    final t = _b.fromRaw(raw);
    if (t.isIssuance && request.params['attestation'] != null) {
      t.x = hex.decode(request.params['attestation'] as String);
    }
    return t;
  }

  /// The voucher and the wallet key its header names as owner.
  Future<(FnftTx, LtKey)> _held(PluginTransactionRequest request) async {
    final t = await _token(request);
    if (t.isIssuance) {
      if (t.x.isEmpty) throw ArgumentError('${request.params['token']} is an issuance: the transfer carries the issuer\'s attestation');
      final why = FnftIdentity.attestationError(t);
      if (why != null) throw ArgumentError('the attestation for ${request.params['token']}: $why');
    }
    return (t, await PluginSupport.ownerKey(request, t.owner));
  }

  void _check(List<int> raw, FnftTx from) =>
      PluginSupport.checkTokenSpend(raw, from.lock(_b.code), from.value, PluginSupport.show(from.out));

  TransactionBuilderResult _result(List<int> raw, List<int> inputSats) {
    final tx = Transaction.fromHex(hex.encode(raw));
    return TransactionBuilderResult(primaryTx: tx, primaryFeeSats: PluginSupport.fee(tx, inputSats));
  }
}

/// The Voucher NFT's sale version (TSL1_LT_VNFT_S) as a libspiffy plugin: the actions
/// of [LtVnftPlugin], and the swap's ([FuelSale]).
class LtVnftSalePlugin extends LtVnftPlugin {
  static const id = 'tsl1_lt_vnft_s';
  static const scriptType = 'lt_vnft_s';

  LtVnftSalePlugin({NetworkType network = NetworkType.TEST})
      : super.archetype(FnftBuilder.saleableVoucher(), id, scriptType, 'Voucher NFT, sale version (TSL1_LT_VNFT_S)', network: network);
}
