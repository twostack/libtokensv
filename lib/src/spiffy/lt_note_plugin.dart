import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import '../../libtokensv.dart';

import 'fuel_sale.dart';
import 'plugin_support.dart';

/// The Note NFT (TSL1_LT_NOTE) as a libspiffy plugin: a fuelled token whose
/// terms say how much of its fuel the holder gets on each way it can end
/// (tstokenlib's `NoteTerms`); the issuer (`payTo`) gets the rest.
///
/// Actions (`params['action']`; key hashes and txids as hex, txids in
/// display order):
///  * `issue`: under `params['issuer']` with the terms `params['maxHops']`
///    (default 0: no limit), `params['payTo']` (default the first funding
///    coin's key hash, the issuing wallet's own), `params['feeCap']`,
///    `params['exit']`, `params['maturity']`, `params['mature']`,
///    `params['callAt']` and `params['call']` (amounts in sats, heights as
///    block heights; `NoteTerms.everything` and `NoteTerms.never` for all
///    and never). The selected coins (one or two) are the fuel.
///  * `transfer`, `topup`: as for the Fuelled NFT; refused past `maxHops`.
///  * `exit`: the holder ends it at any time, split by the terms' `exit`.
///  * `matureExit`: the holder ends it from `maturity` on, split by
///    `mature`. Its nLockTime is the maturity: settle it after that height.
///  * `call`: the issuer ends it from `callAt` on, whoever holds it, split
///    by `call`; signed by the wallet key of `payTo`. The note's
///    transaction comes from the wallet or `params['tokenRaw']`. Settle it
///    after `callAt`.
///  * `reissue`: the issuer issues the successor on output 0 of an exit or
///    a call `params['ended']` (or `params['endedRaw']`) that paid it, with
///    new terms (as for `issue`).
/// The endings take no funding coin; their fee comes from the fuel and may
/// not exceed `feeCap`.
///
/// Every token spend is run through the token's script before the
/// transaction is returned. Fees are the request's rate.
class LtNotePlugin extends TransactionBuilderPlugin {
  static const id = 'tsl1_lt_note';
  static const scriptType = 'lt_note';

  final NetworkType network;
  final FnftBuilder _b;
  final String _id, _scriptType, _name;
  final FuelSale? _sale;
  LtNotePlugin({this.network = NetworkType.TEST})
      : _b = FnftBuilder.note(),
        _id = id,
        _scriptType = scriptType,
        _name = 'Note NFT (TSL1_LT_NOTE)',
        _sale = null;

  /// The sale version ([LtNoteSalePlugin]): this plugin's actions, and the swap's.
  LtNotePlugin.archetype(this._b, this._id, this._scriptType, this._name, {this.network = NetworkType.TEST})
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
  List<String> get supportedActions => [...const ['issue', 'transfer', 'topup', 'exit', 'matureExit', 'call', 'reissue'], if (_sale != null) ...FuelSale.actions];
  @override
  int requiredFundingUtxoCount(String action) => FuelSale.actions.contains(action) ? 0 : (const {'issue', 'topup'}.contains(action) ? 1 : 0);

  List<int>? headerOf(SVScript script) => PluginSupport.fuelHeaderOf(script, _b);

  @override
  String? identifyScript(SVScript script) => headerOf(script) == null ? null : _scriptType;

  /// What libspiffy keeps of a note output: `ownerAddress` makes it the
  /// wallet's; `fuel` is its value; the terms; and what the holder gets of
  /// that value on an exit (`holderOnExit`), from maturity
  /// (`holderAtMaturity`) and if called (`holderIfCalled`), each at the most
  /// fee the terms allow.
  @override
  Map<String, dynamic>? extractMetadata(SVScript script) {
    final h = headerOf(script);
    if (h == null) return null;
    final L = _b.L;
    final tokenId = h.sublist(L.tokenId, L.issuer);
    final owner = hex.encode(h.sublist(L.owner, L.owner + 20));
    final t = NoteTerms.of(h.sublist(L.maxHops, L.maxHops + L.terms));
    final fuel = PluginSupport.leInt(h, L.value, 8);
    int holder(int a) => NoteTerms.split(a, fuel, t.feeCap).$2;
    return {
      'pluginId': _id,
      'scriptType': _scriptType,
      'tokenId': tokenId.every((x) => x == 0) ? null : hex.encode(tokenId.reversed.toList()),
      'issuer': hex.encode(h.sublist(L.issuer, L.issuer + 20)),
      'ownerPKH': owner,
      'ownerAddress': Address.fromPubkeyHash(owner, network).toBase58(),
      'fuel': fuel,
      'maxHops': t.maxHops,
      'hops': h[L.counter],
      'hopsLeft': t.maxHops == 0 ? null : t.maxHops - h[L.counter],
      'payTo': hex.encode(t.payTo),
      'feeCap': t.feeCap,
      'exit': t.exit,
      'maturity': t.maturity,
      'mature': t.mature,
      'callAt': t.callAt,
      'call': t.call,
      'callableBeforeMaturity': t.callAt < t.maturity,
      'holderOnExit': holder(t.exit),
      'holderAtMaturity': holder(t.mature),
      'holderIfCalled': holder(t.call),
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
      case 'exit':
      case 'matureExit':
      case 'call':
        return tx.inputs.length == 1 &&
            (tx.outputs.length == 1 || tx.outputs.length == 2) &&
            tx.outputs.every((o) => o.script.buffer.length == 25 && o.script.buffer[0] == OpCodes.OP_DUP);
      default:
        return false;
    }
  }

  NoteTerms _terms(Map<String, dynamic> p, List<int> defaultPayTo) => NoteTerms(
        maxHops: p['maxHops'] as int? ?? 0,
        payTo: p['payTo'] == null ? defaultPayTo : PluginSupport.keyHash(p['payTo']),
        feeCap: p['feeCap'] as int,
        exit: p['exit'] as int,
        maturity: p['maturity'] as int,
        mature: p['mature'] as int,
        callAt: p['callAt'] as int,
        call: p['call'] as int,
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

      case 'exit':
      case 'matureExit':
        final (from, owner) = await _held(request);
        final r = action == 'exit'
            ? _b.exit(from: from, ownerKey: owner, satsPerKb: rate)
            : _b.matureExit(from: from, ownerKey: owner, satsPerKb: rate);
        _check(r, from);
        return _result(r, [from.value]);

      case 'call':
        final from = await _token(request);
        final issuerKey = await PluginSupport.ownerKey(request, from.noteTerms.payTo);
        final c = _b.call(from: from, issuerKey: issuerKey, lockHeight: p['lockHeight'] as int?, satsPerKb: rate);
        _check(c, from);
        return _result(c, [from.value]);

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
  /// exit or call, and [redeemedRaw], the transaction whose note it ended.
  /// The link carries the ended note's terms.
  LtLink link(List<int> endRaw, List<int> redeemedRaw) {
    final g = _b.fromRaw(redeemedRaw);
    return LtLink(endRaw, g.rec, g.termBytes);
  }

  /// The note the request spends, from the wallet or `params['tokenRaw']`.
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

  /// The note and the wallet key its header names as owner.
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

/// The Note NFT's sale version (TSL1_LT_NOTE_S) as a libspiffy plugin: the actions
/// of [LtNotePlugin], and the swap's ([FuelSale]).
class LtNoteSalePlugin extends LtNotePlugin {
  static const id = 'tsl1_lt_note_s';
  static const scriptType = 'lt_note_s';

  LtNoteSalePlugin({NetworkType network = NetworkType.TEST})
      : super.archetype(FnftBuilder.saleableNote(), id, scriptType, 'Note NFT, sale version (TSL1_LT_NOTE_S)', network: network);
}
