
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import '../../libtokensv.dart';

import 'plugin_support.dart';

List<int> _h256(List<int> b) => sha256(sha256(b));

/// The covenant NFT (TSL1_LT_NFT) as a libspiffy plugin.
///
/// libspiffy picks and signs the funding, records what is built and makes
/// the BEEF; tstokenlib builds the token's transactions. The token's own
/// input is signed with the key the token's header names as its owner,
/// through [PluginTransactionRequest.keyFor]: the signature covers only the
/// code after the separator, where no owner is written.
///
/// Actions (`params['action']`; key hashes and txids as hex, txids in
/// display order). Issuance and distribution are separate steps: `issue`
/// and `reissue` always make the token the issuing wallet's own, and
/// `transfer` distributes it.
///  * `issue`: an issuance under `params['issuer']`, the issuer's Rabin key
///    hash, owned by the first funding coin's key. Two funding coins: the
///    first coin (refunded) and the funding.
///  * `transfer`: the token at output 1 of `params['token']` to
///    `params['to']`. When that transaction is the issuance,
///    `params['attestation']` is the issuer's attestation over its txid,
///    checked before anything is built.
///  * `end`: the token at output 1 of `params['token']` spent on the cheap
///    path, so that it is no longer a token; everything to its owner. It
///    cannot be undone: `params['irreversible']` must be `true`.
///  * `reissue`: `end`, and its successor issued on the end's output 0 to
///    the ended token's owner (the issuer, who took it back), under the same
///    issuer: the end is the primary transaction and the successor the
///    paired one, built from one reservation so that nothing else spends the
///    end's output 0 in between. Two funding coins. Only the issuer can
///    attest the successor, so `params['issuer']` must be the token's issuer
///    key hash: the host's statement that this wallet is the issuer's.
///
/// `issue` with `params['payload']` (hex) issues on a payload transaction
/// (tstokenlib's `LtPayload`): the primary transaction is the payload
/// transaction, from the first funding coin, and the paired one the
/// issuance, whose input 1 spends the payload transaction's output 1 and
/// input 0 the second funding coin (the two coins `issue` asks for; called
/// directly with one coin, the payload transaction's change is input 0).
///
/// The swap (tstokenlib's `LtSwap`): a token sold for satoshis in its own
/// transfer, signed by both sides. Whoever signs first records a **half**
/// (a transaction the network refuses, with a placeholder for the other
/// side's signature) as a deferred payment, which holds that side's input;
/// the half is the message to the other side. Whoever signs second
/// completes and records the swap, and settles it. The first signer then
/// gives the completed swap to libspiffy (`CompleteDeferredPaymentCommand`
/// on the half's txid), which records it in the half's place. To withdraw a
/// half, reclaim it (`ReclaimDeferredPaymentCommand`): that spends the held
/// input, which is the only thing that takes the signature back.
///  * `swapBid` (the buyer signs first): `params['tokenTx']` (the token's
///    transaction, hex, from the seller), `params['payTo']`,
///    `params['price']`, `params['coin']` (`txid:vout` of a coin of this
///    wallet worth exactly the price plus the fee), `params['newOwner']`
///    (default the coin's key hash), `params['anchorTx']` (the issuer's
///    identity anchor, hex) and optional `params['links']` (`LtLinks`, hex):
///    the token is checked as a payee checks it before anything is signed.
///  * `swapAccept` (the seller completes a bid): `params['half']` (the bid,
///    hex), `params['fundTx']` (the buyer's coin's transaction, hex) and
///    `params['price']`, the price agreed: the bid must pay exactly that to
///    a key of this wallet, for a token this wallet holds.
///  * `swapAsk` (the seller signs first): `params['token']` (txid),
///    `params['price']`, `params['payTo']` (default the token's owner key),
///    and the buyer's `params['fundOut']` (`txid:vout`),
///    `params['fundSats']`, `params['fundPub']` and `params['newOwner']`.
///  * `swapTake` (the buyer completes an ask): `params['half']`,
///    `params['tokenTx']`, `params['price']`, `params['anchorTx']` and
///    optional `params['links']`; the buyer's coin is the one the ask names,
///    which must be this wallet's.
/// All four take no funding coin: send them with `amount: 0`.
///
/// The Listed NFT ([LtLnftPlugin]) adds three actions:
///  * `list`: the token at output 1 of `params['token']` moved to its own
///    owner with `params['price']` in the header: from then on anyone may buy
///    it for that price. One funding coin.
///  * `withdraw`: the same with no price. One funding coin.
///  * `buy`: the listed token at output 1 of `params['listingTx']` (hex)
///    bought with `params['coin']` (`txid:vout` of a coin of this wallet
///    worth exactly the price plus the fee), for `params['newOwner']`
///    (default the coin's key hash). `params['maxPrice']` is the most this
///    wallet pays; `params['anchorTx']` and optional `params['links']` are
///    for the payee check, made before anything is signed. No funding coin:
///    send it with `amount: 0`.
///
/// Every token spend is run through the token's script before the
/// transaction is returned.
///
/// Fees are the request's rate on each transaction's size; a swap's and a
/// purchase's fee is the buyer's coin less the price.
class LtNftPlugin extends TransactionBuilderPlugin {
  static const id = 'tsl1_lt_nft';
  static const scriptType = 'lt_nft';

  final NetworkType network;
  final LtBuilder _b;
  final String _id, _scriptType, _name;
  LtNftPlugin({this.network = NetworkType.TEST})
      : _b = LtBuilder(LtLayout.nft, LtScriptGen.nft.code().buffer),
        _id = id,
        _scriptType = scriptType,
        _name = 'Covenant NFT (TSL1_LT_NFT)';

  /// Another archetype of the covenant NFT's family, under its own plugin id
  /// and script type ([LtLnftPlugin]).
  LtNftPlugin.archetype(this._b, this._id, this._scriptType, this._name, {this.network = NetworkType.TEST});

  /// The builder this plugin builds with: the NFT's layout and code.
  LtBuilder get builder => _b;

  @override
  String get pluginId => _id;
  @override
  String get displayName => _name;
  @override
  List<String> get scriptTypes => [_scriptType];
  @override
  List<String> get supportedActions => [
        'issue', 'transfer', 'end', 'reissue', 'swapBid', 'swapAccept', 'swapAsk', 'swapTake', //
        if (_b.L.listed) ...['list', 'withdraw', 'buy'],
      ];
  @override
  int requiredFundingUtxoCount(String action) => switch (action) {
        'issue' || 'reissue' => 2,
        'swapBid' || 'swapAccept' || 'swapAsk' || 'swapTake' || 'buy' => 0,
        _ => 1,
      };

  late final LtSwap _swap = LtSwap(_b);

  /// The header of a token output's [script], or null when [script] is not
  /// `PUSH(header) OP_CODESEPARATOR code` with this archetype's code.
  List<int>? headerOf(SVScript script) {
    final b = script.buffer;
    final L = _b.L;
    const lead = 2; // OP_PUSHDATA1, length
    if (b.length != lead + L.size + 1 + _b.code.length) return null;
    if (b[0] != OpCodes.OP_PUSHDATA1 || b[1] != L.size || b[lead + L.size] != OpCodes.OP_CODESEPARATOR) return null;
    for (var i = 0; i < _b.code.length; i++) {
      if (b[lead + L.size + 1 + i] != _b.code[i]) return null;
    }
    return b.sublist(lead, lead + L.size);
  }

  @override
  String? identifyScript(SVScript script) => headerOf(script) == null ? null : _scriptType;

  /// What libspiffy keeps of a token output: `ownerAddress` makes it the
  /// wallet's (and keeps it out of payments), `tokenId` is null in the
  /// issuance, whose txid is the token id.
  @override
  Map<String, dynamic>? extractMetadata(SVScript script) {
    final h = headerOf(script);
    if (h == null) return null;
    final L = _b.L;
    final tokenId = h.sublist(L.tokenId, L.issuer);
    final owner = hex.encode(h.sublist(L.owner, L.owner + 20));
    return {
      'pluginId': _id,
      'scriptType': _scriptType,
      'tokenId': tokenId.every((x) => x == 0) ? null : hex.encode(tokenId.reversed.toList()),
      'issuer': hex.encode(h.sublist(L.issuer, L.issuer + 20)),
      'ownerPKH': owner,
      'ownerAddress': Address.fromPubkeyHash(owner, network).toBase58(),
      if (L.listed) 'price': PluginSupport.leInt(h, L.price, 8),
    };
  }

  @override
  LockingScriptBuilder? createLockBuilder(PluginOutputSpec spec) => null;
  @override
  UnlockingScriptBuilder? createUnlockBuilder(PluginUnlockSpec spec) => null;

  @override
  bool validateTransactionStructure(Transaction tx, String action) {
    final raw = hex.decode(tx.serialize());
    switch (action) {
      case 'issue':
      case 'transfer':
      case 'witness': // the reissue's paired successor, an issuance
        // an issue with a payload is paired: the primary is the payload transaction
        if (action == 'issue' && LtPayload.isPayloadTx(raw)) return true;
        try {
          final t = _b.fromRaw(raw);
          return action == 'transfer' ? !t.isIssuance : action == 'issue' || action == 'witness' ? t.isIssuance : false;
        } on ArgumentError {
          return false;
        }
      case 'list':
      case 'withdraw':
        if (!_b.L.listed) return false;
        try {
          final t = _b.fromRaw(raw);
          return !t.isIssuance && (t.price != 0) == (action == 'list');
        } on ArgumentError {
          return false;
        }
      case 'buy':
        if (!_b.L.listed) return false;
        try {
          final t = _b.fromRaw(raw);
          return t.bought && t.price == 0 && tx.inputs.length == 2 && tx.outputs.length == 2;
        } on ArgumentError {
          return false;
        }
      case 'swapBid':
      case 'swapAccept':
      case 'swapAsk':
      case 'swapTake':
        try {
          final t = _b.fromRaw(raw);
          return !t.isIssuance && tx.inputs.length == 2 && tx.outputs.length == 2;
        } on ArgumentError {
          return false;
        }
      case 'end':
      case 'reissue': // the primary of a reissue is the end
        return tx.inputs.length == 2 &&
            tx.outputs.isNotEmpty &&
            tx.outputs.every((o) => o.script.buffer.length == 25 && o.script.buffer[0] == OpCodes.OP_DUP);
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
    // an issue with a payload needs one coin when called directly (the payload transaction's change is the issuance's input 0)
    final needed = action == 'issue' && p['payload'] != null ? 1 : requiredFundingUtxoCount(action);
    if (funds.length < needed) {
      throw ArgumentError('$action needs $needed funding coins, got ${funds.length}');
    }

    switch (action) {
      case 'issue' when p['payload'] != null:
        return _issueWithPayload(request, funds[0], funds.length > 1 ? funds[1] : null, rate);

      case 'issue':
        final t = _b.issue(
          first: funds[0],
          fund: funds[1],
          issuerPkh: PluginSupport.keyHash(p['issuer']),
          owner: funds[0].pkh,
          satsPerKb: rate,
        );
        return _result(t.raw, [funds[0].sats, funds[1].sats]);

      case 'transfer':
        final (from, owner) = await _held(request);
        final t = _b.transfer(
            from: from, k: 1, ownerKey: owner, fund: funds[0], outs: [LtOut(PluginSupport.keyHash(p['to']))], satsPerKb: rate);
        PluginSupport.checkTokenSpend(t.raw, from.lock(1, _b.code), 1, PluginSupport.show(outpoint(from.txid, 1)));
        return _result(t.raw, [1, funds[0].sats]);

      case 'list' || 'withdraw' when _b.L.listed:
        final (from, owner) = await _held(request);
        final price = action == 'list' ? p['price'] : 0;
        if (price is! int || (action == 'list' && price < 1)) throw ArgumentError('list takes a price of at least 1 sat');
        final t = _b.transfer(from: from, k: 1, ownerKey: owner, fund: funds[0], outs: [LtOut(owner.pkh)], price: price, satsPerKb: rate);
        PluginSupport.checkTokenSpend(t.raw, from.lock(1, _b.code), 1, PluginSupport.show(outpoint(from.txid, 1)));
        return _result(t.raw, [1, funds[0].sats]);

      case 'buy' when _b.L.listed:
        final listingTx = hex.decode(p['listingTx'] as String);
        final maxPrice = p['maxPrice'];
        if (maxPrice is! int) throw ArgumentError('buy takes maxPrice, the most this wallet pays');
        await _checkToken(request, listingTx);
        final listing = _b.fromRaw(listingTx);
        if (listing.isIssuance) throw ArgumentError('an issuance is distributed by its issuer, not bought');
        if (listing.price == 0) throw ArgumentError('the token is not listed');
        if (listing.price > maxPrice) throw ArgumentError('the token is listed at ${listing.price}, over the maximum $maxPrice');
        if (await _holds(request, listing.h1.sublist(_b.L.owner, _b.L.owner + 20))) {
          throw ArgumentError('this wallet holds the token: withdraw the listing instead');
        }
        final (coinTx, vout) = await _coin(request, p['coin'] as String);
        final coin = coinTx.outputs[vout];
        final coinKey = await PluginSupport.ownerKey(request, _p2pkhHash(coin.script.buffer, 'the coin'));
        final fund = LtCoin(outpoint(hex.decode(coinTx.id).reversed.toList(), vout), coinKey, coin.satoshis.toInt());
        if (fund.sats - listing.price < 1) {
          throw ArgumentError('the coin (${fund.sats} sats) leaves no fee over the price ${listing.price}');
        }
        final t = _b.buy(from: listing, fund: fund, newOwner: p['newOwner'] == null ? coinKey.pkh : PluginSupport.keyHash(p['newOwner']));
        PluginSupport.checkTokenSpend(t.raw, listing.lock(1, _b.code), 1, PluginSupport.show(outpoint(listing.txid, 1)));
        return _result(t.raw, [1, fund.sats]);

      case 'end':
        if (p['irreversible'] != true) {
          throw ArgumentError('end destroys the token for good: pass irreversible: true');
        }
        final (from, owner) = await _held(request);
        final e = _b.end(from: from, k: 1, ownerKey: owner, fund: funds[0], changePkh: owner.pkh, satsPerKb: rate);
        PluginSupport.checkTokenSpend(e, from.lock(1, _b.code), 1, PluginSupport.show(outpoint(from.txid, 1)));
        return _result(e, [1, funds[0].sats]);

      case 'reissue':
        final (from, owner) = await _held(request);
        final issuer = hex.encode(from.h1.sublist(_b.L.issuer, _b.L.issuer + 20));
        if (p['issuer'] != issuer) {
          throw ArgumentError('reissue is the issuer\'s operation: params[\'issuer\'] must be the token\'s issuer $issuer; '
              'a successor no one can attest is a token ended for nothing');
        }
        final e = _b.end(from: from, k: 1, ownerKey: owner, fund: funds[0], changePkh: owner.pkh, satsPerKb: rate);
        PluginSupport.checkTokenSpend(e, from.lock(1, _b.code), 1, PluginSupport.show(outpoint(from.txid, 1)));
        final r = _b.reissue(
          ended: e,
          endKey: owner,
          fund: funds[1],
          issuerPkh: from.h1.sublist(_b.L.issuer, _b.L.issuer + 20),
          owner: owner.pkh,
          satsPerKb: rate,
        );
        final eTx = Transaction.fromHex(hex.encode(e));
        final rTx = Transaction.fromHex(hex.encode(r.raw));
        return TransactionBuilderResult.paired(
          primaryTx: eTx,
          primaryFeeSats: PluginSupport.fee(eTx, [1, funds[0].sats]),
          witnessTx: rTx,
          witnessFeeSats: PluginSupport.fee(rTx, [eTx.outputs[0].satoshis.toInt(), funds[1].sats]),
        );

      case 'swapBid':
        final tokenTx = hex.decode(p['tokenTx'] as String);
        await _checkToken(request, tokenTx);
        final sold = _b.fromRaw(tokenTx);
        if (await _holds(request, sold.h1.sublist(_b.L.owner, _b.L.owner + 20))) {
          throw ArgumentError('this wallet holds the token: a bid buys from someone else');
        }
        final (coinTx, vout) = await _coin(request, p['coin'] as String);
        final coin = coinTx.outputs[vout];
        final coinKey = await PluginSupport.ownerKey(request, _p2pkhHash(coin.script.buffer, 'the coin'));
        final terms = LtSwapTerms(
          tokenTx: tokenTx,
          payTo: PluginSupport.keyHash(p['payTo']),
          price: p['price'] as int,
          fundOut: outpoint(hex.decode(coinTx.id).reversed.toList(), vout),
          fundSats: coin.satoshis.toInt(),
          fundPub: coinKey.pub,
          newOwner: p['newOwner'] == null ? coinKey.pkh : PluginSupport.keyHash(p['newOwner']),
        );
        final half = _swap.bid(terms, coinKey);
        return _result(half.raw, [1, terms.fundSats]);

      case 'swapAccept':
        final half = hex.decode(p['half'] as String);
        final fundTx = hex.decode(p['fundTx'] as String);
        final h = Transaction.fromHex(p['half'] as String);
        final tokenTx = await PluginSupport.lookup(request, h.inputs[0].prevTxnId);
        final f = Transaction.fromHex(p['fundTx'] as String);
        if (f.id != h.inputs[1].prevTxnId || h.inputs[1].prevTxnOutputIndex >= f.outputs.length) {
          throw ArgumentError('fundTx is not the transaction of the bid\'s coin');
        }
        final read = _swap.readHalf(half,
            tokenTx: tokenTx, fundSats: f.outputs[h.inputs[1].prevTxnOutputIndex].satoshis.toInt());
        if (!read.isBid) throw ArgumentError('the half is an ask, not a bid: the buyer takes an ask (swapTake)');
        _agreed(read.terms, p['price']);
        await PluginSupport.ownerKey(request, read.terms.payTo); // the price is paid to this wallet
        final from = _b.fromRaw(tokenTx);
        final owner = await PluginSupport.ownerKey(request, from.h1.sublist(_b.L.owner, _b.L.owner + 20));
        _swap.checkBid(read.terms, read.buyerSig!, fundTx);
        final s = _swap.assemble(read.terms, seller: owner, buyer: LtGivenSignature(read.terms.fundPub, read.buyerSig!));
        _verified(read.terms, s.raw);
        return _result(s.raw, [1, read.terms.fundSats]);

      case 'swapAsk':
        final (from, owner) = await _held(request);
        if (from.isIssuance) throw ArgumentError('an issuance is distributed by its issuer, not sold');
        final terms = LtSwapTerms(
          tokenTx: from.raw,
          payTo: p['payTo'] == null ? owner.pkh : PluginSupport.keyHash(p['payTo']),
          price: p['price'] as int,
          fundOut: _outpointOf(p['fundOut'] as String),
          fundSats: p['fundSats'] as int,
          fundPub: hex.decode(p['fundPub'] as String),
          newOwner: PluginSupport.keyHash(p['newOwner']),
        );
        await PluginSupport.ownerKey(request, terms.payTo);
        final half = _swap.ask(terms, owner);
        return _result(half.raw, [1, terms.fundSats]);

      case 'swapTake':
        final half = hex.decode(p['half'] as String);
        final tokenTx = hex.decode(p['tokenTx'] as String);
        await _checkToken(request, tokenTx);
        final h = Transaction.fromHex(p['half'] as String);
        final (coinTx, vout) = await _coin(request, '${h.inputs[1].prevTxnId}:${h.inputs[1].prevTxnOutputIndex}');
        final read = _swap.readHalf(half, tokenTx: tokenTx, fundSats: coinTx.outputs[vout].satoshis.toInt());
        if (read.isBid) throw ArgumentError('the half is a bid, not an ask: the seller accepts a bid (swapAccept)');
        _agreed(read.terms, p['price']);
        final coinKey = await PluginSupport.ownerKey(request, _p2pkhHash(coinTx.outputs[vout].script.buffer, 'the coin'));
        final s = _swap.assemble(read.terms, seller: LtGivenSignature(read.sellerPub!, read.sellerSig!), buyer: coinKey);
        _verified(read.terms, s.raw);
        return _result(s.raw, [1, read.terms.fundSats]);

      default:
        throw ArgumentError('unknown action $action');
    }
  }

  /// The payload transaction from [coin], then the issuance on it (paired):
  /// its input 1 the payload transaction's output 1, its input 0 [second]
  /// when the wallet gave a second coin (libspiffy funds `issue` with two),
  /// or the payload transaction's change.
  Future<TransactionBuilderResult> _issueWithPayload(PluginTransactionRequest request, LtCoin coin, LtCoin? second, int rate) async {
    final p = request.params;
    final payload = hex.decode(p['payload'] as String);
    final (pRaw, pCoin) = LtPayload.build(coin: coin, payload: payload, fundSats: 1000, satsPerKb: rate);
    final pTx = Transaction.fromHex(hex.encode(pRaw));
    if (second == null && pTx.outputs.length != 3) throw ArgumentError('the funding coin is too small for a payload and an issuance');
    final first = second ?? LtCoin(outpoint(_h256(pRaw), 2), coin.key, pTx.outputs[2].satoshis.toInt());
    final t = _b.issue(first: first, fund: pCoin, issuerPkh: PluginSupport.keyHash(p['issuer']), owner: coin.pkh, satsPerKb: rate);
    final iTx = Transaction.fromHex(hex.encode(t.raw));
    return TransactionBuilderResult.paired(
      primaryTx: pTx,
      primaryFeeSats: PluginSupport.fee(pTx, [coin.sats]),
      witnessTx: iTx,
      witnessFeeSats: PluginSupport.fee(iTx, [first.sats, pCoin.sats]),
    );
  }

  /// The payee's check of the token a swap sells, before this wallet signs.
  Future<void> _checkToken(PluginTransactionRequest request, List<int> tokenTx) async {
    final p = request.params;
    final from = _b.fromRaw(tokenTx);
    final anchor = p['anchorTx'] as String? ?? (throw ArgumentError('a buyer checks the token first: pass anchorTx'));
    await LtReceive.check(
      b: _b,
      raw: tokenTx,
      ownerPkh: from.h1.sublist(_b.L.owner, _b.L.owner + 20),
      anchorTx: Transaction.fromHex(anchor),
      links: p['links'] == null ? const [] : LtLinks.decode(hex.decode(p['links'] as String)),
    );
  }

  /// Whether this wallet holds the key whose hash is [pkh].
  static Future<bool> _holds(PluginTransactionRequest request, List<int> pkh) async {
    try {
      await request.keyFor(hex.encode(pkh));
      return true;
    } catch (_) {
      return false;
    }
  }

  /// The wallet's coin `txid:vout` and its transaction.
  Future<(Transaction, int)> _coin(PluginTransactionRequest request, String key) async {
    final parts = key.split(':');
    if (parts.length != 2) throw ArgumentError('a coin is txid:vout, not $key');
    final tx = Transaction.fromHex(hex.encode(await PluginSupport.lookup(request, parts[0])));
    final vout = int.parse(parts[1]);
    if (vout >= tx.outputs.length) throw ArgumentError('$key has no such output');
    return (tx, vout);
  }

  static List<int> _p2pkhHash(List<int> script, String what) {
    if (script.length != 25 || script[0] != OpCodes.OP_DUP) throw ArgumentError('$what is not P2PKH');
    return script.sublist(3, 23);
  }

  static List<int> _outpointOf(String key) {
    final parts = key.split(':');
    if (parts.length != 2) throw ArgumentError('an outpoint is txid:vout, not $key');
    return outpoint(hex.decode(parts[0]).reversed.toList(), int.parse(parts[1]));
  }

  static void _agreed(LtSwapTerms t, Object? price) {
    if (price is! int) throw ArgumentError('pass the agreed price');
    if (t.price != price) throw ArgumentError('the half pays ${t.price}, not the agreed $price');
  }

  void _verified(LtSwapTerms t, List<int> raw) {
    try {
      _swap.verify(t, raw);
    } on LtRefused catch (e) {
      // libspiffy builds in passes, the first with stand-in signatures
      throw StateError('the swap does not verify: ${e.reason}');
    }
  }

  /// The txid (display order) of the issuer's identity anchor that the token
  /// transfer [transferRaw] names: the payee fetches that transaction (with
  /// its merkle proof) to run the payee check. Its record ends with the
  /// issuer's attestation, whose first 32 bytes are the anchor's txid.
  /// Throws for anything but a token transfer of this code.
  String anchorTxid(List<int> transferRaw) {
    final t = _b.fromRaw(transferRaw);
    if (t.isIssuance) throw ArgumentError('an issuance carries no attestation: a holder is paid by a transfer');
    final rec = t.rec;
    final blob = rec.sublist(rec.length - LtIssuerBlob.size);
    return hex.encode(blob.sublist(LtIssuerBlob.identityTxId, LtIssuerBlob.ed25519PubKey).reversed.toList());
  }

  /// The reissue link a holder of the successor passes on (tstokenlib's
  /// `LtSuccession`): [endRaw], the primary transaction of a `reissue`, and
  /// [redeemedRaw], the transaction whose token output it ended. The issuer's
  /// wallet holds both.
  LtLink link(List<int> endRaw, List<int> redeemedRaw) => LtLink(endRaw, _b.fromRaw(redeemedRaw).rec);

  /// The token the request spends, read back from the wallet's own copy of
  /// its transaction, and the wallet key its header names as owner.
  Future<(LtTx, LtKey)> _held(PluginTransactionRequest request) async {
    final txid = request.params['token'] as String;
    final t = _b.fromRaw(await PluginSupport.lookup(request, txid));
    if (t.isIssuance) {
      final a = request.params['attestation'] as String?;
      if (a == null) throw ArgumentError('$txid is an issuance: the transfer carries the issuer\'s attestation');
      t.x = hex.decode(a);
      // the script checks this at the first spend: refuse here, before
      // building a transaction every node refuses
      final why = LtIdentity.attestationError(t);
      if (why != null) throw ArgumentError('the attestation for $txid: $why');
    }
    return (t, await PluginSupport.ownerKey(request, t.h1.sublist(_b.L.owner, _b.L.owner + 20)));
  }

  TransactionBuilderResult _result(List<int> raw, List<int> inputSats) {
    final tx = Transaction.fromHex(hex.encode(raw));
    return TransactionBuilderResult(primaryTx: tx, primaryFeeSats: PluginSupport.fee(tx, inputSats));
  }
}

/// The Listed NFT (TSL1_LT_LNFT) as a libspiffy plugin: the covenant NFT's
/// actions, and `list`, `withdraw` and `buy` ([LtNftPlugin]).
class LtLnftPlugin extends LtNftPlugin {
  static const id = 'tsl1_lt_lnft';
  static const scriptType = 'lt_lnft';

  LtLnftPlugin({NetworkType network = NetworkType.TEST})
      : super.archetype(LtBuilder(LtLayout.lnft, LtScriptGen.lnft.code().buffer), id, scriptType, 'Listed NFT (TSL1_LT_LNFT)',
            network: network);
}
