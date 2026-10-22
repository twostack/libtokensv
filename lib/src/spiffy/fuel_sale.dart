import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import '../../libtokensv.dart';

import 'plugin_support.dart';

/// The swap actions of a fuelled sale version (TSL1_LT_FNFT_S, _VNFT_S,
/// _NOTE_S; tstokenlib's `FnftSwap`): the covenant NFT plugin's
/// `swapBid`, `swapAccept`, `swapAsk` and `swapTake`, with the same
/// parameters, halves and deferred payments ([LtNftPlugin]). The token is
/// output 0 and the price output 1; the token keeps its fuel, and the
/// buyer's coin pays the price and the fee. None takes a funding coin.
class FuelSale {
  static const actions = ['swapBid', 'swapAccept', 'swapAsk', 'swapTake'];

  final FnftBuilder b;
  final FnftSwap _swap;
  FuelSale(this.b) : _swap = FnftSwap(b);

  /// A half or a sale of this code: two inputs, the token and the price.
  bool validate(Transaction tx) {
    try {
      final t = b.fromRaw(hex.decode(tx.serialize()));
      return !t.isIssuance && t.paid && tx.inputs.length == 2 && tx.outputs.length == 2;
    } on ArgumentError {
      return false;
    }
  }

  /// Builds [action]; [held] reads the token this wallet holds
  /// (`params['token']`) and the key that owns it.
  Future<TransactionBuilderResult> build(
    PluginTransactionRequest request,
    String action,
    Future<(FnftTx, LtKey)> Function() held,
  ) async {
    final p = request.params;
    switch (action) {
      case 'swapBid':
        final tokenTx = hex.decode(p['tokenTx'] as String);
        await _checkToken(request, tokenTx);
        final sold = b.fromRaw(tokenTx);
        if (await _holds(request, sold.owner)) throw ArgumentError('this wallet holds the token: a bid buys from someone else');
        final (coinTx, vout) = await _coin(request, p['coin'] as String);
        final coin = coinTx.outputs[vout];
        final coinKey = await PluginSupport.ownerKey(request, _p2pkhHash(coin.script.buffer));
        final terms = LtSwapTerms(
          tokenTx: tokenTx,
          payTo: PluginSupport.keyHash(p['payTo']),
          price: p['price'] as int,
          fundOut: outpoint(hex.decode(coinTx.id).reversed.toList(), vout),
          fundSats: coin.satoshis.toInt(),
          fundPub: coinKey.pub,
          newOwner: p['newOwner'] == null ? coinKey.pkh : PluginSupport.keyHash(p['newOwner']),
        );
        return _result(_swap.bid(terms, coinKey).raw, [sold.value, terms.fundSats]);

      case 'swapAccept':
        final half = hex.decode(p['half'] as String);
        final h = Transaction.fromHex(p['half'] as String);
        final tokenTx = await PluginSupport.lookup(request, h.inputs[0].prevTxnId);
        final f = Transaction.fromHex(p['fundTx'] as String);
        if (f.id != h.inputs[1].prevTxnId || h.inputs[1].prevTxnOutputIndex >= f.outputs.length) {
          throw ArgumentError('fundTx is not the transaction of the bid\'s coin');
        }
        final read = _swap.readHalf(half, tokenTx: tokenTx, fundSats: f.outputs[h.inputs[1].prevTxnOutputIndex].satoshis.toInt());
        if (!read.isBid) throw ArgumentError('the half is an ask, not a bid: the buyer takes an ask (swapTake)');
        _agreed(read.terms, p['price']);
        await PluginSupport.ownerKey(request, read.terms.payTo); // the price is paid to this wallet
        final from = b.fromRaw(tokenTx);
        final owner = await PluginSupport.ownerKey(request, from.owner);
        _swap.checkBid(read.terms, read.buyerSig!, hex.decode(p['fundTx'] as String));
        final s = _swap.assemble(read.terms, seller: owner, buyer: LtGivenSignature(read.terms.fundPub, read.buyerSig!));
        _verified(read.terms, s.raw);
        return _result(s.raw, [from.value, read.terms.fundSats]);

      case 'swapAsk':
        final (from, owner) = await held();
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
        return _result(_swap.ask(terms, owner).raw, [from.value, terms.fundSats]);

      case 'swapTake':
        final half = hex.decode(p['half'] as String);
        final tokenTx = hex.decode(p['tokenTx'] as String);
        await _checkToken(request, tokenTx);
        final h = Transaction.fromHex(p['half'] as String);
        final (coinTx, vout) = await _coin(request, '${h.inputs[1].prevTxnId}:${h.inputs[1].prevTxnOutputIndex}');
        final read = _swap.readHalf(half, tokenTx: tokenTx, fundSats: coinTx.outputs[vout].satoshis.toInt());
        if (read.isBid) throw ArgumentError('the half is a bid, not an ask: the seller accepts a bid (swapAccept)');
        _agreed(read.terms, p['price']);
        final coinKey = await PluginSupport.ownerKey(request, _p2pkhHash(coinTx.outputs[vout].script.buffer));
        final s = _swap.assemble(read.terms, seller: LtGivenSignature(read.sellerPub!, read.sellerSig!), buyer: coinKey);
        _verified(read.terms, s.raw);
        return _result(s.raw, [b.fromRaw(tokenTx).value, read.terms.fundSats]);

      default:
        throw ArgumentError('unknown action $action');
    }
  }

  /// The payee's check of the token a sale sells, before this wallet signs.
  Future<void> _checkToken(PluginTransactionRequest request, List<int> tokenTx) async {
    final p = request.params;
    final anchor = p['anchorTx'] as String? ?? (throw ArgumentError('a buyer checks the token first: pass anchorTx'));
    await FnftReceive.check(
      b: b,
      raw: tokenTx,
      ownerPkh: b.fromRaw(tokenTx).owner,
      anchorTx: Transaction.fromHex(anchor),
      links: p['links'] == null ? const [] : LtLinks.decode(hex.decode(p['links'] as String)),
    );
  }

  static Future<bool> _holds(PluginTransactionRequest request, List<int> pkh) async {
    try {
      await request.keyFor(hex.encode(pkh));
      return true;
    } catch (_) {
      return false;
    }
  }

  static Future<(Transaction, int)> _coin(PluginTransactionRequest request, String key) async {
    final parts = key.split(':');
    if (parts.length != 2) throw ArgumentError('a coin is txid:vout, not $key');
    final tx = Transaction.fromHex(hex.encode(await PluginSupport.lookup(request, parts[0])));
    final vout = int.parse(parts[1]);
    if (vout >= tx.outputs.length) throw ArgumentError('$key has no such output');
    return (tx, vout);
  }

  static List<int> _p2pkhHash(List<int> script) {
    if (script.length != 25 || script[0] != OpCodes.OP_DUP) throw ArgumentError('the coin is not P2PKH');
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
      throw StateError('the sale does not verify: ${e.reason}');
    }
  }

  static TransactionBuilderResult _result(List<int> raw, List<int> inputSats) {
    final tx = Transaction.fromHex(hex.encode(raw));
    return TransactionBuilderResult(primaryTx: tx, primaryFeeSats: PluginSupport.fee(tx, inputSats));
  }
}
