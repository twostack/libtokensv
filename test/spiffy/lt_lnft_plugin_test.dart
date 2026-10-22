// The Listed NFT plugin (LtLnftPlugin) against stand-in wallets
// (support.dart): list, buy, withdraw, and the refusals a buyer's wallet
// makes before it signs. Every token input is run through the interpreter.
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  final plugin = LtLnftPlugin();
  late Transaction anchor;
  late LtIssuer issuer;

  setUpAll(() async {
    final rabin = Rabin.generateKeyPair(1024);
    anchor = await anchorFor(rabin);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  final issuerKey = key(91), sellerKey = key(92), buyerKey = key(93);
  final issuerTxs = <String, String>{}, sellerTxs = <String, String>{}, buyerTxs = <String, String>{};
  Wallet issuerWallet() => Wallet([issuerKey], issuerKey, issuerTxs);
  Wallet sellerWallet() => Wallet([sellerKey, key(94)], key(94), sellerTxs);
  Wallet buyerWallet() => Wallet([buyerKey, key(95)], key(95), buyerTxs);
  String attest(Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
  const price = 40000, fee = 300;
  var n = 0;

  /// A token issued, distributed to the seller, and listed by the seller at [at].
  Future<(Transaction, Transaction)> listed(int at) async {
    final iw = issuerWallet(), sw = sellerWallet();
    final iss = (await plugin.buildTransaction(iw.request({'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, coins: 2))).primaryTx;
    iw.record(iss);
    final t1 = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(sellerKey), 'attestation': attest(iss)})))
        .primaryTx;
    sw.record(t1);
    final l = (await plugin.buildTransaction(sw.request({'action': 'list', 'token': t1.id, 'price': at}))).primaryTx;
    expect(plugin.validateTransactionStructure(l, 'list'), isTrue);
    spends(l, 0, t1.outputs[1].script.buffer, 1);
    sw.record(l);
    return (t1, l);
  }

  Transaction buyersCoin(int sats) {
    List<int> le(int v, int k) => [for (var i = 0; i < k; i++) (v >> (8 * i)) & 0xff];
    final raw = [
      ...le(1, 4), 1, ...sha256([++n, 9]), ...le(0, 4), 0, ...le(0xffffffff, 4), //
      1, ...le(sats, 8), 0x19, ...p2pkhScript(buyerKey), ...le(0, 4),
    ];
    final tx = Transaction.fromHex(hex.encode(raw));
    buyerWallet().record(tx);
    return tx;
  }

  Map<String, dynamic> buy(Transaction l, Transaction coin, {int maxPrice = price}) =>
      {'action': 'buy', 'listingTx': l.serialize(), 'coin': '${coin.id}:0', 'maxPrice': maxPrice, 'anchorTx': anchor.serialize()};

  test('the plugin: its own id, script type and code; the price in the metadata', () async {
    expect(plugin.pluginId, LtLnftPlugin.id);
    expect(plugin.scriptTypes, [LtLnftPlugin.scriptType]);
    expect(plugin.supportedActions, containsAll(['list', 'withdraw', 'buy', 'swapBid']));
    expect(LtNftPlugin().supportedActions, isNot(contains('buy')));
    final (_, l) = await listed(price);
    expect(plugin.extractMetadata(l.outputs[1].script)!['price'], price);
    expect(plugin.identifyScript(l.outputs[1].script), LtLnftPlugin.scriptType);
    expect(LtNftPlugin().identifyScript(l.outputs[1].script), isNull, reason: 'another code');
  });

  test('list, then a stranger buys with no word from the seller; the buyer moves the token on', () async {
    final bw = buyerWallet();
    final (_, l) = await listed(price);
    final coin = buyersCoin(price + fee);
    final p = (await plugin.buildTransaction(bw.request(buy(l, coin), coins: 0))).primaryTx;
    expect(plugin.validateTransactionStructure(p, 'buy'), isTrue);
    spends(p, 0, l.outputs[1].script.buffer, 1);
    spends(p, 1, p2pkhScript(buyerKey), price + fee);
    expect((p.outputs[0].satoshis.toInt(), hex.encode(p.outputs[0].script.buffer)), (price, hex.encode(p2pkhScript(sellerKey))));
    final meta = plugin.extractMetadata(p.outputs[1].script)!;
    expect((meta['ownerAddress'], meta['price']), (addressOf(buyerKey), 0));
    final held = await LtNftReceive.check(plugin: plugin, beef: beefOf(p), ownerAddress: addressOf(buyerKey), anchorTx: anchor);
    expect(held.tokenId, isNotEmpty);
    bw.record(p);
    final next = (await plugin.buildTransaction(bw.request({'action': 'transfer', 'token': p.id, 'to': pkhHex(key(96))}))).primaryTx;
    spends(next, 0, p.outputs[1].script.buffer, 1);
  });

  test('withdraw: the next output is not listed, and a purchase of it is refused', () async {
    final sw = sellerWallet();
    final (_, l) = await listed(price);
    final w = (await plugin.buildTransaction(sw.request({'action': 'withdraw', 'token': l.id}))).primaryTx;
    expect(plugin.validateTransactionStructure(w, 'withdraw'), isTrue);
    spends(w, 0, l.outputs[1].script.buffer, 1);
    expect(plugin.extractMetadata(w.outputs[1].script)!['price'], 0);
    await expectLater(plugin.buildTransaction(buyerWallet().request(buy(w, buyersCoin(price + fee)), coins: 0)),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('not listed'))));
  });

  test('refused before signing: over the maximum, the seller\'s own wallet, a coin with no fee, no payee check', () async {
    final (_, l) = await listed(price);
    final coin = buyersCoin(price + fee);
    Future<void> refused(Wallet w, Map<String, dynamic> params, String why) => expectLater(
        plugin.buildTransaction(w.request(params, coins: 0)), throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains(why))));
    await refused(buyerWallet(), buy(l, coin, maxPrice: price - 1), 'over the maximum');
    final sw = sellerWallet();
    final own = buyersCoin(price + fee);
    sw.record(own);
    await refused(sw, buy(l, own), 'holds the token');
    await refused(buyerWallet(), buy(l, buyersCoin(price)), 'no fee');
    await refused(buyerWallet(), {...buy(l, coin)}..remove('anchorTx'), 'anchorTx');
  });
}
