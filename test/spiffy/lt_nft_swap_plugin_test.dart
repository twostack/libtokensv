// The covenant NFT plugin's swap and payload actions against stand-in
// wallets (support.dart). The seller's and the buyer's wallets keep separate
// transaction logs: each sees only what the other sends it. Every input is
// run through the script interpreter.
import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  final plugin = LtNftPlugin();
  late Transaction anchor;
  late LtIssuer issuer;

  setUpAll(() async {
    final rabin = Rabin.generateKeyPair(1024);
    anchor = await anchorFor(rabin);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  final issuerKey = key(81), sellerKey = key(82), buyerKey = key(83);
  final issuerTxs = <String, String>{}, sellerTxs = <String, String>{}, buyerTxs = <String, String>{};
  Wallet issuerWallet() => Wallet([issuerKey], issuerKey, issuerTxs);
  Wallet sellerWallet() => Wallet([sellerKey, key(84)], key(84), sellerTxs);
  Wallet buyerWallet() => Wallet([buyerKey, key(85)], key(85), buyerTxs);
  String attest(Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
  const price = 40000, fee = 500;

  /// A token issued, distributed to the seller, and in the seller's log.
  Future<Transaction> sellersToken() async {
    final iw = issuerWallet();
    final iss = (await plugin.buildTransaction(iw.request({'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, coins: 2)))
        .primaryTx;
    iw.record(iss);
    final t1 = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(sellerKey), 'attestation': attest(iss)})))
        .primaryTx;
    sellerWallet().record(t1);
    return t1;
  }

  /// A coin of exactly [sats] to the buyer, in the buyer's log.
  Transaction buyersCoin(int sats) {
    List<int> le(int v, int n) => [for (var i = 0; i < n; i++) (v >> (8 * i)) & 0xff];
    final raw = [
      ...le(1, 4), 1, ...sha256([sellerTxs.length, buyerTxs.length, 7]), ...le(0, 4), 0, ...le(0xffffffff, 4), //
      1, ...le(sats, 8), 0x19, ...p2pkhScript(buyerKey), ...le(0, 4),
    ];
    final tx = Transaction.fromHex(hex.encode(raw));
    buyerWallet().record(tx);
    return tx;
  }

  test('a bid: the buyer signs first, the seller completes; both inputs verify and the buyer moves the token on', () async {
    final sw = sellerWallet(), bw = buyerWallet();
    final t1 = await sellersToken();
    final coin = buyersCoin(price + fee);

    final half = (await plugin.buildTransaction(bw.request({
      'action': 'swapBid',
      'tokenTx': t1.serialize(),
      'payTo': pkhHex(sellerKey),
      'price': price,
      'coin': '${coin.id}:0',
      'anchorTx': anchor.serialize(),
    }, coins: 0)))
        .primaryTx;
    expect(plugin.validateTransactionStructure(half, 'swapBid'), isTrue);
    spends(half, 1, p2pkhScript(buyerKey), price + fee);
    expect(() => spends(half, 0, t1.outputs[1].script.buffer, 1), throwsA(anything), reason: 'a half is not a valid transaction');

    final swap = (await plugin.buildTransaction(
            sw.request({'action': 'swapAccept', 'half': half.serialize(), 'fundTx': coin.serialize(), 'price': price}, coins: 0)))
        .primaryTx;
    expect(plugin.validateTransactionStructure(swap, 'swapAccept'), isTrue);
    spends(swap, 0, t1.outputs[1].script.buffer, 1);
    spends(swap, 1, p2pkhScript(buyerKey), price + fee);
    expect(swap.outputs[0].satoshis.toInt(), price);
    expect(hex.encode(swap.outputs[0].script.buffer), hex.encode(p2pkhScript(sellerKey)));
    expect(plugin.extractMetadata(swap.outputs[1].script)!['ownerAddress'], addressOf(buyerKey));
    expect(swap.inputs[1].script!.toHex(), half.inputs[1].script!.toHex(), reason: 'the buyer\'s input is the bid\'s');

    // the buyer receives the swap and moves the token on
    final held = await LtNftReceive.check(plugin: plugin, beef: beefOf(swap), ownerAddress: addressOf(buyerKey), anchorTx: anchor);
    expect(held.tokenId, isNotEmpty);
    bw.record(swap);
    final next = (await plugin.buildTransaction(bw.request({'action': 'transfer', 'token': swap.id, 'to': pkhHex(key(86))})))
        .primaryTx;
    spends(next, 0, swap.outputs[1].script.buffer, 1);
  });

  test('an ask: the seller signs first, the buyer completes', () async {
    final sw = sellerWallet(), bw = buyerWallet();
    final t1 = await sellersToken();
    final coin = buyersCoin(price + fee);
    final half = (await plugin.buildTransaction(sw.request({
      'action': 'swapAsk',
      'token': t1.id,
      'price': price,
      'fundOut': '${coin.id}:0',
      'fundSats': price + fee,
      'fundPub': hex.encode(buyerKey.lt.pub),
      'newOwner': pkhHex(buyerKey),
    }, coins: 0)))
        .primaryTx;
    spends(half, 0, t1.outputs[1].script.buffer, 1);

    final swap = (await plugin.buildTransaction(bw.request({
      'action': 'swapTake',
      'half': half.serialize(),
      'tokenTx': t1.serialize(),
      'price': price,
      'anchorTx': anchor.serialize(),
    }, coins: 0)))
        .primaryTx;
    spends(swap, 0, t1.outputs[1].script.buffer, 1);
    spends(swap, 1, p2pkhScript(buyerKey), price + fee);
    expect(swap.inputs[0].script!.toHex(), half.inputs[0].script!.toHex());
  });

  test('refused: a bid at another price, to a key the seller does not hold, for a token the seller does not hold; '
      'a bid without the anchor; an ask accepted as a bid', () async {
    final sw = sellerWallet(), bw = buyerWallet();
    final t1 = await sellersToken();
    final coin = buyersCoin(price + fee);
    Future<Transaction> bid(String payTo) async => (await plugin.buildTransaction(bw.request({
          'action': 'swapBid',
          'tokenTx': t1.serialize(),
          'payTo': payTo,
          'price': price,
          'coin': '${coin.id}:0',
          'anchorTx': anchor.serialize(),
        }, coins: 0)))
            .primaryTx;
    Future<void> accept(Transaction half, {int at = price, Wallet? w}) => plugin.buildTransaction(
        (w ?? sw).request({'action': 'swapAccept', 'half': half.serialize(), 'fundTx': coin.serialize(), 'price': at}, coins: 0));

    final half = await bid(pkhHex(sellerKey));
    expect(() => accept(half, at: price + 1),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('not the agreed'))));
    final wrongPayee = await bid(pkhHex(key(99)));
    expect(() => accept(wrongPayee), throwsA(isA<StateError>().having((e) => e.message, 'message', contains('holds no key'))));
    final stranger = Wallet([key(98)], key(98), <String, String>{});
    expect(() => accept(half, w: stranger),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('does not hold transaction'))));
    expect(
        () => plugin.buildTransaction(bw.request({
              'action': 'swapBid',
              'tokenTx': t1.serialize(),
              'payTo': pkhHex(sellerKey),
              'price': price,
              'coin': '${coin.id}:0',
            }, coins: 0)),
        throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('anchorTx'))));
    final ask = (await plugin.buildTransaction(sw.request({
      'action': 'swapAsk',
      'token': t1.id,
      'price': price,
      'fundOut': '${coin.id}:0',
      'fundSats': price + fee,
      'fundPub': hex.encode(buyerKey.lt.pub),
      'newOwner': pkhHex(buyerKey),
    }, coins: 0)))
        .primaryTx;
    expect(() => accept(ask), throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('an ask'))));
  });

  test('issue with a payload: the payload transaction, then the issuance on it; from two coins as the wallet funds it, or from one', () async {
    final iw = issuerWallet();
    final content = utf8.encode('{"name":"Plugin Payload Token"}');
    // one coin: the issuance's input 0 is the payload transaction's change
    final r1 = await plugin.buildTransaction(iw.request({'action': 'issue', 'issuer': hex.encode(issuer.pkh), 'payload': hex.encode(content)}, coins: 1));
    final p1 = r1.primaryTx, iss1 = r1.witnessTx!;
    spends(iss1, 0, p1.outputs[2].script.buffer, p1.outputs[2].satoshis.toInt());
    spends(iss1, 1, p1.outputs[1].script.buffer, p1.outputs[1].satoshis.toInt());
    // two coins, as libspiffy funds an issue: the second is the issuance's input 0, both spent
    final r = await plugin.buildTransaction(
        iw.request({'action': 'issue', 'issuer': hex.encode(issuer.pkh), 'payload': hex.encode(content)}, coins: 2));
    final p = r.primaryTx, iss = r.witnessTx!;
    expect(plugin.validateTransactionStructure(p, 'issue'), isTrue, reason: 'the primary is validated as an issue by the wallet');
    expect(plugin.validateTransactionStructure(iss, 'witness'), isTrue);
    spends(p, 0, p2pkhScript(issuerKey), 100000);
    expect(iss.inputs[0].prevTxnId, isNot(p.id));
    spends(iss, 0, p2pkhScript(issuerKey), 100000);
    spends(iss, 1, p.outputs[1].script.buffer, p.outputs[1].satoshis.toInt());
    expect(utf8.decode(LtPayload.of(hex.decode(iss.serialize()), hex.decode(p.serialize()))), utf8.decode(content));
    iw.record(p);
    iw.record(iss);
    final t1 = (await plugin.buildTransaction(
            iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(key(87)), 'attestation': attest(iss)})))
        .primaryTx;
    final held = await LtNftReceive.check(
        plugin: plugin, beef: beefOf(t1), ownerAddress: addressOf(key(87)), anchorTx: anchor, payloadTx: hex.decode(p.serialize()));
    expect(utf8.decode(held.payload!), utf8.decode(content));
  });
}
