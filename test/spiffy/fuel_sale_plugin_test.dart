// The sale versions of the fuelled family as plugins (LtFnftSalePlugin,
// LtVnftSalePlugin, LtNoteSalePlugin) against stand-in wallets
// (support.dart): a bid the seller accepts, an ask the buyer takes, and the
// refusals. The token is output 0 and keeps its fuel; the price is output
// 1. Every input is run through the script interpreter.
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'support.dart';

void main() {
  late Transaction anchor;
  late LtIssuer issuer;
  setUpAll(() async {
    final rabin = Rabin.generateKeyPair(1024);
    anchor = await anchorFor(rabin);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  final issuerKey = key(101), sellerKey = key(102), buyerKey = key(103);
  String attest(Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
  const price = 40000, fee = 300;
  var n = 0;

  final cases = <(TransactionBuilderPlugin, Map<String, dynamic> Function())>[
    (LtFnftSalePlugin(), () => {}),
    (LtVnftSalePlugin(), () => {'maxHops': 5, 'expiry': 1000, 'feeCap': 500}),
    (LtNoteSalePlugin(), () => {'feeCap': 500, 'exit': 0, 'maturity': 1000, 'mature': NoteTerms.everything, 'callAt': NoteTerms.never, 'call': 0}),
  ];

  for (final (plugin, terms) in cases) {
    group(plugin.pluginId, () {
      final issuerTxs = <String, String>{}, sellerTxs = <String, String>{}, buyerTxs = <String, String>{};
      Wallet issuerWallet() => Wallet([issuerKey], issuerKey, issuerTxs);
      Wallet sellerWallet() => Wallet([sellerKey, key(104)], key(104), sellerTxs);
      Wallet buyerWallet() => Wallet([buyerKey, key(105)], key(105), buyerTxs);

      Future<Transaction> sellersToken() async {
        final iw = issuerWallet();
        final iss = (await plugin.buildTransaction(iw.request({'action': 'issue', 'issuer': hex.encode(issuer.pkh), ...terms()}))).primaryTx;
        iw.record(iss);
        final t1 = (await plugin.buildTransaction(
                iw.request({'action': 'transfer', 'token': iss.id, 'to': pkhHex(sellerKey), 'attestation': attest(iss)}, coins: 0)))
            .primaryTx;
        sellerWallet().record(t1);
        return t1;
      }

      Transaction buyersCoin(int sats) {
        List<int> le(int v, int k) => [for (var i = 0; i < k; i++) (v >> (8 * i)) & 0xff];
        final raw = [
          ...le(1, 4), 1, ...sha256([++n, 11, plugin.pluginId.length]), ...le(0, 4), 0, ...le(0xffffffff, 4), //
          1, ...le(sats, 8), 0x19, ...p2pkhScript(buyerKey), ...le(0, 4),
        ];
        final tx = Transaction.fromHex(hex.encode(raw));
        buyerWallet().record(tx);
        return tx;
      }

      void sold(Transaction t1, Transaction s) {
        spends(s, 0, t1.outputs[0].script.buffer, t1.outputs[0].satoshis.toInt());
        spends(s, 1, p2pkhScript(buyerKey), price + fee);
        expect((s.outputs[1].satoshis.toInt(), hex.encode(s.outputs[1].script.buffer)), (price, hex.encode(p2pkhScript(sellerKey))));
        expect(s.outputs[0].satoshis, t1.outputs[0].satoshis, reason: 'the token keeps its fuel');
        expect(plugin.extractMetadata(s.outputs[0].script)!['ownerAddress'], addressOf(buyerKey));
      }

      test('a bid the seller accepts; the buyer moves the token on', () async {
        final t1 = await sellersToken();
        final coin = buyersCoin(price + fee);
        final half = (await plugin.buildTransaction(buyerWallet().request({
          'action': 'swapBid', 'tokenTx': t1.serialize(), 'payTo': pkhHex(sellerKey), 'price': price, //
          'coin': '${coin.id}:0', 'anchorTx': anchor.serialize(),
        }, coins: 0)))
            .primaryTx;
        expect(plugin.validateTransactionStructure(half, 'swapBid'), isTrue);
        final s = (await plugin.buildTransaction(sellerWallet()
                .request({'action': 'swapAccept', 'half': half.serialize(), 'fundTx': coin.serialize(), 'price': price}, coins: 0)))
            .primaryTx;
        expect(plugin.validateTransactionStructure(s, 'swapAccept'), isTrue);
        sold(t1, s);
        final bw = buyerWallet()..record(s);
        final next = (await plugin.buildTransaction(bw.request({'action': 'transfer', 'token': s.id, 'to': pkhHex(key(106))}, coins: 0)))
            .primaryTx;
        spends(next, 0, s.outputs[0].script.buffer, s.outputs[0].satoshis.toInt());
      });

      test('an ask the buyer takes', () async {
        final t1 = await sellersToken();
        final coin = buyersCoin(price + fee);
        final half = (await plugin.buildTransaction(sellerWallet().request({
          'action': 'swapAsk', 'token': t1.id, 'price': price, 'fundOut': '${coin.id}:0', 'fundSats': price + fee, //
          'fundPub': hex.encode(buyerKey.lt.pub), 'newOwner': pkhHex(buyerKey),
        }, coins: 0)))
            .primaryTx;
        final s = (await plugin.buildTransaction(buyerWallet().request(
                {'action': 'swapTake', 'half': half.serialize(), 'tokenTx': t1.serialize(), 'price': price, 'anchorTx': anchor.serialize()},
                coins: 0)))
            .primaryTx;
        sold(t1, s);
      });

      test('refused: a bid at another price than agreed; a bid on the wallet\'s own token', () async {
        final t1 = await sellersToken();
        final coin = buyersCoin(price + fee);
        final half = (await plugin.buildTransaction(buyerWallet().request({
          'action': 'swapBid', 'tokenTx': t1.serialize(), 'payTo': pkhHex(sellerKey), 'price': price, //
          'coin': '${coin.id}:0', 'anchorTx': anchor.serialize(),
        }, coins: 0)))
            .primaryTx;
        await expectLater(
            plugin.buildTransaction(sellerWallet()
                .request({'action': 'swapAccept', 'half': half.serialize(), 'fundTx': coin.serialize(), 'price': price + 1}, coins: 0)),
            throwsA(isA<ArgumentError>()));
        final sw = sellerWallet();
        final own = buyersCoin(price + fee);
        sw.record(own);
        await expectLater(
            plugin.buildTransaction(Wallet([sellerKey, buyerKey], key(104), {...sellerTxs, ...buyerTxs}).request({
              'action': 'swapBid', 'tokenTx': t1.serialize(), 'payTo': pkhHex(sellerKey), 'price': price, //
              'coin': '${own.id}:0', 'anchorTx': anchor.serialize(),
            }, coins: 0)),
            throwsA(isA<ArgumentError>().having((e) => '${e.message}', 'message', contains('holds the token'))));
      });
    });
  }

  test('the base archetypes have no swap: their tokens cannot be sold this way', () {
    for (final p in [LtFnftPlugin(), LtVnftPlugin(), LtNotePlugin()]) {
      expect(p.supportedActions, isNot(contains('swapBid')), reason: p.pluginId);
    }
    expect(LtVnftSalePlugin().supportedActions, containsAll(['redeem', 'forceRedeem', 'swapBid', 'swapTake']));
    expect(LtNoteSalePlugin().supportedActions, containsAll(['exit', 'call', 'swapAccept', 'swapAsk']));
  });
}
