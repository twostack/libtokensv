// The adopted sale shapes between two real libspiffy wallets
// (spiffy_harness.dart):
//  * a Voucher NFT's sale version (LtVnftSalePlugin): the buyer bids (the
//    half holds its coin), the seller accepts and settles, the buyer
//    completes its half and redeems the voucher;
//  * a Listed NFT (LtLnftPlugin): the seller lists, the buyer buys with no
//    word from the seller and moves the token on.
// Every token input is run through the interpreter.
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart' as dartsv;
import 'package:libspiffy/coordinator.dart' as coord;
import 'package:libspiffy/libspiffy.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'spiffy_harness.dart';
import 'support.dart' show anchorFor;

void main() {
  final voucher = LtVnftSalePlugin(), listed = LtLnftPlugin();
  late SpiffyHarness seller, buyer;
  late LtIssuer issuer;
  late dartsv.Transaction anchor;
  final buyerXpriv = dartsv.HDPrivateKey.fromSeed(hex.encode(List<int>.generate(32, (i) => 0x50 + i)), dartsv.NetworkType.TEST).xprivkey;

  setUpAll(() async {
    await SpiffyHarness.initIsar();
    final rabin = Rabin.generateKeyPair(1024);
    anchor = await anchorFor(rabin);
    issuer = LtIdentity.issuer(rabin, anchor);
  });
  setUp(() async {
    PluginRegistry().register(voucher);
    PluginRegistry().register(listed);
    seller = SpiffyHarness(wallet: 'seller');
    buyer = SpiffyHarness(wallet: 'buyer');
    await seller.start();
    await buyer.start();
  });
  tearDown(() async {
    PluginRegistry().unregister(LtVnftSalePlugin.id);
    PluginRegistry().unregister(LtLnftPlugin.id);
    await seller.stop();
    await buyer.stop();
  });

  void spends(dartsv.Transaction tx, int i, List<int> lock, int sats) => dartsv.Interpreter().correctlySpends(tx.inputs[i].script!,
      dartsv.SVScript.fromByteArray(lock), tx, i, {dartsv.VerifyFlag.SIGHASH_FORKID, dartsv.VerifyFlag.UTXO_AFTER_GENESIS},
      dartsv.Coin.ofSat(BigInt.from(sats)));
  String attest(dartsv.Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
  Future<BEEFPaymentResponse> act(SpiffyHarness h, TransactionBuilderPlugin p, Map<String, dynamic> params,
      {int amount = 1, bool settle = true}) async {
    final r = await h.pay(p.pluginId, p.scriptTypes.single, params, amount: amount, settleIt: settle);
    expect(r.success, isTrue, reason: r.error);
    return r;
  }

  test('a Voucher NFT sold: bid, accept, complete; the buyer redeems it', () async {
    await seller.createWallet(coins: 4);
    await buyer.createWallet(coins: 4, xpriv: buyerXpriv);
    final iss = seller.subject((await act(seller, voucher,
            {'action': 'issue', 'issuer': hex.encode(issuer.pkh), 'maxHops': 5, 'expiry': 1000, 'feeCap': 500}, amount: 20000))
        .beefBytes);
    await seller.spendable(iss.id, 0);
    final second = SpiffyHarness.pkhOfAddress(seller.second);
    final t1 = seller.subject(
        (await act(seller, voucher, {'action': 'transfer', 'token': iss.id, 'to': second, 'attestation': attest(iss)}, amount: 0))
            .beefBytes);
    await seller.spendable(t1.id, 0);

    const price = 30000, fee = 400;
    final coinTx = await buyer.receiveCoin(buyer.second, price + fee);
    final half = buyer.subject((await act(buyer, voucher, {
      'action': 'swapBid', 'tokenTx': t1.serialize(), 'payTo': SpiffyHarness.pkhOfAddress(seller.root), 'price': price, //
      'coin': '${coinTx.id}:0', 'anchorTx': anchor.serialize(),
    }, amount: 0, settle: false))
        .beefBytes);
    expect(await buyer.available(coinTx.id, 0), isFalse, reason: 'the bid holds the coin');

    final sr = await act(seller, voucher, {'action': 'swapAccept', 'half': half.serialize(), 'fundTx': coinTx.serialize(), 'price': price},
        amount: 0);
    final sale = seller.subject(sr.beefBytes);
    spends(sale, 0, t1.outputs[0].script.buffer, t1.outputs[0].satoshis.toInt());
    spends(sale, 1, coinTx.outputs[0].script.buffer, price + fee);
    expect(sale.outputs[0].satoshis, t1.outputs[0].satoshis, reason: 'the voucher keeps its fuel');
    expect(sr.spentUtxoKeys, ['${t1.id}:0'], reason: 'the seller\'s wallet spends only its token');
    await seller.eventually(() => seller.available(sale.id, 1), 'the price paid to the seller');

    final completed = await buyer.command<coord.DeferredPaymentCompletedEvent>(
        coord.CompleteDeferredPaymentCommand(walletId: buyer.wallet, txid: half.id, rawHex: sale.serialize()), (e) => e.txid == half.id);
    expect(completed.success, isTrue, reason: completed.error);
    await buyer.settle(sr.beefBytes, sale.id);
    await buyer.spendable(sale.id, 0);

    final red = buyer.subject((await act(buyer, voucher, {'action': 'redeem', 'token': sale.id}, amount: 0)).beefBytes);
    spends(red, 0, sale.outputs[0].script.buffer, sale.outputs[0].satoshis.toInt());
    print('voucher sale ${sale.serialize().length ~/ 2} B; redemption ${red.serialize().length ~/ 2} B');
  }, timeout: const Timeout(Duration(minutes: 10)));

  test('a Listed NFT: the seller lists, the buyer buys with no word from the seller, and moves it on', () async {
    await seller.createWallet(coins: 4);
    await buyer.createWallet(coins: 4, xpriv: buyerXpriv);
    final iss = seller.subject((await act(seller, listed, {'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, amount: 70000)).beefBytes);
    await seller.spendable(iss.id, 1);
    final second = SpiffyHarness.pkhOfAddress(seller.second);
    final t1 = seller
        .subject((await act(seller, listed, {'action': 'transfer', 'token': iss.id, 'to': second, 'attestation': attest(iss)})).beefBytes);
    await seller.spendable(t1.id, 1);
    const price = 25000, fee = 400;
    final l = seller.subject((await act(seller, listed, {'action': 'list', 'token': t1.id, 'price': price})).beefBytes);
    spends(l, 0, t1.outputs[1].script.buffer, 1);
    await seller.spendable(l.id, 1);

    final coinTx = await buyer.receiveCoin(buyer.second, price + fee);
    final br = await act(buyer, listed, {
      'action': 'buy', 'listingTx': l.serialize(), 'coin': '${coinTx.id}:0', 'maxPrice': price, 'anchorTx': anchor.serialize(),
    }, amount: 0);
    final p = buyer.subject(br.beefBytes);
    spends(p, 0, l.outputs[1].script.buffer, 1);
    spends(p, 1, coinTx.outputs[0].script.buffer, price + fee);
    expect(br.spentUtxoKeys, ['${coinTx.id}:0'], reason: 'the buyer\'s wallet spends only its coin');
    expect(p.outputs[0].satoshis.toInt(), price);
    await buyer.spendable(p.id, 1);
    final next = buyer.subject(
        (await act(buyer, listed, {'action': 'transfer', 'token': p.id, 'to': SpiffyHarness.pkhOfAddress(buyer.root)})).beefBytes);
    spends(next, 0, p.outputs[1].script.buffer, 1);
    print('listing ${l.serialize().length ~/ 2} B; purchase ${p.serialize().length ~/ 2} B');
  }, timeout: const Timeout(Duration(minutes: 10)));
}
