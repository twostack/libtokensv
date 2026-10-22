// The swap between two real libspiffy wallets (spiffy_harness.dart), each in
// its own actor system with its own keys. The seller holds a covenant NFT;
// the buyer holds a coin of exactly the price plus the fee, bids (the half
// holds the coin and is never broadcast), the seller accepts and settles the
// swap, and the buyer completes its half with the swap
// (CompleteDeferredPaymentCommand) and moves the token on. A second bid is
// withdrawn by reclaiming it. Every input is run through the interpreter.
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart' as dartsv;
import 'package:libspiffy/coordinator.dart' as coord;
import 'package:libspiffy/libspiffy.dart';
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

import 'spiffy_harness.dart';
import 'support.dart' show anchorFor;

void main() {
  final plugin = LtNftPlugin();
  late SpiffyHarness seller, buyer;
  late LtIssuer issuer;
  late dartsv.Transaction anchor;
  final buyerXpriv = dartsv.HDPrivateKey.fromSeed(hex.encode(List<int>.generate(32, (i) => 0x40 + i)), dartsv.NetworkType.TEST).xprivkey;

  setUpAll(() async {
    await SpiffyHarness.initIsar();
    final rabin = Rabin.generateKeyPair(1024);
    anchor = await anchorFor(rabin);
    issuer = LtIdentity.issuer(rabin, anchor);
  });
  setUp(() async {
    PluginRegistry().register(plugin);
    seller = SpiffyHarness(wallet: 'seller');
    buyer = SpiffyHarness(wallet: 'buyer');
    await seller.start();
    await buyer.start();
  });
  tearDown(() async {
    PluginRegistry().unregister(LtNftPlugin.id);
    await seller.stop();
    await buyer.stop();
  });

  void spends(dartsv.Transaction tx, int i, List<int> lock, int sats) => dartsv.Interpreter().correctlySpends(tx.inputs[i].script!,
      dartsv.SVScript.fromByteArray(lock), tx, i, {dartsv.VerifyFlag.SIGHASH_FORKID, dartsv.VerifyFlag.UTXO_AFTER_GENESIS},
      dartsv.Coin.ofSat(BigInt.from(sats)));

  test('bid, accept, complete; a second bid withdrawn', () async {
    await seller.createWallet(coins: 4);
    await buyer.createWallet(coins: 4, xpriv: buyerXpriv);
    String attest(dartsv.Transaction t) => hex.encode(issuer.attest(hex.decode(t.id).reversed.toList()));
    Future<BEEFPaymentResponse> act(SpiffyHarness h, Map<String, dynamic> params, {int amount = 1, bool settle = true}) async {
      final r = await h.pay(LtNftPlugin.id, LtNftPlugin.scriptType, params, amount: amount, settleIt: settle);
      expect(r.success, isTrue, reason: r.error);
      return r;
    }

    // the seller issues to itself and distributes to its second address
    final iss = seller.subject((await act(seller, {'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, amount: 70000)).beefBytes);
    await seller.spendable(iss.id, 1);
    final second = SpiffyHarness.pkhOfAddress(seller.second);
    final t1 = seller.subject(
        (await act(seller, {'action': 'transfer', 'token': iss.id, 'to': second, 'attestation': attest(iss)})).beefBytes);
    await seller.spendable(t1.id, 1);

    // the buyer holds a coin of exactly the price and the fee
    const price = 30000, fee = 400;
    final coinTx = await buyer.receiveCoin(buyer.second, price + fee);
    const vout = 0;

    // the bid: recorded, its coin held, never broadcast
    Future<dartsv.Transaction> bid() async => buyer.subject((await act(buyer, {
          'action': 'swapBid',
          'tokenTx': t1.serialize(),
          'payTo': SpiffyHarness.pkhOfAddress(seller.root),
          'price': price,
          'coin': '${coinTx.id}:$vout',
          'anchorTx': anchor.serialize(),
        }, amount: 0, settle: false))
            .beefBytes);
    final half = await bid();
    expect(await buyer.available(coinTx.id, vout), isFalse, reason: 'the bid holds the coin');
    expect((await buyer.spiffy.walletStorage.getDeferredPayment(buyer.wallet, half.id))?.state, DeferredPaymentState.outstanding);

    // the seller accepts and settles the swap
    final sr = await act(seller, {'action': 'swapAccept', 'half': half.serialize(), 'fundTx': coinTx.serialize(), 'price': price},
        amount: 0);
    final swap = seller.subject(sr.beefBytes);
    spends(swap, 0, t1.outputs[1].script.buffer, 1);
    spends(swap, 1, coinTx.outputs[vout].script.buffer, price + fee);
    expect(sr.spentUtxoKeys, ['${t1.id}:1'], reason: 'the seller\'s wallet spends only its token');
    expect(await seller.available(t1.id, 1), isFalse);
    await seller.eventually(() => seller.available(swap.id, 0), 'the price paid to the seller');

    // the buyer completes its half with the swap the seller sent
    final completed = await buyer.command<coord.DeferredPaymentCompletedEvent>(
        coord.CompleteDeferredPaymentCommand(walletId: buyer.wallet, txid: half.id, rawHex: swap.serialize()), (e) => e.txid == half.id);
    expect(completed.success, isTrue, reason: completed.error);
    expect(completed.completedTxid, swap.id);
    expect((await buyer.spiffy.walletStorage.getDeferredPayment(buyer.wallet, half.id))?.state, DeferredPaymentState.completed);
    await buyer.settle(sr.beefBytes, swap.id); // the BEEF the seller sent with the swap
    await buyer.spendable(swap.id, 1);
    expect((await buyer.spiffy.walletStorage.getUTXO(buyer.wallet, half.id, 1))?.status, UTXOStatus.voided,
        reason: 'the half\'s own outputs are void: it is never mined');

    // the buyer moves the token on
    final next = buyer.subject((await act(buyer, {'action': 'transfer', 'token': swap.id, 'to': SpiffyHarness.pkhOfAddress(buyer.root)}))
        .beefBytes);
    spends(next, 0, swap.outputs[1].script.buffer, 1);

    // a bid on a token this wallet holds is refused
    final own = await buyer.pay(LtNftPlugin.id, LtNftPlugin.scriptType, {
      'action': 'swapBid',
      'tokenTx': next.serialize(),
      'payTo': SpiffyHarness.pkhOfAddress(seller.root),
      'price': price,
      'coin': '${coinTx.id}:$vout',
      'anchorTx': anchor.serialize(),
    }, amount: 0, settleIt: false);
    expect(own.success, isFalse);
    expect(own.error, contains('holds the token'));

    // a second token of the seller's, and a bid on it withdrawn: the reclaim
    // spends the held coin back
    dartsv.Transaction lastOf(Uint8List beef) => dartsv.Transaction.fromHex(hex.encode(BEEF.parse(beef).txs.last));
    final iss2 = lastOf((await act(seller, {'action': 'issue', 'issuer': hex.encode(issuer.pkh)}, amount: 70000)).beefBytes);
    await seller.spendable(iss2.id, 1);
    final u1 = lastOf((await act(seller, {'action': 'transfer', 'token': iss2.id, 'to': second, 'attestation': attest(iss2)})).beefBytes);
    final coin2 = await buyer.receiveCoin(buyer.second, price + fee + 1);
    const v2 = 0;
    final half2 = buyer.subject((await act(buyer, {
      'action': 'swapBid',
      'tokenTx': u1.serialize(),
      'payTo': SpiffyHarness.pkhOfAddress(seller.root),
      'price': price,
      'coin': '${coin2.id}:$v2',
      'anchorTx': anchor.serialize(),
    }, amount: 0, settle: false))
        .beefBytes);
    final reclaimed = await buyer.command<coord.DeferredPaymentReclaimedEvent>(
        coord.ReclaimDeferredPaymentCommand(walletId: buyer.wallet, txid: half2.id), (e) => e.txid == half2.id);
    expect(reclaimed.success, isTrue, reason: reclaimed.error);
    expect(reclaimed.reclaimedUtxoKeys, ['${coin2.id}:$v2']);
    print('swap ${swap.serialize().length ~/ 2} B; half ${half.serialize().length ~/ 2} B; withdrawn by ${reclaimed.reclaimTxid}');
  }, timeout: const Timeout(Duration(minutes: 10)));
}
