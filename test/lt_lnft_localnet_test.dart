@Tags(['localnet'])
library;

// Research spike (WITNESS_LINEAGE_RESEARCH.md 9.14): TSL1_LT_LNFT on a real
// node. A token listed at 25,000 sats, bought by a stranger with no message
// to its owner, moved on by the buyer; then a second listing whose
// withdrawal and purchase are sent together: exactly one is mined.
//
//   LT_LOCALNET=1 dart test test/lt_lnft_localnet_test.dart
import 'dart:io';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:libtokensv/src/builder/identity_anchor_builder.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_identity.dart';
import 'package:libtokensv/src/lt/lt_layout.dart';
import 'package:libtokensv/src/lt/lt_script_gen.dart';
import 'package:libtokensv/src/lt/lt_wallet.dart';
import 'localnet.dart';

final env = Platform.environment;
SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x11580000 + i));
Address addressOf(SVPrivateKey k) => Address.fromPublicKey(k.publicKey, NetworkType.TEST);
Transaction txOf(List<int> raw) => Transaction.fromHex(hex.encode(raw));

void main() {
  test('Listed NFTs on localnet: bought by a stranger; a withdrawal racing a purchase', () async {
    final net = Localnet(viaRpc: env['LT_BROADCAST'] == 'rpc');
    await net.ready();
    final b = LtBuilder(LtLayout.lnft, LtScriptGen.lnft.code().buffer);
    final issuerKey = key(100), owner = key(1), stranger = key(2);
    final rabin = Rabin.generateKeyPair(1024);

    Future<LtCoin> coinFor(SVPrivateKey k, int sats) async {
      final tx = await net.fund(addressOf(k), BigInt.from(sats));
      final vout = tx.outputs.indexWhere((o) => hex.encode(o.script.buffer) == hex.encode(p2pkh(pkhOf(k))));
      return LtCoin(outpoint(h256(hex.decode(tx.serialize())), vout), k.lt, tx.outputs[vout].satoshis.toInt());
    }

    Future<bool> unspent(List<int> out) async =>
        await net.rpc('gettxout', [hex.encode(out.sublist(0, 32).reversed.toList()), out[32], true]) != null;

    final sigHashAll = SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value;
    final iAddr = addressOf(issuerKey);
    final seed = await net.fund(iAddr, BigInt.from(100000));
    final seedVout = seed.outputs.indexWhere((o) => hex.encode(o.script.buffer) == hex.encode(p2pkh(pkhOf(issuerKey))));
    final anchorFunding = TransactionBuilder()
        .spendFromTxnWithSigner(DefaultTransactionSigner(sigHashAll, issuerKey), seed, seedVout, TransactionInput.MAX_SEQ_NUMBER,
            P2PKHUnlockBuilder(issuerKey.publicKey))
        .spendToLockBuilder(P2PKHLockBuilder.fromAddress(iAddr), BigInt.from(546))
        .spendToLockBuilder(P2PKHLockBuilder.fromAddress(iAddr), BigInt.from(99000))
        .sendChangeToPKH(iAddr)
        .withFeePerKb(1)
        .build(false);
    await net.submit('fund anchor', anchorFunding);
    final ed = Ed25519();
    final wand = await ed.newSignatureWandFromKeyPair(await ed.newKeyPairFromSeed(List<int>.generate(32, (i) => 0xb0 + i)));
    final anchorTx = await IdentityAnchorBuilder(LtIdentity.anchorMetadata(rabin, {'name': 'Localnet Listing Issuer'}))
        .buildTransaction(anchorFunding, DefaultTransactionSigner(sigHashAll, issuerKey), issuerKey.publicKey, iAddr, wand);
    await net.submit('anchor', anchorTx);
    final issuer = LtIdentity.issuer(rabin, anchorTx);

    Future<LtTx> listing(int price) async {
      final iss = b.issue(first: await coinFor(issuerKey, 3000), fund: await coinFor(issuerKey, 3000), issuerPkh: issuer.pkh,
          owner: pkhOf(issuerKey), satsPerKb: 1);
      iss.x = issuer.attest(iss.txid);
      await net.submit('issue', txOf(iss.raw));
      final t1 = b.transfer(from: iss, k: 1, ownerKey: issuerKey.lt, fund: await coinFor(issuerKey, 3000), outs: [LtOut(pkhOf(owner))],
          satsPerKb: 1);
      await net.submit('distribute', txOf(t1.raw));
      final l = b.transfer(from: t1, k: 1, ownerKey: owner.lt, fund: await coinFor(owner, 3000), outs: [LtOut(pkhOf(owner))],
          price: price, satsPerKb: 1);
      await net.submit('list', txOf(l.raw));
      return l;
    }

    // bought by a stranger, moved on
    const price = 25000;
    final l = await listing(price);
    final buy = b.buy(from: l, fund: await coinFor(stranger, price + 50), newOwner: pkhOf(stranger));
    await net.submit('buy', txOf(buy.raw));
    final next = b.transfer(from: buy, k: 1, ownerKey: stranger.lt, fund: await coinFor(stranger, 3000), outs: [LtOut(pkhOf(key(3)))],
        satsPerKb: 1);
    await net.submit('hop after', txOf(next.raw));
    final held = await LtReceive.check(b: b, raw: next.raw, ownerPkh: pkhOf(key(3)), anchorTx: anchorTx);
    expect(held.tokenId, isNotEmpty);

    // a withdrawal and a purchase sent together
    final l2 = await listing(price);
    final withdraw = b.transfer(from: l2, k: 1, ownerKey: owner.lt, fund: await coinFor(owner, 3000), outs: [LtOut(pkhOf(owner))],
        satsPerKb: 1);
    final rival = b.buy(from: l2, fund: await coinFor(stranger, price + 50), newOwner: pkhOf(stranger));
    final results = <String>[];
    for (final (name, raw) in [('purchase', rival.raw), ('withdrawal', withdraw.raw)]) {
      try {
        await net.rpc('sendrawtransaction', [hex.encode(raw)]);
        results.add('$name accepted');
      } on StateError catch (e) {
        results.add('$name refused: ${'$e'.split('\n').first}');
      }
    }
    await net.mine();
    final bought = await unspent(outpoint(rival.txid, 1)), withdrawn = await unspent(outpoint(withdraw.txid, 1));
    expect(bought != withdrawn, isTrue, reason: 'exactly one mined');
    print('race: ${results.join('; ')}; ${bought ? 'the purchase' : 'the withdrawal'} was mined');
    print('sizes: list ${l.raw.length} B, buy ${buy.raw.length} B, hop after ${next.raw.length} B');

    // a purchase at hop 20: 18 transfers, then listed, then bought
    var t = await listing(0);
    for (var n = 0; n < 18; n++) {
      final from = n == 0 ? owner : key(40 + n - 1);
      t = b.transfer(from: t, k: 1, ownerKey: from.lt, fund: await coinFor(from, 3000), outs: [LtOut(pkhOf(key(40 + n)))],
          price: n == 17 ? price : 0, satsPerKb: 1);
      await net.submit('hop ${n + 3}', txOf(t.raw));
    }
    final buy20 = b.buy(from: t, fund: await coinFor(stranger, price + 200), newOwner: pkhOf(stranger));
    await net.submit('buy at hop 21', txOf(buy20.raw));
    final held20 = await LtReceive.check(b: b, raw: buy20.raw, ownerPkh: pkhOf(stranger), anchorTx: anchorTx);
    expect(held20.tokenId, isNotEmpty);
    print('hop 21 purchase ${buy20.raw.length} B (record ${buy20.rec.length} B)');
  }, skip: env['LT_LOCALNET'] == null ? 'set LT_LOCALNET=1 with ../localnet running' : false, timeout: const Timeout(Duration(minutes: 10)));
}
