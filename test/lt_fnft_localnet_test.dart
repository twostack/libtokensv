@Tags(['localnet'])
library;

// The Fuelled NFT (TSL1_LT_FNFT) on a real node: issued with fuel to the
// issuer, distributed, transferred hop by hop paying its own fees, topped
// up, redeemed, ended (its value returned on output 0), reissued fuelled by
// that value, distributed again; a token claiming more than its inputs and a
// second issuance on the end's output 0 are refused; the payee follows the
// link back to the first token; the last holder burns it.
//
//   LT_LOCALNET=1 dart test test/lt_fnft_localnet_test.dart
//
// LT_HOPS (default 20). Needs ../localnet running.
import 'dart:io';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:libtokensv/src/builder/identity_anchor_builder.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_fnft_builder.dart';
import 'package:libtokensv/src/lt/lt_fnft_wallet.dart';
import 'package:libtokensv/src/lt/lt_identity.dart';
import 'package:libtokensv/src/lt/lt_wallet.dart';
import 'localnet.dart';

final env = Platform.environment;
SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x1f8a0000 + i));
Address addressOf(SVPrivateKey k) => Address.fromPublicKey(k.publicKey, NetworkType.TEST);
Transaction txOf(List<int> raw) => Transaction.fromHex(hex.encode(raw));

void main() {
  test('a Fuelled NFT on localnet', () async {
    final net = Localnet(viaRpc: env['LT_BROADCAST'] == 'rpc');
    await net.ready();
    final hops = int.parse(env['LT_HOPS'] ?? '20');
    const rate = 1; // sats per kB
    final b = FnftBuilder.standard();
    final issuerKey = key(100);
    final rabin = Rabin.generateKeyPair(1024);
    print('code ${b.code.length} B, height ${await net.height()}');

    Future<LtCoin> coinFor(SVPrivateKey k, int sats) async {
      final tx = await net.fund(addressOf(k), BigInt.from(sats));
      final vout = tx.outputs.indexWhere((o) => hex.encode(o.script.buffer) == hex.encode(p2pkh(pkhOf(k))));
      return LtCoin(outpoint(h256(hex.decode(tx.serialize())), vout), k.lt, tx.outputs[vout].satoshis.toInt());
    }

    final sizes = <String>[];
    Future<void> submit(String name, List<int> raw) async {
      await net.submit(name, txOf(raw));
      sizes.add('$name ${raw.length}');
    }

    // the issuer's identity anchor, mined
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
    final wand = await ed.newSignatureWandFromKeyPair(await ed.newKeyPairFromSeed(List<int>.generate(32, (i) => 0x50 + i)));
    final anchorTx = await IdentityAnchorBuilder(LtIdentity.anchorMetadata(rabin, {'name': 'Localnet FNFT Issuer'}))
        .buildTransaction(anchorFunding, DefaultTransactionSigner(sigHashAll, issuerKey), issuerKey.publicKey, iAddr, wand);
    await net.submit('anchor', anchorTx);
    final issuer = LtIdentity.issuer(rabin, anchorTx);

    // issue to the issuer with 3,000 sats of fuel, then distribute
    var t = b.issue(first: await coinFor(issuerKey, 3000), issuerPkh: issuer.pkh, owner: pkhOf(issuerKey), satsPerKb: rate);
    t.x = issuer.attest(t.txid);
    await submit('issue', t.raw);
    final first = t;
    final chain = <FnftTx>[t];
    // hop n is owned by key(n) (hop 0 by the issuer)
    for (var n = 1; n <= hops; n++) {
      final topUp = n == hops ~/ 2 ? await coinFor(key(9000), 20000) : null;
      t = b.transfer(from: t, ownerKey: (n == 1 ? issuerKey : key(n - 1)).lt, to: pkhOf(key(n)), fund: topUp, satsPerKb: rate);
      await submit(topUp == null ? 'hop $n' : 'hop $n+', t.raw);
      chain.add(t);
    }
    print('fuel: issue ${first.value}, hop 1 ${chain[1].value}, hop ${hops ~/ 2 - 1} ${chain[hops ~/ 2 - 1].value}, '
        'hop ${hops ~/ 2} ${chain[hops ~/ 2].value} (topped up), hop $hops ${t.value}');
    final sw = Stopwatch()..start();
    final held = await FnftReceive.check(b: b, raw: t.raw, ownerPkh: pkhOf(key(hops)), anchorTx: anchorTx);
    print('payee check of hop $hops (${t.raw.length} B), script run included: ${sw.elapsedMilliseconds} ms');
    expect(held.tokenId, first.txid);

    // a transfer claiming 1,000 sats more than its input: refused by consensus
    final inflate = b.transfer(from: t, ownerKey: key(hops).lt, to: pkhOf(key(99)), fee: -1000);
    try {
      await net.rpc('sendrawtransaction', [hex.encode(inflate.raw)]);
      fail('the node accepted a token worth more than its inputs');
    } on StateError catch (e) {
      expect('$e', contains('in-belowout'));
      print('inflated value: $e');
    }

    // redemption to the issuer; the end returns the fuel; the reissue is fuelled by it
    final back = b.transfer(from: t, ownerKey: key(hops).lt, to: pkhOf(issuerKey), satsPerKb: rate);
    await submit('redeem', back.raw);
    final ended = b.end(from: back, ownerKey: issuerKey.lt, payTo: pkhOf(issuerKey), satsPerKb: rate);
    await submit('end', ended);
    var r = b.reissue(ended: ended, endKey: issuerKey.lt, issuerPkh: issuer.pkh, satsPerKb: rate);
    r.x = issuer.attest(r.txid);
    await submit('reissue', r.raw);
    print('end returned ${txOf(ended).outputs[0].satoshis} sats; the successor holds ${r.value}');
    expect(await FnftSuccession.verify(b: b, r: r, predecessor: first.txid, ended: ended, recG: back.rec, anchorTx: anchorTx),
        isNull);
    final second = b.reissue(ended: ended, endKey: issuerKey.lt, issuerPkh: issuer.pkh, fee: 5);
    try {
      await net.rpc('sendrawtransaction', [hex.encode(second.raw)]);
      fail('the node accepted a second issuance on the end\'s output 0');
    } on StateError catch (e) {
      expect('$e', contains('Missing inputs'));
      print('second issuance on the end\'s output 0: $e');
    }

    // distribute the successor; the payee follows the link to the first token
    r = b.transfer(from: r, ownerKey: issuerKey.lt, to: pkhOf(key(1)), satsPerKb: rate);
    await submit('hop 1*', r.raw);
    final link = LtLink(ended, back.rec);
    final again = await FnftReceive.check(b: b, raw: r.raw, ownerPkh: pkhOf(key(1)), anchorTx: anchorTx, links: [link]);
    expect(again.originId, first.txid);
    print('links ${LtLinks.encode([link]).length} B');

    // the holder burns it: no funding input
    final burn = b.end(from: r, ownerKey: key(1).lt, payTo: pkhOf(key(1)), satsPerKb: rate);
    await submit('burn', burn);
    print('burn returned ${txOf(burn).outputs.single.satoshis} sats');

    print('\nsizes: ${sizes.join(', ')}');
    print('growth ${((chain[hops ~/ 2 - 1].raw.length - chain[1].raw.length) / (hops ~/ 2 - 2)).toStringAsFixed(1)} B/hop');
  }, skip: env['LT_LOCALNET'] == null ? 'set LT_LOCALNET=1 with ../localnet running' : false, timeout: const Timeout(Duration(minutes: 20)));
}
