@Tags(['localnet'])
library;

// The Voucher NFT (TSL1_LT_VNFT) on a real node. Three vouchers under one
// issuer, each with maxHops 3:
//  A: three transfers, a fourth refused, the holder redeems to the issuer,
//     the issuer reissues it with new terms, the payee follows the link;
//  B: the issuer's force-redemption sent before the expiry is not mined
//     while the expiry is ahead, and the holder's own redemption replaces it;
//     one with an nLockTime below the expiry is refused by the script;
//  C: after the expiry the issuer forces the redemption from the holder.
//
//   LT_LOCALNET=1 dart test test/lt_vnft_localnet_test.dart
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
SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x1f9a0000 + i));
Address addressOf(SVPrivateKey k) => Address.fromPublicKey(k.publicKey, NetworkType.TEST);
Transaction txOf(List<int> raw) => Transaction.fromHex(hex.encode(raw));

void main() {
  test('Voucher NFTs on localnet: the hop limit, redemption, force-redemption after the expiry, reissue', () async {
    final net = Localnet(viaRpc: env['LT_BROADCAST'] == 'rpc');
    await net.ready();
    const rate = 1;
    final b = FnftBuilder.voucher();
    final issuerKey = key(100);
    final rabin = Rabin.generateKeyPair(1024);
    print('code ${b.code.length} B, height ${await net.height()}');

    Future<LtCoin> coinFor(SVPrivateKey k, int sats) async {
      final tx = await net.fund(addressOf(k), BigInt.from(sats));
      final vout = tx.outputs.indexWhere((o) => hex.encode(o.script.buffer) == hex.encode(p2pkh(pkhOf(k))));
      return LtCoin(outpoint(h256(hex.decode(tx.serialize())), vout), k.lt, tx.outputs[vout].satoshis.toInt());
    }

    Future<String> refusedByNode(List<int> raw) async {
      try {
        await net.rpc('sendrawtransaction', [hex.encode(raw)]);
      } on StateError catch (e) {
        return '$e';
      }
      fail('the node accepted it');
    }

    Future<bool> unspent(List<int> out) async {
      final txid = hex.encode(out.sublist(0, 32).reversed.toList());
      return await net.rpc('gettxout', [txid, out[32], true]) != null;
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
    final wand = await ed.newSignatureWandFromKeyPair(await ed.newKeyPairFromSeed(List<int>.generate(32, (i) => 0x60 + i)));
    final anchorTx = await IdentityAnchorBuilder(LtIdentity.anchorMetadata(rabin, {'name': 'Localnet Voucher Issuer'}))
        .buildTransaction(anchorFunding, DefaultTransactionSigner(sigHashAll, issuerKey), issuerKey.publicKey, iAddr, wand);
    await net.submit('anchor', anchorTx);
    final issuer = LtIdentity.issuer(rabin, anchorTx);

    final expiry = await net.height() + 30;
    VoucherTerms terms({int maxHops = 3, int? exp}) =>
        VoucherTerms(maxHops: maxHops, expiry: exp ?? expiry, redeemTo: pkhOf(issuerKey), feeCap: 500);

    /// A voucher issued to the issuer with 3,000 sats of fuel and distributed
    /// to holder [h] (key(h)): its issuance and first transfer.
    Future<(FnftTx, FnftTx)> voucher(int h, {VoucherTerms? t}) async {
      final i = b.issue(first: await coinFor(issuerKey, 3000), issuerPkh: issuer.pkh, owner: pkhOf(issuerKey), terms: t ?? terms(),
          satsPerKb: rate);
      i.x = issuer.attest(i.txid);
      await net.submit('issue', txOf(i.raw));
      final t1 = b.transfer(from: i, ownerKey: issuerKey.lt, to: pkhOf(key(h)), satsPerKb: rate);
      await net.submit('distribute', txOf(t1.raw));
      return (i, t1);
    }

    // ---- A: the hop limit, the holder's redemption, reissue
    final (aIss, a1) = await voucher(1);
    final a2 = b.transfer(from: a1, ownerKey: key(1).lt, to: pkhOf(key(2)), satsPerKb: rate);
    await net.submit('A hop 2', txOf(a2.raw));
    final a3 = b.transfer(from: a2, ownerKey: key(2).lt, to: pkhOf(key(3)), satsPerKb: rate);
    await net.submit('A hop 3', txOf(a3.raw));
    expect(a3.hopsLeft, 0);
    final past = b.transfer(from: a3, ownerKey: key(3).lt, to: pkhOf(key(4)), satsPerKb: rate, counterOverride: 4);
    print('A: a fourth transfer: ${(await refusedByNode(past.raw)).split('\n').first}');
    final aRedeem = b.redeem(from: a3, ownerKey: key(3).lt, satsPerKb: rate);
    await net.submit('A redeem', txOf(aRedeem));
    print('A: redeemed ${a3.value} sats of fuel, ${txOf(aRedeem).outputs.single.satoshis} to the issuer, ${aRedeem.length} B');
    var r = b.reissue(ended: aRedeem, endKey: issuerKey.lt, issuerPkh: issuer.pkh, terms: terms(maxHops: 5), satsPerKb: rate);
    r.x = issuer.attest(r.txid);
    await net.submit('A reissue', txOf(r.raw));
    r = b.transfer(from: r, ownerKey: issuerKey.lt, to: pkhOf(key(5)), satsPerKb: rate);
    await net.submit('A hop 1*', txOf(r.raw));
    final held = await FnftReceive.check(
        b: b, raw: r.raw, ownerPkh: pkhOf(key(5)), anchorTx: anchorTx, links: [LtLink(aRedeem, a3.rec, terms().bytes)]);
    expect(held.originId, aIss.txid);
    expect(held.tx.terms.maxHops, 5);
    print('A: the reissue (maxHops 5) traces back to the first voucher; hops left ${held.tx.hopsLeft}');

    // ---- B: a force-redemption before the expiry
    final (_, b1) = await voucher(11);
    final low = b.forceRedeem(from: b1, issuerKey: issuerKey.lt, lockHeight: expiry - 1, satsPerKb: rate);
    print('B: an nLockTime below the expiry: ${(await refusedByNode(low)).split('\n').first}');
    final early = b.forceRedeem(from: b1, issuerKey: issuerKey.lt, satsPerKb: rate);
    try {
      await net.rpc('sendrawtransaction', [hex.encode(early)]);
      print('B: the force-redemption sent ${expiry - await net.height()} blocks before the expiry: taken as non-final');
    } on StateError catch (e) {
      print('B: the force-redemption sent before the expiry: refused, $e');
    }
    await net.mine(3);
    expect(await unspent(b1.out), isTrue, reason: 'not mined before the expiry');
    final bRedeem = b.redeem(from: b1, ownerKey: key(11).lt, satsPerKb: rate);
    await net.submit('B redeem (the holder, final)', txOf(bRedeem));
    expect(await unspent(b1.out), isFalse);
    print('B: the holder\'s own redemption replaced it and was mined');

    // ---- C: after the expiry the issuer forces the redemption
    final (_, c1) = await voucher(21);
    final h = await net.height();
    if (h < expiry) await net.mine(expiry - h);
    final forced = b.forceRedeem(from: c1, issuerKey: issuerKey.lt, satsPerKb: rate);
    await net.submit('C force-redeem', txOf(forced));
    print('C: at height ${await net.height()} (expiry $expiry) the issuer took ${txOf(forced).outputs.single.satoshis} sats, '
        '${forced.length} B');
    expect(await FnftSuccession.verify(
        b: b, r: (b.reissue(ended: forced, endKey: issuerKey.lt, issuerPkh: issuer.pkh, terms: terms(exp: expiry + 100), satsPerKb: rate)
          ..x = const []), predecessor: c1.tokenId, ended: forced, recG: c1.rec, anchorTx: anchorTx, terms: terms().bytes),
        'the successor: the record has no issuer attestation', reason: 'the link checks out up to the (unset) attestation');
  }, skip: env['LT_LOCALNET'] == null ? 'set LT_LOCALNET=1 with ../localnet running' : false, timeout: const Timeout(Duration(minutes: 20)));
}
