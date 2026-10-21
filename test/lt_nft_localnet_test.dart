@Tags(['localnet'])
library;

// The covenant NFT (TSL1_LT_NFT) on a real node: issued, transferred hop by
// hop, redeemed (sent back to the issuer, who spends it on the cheap path,
// which ends it as a token) and reissued as a fresh lineage on the end's
// output 0, which makes it the one successor: a second issuance on that
// output is refused. Every
// transaction goes in through ARC in Extended Format, with ARC's script
// validation on, and is mined before the next one is built on it.
//
//   LT_LOCALNET=1 dart test test/lt_nft_localnet_test.dart
//
// LT_HOPS (default 20) sets the length of the first lineage. With
// LT_BROADCAST=rpc the transactions go to the node's sendrawtransaction
// instead of ARC. Needs ../localnet running (docker compose up -d).
import 'dart:io';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:cryptography/cryptography.dart';
import 'package:libtokensv/src/builder/identity_anchor_builder.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_identity.dart';
import 'package:libtokensv/src/lt/lt_layout.dart';
import 'package:libtokensv/src/lt/lt_script_gen.dart';
import 'package:libtokensv/src/lt/lt_succession.dart';
import 'package:libtokensv/src/lt/lt_wallet.dart';
import 'localnet.dart';

const L = LtLayout.nft;
final env = Platform.environment;

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x1f7a0000 + i));
Address addressOf(SVPrivateKey k) => Address.fromPublicKey(k.publicKey, NetworkType.TEST);
Transaction txOf(List<int> raw) => Transaction.fromHex(hex.encode(raw));

void main() {
  test('a covenant NFT issued, transferred, redeemed and reissued on localnet', () async {
    final net = Localnet(viaRpc: env['LT_BROADCAST'] == 'rpc');
    await net.ready();
    final hops = int.parse(env['LT_HOPS'] ?? '20');
    final rate = int.parse(env['LT_FEE_RATE'] ?? '1'); // sats per kB
    final code = LtScriptGen.nft.code().buffer;
    final b = LtBuilder(L, code);
    final funder = key(9000);
    final issuerKey = key(100); // the issuer's wallet key, which redemption returns the token to
    final rabin = Rabin.generateKeyPair(1024);
    print('code ${code.length} B, lock ${LtScriptGen(L).lock(List.filled(L.size, 0), code).length} B, '
        'height ${await net.height()}, via ${net.viaRpc ? 'node RPC' : 'ARC'}');

    /// A P2PKH coin from the node's wallet: [sats] to [k], mined.
    Future<LtCoin> coinFor(SVPrivateKey k, int sats) async {
      final tx = await net.fund(addressOf(k), BigInt.from(sats));
      final raw = hex.decode(tx.serialize());
      final pkh = hex.encode(pkhOf(k));
      final vout = tx.outputs.indexWhere((o) => hex.encode(o.script.buffer) == hex.encode(p2pkh(hex.decode(pkh))));
      return LtCoin(outpoint(h256(raw), vout), k.lt, tx.outputs[vout].satoshis.toInt());
    }

    /// Output 0 of [t], its change, as the next funding coin.
    LtCoin changeOf(LtTx t) {
      final amt = t.h1.sublist(L.changeAmt, L.changePkh);
      var v = 0;
      for (var i = 7; i >= 0; i--) {
        v = (v << 8) | amt[i];
      }
      return LtCoin(outpoint(t.txid, 0), funder.lt, v);
    }

    // ---- the issuer's identity anchor, published and mined: its funding
    // must be output 1 of its funding transaction
    final sigHashAll = SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value;
    final iAddr = addressOf(issuerKey);
    final seedTx = await net.fund(iAddr, BigInt.from(100000));
    final seedVout = seedTx.outputs.indexWhere((o) => o.script.buffer.length == 25 &&
        hex.encode(o.script.buffer) == hex.encode(p2pkh(pkhOf(issuerKey))));
    final anchorFunding = TransactionBuilder()
        .spendFromTxnWithSigner(DefaultTransactionSigner(sigHashAll, issuerKey), seedTx, seedVout,
            TransactionInput.MAX_SEQ_NUMBER, P2PKHUnlockBuilder(issuerKey.publicKey))
        .spendToLockBuilder(P2PKHLockBuilder.fromAddress(iAddr), BigInt.from(546))
        .spendToLockBuilder(P2PKHLockBuilder.fromAddress(iAddr), BigInt.from(99000))
        .sendChangeToPKH(iAddr)
        .withFeePerKb(1)
        .build(false);
    await net.submit('fund anchor', anchorFunding);
    final ed = Ed25519();
    final wand = await ed.newSignatureWandFromKeyPair(await ed.newKeyPairFromSeed(List<int>.generate(32, (i) => 0x40 + i)));
    final anchorTx = await IdentityAnchorBuilder(LtIdentity.anchorMetadata(rabin, {'name': 'Localnet Issuer'}))
        .buildTransaction(anchorFunding, DefaultTransactionSigner(sigHashAll, issuerKey), issuerKey.publicKey, iAddr, wand);
    await net.submit('anchor', anchorTx);
    final issuer = LtIdentity.issuer(rabin, anchorTx);

    final sizes = <(String, int)>[];
    Future<void> submit(String name, LtTx t) async {
      await net.submit(name, txOf(t.raw));
      sizes.add((name, t.raw.length));
    }

    Future<LtTx> issue(SVPrivateKey first, LtCoin fund) async {
      final t = b.issue(
        first: await coinFor(first, 10000),
        fund: fund,
        issuerPkh: issuer.pkh,
        owner: pkhOf(first),
        satsPerKb: rate,
      );
      t.x = issuer.attest(t.txid);
      return t;
    }

    // ---- issuance, then [hops] transfers: hop n is owned by key(n)
    var fund = await coinFor(funder, 1000000);
    var t = await issue(key(0), fund);
    await submit('issue', t);
    fund = changeOf(t);
    for (var n = 1; n <= hops; n++) {
      t = b.transfer(from: t, k: 1, ownerKey: key(n - 1).lt, fund: fund, outs: [LtOut(pkhOf(key(n)))], satsPerKb: rate);
      await submit('hop $n', t);
      fund = changeOf(t);
    }
    final first = t;
    expect(await LtIdentity.verify(first, anchorTx), isNull, reason: 'the token verifies against its mined identity anchor');
    print('hop $hops verifies against identity anchor ${anchorTx.id}');
    final sw = Stopwatch()..start();
    final held = await LtReceive.check(b: b, raw: first.raw, ownerPkh: pkhOf(key(hops)), anchorTx: anchorTx);
    print('payee check of hop $hops (${first.raw.length} B), script run included: ${sw.elapsedMilliseconds} ms');
    expect(held.tokenId, first.tokenId);

    // ---- the network refuses what the script refuses: the tip relabelled
    // as another token, and the tip spent as if its parent were another
    // transaction (step B), each sent and refused, so the tip stays spendable
    Future<String> refusal(LtTx bad) async {
      try {
        await net.submit('bad', txOf(bad.raw));
      } on StateError catch (e) {
        return '$e';
      }
      fail('the network accepted an invalid hop');
    }

    final relabel = b.transfer(from: t, k: 1, ownerKey: key(hops).lt, fund: fund, outs: [LtOut(pkhOf(key(99)))],
        tokenIdOverride: sha256([7]));
    print('relabelled hop: ${(await refusal(relabel)).split('\n').first}');
    // the parent's record replaced by bytes of the same length
    final wrongParent = b.transfer(from: t, k: 1, ownerKey: key(hops).lt, fund: fund, outs: [LtOut(pkhOf(key(99)))],
        recPOverride: [...changeOf(t).out, ...List.filled(t.rec.length - 36, 0)]);
    print('fabricated parent record: ${(await refusal(wrongParent)).split('\n').first}');

    // ---- redemption: the holder sends it to the issuer, who ends it; the
    // end's output 0 is the issuer's, the coin the successor spends
    final back = b.transfer(from: t, k: 1, ownerKey: key(hops).lt, fund: fund, outs: [LtOut(pkhOf(issuerKey))], satsPerKb: rate);
    await submit('redeem', back);
    fund = changeOf(back);
    final ended = b.end(from: back, k: 1, ownerKey: issuerKey.lt, fund: fund, changePkh: pkhOf(issuerKey), satsPerKb: rate);
    await net.submit('end', txOf(ended));
    sizes.add(('end', ended.length));

    // ---- reissue: the issuance on the end's output 0, to the holder who
    // redeemed, a fresh lineage, and one hop on it
    fund = await coinFor(funder, 1000000);
    var r = b.reissue(ended: ended, endKey: issuerKey.lt, fund: fund, issuerPkh: issuer.pkh, owner: pkhOf(key(hops)), satsPerKb: rate);
    r.x = issuer.attest(r.txid);
    await submit('reissue', r);
    expect(await LtSuccession.verify(b: b, r: r, predecessor: first.tokenId, ended: ended, recG: back.rec, anchorTx: anchorTx),
        isNull, reason: 'the reissue succeeds the token the end retired');
    print('reissue ${hex.encode(r.txid.reversed.toList())} succeeds ${hex.encode(first.tokenId.reversed.toList())}, '
        'evidence ${ended.length + back.rec.length} B (end ${ended.length} + record ${back.rec.length})');

    // a second issuance on the same output 0, sent to the node itself (ARC
    // files a transaction whose input is already spent in a block as an
    // orphan, waiting for a parent, rather than refusing it)
    final second = b.reissue(ended: ended, endKey: issuerKey.lt, fund: await coinFor(funder, 100000), issuerPkh: issuer.pkh,
        owner: pkhOf(key(99)), satsPerKb: rate);
    try {
      await net.rpc('sendrawtransaction', [hex.encode(second.raw)]);
      fail('the node accepted a second issuance on the end\'s output 0');
    } on StateError catch (e) {
      expect('$e', contains('Missing inputs')); // SV Node: -25, its input is spent
      print('second issuance on the end\'s output 0: $e');
    }

    fund = changeOf(r);
    r = b.transfer(from: r, k: 1, ownerKey: key(hops).lt, fund: fund, outs: [LtOut(pkhOf(key(1)))], satsPerKb: rate);
    await submit('hop 1*', r);
    final link = LtLink(ended, back.rec);
    final again = await LtReceive.check(b: b, raw: r.raw, ownerPkh: pkhOf(key(1)), anchorTx: anchorTx, links: [link]);
    expect(again.originId, first.tokenId, reason: 'the reissued token traces back to the first one');
    print('hop 1* is token ${hex.encode(again.tokenId.reversed.toList()).substring(0, 16)}…, origin '
        '${hex.encode(again.originId.reversed.toList()).substring(0, 16)}…; links ${LtLinks.encode([link]).length} B');

    expect(r.tokenId, isNot(first.tokenId));
    print('\nsizes: ${[for (final (n, s) in sizes) '$n $s'].join(', ')}');
    final h1 = sizes.firstWhere((e) => e.$1 == 'hop 1').$2, hN = sizes.firstWhere((e) => e.$1 == 'hop $hops').$2;
    if (hops > 1) print('growth ${((hN - h1) / (hops - 1)).toStringAsFixed(1)} B/hop (hop 1 $h1 B, hop $hops $hN B)');
  }, skip: env['LT_LOCALNET'] == null ? 'set LT_LOCALNET=1 with ../localnet running' : false, timeout: const Timeout(Duration(minutes: 20)));
}
