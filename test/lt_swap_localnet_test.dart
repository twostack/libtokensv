@Tags(['localnet'])
library;

// The swap and the payload transaction on a real node: a covenant NFT issued
// on a payload transaction, a swap at hop 1, transfers to hop 20, a swap at
// hop 20, the payload read back from the token's transaction there, and a
// swap sent together with the seller's conflicting self-transfer: exactly
// one is mined, and the loser costs its sender nothing.
//
//   LT_LOCALNET=1 dart test test/lt_swap_localnet_test.dart
import 'dart:convert';
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
import 'package:libtokensv/src/lt/lt_payload.dart';
import 'package:libtokensv/src/lt/lt_script_gen.dart';
import 'package:libtokensv/src/lt/lt_swap.dart';
import 'package:libtokensv/src/lt/lt_wallet.dart';
import 'localnet.dart';

final env = Platform.environment;
SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x5a9c0000 + i));
Address addressOf(SVPrivateKey k) => Address.fromPublicKey(k.publicKey, NetworkType.TEST);
Transaction txOf(List<int> raw) => Transaction.fromHex(hex.encode(raw));

void main() {
  test('swaps and a payload on localnet', () async {
    final net = Localnet(viaRpc: env['LT_BROADCAST'] == 'rpc');
    await net.ready();
    final code = LtScriptGen.nft.code().buffer;
    final b = LtBuilder(LtLayout.nft, code);
    final swap = LtSwap(b);
    final issuerKey = key(100);
    final rabin = Rabin.generateKeyPair(1024);

    Future<(Transaction, LtCoin)> coinFor(SVPrivateKey k, int sats) async {
      final tx = await net.fund(addressOf(k), BigInt.from(sats));
      final vout = tx.outputs.indexWhere((o) => hex.encode(o.script.buffer) == hex.encode(p2pkh(pkhOf(k))));
      return (tx, LtCoin(outpoint(h256(hex.decode(tx.serialize())), vout), k.lt, tx.outputs[vout].satoshis.toInt()));
    }

    Future<bool> unspent(List<int> out) async {
      final txid = hex.encode(out.sublist(0, 32).reversed.toList());
      return await net.rpc('gettxout', [txid, out[32], true]) != null;
    }

    // the issuer's identity anchor
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
    final wand = await ed.newSignatureWandFromKeyPair(await ed.newKeyPairFromSeed(List<int>.generate(32, (i) => 0x70 + i)));
    final anchorTx = await IdentityAnchorBuilder(LtIdentity.anchorMetadata(rabin, {'name': 'Localnet Swap Issuer'}))
        .buildTransaction(anchorFunding, DefaultTransactionSigner(sigHashAll, issuerKey), issuerKey.publicKey, iAddr, wand);
    await net.submit('anchor', anchorTx);
    final issuer = LtIdentity.issuer(rabin, anchorTx);

    // the payload transaction, then the issuance on its output 1
    final content = utf8.encode('{"name":"Localnet Swap Token","terms":"sha256:aa55"}');
    final (_, pc) = await coinFor(issuerKey, 20000);
    final (pRaw, pCoin) = LtPayload.build(coin: pc, payload: content, fundSats: 5000, satsPerKb: 1);
    await net.submit('payload', txOf(pRaw));
    final (_, first) = await coinFor(issuerKey, 3000);
    final iss = b.issue(first: first, fund: pCoin, issuerPkh: issuer.pkh, owner: pkhOf(issuerKey), satsPerKb: 1);
    iss.x = issuer.attest(iss.txid);
    await net.submit('issue', txOf(iss.raw));

    Future<LtTx> hop(LtTx from, SVPrivateKey owner, SVPrivateKey to) async {
      final (_, f) = await coinFor(owner, 20000);
      final t = b.transfer(from: from, k: 1, ownerKey: owner.lt, fund: f, outs: [LtOut(pkhOf(to))], satsPerKb: 1);
      await net.submit('hop', txOf(t.raw));
      return t;
    }

    /// The buyer bids first; the seller checks the bid, signs and sends.
    Future<LtTx> sell(LtTx token, SVPrivateKey seller, SVPrivateKey buyer, int price, String name) async {
      const fee = 500;
      final (fTx, fund) = await coinFor(buyer, price + fee);
      final t = LtSwapTerms(
          tokenTx: token.raw, payTo: pkhOf(seller), price: price, fundOut: fund.out, fundSats: fund.sats, fundPub: fund.pub,
          newOwner: pkhOf(buyer));
      final bid = buyer.lt.sign(swap.signing(t, 1));
      swap.checkBid(t, bid, hex.decode(fTx.serialize()));
      final s = swap.assemble(t, seller: seller.lt, buyer: LtGivenSignature(buyer.lt.pub, bid));
      swap.verify(t, s.raw);
      await net.submit(name, txOf(s.raw));
      return s;
    }

    // distribute to A, A sells to B at hop 2
    var t = await hop(iss, issuerKey, key(1));
    t = await sell(t, key(1), key(2), 40000, 'swap h2');
    print('swap at hop 2: ${t.raw.length} B');
    // on to hop 20
    for (var n = 3; n < 20; n++) {
      t = await hop(t, key(n - 1), key(n));
    }
    t = await sell(t, key(19), key(20), 70000, 'swap h20');
    print('swap at hop 20: ${t.raw.length} B');
    final held = await LtReceive.check(b: b, raw: t.raw, ownerPkh: pkhOf(key(20)), anchorTx: anchorTx, payloadTx: pRaw);
    expect(utf8.decode(held.payload!), utf8.decode(content));
    expect(hex.encode(held.tokenId), hex.encode(iss.txid));

    // the race: a swap and the seller's own transfer of the same token
    const price = 30000, fee = 500;
    final (fTx, fund) = await coinFor(key(21), price + fee);
    final terms = LtSwapTerms(
        tokenTx: t.raw, payTo: pkhOf(key(20)), price: price, fundOut: fund.out, fundSats: fund.sats, fundPub: fund.pub,
        newOwner: pkhOf(key(21)));
    final s = swap.assemble(terms, seller: key(20).lt, buyer: key(21).lt);
    final (_, sf) = await coinFor(key(20), 20000);
    final self = b.transfer(from: t, k: 1, ownerKey: key(20).lt, fund: sf, outs: [LtOut(pkhOf(key(22)))], satsPerKb: 1);
    final results = <String>[];
    for (final (name, raw) in [('self-transfer', self.raw), ('swap', s.raw)]) {
      try {
        await net.rpc('sendrawtransaction', [hex.encode(raw)]);
        results.add('$name accepted');
      } on StateError catch (e) {
        results.add('$name refused: ${'$e'.split('\n').first}');
      }
    }
    await net.mine();
    final selfMined = await unspent(outpoint(self.txid, 1));
    final swapMined = await unspent(outpoint(s.txid, 1));
    print('race: ${results.join('; ')}');
    expect(selfMined != swapMined, isTrue, reason: 'exactly one is mined');
    expect(await unspent(fund.out), !swapMined, reason: 'the buyer\'s coin is spent only if the swap was mined');
    print('race: ${selfMined ? 'the self-transfer' : 'the swap'} was mined; the buyer\'s coin is '
        '${swapMined ? 'spent' : 'still unspent'}');
  }, skip: env['LT_LOCALNET'] == null ? 'set LT_LOCALNET=1 with ../localnet running' : false, timeout: const Timeout(Duration(minutes: 20)));
}
