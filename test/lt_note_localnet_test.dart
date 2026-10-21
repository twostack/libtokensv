@Tags(['localnet'])
library;

// The Note NFT (TSL1_LT_NOTE) on a real node. Three notes under one issuer:
//  A: a deposit (exit 30,000 early, everything from maturity): the holder's
//     early exit splits the fuel; the issuer reissues from it;
//  B: a callable note: the mature exit sent before maturity is not mined,
//     and a transfer replaces it; the call sent before callAt is not mined,
//     and the holder's early exit replaces it;
//  C: after maturity the holder's mature exit is mined at once.
//
//   LT_LOCALNET=1 dart test test/lt_note_localnet_test.dart
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
SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x40e80000 + i));
Address addressOf(SVPrivateKey k) => Address.fromPublicKey(k.publicKey, NetworkType.TEST);
Transaction txOf(List<int> raw) => Transaction.fromHex(hex.encode(raw));

void main() {
  test('Note NFTs on localnet: a split exit, maturity and call enforced by the network, a reissue', () async {
    final net = Localnet(viaRpc: env['LT_BROADCAST'] == 'rpc');
    await net.ready();
    const rate = 1;
    final b = FnftBuilder.note();
    final issuerKey = key(100);
    final payTo = pkhOf(issuerKey);
    final rabin = Rabin.generateKeyPair(1024);
    print('code ${b.code.length} B, height ${await net.height()}');

    Future<LtCoin> coinFor(SVPrivateKey k, int sats) async {
      final tx = await net.fund(addressOf(k), BigInt.from(sats));
      final vout = tx.outputs.indexWhere((o) => hex.encode(o.script.buffer) == hex.encode(p2pkh(pkhOf(k))));
      return LtCoin(outpoint(h256(hex.decode(tx.serialize())), vout), k.lt, tx.outputs[vout].satoshis.toInt());
    }

    Future<bool> unspent(List<int> out) async =>
        await net.rpc('gettxout', [hex.encode(out.sublist(0, 32).reversed.toList()), out[32], true]) != null;

    Future<void> sendEarly(String name, List<int> raw) async {
      try {
        await net.rpc('sendrawtransaction', [hex.encode(raw)]);
        print('$name: taken as non-final');
      } on StateError catch (e) {
        print('$name: refused, ${'$e'.split('\n').first}');
      }
    }

    // the issuer's identity anchor
    final sigHashAll = SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value;
    final iAddr = addressOf(issuerKey);
    final seed = await net.fund(iAddr, BigInt.from(100000));
    final seedVout = seed.outputs.indexWhere((o) => hex.encode(o.script.buffer) == hex.encode(p2pkh(payTo)));
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
    final wand = await ed.newSignatureWandFromKeyPair(await ed.newKeyPairFromSeed(List<int>.generate(32, (i) => 0x90 + i)));
    final anchorTx = await IdentityAnchorBuilder(LtIdentity.anchorMetadata(rabin, {'name': 'Localnet Note Issuer'}))
        .buildTransaction(anchorFunding, DefaultTransactionSigner(sigHashAll, issuerKey), issuerKey.publicKey, iAddr, wand);
    await net.submit('anchor', anchorTx);
    final issuer = LtIdentity.issuer(rabin, anchorTx);

    /// A note under [terms] with 50,000 sats of fuel, distributed to key(h).
    Future<FnftTx> note(NoteTerms terms, int h) async {
      final i = b.issue(first: await coinFor(issuerKey, 50000), issuerPkh: issuer.pkh, owner: payTo, terms: terms, satsPerKb: rate);
      i.x = issuer.attest(i.txid);
      await net.submit('issue', txOf(i.raw));
      final t1 = b.transfer(from: i, ownerKey: issuerKey.lt, to: pkhOf(key(h)), satsPerKb: rate);
      await net.submit('distribute', txOf(t1.raw));
      return t1;
    }

    final height = await net.height();

    // ---- A: a deposit's early exit splits the fuel; a reissue from it
    final deposit = NoteTerms.deposit(payTo: payTo, feeCap: 500, at: height + 1000, early: 30000);
    final a1 = await note(deposit, 1);
    final aExit = b.exit(from: a1, ownerKey: key(1).lt, satsPerKb: rate);
    await net.submit('A exit', txOf(aExit));
    final outs = [for (final o in txOf(aExit).outputs) o.satoshis.toInt()];
    expect(outs.last, 30000);
    print('A: early exit of ${a1.value} sats: $outs (issuer, holder), ${aExit.length} B');
    var r = b.reissue(ended: aExit, endKey: issuerKey.lt, issuerPkh: issuer.pkh, terms: deposit, satsPerKb: rate);
    r.x = issuer.attest(r.txid);
    await net.submit('A reissue', txOf(r.raw));
    r = b.transfer(from: r, ownerKey: issuerKey.lt, to: pkhOf(key(5)), satsPerKb: rate);
    await net.submit('A hop 1*', txOf(r.raw));
    final held = await FnftReceive.check(
        b: b, raw: r.raw, ownerPkh: pkhOf(key(5)), anchorTx: anchorTx, links: [LtLink(aExit, a1.rec, deposit.bytes)]);
    expect(hex.encode(held.originId), hex.encode(a1.tokenId));

    // ---- B: maturity and callAt are enforced by the network
    final maturity = await net.height() + 25, callAt = maturity - 5;
    final callable = NoteTerms.callable(payTo: payTo, feeCap: 500, at: maturity, callAt: callAt, floor: 20000);
    final b1 = await note(callable, 11);
    await sendEarly('B mature exit ${maturity - await net.height()} blocks early', b.matureExit(from: b1, ownerKey: key(11).lt, satsPerKb: rate));
    await net.mine(2);
    expect(await unspent(b1.out), isTrue, reason: 'not mined before maturity');
    final b2 = b.transfer(from: b1, ownerKey: key(11).lt, to: pkhOf(key(12)), satsPerKb: rate);
    await net.submit('B transfer (replaces it)', txOf(b2.raw));
    await sendEarly('B call ${callAt - await net.height()} blocks early', b.call(from: b2, issuerKey: issuerKey.lt, satsPerKb: rate));
    await net.mine(2);
    expect(await unspent(b2.out), isTrue, reason: 'not mined before callAt');
    final bExit = b.exit(from: b2, ownerKey: key(12).lt, satsPerKb: rate);
    await net.submit('B exit (replaces the call)', txOf(bExit));

    // ---- C: after maturity the mature exit is mined at once
    final c1 = await note(callable, 21);
    final h = await net.height();
    if (h < maturity) await net.mine(maturity - h);
    final cm = b.matureExit(from: c1, ownerKey: key(21).lt, satsPerKb: rate);
    await net.submit('C mature exit', txOf(cm));
    print('C: at height ${await net.height()} (maturity $maturity) the holder took '
        '${txOf(cm).outputs.single.satoshis} of ${c1.value} sats, ${cm.length} B');
    expect(hex.encode(txOf(cm).outputs.single.script.buffer), hex.encode(p2pkh(pkhOf(key(21)))));
  }, skip: env['LT_LOCALNET'] == null ? 'set LT_LOCALNET=1 with ../localnet running' : false, timeout: const Timeout(Duration(minutes: 20)));
}
