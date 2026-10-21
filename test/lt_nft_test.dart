// TSL1_LT_NFT through the interpreter: the indivisible lineage token and the
// attacks each check refuses. It has no reset: it is redeemed and reissued.
//
// Run: dart test test/lt_nft_test.dart
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:cryptography/cryptography.dart';
import 'package:libtokensv/src/builder/identity_anchor_builder.dart';
import 'package:libtokensv/src/builder/map_lockbuilder.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_identity.dart';
import 'package:libtokensv/src/lt/lt_layout.dart';
import 'package:libtokensv/src/lt/lt_script_gen.dart';
import 'package:libtokensv/src/lt/lt_succession.dart';
import 'package:libtokensv/src/lt/lt_wallet.dart';
import 'package:libtokensv/src/script_gen/stk.dart';

const L = LtLayout.nft;

final flags = {
  VerifyFlag.SIGHASH_FORKID,
  VerifyFlag.LOW_S,
  VerifyFlag.NULLFAIL,
  VerifyFlag.MINIMALDATA,
  VerifyFlag.MINIMALIF,
  VerifyFlag.SIGPUSHONLY,
  VerifyFlag.UTXO_AFTER_GENESIS,
};

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x5eed0000 + i));
final funder = key(9000);
final attacker = key(9001);

var _coin = 0;
LtCoin coin(SVPrivateKey k) => LtCoin(outpoint(sha256(le(++_coin, 4)), _coin % 3), k.lt, 100000);

void spend(List<int> raw, int i, List<int> lock, int sats) {
  final tx = Transaction.fromHex(hex.encode(raw));
  expect(tx.serialize(), hex.encode(raw), reason: 'dartsv must round-trip the bytes');
  Interpreter().correctlySpends(
    tx.inputs[i].script!,
    SVScript.fromByteArray(Uint8List.fromList(lock)),
    tx,
    i,
    flags,
    Coin.valueOf(BigInt.from(sats)),
  );
}

Matcher refusedComparing(List<int> a, List<int> b) => throwsA(
  isA<ScriptException>()
      .having((x) => x.error, 'error', ScriptError.SCRIPT_ERR_EQUALVERIFY)
      .having((x) => x.cause, 'cause', allOf(contains(hex.encode(a)), contains(hex.encode(b)))),
);

Matcher refusedWith(ScriptError e) => throwsA(isA<ScriptException>().having((x) => x.error, 'error', e));

late LtIssuer issuer;
final funderLock = p2pkh(pkhOf(funder));

/// [verifyAll] for a transaction funded by [funder]'s coin of [fundKey].
void verifyAll2(LtTx t, LtTx from, List<int> code, SVPrivateKey fundKey) {
  spend(t.raw, 0, from.lock(1, code), 1);
  spend(t.raw, 1, p2pkh(pkhOf(fundKey)), 100000);
}

void verifyAll(LtTx t, LtTx from, List<int> code) {
  spend(t.raw, 0, from.lock(1, code), 1);
  spend(t.raw, 1, funderLock, 100000);
}

LtTx issuance(LtBuilder b, {LtIssuer? by}) {
  final iss = by ?? issuer;
  final t = b.issue(
    first: coin(key(0)),
    fund: coin(funder),
    issuerPkh: iss.pkh,
    owner: pkhOf(key(0)),
  );
  t.x = iss.attest(t.txid);
  return t;
}

/// A transfer of ([from], 1), owned by key(n), to key(n + 1).
LtTx hop(LtBuilder b, LtTx from, int n, {List<int>? reset}) =>
    b.transfer(from: from, k: 1, ownerKey: key(n).lt, fund: coin(funder), outs: [LtOut(pkhOf(key(n + 1)))], reset: reset);

/// Issuance plus [hops] transfers; hop n is owned by key(n).
List<LtTx> chain(LtBuilder b, int hops) {
  final out = [issuance(b)];
  for (var n = 1; n <= hops; n++) {
    out.add(hop(b, out.last, n - 1));
  }
  return out;
}

/// An identity anchor for [rabin], built by [IdentityAnchorBuilder] from a
/// fabricated funding transaction; [meta] replaces the metadata it would
/// carry.
Future<Transaction> anchorFor(RabinKeyPair rabin, {Map<String, String>? meta, int seed = 0}) async {
  final k = key(7000 + seed);
  final address = Address.fromPublicKey(k.publicKey, NetworkType.TEST);
  final funding = (TransactionBuilder()
        .spendFromOutpoint(
            TransactionOutpoint(hex.encode(List<int>.generate(32, (i) => i + seed)), 0, BigInt.from(200000),
                P2PKHLockBuilder.fromAddress(address).getScriptPubkey()),
            TransactionInput.MAX_SEQ_NUMBER,
            P2PKHUnlockBuilder(k.publicKey))
        .spendToLockBuilder(P2PKHLockBuilder.fromAddress(address), BigInt.from(546))
        .spendToLockBuilder(P2PKHLockBuilder.fromAddress(address), BigInt.from(199000))
        ..withOption(TransactionOption.DISABLE_DUST_OUTPUTS))
      .build(false);
  final ed = Ed25519();
  final wand = await ed.newSignatureWandFromKeyPair(await ed.newKeyPairFromSeed(List<int>.generate(32, (i) => i + seed)));
  return IdentityAnchorBuilder(meta ?? LtIdentity.anchorMetadata(rabin, {'name': 'Test Issuer'})).buildTransaction(
      funding, DefaultTransactionSigner(SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value, k), k.publicKey,
      address, wand);
}

void main() {
  final code = LtScriptGen.nft.code().buffer;
  final b = LtBuilder(L, code);

  setUpAll(() {
    issuer = LtIssuer(Rabin.generateKeyPair(1024), sha256([1]), sha256([2]));
  });

  test('the script fits the 3-byte varint the preimage parse assumes', () {
    expect(code.length, inInclusiveRange(253, 0xffff));
  });

  test('an honest chain verifies on every input at every hop', () {
    final c = chain(b, 8);
    for (var n = 1; n < c.length; n++) {
      verifyAll(c[n], c[n - 1], code);
    }
    expect(c[1].tokenId, c[0].txid);
    expect(c[8].amount(1), 1);
  });

  test('the builder refuses amounts, splits and passengers', () {
    final c = chain(b, 1);
    expect(
      () => b.transfer(from: c[1], k: 1, ownerKey: key(1).lt, fund: coin(funder), outs: [LtOut(pkhOf(key(2)), 2)]),
      throwsArgumentError,
    );
    expect(
      () => b.transfer(
        from: c[1],
        k: 1,
        ownerKey: key(1).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(2))), LtOut(pkhOf(key(3)))],
      ),
      throwsArgumentError,
    );
    expect(
      () => b.transfer(
        from: c[1],
        k: 1,
        ownerKey: key(1).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(2)))],
        passenger: LtPassenger(c[1], 1, key(1).lt),
      ),
      throwsArgumentError,
    );
  });

  group('the lineage', () {
    test('a fabricated parent is refused (step B), and accepted once step B is removed', () {
      final c = chain(b, 3);
      final theirs = coin(attacker);
      final f = b.transfer(
        from: c[2],
        k: 1,
        ownerKey: attacker.lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(attacker))],
        in0Override: theirs.out,
      );
      final t = hop(b, f, 9001);
      expect(() => spend(t.raw, 0, f.lock(1, code), 1), refusedComparing(c[2].txid, theirs.out.sublist(0, 32)));

      final weak = LtScriptGen.nft.code(stepB: false).buffer;
      final wb = LtBuilder(L, weak);
      final w = chain(wb, 3);
      final fw = wb.transfer(
        from: w[2],
        k: 1,
        ownerKey: attacker.lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(attacker))],
        in0Override: theirs.out,
      );
      verifyAll(hop(wb, fw, 9001), fw, weak);
    });

    test('a verbatim copy of a token output cannot be spent (step A)', () {
      final c = chain(b, 2);
      final theirs = coin(attacker);
      final raw = Uint8List.fromList([
        ...le(1, 4), 1, ...theirs.out, 0, 0xff, 0xff, 0xff, 0xff, //
        1, ...b.tokenOut(c[2].h1), ...le(0, 4),
      ]);
      final clone = LtTx(L, c[2].h1, null, c[2].sigs, c[2].x, raw);
      final t = hop(b, clone, 2);
      expect(() => spend(t.raw, 0, clone.lock(1, code), 1), refusedComparing(c[2].txid, clone.txid));
    });

    test('a token cannot be relabelled', () {
      final c = chain(b, 2);
      final t = b.transfer(
        from: c[2],
        k: 1,
        ownerKey: key(2).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(3)))],
        tokenIdOverride: sha256([7]),
      );
      expect(() => spend(t.raw, 0, c[2].lock(1, code), 1), refusedComparing(c[2].tokenId, sha256([7])));
    });

    test('a transfer cannot be made without the owner\'s key, on either path', () {
      final c = chain(b, 2);
      final t = b.transfer(from: c[2], k: 1, ownerKey: attacker.lt, fund: coin(funder), outs: [LtOut(pkhOf(attacker))]);
      expect(() => spend(t.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_EQUALVERIFY));
      final cheap = b.transfer(
        from: c[2],
        k: 1,
        ownerKey: attacker.lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(attacker))],
        cheap: true,
      );
      expect(() => spend(cheap.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_EQUALVERIFY));
    });

    test('the owner can spend on the cheap path, and that output is dead as a token', () {
      final c = chain(b, 2);
      final fund = coin(funder);
      final g = b.transfer(from: c[2], k: 1, ownerKey: key(2).lt, fund: fund, outs: [LtOut(pkhOf(key(3)))], cheap: true);
      spend(g.raw, 0, c[2].lock(1, code), 1);
      spend(g.raw, 1, funderLock, 100000);
      final asIfNormal = b.transfer(from: c[2], k: 1, ownerKey: key(2).lt, fund: fund, outs: [LtOut(pkhOf(key(3)))]);
      final t = hop(b, g, 3);
      expect(() => spend(t.raw, 0, g.lock(1, code), 1), refusedComparing(asIfNormal.txid, g.txid));
    });

    test('a version 2 transfer is refused', () {
      final c = chain(b, 2);
      final t = b.transfer(
        from: c[2],
        k: 1,
        ownerKey: key(2).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(3)))],
        version: 2,
      );
      expect(() => spend(t.raw, 0, c[2].lock(1, code), 1), refusedComparing([2, 0, 0, 0], [1, 0, 0, 0]));
    });

    test('a relayer cannot alter the child header: every signature covers it', () {
      final c = chain(b, 2);
      final t = hop(b, c[2], 2);
      final h = [...t.h1]..setRange(L.changePkh, L.in0, pkhOf(attacker));
      final body = t.raw.length - 4 - b.tokenOut(t.h1).length;
      final patched = [...t.raw.sublist(0, body), ...b.tokenOut(h), ...le(0, 4)];
      expect(
        () => spend(patched, 0, c[2].lock(1, code), 1),
        anyOf(refusedWith(ScriptError.SCRIPT_ERR_VERIFY), refusedWith(ScriptError.SCRIPT_ERR_SIG_NULLFAIL)),
      );
      expect(() => spend(patched, 1, funderLock, 100000), refusedWith(ScriptError.SCRIPT_ERR_SIG_NULLFAIL));
    });
  });

  group('the issuance', () {
    test('cannot be activated by anyone but the issuer', () {
      final c = chain(b, 0);
      final other = LtIssuer(Rabin.generateKeyPair(1024), issuer.identityTxId, issuer.ed25519PubKey);
      c[0].x = other.attest(c[0].txid);
      final t = hop(b, c[0], 0);
      expect(() => spend(t.raw, 0, c[0].lock(1, code), 1), refusedComparing(other.pkh, issuer.pkh));
    });

    test('cannot be activated with a replayed attestation', () {
      final genuine = chain(b, 0);
      final counterfeit = chain(b, 0);
      counterfeit[0].x = issuer.attest(genuine[0].txid);
      final t = hop(b, counterfeit[0], 0);
      expect(
        () => spend(t.raw, 0, counterfeit[0].lock(1, code), 1),
        refusedWith(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY),
      );
    });

    test('is accepted with a foreign attestation once the issuer check is removed', () {
      final weak = LtScriptGen.nft.code(issuerCheck: false).buffer;
      final wb = LtBuilder(L, weak);
      final c = chain(wb, 0);
      final other = LtIssuer(Rabin.generateKeyPair(1024), issuer.identityTxId, issuer.ed25519PubKey);
      c[0].x = other.attest(c[0].txid);
      verifyAll(hop(wb, c[0], 0), c[0], weak);
    });

    test('must have the shape later hops can rebuild', () {
      final malformed = b.issue(
        first: coin(key(0)),
        fund: coin(funder),
        issuerPkh: issuer.pkh,
            owner: pkhOf(key(0)),
        extraOutputs: [...le(1, 8), 0x19, ...p2pkh(pkhOf(key(0)))],
      );
      malformed.x = issuer.attest(malformed.txid);
      final t = hop(b, malformed, 0);
      expect(
        () => spend(t.raw, 0, malformed.lock(1, code), 1),
        throwsA(
          isA<ScriptException>()
              .having((x) => x.error, 'error', ScriptError.SCRIPT_ERR_EQUALVERIFY)
              .having((x) => x.cause, 'cause', contains(hex.encode(malformed.txid))),
        ),
      );
    });
  });


  group('the builder', () {
    test('the issuance returns its first coin with the funding\'s change', () {
      final first = coin(key(0)), fund = coin(funder);
      final t = b.issue(first: first, fund: fund, issuerPkh: issuer.pkh, owner: pkhOf(key(0)), fee: 300);
      final tx = Transaction.fromHex(hex.encode(t.raw));
      expect(tx.outputs[0].satoshis.toInt() + tx.outputs[1].satoshis.toInt(), first.sats + fund.sats - 300);
    });

    test('a fee rate prices the transaction by its size', () {
      final c = chain(b, 2);
      final t = b.transfer(from: c[2], k: 1, ownerKey: key(2).lt, fund: coin(funder), outs: [LtOut(pkhOf(key(3)))], satsPerKb: 100);
      final fee = 100000 + 1 - Transaction.fromHex(hex.encode(t.raw)).outputs.fold<int>(0, (a, o) => a + o.satoshis.toInt());
      expect(fee, LtBuilder.feeFor(t.raw.length, 100));
      expect(fee * 1000 / t.raw.length, inInclusiveRange(100, 101));
      verifyAll(t, c[2], code);
    });

    test('refuses funding that does not cover the fee, instead of writing a negative change', () {
      final c = chain(b, 1);
      expect(() => b.transfer(from: c[1], k: 1, ownerKey: key(1).lt, fund: LtCoin(coin(funder).out, funder.lt, 900),
          outs: [LtOut(pkhOf(key(2)))], fee: 900), throwsArgumentError);
      expect(() => b.transfer(from: c[1], k: 1, ownerKey: key(1).lt, fund: LtCoin(coin(funder).out, funder.lt, 50),
          outs: [LtOut(pkhOf(key(2)))], satsPerKb: 100), throwsArgumentError);
      expect(() => b.issue(first: LtCoin(coin(key(0)).out, key(0).lt, 1), fund: LtCoin(coin(funder).out, funder.lt, 10),
          issuerPkh: issuer.pkh, owner: pkhOf(key(0)), fee: 10), throwsArgumentError);
      expect(() => b.end(from: c[1], k: 1, ownerKey: key(1).lt, fund: LtCoin(coin(funder).out, funder.lt, 10),
          changePkh: pkhOf(funder), fee: 11), throwsArgumentError);
    });

    test('end: the owner spends the token on the cheap path to plain outputs only', () {
      final c = chain(b, 2);
      final fund = coin(funder);
      final raw = b.end(from: c[2], k: 1, ownerKey: key(2).lt, fund: fund, changePkh: pkhOf(funder), pay: [(pkhOf(key(5)), 500)], fee: 200);
      spend(raw, 0, c[2].lock(1, code), 1);
      spend(raw, 1, funderLock, 100000);
      final tx = Transaction.fromHex(hex.encode(raw));
      expect(tx.outputs.map((o) => o.script.buffer.length), everyElement(25));
      expect(tx.outputs.fold<int>(0, (a, o) => a + o.satoshis.toInt()), 1 + fund.sats - 200);
      // output 0, the coin a successor spends, is the change, never a payee's
      expect(hex.encode(tx.outputs[0].script.buffer), hex.encode(funderLock));
      expect(hex.encode(tx.outputs[1].script.buffer), hex.encode(p2pkh(pkhOf(key(5)))));
      expect(tx.outputs[1].satoshis.toInt(), 500);
      // and only the owner can: another key's signature is refused
      final theirs = b.end(from: c[2], k: 1, ownerKey: attacker.lt, fund: coin(funder), changePkh: pkhOf(attacker));
      expect(() => spend(theirs, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_EQUALVERIFY));
    });
  });

  group('redeem and reissue', () {
    final issuerKey = key(100);
    late RabinKeyPair rabin;
    late Transaction anchor;
    late LtIssuer iss;
    setUpAll(() async {
      rabin = Rabin.generateKeyPair(1024);
      anchor = await anchorFor(rabin, seed: 3);
      iss = LtIdentity.issuer(rabin, anchor);
    });

    /// An issuance and [hops] hops of X, then G (X redeemed to the issuer),
    /// E (the issuer ends it) and R (the reissue, owned by the redeemer).
    ({List<LtTx> x, Uint8List e, LtTx r}) lifecycle([int hops = 2]) {
      final c = [issuance(b, by: iss)];
      for (var n = 1; n <= hops; n++) {
        c.add(hop(b, c.last, n - 1));
      }
      c.add(b.transfer(from: c.last, k: 1, ownerKey: key(hops).lt, fund: coin(funder), outs: [LtOut(pkhOf(issuerKey))]));
      final e = b.end(from: c.last, k: 1, ownerKey: issuerKey.lt, fund: coin(funder), changePkh: pkhOf(issuerKey), fee: 200);
      final r = b.reissue(ended: e, endKey: issuerKey.lt, fund: coin(funder), issuerPkh: iss.pkh, owner: pkhOf(key(hops)));
      r.x = iss.attest(r.txid);
      return (x: c, e: e, r: r);
    }

    Future<String?> check(LtTx r, List<int> predecessor, List<int> e, List<int> recG, {Transaction? anchorTx}) =>
        LtSuccession.verify(b: b, r: r, predecessor: predecessor, ended: e, recG: recG, anchorTx: anchorTx ?? anchor);

    test('every transaction of the lifecycle is its record rebuilt, and every spend verifies', () {
      final l = lifecycle();
      for (final t in [...l.x, l.r]) {
        expect(b.fromRec(t.rec).raw, t.raw);
      }
      final g = l.x.last;
      verifyAll(g, l.x[2], code);
      spend(l.e, 0, g.lock(1, code), 1);
      final e0 = Transaction.fromHex(hex.encode(l.e)).outputs[0].satoshis.toInt();
      spend(l.r.raw, 0, p2pkh(pkhOf(issuerKey)), e0);
      spend(l.r.raw, 1, funderLock, 100000);
      final r1 = hop(b, l.r, 2);
      verifyAll(r1, l.r, code);
      // the reissue's record starts over
      expect(r1.rec.length, l.x[1].rec.length);
      expect(g.rec.length, l.x[1].rec.length + 2 * (L.size + LtLayout.sigsTwo));
    });

    test('the reissue succeeds the token it ended', () async {
      final l = lifecycle();
      expect(await check(l.r, l.x[0].txid, l.e, l.x.last.rec), isNull);
    });

    test('a token ended at its issuance has a successor, once its attestation verifies', () async {
      final x0 = issuance(b, by: iss);
      final e = b.end(from: x0, k: 1, ownerKey: key(0).lt, fund: coin(funder), changePkh: pkhOf(issuerKey), fee: 200);
      spend(e, 0, x0.lock(1, code), 1);
      final r = b.reissue(ended: e, endKey: issuerKey.lt, fund: coin(funder), issuerPkh: iss.pkh, owner: pkhOf(key(0)));
      r.x = iss.attest(r.txid);
      expect(await check(r, x0.txid, e, x0.rec), isNull);
      // no spend ever checked X0's attestation, so the wallet does
      x0.x = const [];
      expect(await check(r, x0.txid, e, x0.rec), startsWith('the ended issuance'));
    });

    test('refuses a successor of a forged copy: the cheap path takes it, the record cannot', () async {
      final l = lifecycle();
      final g = l.x.last;
      // a cheap-path spend of G:1 that writes a token output of X, as a
      // transfer would; the chain accepts it, and its output's end
      final f = b.transfer(
          from: g, k: 1, ownerKey: issuerKey.lt, fund: coin(funder), outs: [LtOut(pkhOf(issuerKey))], cheap: true);
      spend(f.raw, 0, g.lock(1, code), 1);
      final e = b.end(from: f, k: 1, ownerKey: issuerKey.lt, fund: coin(funder), changePkh: pkhOf(issuerKey), fee: 200);
      spend(e, 0, f.lock(1, code), 1);
      final r = b.reissue(ended: e, endKey: issuerKey.lt, fund: coin(funder), issuerPkh: iss.pkh, owner: pkhOf(key(2)));
      r.x = iss.attest(r.txid);
      expect(await check(r, l.x[0].txid, e, f.rec), 'the record is not of the transaction the ended transaction spent');
    });

    test('refuses a successor of a copy whose input 0 spent something other than a token output', () async {
      final l = lifecycle();
      final g = l.x.last;
      // shaped like G, record and all, but its input 0 spends a coin under
      // a script that takes anything (here an arbitrary outpoint): the
      // script never ran, so its output is not X's
      final f = b.transfer(from: g, k: 1, ownerKey: issuerKey.lt, fund: coin(funder), outs: [LtOut(pkhOf(issuerKey))],
          in0Override: outpoint(sha256([5]), 1));
      final e = b.end(from: f, k: 1, ownerKey: issuerKey.lt, fund: coin(funder), changePkh: pkhOf(issuerKey), fee: 200);
      final r = b.reissue(ended: e, endKey: issuerKey.lt, fund: coin(funder), issuerPkh: iss.pkh, owner: pkhOf(key(2)));
      r.x = iss.attest(r.txid);
      expect(await check(r, l.x[0].txid, e, f.rec), 'the ended token\'s input 0 is not a spend of a token output');
    });

    test('refuses a successor of a transaction that continued the token instead of ending it', () async {
      final l = lifecycle();
      final g = l.x.last;
      final cont = b.transfer(
          from: g, k: 1, ownerKey: issuerKey.lt, fund: coin(issuerKey), outs: [LtOut(pkhOf(key(9)))]);
      verifyAll2(cont, g, code, issuerKey);
      final r = b.reissue(ended: cont.raw, endKey: issuerKey.lt, fund: coin(funder), issuerPkh: iss.pkh, owner: pkhOf(key(2)));
      r.x = iss.attest(r.txid);
      expect(await check(r, l.x[0].txid, cont.raw, g.rec), 'the ended transaction\'s input 0 is not a cheap-path spend');
    });

    test('refuses an issuance on another output of the end', () async {
      final l = lifecycle();
      final g = l.x.last;
      final e = b.end(from: g, k: 1, ownerKey: issuerKey.lt, fund: coin(funder), changePkh: pkhOf(issuerKey),
          pay: [(pkhOf(key(5)), 500)], fee: 200);
      final r = b.issue(first: LtCoin(outpoint(h256(e), 1), key(5).lt, 500), fund: coin(funder), issuerPkh: iss.pkh,
          owner: pkhOf(key(5)));
      r.x = iss.attest(r.txid);
      expect(await check(r, l.x[0].txid, e, g.rec), 'the successor does not spend output 0 of the ended transaction');
      // and the builder will not make one on a coin the end did not pay to the key
      expect(() => b.reissue(ended: e, endKey: key(5).lt, fund: coin(funder), issuerPkh: iss.pkh, owner: pkhOf(key(5))),
          throwsArgumentError);
    });

    test('the payee follows the links to the origin, newest first, through two reissues', () async {
      final l = lifecycle();
      final g = l.x.last;
      final link1 = LtLink(l.e, g.rec);
      // R hops twice, is redeemed and reissued again as R2, which hops once
      final r1 = hop(b, l.r, 2), r2 = hop(b, r1, 3);
      final g2 = b.transfer(from: r2, k: 1, ownerKey: key(4).lt, fund: coin(funder), outs: [LtOut(pkhOf(issuerKey))]);
      final e2 = b.end(from: g2, k: 1, ownerKey: issuerKey.lt, fund: coin(funder), changePkh: pkhOf(issuerKey), fee: 200);
      final rr = b.reissue(ended: e2, endKey: issuerKey.lt, fund: coin(funder), issuerPkh: iss.pkh, owner: pkhOf(key(4)));
      rr.x = iss.attest(rr.txid);
      final rr1 = hop(b, rr, 4);
      final link2 = LtLink(e2, g2.rec);
      Future<LtHolding> recv(List<LtLink> links) =>
          LtReceive.check(b: b, raw: rr1.raw, ownerPkh: pkhOf(key(5)), anchorTx: anchor, links: links);

      final h = await recv(LtLinks.decode(LtLinks.encode([link2, link1])));
      expect(h.tokenId, rr.txid);
      expect(h.originId, l.x[0].txid);
      expect((await recv([link2])).originId, l.r.txid);
      expect((await recv([])).originId, rr.txid, reason: 'without links it is only itself');
      // oldest first, or a link of another token, does not connect
      expect(() => recv([link1, link2]), throwsA(isA<LtRefused>().having((e) => e.reason, 'reason',
          'link 0: the successor does not spend output 0 of the ended transaction')));
      final other = lifecycle();
      expect(() => recv([link2, LtLink(other.e, other.x.last.rec)]), throwsA(isA<LtRefused>()));
      // a record whose tail is another token's issuance
      final g2Forged = [...g2.rec.sublist(0, g2.rec.length - 712), ...other.x[0].rec];
      expect(() => LtReceive.issuanceOf(b, b.fromRec(g2Forged)),
          throwsA(isA<LtRefused>().having((e) => e.reason, 'reason', contains('another token'))));
      print('links for two reissues: ${LtLinks.encode([link2, link1]).length} B');
    });

    test('refuses a successor under another issuer, another predecessor, or a tampered record', () async {
      final l = lifecycle();
      final g = l.x.last;
      final otherRabin = Rabin.generateKeyPair(1024);
      final otherAnchor = await anchorFor(otherRabin, seed: 4);
      final other = LtIdentity.issuer(otherRabin, otherAnchor);
      final theirs = b.reissue(ended: l.e, endKey: issuerKey.lt, fund: coin(funder), issuerPkh: other.pkh, owner: pkhOf(key(2)));
      theirs.x = other.attest(theirs.txid);
      expect(await check(theirs, l.x[0].txid, l.e, g.rec, anchorTx: otherAnchor), 'the successor names another issuer');

      expect(await check(l.r, sha256([9]), l.e, g.rec), 'the ended token is not the predecessor');

      final bad = [...g.rec];
      bad[L.size + 10] ^= 1; // a byte of the sender's signature
      expect(await check(l.r, l.x[0].txid, l.e, bad), 'the record is not of the transaction the ended transaction spent');
      // the parent record inside G's: G's txid moves with it
      final badP = [...g.rec];
      badP[L.size + LtLayout.sigsTwo + 5] ^= 1;
      expect(await check(l.r, l.x[0].txid, l.e, badP), 'the record is not of the transaction the ended transaction spent');
    });
  });

  test('a key that signs as a wallet does, from the unsigned transaction, makes the same transactions', () {
    final c = chain(b, 1);
    final viaWallet = _TxSignerKey(key(1)), funding = _TxSignerKey(funder);
    final fund = coin(funder);
    final a = b.transfer(from: c[1], k: 1, ownerKey: key(1).lt, fund: fund, outs: [LtOut(pkhOf(key(2)))]);
    final w = b.transfer(from: c[1], k: 1, ownerKey: viaWallet, fund: LtCoin(fund.out, funding, fund.sats), outs: [LtOut(pkhOf(key(2)))]);
    expect(w.raw, a.raw);
    expect(viaWallet.signed, 1);
    expect(funding.signed, 1);
    final e1 = b.end(from: c[1], k: 1, ownerKey: key(1).lt, fund: fund, changePkh: pkhOf(funder));
    final e2 = b.end(from: c[1], k: 1, ownerKey: viaWallet, fund: LtCoin(fund.out, funding, fund.sats), changePkh: pkhOf(funder));
    expect(e2, e1);
  });

  group('the payee', () {
    late RabinKeyPair rabin;
    late Transaction anchor;
    late LtIssuer iss;
    setUpAll(() async {
      rabin = Rabin.generateKeyPair(1024);
      anchor = await anchorFor(rabin, seed: 5);
      iss = LtIdentity.issuer(rabin, anchor);
    });

    List<LtTx> issued(int hops) {
      final c = [issuance(b, by: iss)];
      for (var n = 1; n <= hops; n++) {
        c.add(hop(b, c.last, n - 1));
      }
      return c;
    }

    Future<LtHolding> receive(List<int> raw, SVPrivateKey to, {List<int>? attestation, Transaction? anchorTx}) =>
        LtReceive.check(b: b, raw: raw, ownerPkh: pkhOf(to), anchorTx: anchorTx ?? anchor, attestation: attestation);

    Matcher refused(String why) => throwsA(isA<LtRefused>().having((e) => e.reason, 'reason', contains(why)));

    test('every transaction reads back from its raw bytes, record and all', () {
      final c = issued(4);
      for (final t in c) {
        final r = b.fromRaw(t.raw);
        expect(r.raw, t.raw);
        expect(r.rec, t.isIssuance ? t.headersAndSigs : t.rec, reason: 'an issuance carries no attestation');
      }
    });

    test('accepts a token paid to it, and holds what the next transfer needs', () async {
      final c = issued(3);
      final sw = Stopwatch()..start();
      final h = await receive(c[3].raw, key(3));
      print('payee check of hop 3 (${c[3].raw.length} B), script run included: ${sw.elapsedMilliseconds} ms');
      expect(h.tokenId, c[0].txid);
      expect(h.originId, c[0].txid);
      expect(h.out, outpoint(c[3].txid, 1));
      expect(h.tx.rec, c[3].rec);
      // the holding is enough to pay it on
      final next = b.transfer(from: h.tx, k: 1, ownerKey: key(3).lt, fund: coin(funder), outs: [LtOut(pkhOf(key(4)))]);
      verifyAll(next, c[3], code);
    });

    test('an issuance is accepted with its attestation, and refused without it', () async {
      final c = issued(0);
      expect((await receive(c[0].raw, key(0), attestation: iss.attest(c[0].txid))).tokenId, c[0].txid);
      expect(() => receive(c[0].raw, key(0)), refused('comes with its issuer attestation'));
      expect(() => receive(c[0].raw, key(0), attestation: iss.attest(sha256([1]))),
          refused('issuer: the issuer\'s Rabin signature does not verify'));
    });

    test('refuses a token paid to another key, and one under another anchor', () async {
      final c = issued(2);
      expect(() => receive(c[2].raw, key(9)), refused('not paid to this key'));
      final other = await anchorFor(Rabin.generateKeyPair(1024), seed: 6);
      expect(() => receive(c[2].raw, key(2), anchorTx: other), refused('issuer: the attestation names another anchor'));
    });

    test('refuses what is not a transfer of this code: a cheap-path spend, another script', () async {
      final c = issued(2);
      final f = b.transfer(from: c[2], k: 1, ownerKey: key(2).lt, fund: coin(funder), outs: [LtOut(pkhOf(key(3)))], cheap: true);
      expect(() => receive(f.raw, key(3)), refused('input 0 is not a normal-path spend'));
      final weak = LtScriptGen.nft.code(stepB: false).buffer;
      final bw = LtBuilder(L, weak);
      final w = bw.transfer(from: c[2], k: 1, ownerKey: key(2).lt, fund: coin(funder), outs: [LtOut(pkhOf(key(3)))]);
      expect(() => receive(w.raw, key(3)), refused('not the transaction its record rebuilds'));
    });

    test('refuses a parent its input does not spend, and a spend the script refuses', () async {
      final c = issued(2);
      final moved = b.transfer(from: c[2], k: 1, ownerKey: key(2).lt, fund: coin(funder), outs: [LtOut(pkhOf(key(3)))],
          in0Override: outpoint(sha256([5]), 1));
      expect(() => receive(moved.raw, key(3)), refused('input 0 does not spend the token output'));
      // the shape is right but the sender is not the owner: only the script says so
      final theirs = b.transfer(from: c[2], k: 1, ownerKey: attacker.lt, fund: coin(funder), outs: [LtOut(pkhOf(key(3)))]);
      expect(() => receive(theirs.raw, key(3)), refused('the token\'s script refuses the spend'));
      expect((await LtReceive.check(b: b, raw: theirs.raw, ownerPkh: pkhOf(key(3)), anchorTx: anchor, runScript: false)).tokenId,
          c[0].txid, reason: 'without the script run it passes: the network refuses it later');
    });
  });

  group('the issuer identity', () {
    test('a token issued under an identity anchor verifies against it, at the issuance and at hop 3', () async {
      final rabin = Rabin.generateKeyPair(1024);
      final anchor = await anchorFor(rabin);
      final iss = LtIdentity.issuer(rabin, anchor);
      expect(iss.identityTxId, h256(hex.decode(anchor.serialize())));
      final c = [issuance(b, by: iss)];
      for (var n = 1; n <= 3; n++) {
        c.add(hop(b, c.last, n - 1));
      }
      verifyAll(c[1], c[0], code);
      expect(await LtIdentity.verify(c[0], anchor), isNull);
      expect(await LtIdentity.verify(c[3], anchor), isNull);
    });

    test('attestationError: the script\'s own check, without the anchor', () {
      final c = chain(b, 1);
      expect(LtIdentity.attestationError(c[0]), isNull);
      expect(LtIdentity.attestationError(c[1]), isNull, reason: 'a transfer\'s record ends with it');
      final other = LtIssuer(Rabin.generateKeyPair(1024), sha256([1]), sha256([2]));
      c[0].x = other.attest(c[0].txid);
      expect(LtIdentity.attestationError(c[0]), 'the attestation is by another Rabin key');
      c[0].x = issuer.attest(sha256([3]));
      expect(LtIdentity.attestationError(c[0]), 'the issuer\'s Rabin signature does not verify');
      c[0].x = const [];
      expect(LtIdentity.attestationError(c[0]), 'the record has no issuer attestation');
    });

    test('refuses an anchor for another key, an attestation naming another anchor, and a tampered anchor', () async {
      final rabin = Rabin.generateKeyPair(1024);
      final anchor = await anchorFor(rabin);
      // an anchor that names another Rabin key: no issuer from it, and a token by this key does not verify against it
      final other = await anchorFor(Rabin.generateKeyPair(1024), seed: 1);
      expect(() => LtIdentity.issuer(rabin, other), throwsArgumentError);
      final t = hop(b, issuance(b, by: LtIdentity.issuer(rabin, anchor)), 0);
      expect(await LtIdentity.verify(t, other), isNotNull);
      // the issuer's attestation naming an identity txid that is not this anchor's
      final fake = LtIssuer(rabin, sha256([9]), hex.decode(IdentityAnchorBuilder.extractPublicKey(anchor)));
      expect(await LtIdentity.verify(hop(b, issuance(b, by: fake), 0), anchor), 'the attestation names another anchor');
      // the anchor's metadata changed after it was signed
      final tampered = Transaction.fromHex(anchor.serialize());
      tampered.outputs[1] = TransactionOutput(BigInt.zero,
          MapLockBuilder.fromMap({'app': 'tsl1', 'type': 'issuer_identity', ...LtIdentity.anchorMetadata(rabin, {'name': 'Someone Else'})}).getScriptPubkey());
      expect(await LtIdentity.verify(t, tampered), isNotNull);
    });
  });

  test('cannot be reset: the builder refuses, and the header has no attesters or flags', () {
    final c = chain(b, 2);
    expect(() => hop(b, c[2], 2, reset: c[2].rec), throwsArgumentError);
    expect(() => b.header(tokenId: c[2].tokenId, issuer: issuer.pkh, attesters: List.filled(20, 0), owner: pkhOf(key(1)),
        changeAmt: 1, changePkh: pkhOf(funder), in0: LtBuilder.zero36, fundIn: LtBuilder.zero36), throwsArgumentError);
    expect(L.size, 172);
  });

  test(
    'a chain past 65,535 bytes of record switches to the wide encodings and still verifies',
    () {
      final c = chain(b, 200);
      final cross = c.indexWhere((t) => t.rec.length > 0xffff);
      expect(cross, greaterThan(100));
      for (var n = cross - 1; n <= cross + 2; n++) {
        verifyAll(c[n + 1], c[n], code);
      }
    },
    timeout: const Timeout(Duration(minutes: 5)),
  );

  test('sizes', () {
    final c = chain(b, 20);
    print('script (after the separator): ${code.length} B');
    for (final iss in [true, false]) {
      final s = Stk(['rec', 'code']);
      LtScriptGen.nft.emitRebuild(s, 'rec', 'code', 'txid', issuance: iss);
      print('  one rebuild${iss ? ' (with the issuance branch)' : ''}: ${s.b.build().buffer.length} B');
    }
    print('locking script: ${c[0].lock(1, code).length} B (header ${L.size} B)');
    for (final n in [0, 1, 2, 3, 10, 20]) {
      print('hop ${n.toString().padLeft(3)}: ${c[n].raw.length.toString().padLeft(6)} B');
    }
    print(
      'growth per hop: ${c[11].raw.length - c[10].raw.length} B (record: ${c[11].rec.length - c[10].rec.length} B)',
    );
    expect(c[11].rec.length - c[10].rec.length, L.size + LtLayout.sigsTwo);
  });
}

/// An [LtKey] that signs as a wallet's transaction signer does: dartsv's
/// own sighash over the unsigned transaction, the script code and the
/// amount, never the builder's preimage (which it checks against).
class _TxSignerKey extends LtKey {
  final SVPrivateKey key;
  var signed = 0;
  _TxSignerKey(this.key);
  @override
  List<int> get pub => pubOf(key);
  @override
  List<int> sign(LtSigning s) {
    final tx = Transaction.fromHex(hex.encode(s.unsigned));
    final digest = hex.decode(Sighash().hash(tx, sighashAllForkId, s.input,
        SVScript.fromByteArray(Uint8List.fromList(s.scriptCode)), BigInt.from(s.sats))).reversed.toList();
    expect(digest, sha256Twice(s.preimage), reason: 'the preimage is the one the transaction makes');
    final i = tx.inputs[s.input];
    tx.inputs[s.input] = TransactionInput(i.prevTxnId, i.prevTxnOutputIndex, i.sequenceNumber,
        scriptBuilder: P2PKHUnlockBuilder(key.publicKey));
    DefaultTransactionSigner(sighashAllForkId, key).sign(
        tx, TransactionOutput(BigInt.from(s.sats), SVScript.fromByteArray(Uint8List.fromList(s.scriptCode))), s.input);
    signed++;
    return hex.decode(tx.inputs[s.input].scriptBuilder!.signatures.last.toTxFormat());
  }
}
