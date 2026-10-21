// TSL1_LT_FNFT through the interpreter: the Fuelled NFT pays its fees from
// the token's value; top-ups, running dry, the burn, reissue and succession,
// the payee's check, and the refusals.
//
// Run: dart test test/lt_fnft_test.dart
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:libtokensv/src/builder/identity_anchor_builder.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_fnft_builder.dart';
import 'package:libtokensv/src/lt/lt_fnft_script_gen.dart';
import 'package:libtokensv/src/lt/lt_fnft_wallet.dart';
import 'package:libtokensv/src/lt/lt_identity.dart';
import 'package:libtokensv/src/lt/lt_wallet.dart';

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x0f0e0000 + i));
final funder = key(9000), attacker = key(9001), issuerKey = key(100);
var _c = 0;
LtCoin coin(SVPrivateKey k, [int sats = 100000]) => LtCoin(outpoint(sha256(le(++_c, 4)), 0), k.lt, sats);

final flags = {
  VerifyFlag.SIGHASH_FORKID,
  VerifyFlag.LOW_S,
  VerifyFlag.NULLFAIL,
  VerifyFlag.MINIMALDATA,
  VerifyFlag.MINIMALIF,
  VerifyFlag.SIGPUSHONLY,
  VerifyFlag.UTXO_AFTER_GENESIS,
};

void spend(List<int> raw, int i, List<int> lock, int sats) {
  final tx = Transaction.fromHex(hex.encode(raw));
  expect(tx.serialize(), hex.encode(raw), reason: 'dartsv must round-trip the bytes');
  Interpreter().correctlySpends(
      tx.inputs[i].script!, SVScript.fromByteArray(Uint8List.fromList(lock)), tx, i, flags, Coin.valueOf(BigInt.from(sats)));
}

Matcher refused() => throwsA(isA<ScriptException>());
Matcher refusedBy(String why) => throwsA(isA<LtRefused>().having((e) => e.reason, 'reason', contains(why)));

Future<Transaction> anchorFor(RabinKeyPair rabin, {int seed = 0}) async {
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
  return IdentityAnchorBuilder(LtIdentity.anchorMetadata(rabin, {'name': 'Test Issuer'})).buildTransaction(
      funding, DefaultTransactionSigner(SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value, k), k.publicKey,
      address, wand);
}

void main() {
  final b = FnftBuilder.standard();
  final code = b.code;
  late RabinKeyPair rabin;
  late Transaction anchor;
  late LtIssuer issuer;
  setUpAll(() async {
    rabin = Rabin.generateKeyPair(1024);
    anchor = await anchorFor(rabin);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  /// Issued to the issuer's own key with [fuel] sats.
  FnftTx issuance({int fuel = 50000, LtCoin? fund}) {
    final t = b.issue(first: coin(issuerKey, fuel + 300), fund: fund, issuerPkh: issuer.pkh, owner: pkhOf(issuerKey), fee: 300);
    t.x = issuer.attest(t.txid);
    return t;
  }

  SVPrivateKey ownerOf(int n) => n == 0 ? issuerKey : key(n);

  /// hop n: owned by ownerOf(n), to key(n + 1).
  FnftTx hop(FnftTx from, int n, {LtCoin? topUp, int fee = 700, List<int>? to}) =>
      b.transfer(from: from, ownerKey: ownerOf(n).lt, to: to ?? pkhOf(key(n + 1)), fund: topUp, fee: fee);

  void verify(FnftTx t, FnftTx from, {LtCoin? topUp}) {
    spend(t.raw, 0, from.lock(code), from.value);
    if (topUp != null) spend(t.raw, 1, p2pkh(topUp.pkh), topUp.sats);
  }

  List<FnftTx> chain(int hops, {int fuel = 50000}) {
    final c = [issuance(fuel: fuel)];
    for (var n = 1; n <= hops; n++) {
      c.add(hop(c.last, n - 1));
    }
    return c;
  }

  group('the fuel', () {
    test('hops with no funding input: the token pays its own fees, and every hop verifies', () {
      final c = chain(8);
      for (var n = 1; n <= 8; n++) {
        verify(c[n], c[n - 1]);
      }
      expect(c[8].value, 50000 - 8 * 700);
      final tx = Transaction.fromHex(hex.encode(c[8].raw));
      expect(tx.inputs, hasLength(1));
      expect(tx.outputs, hasLength(1));
    });

    test('a top-up sweeps a coin into the token; the hops after it verify at every depth', () {
      final c = [issuance(fuel: 2000)];
      c.add(hop(c.last, 0));
      verify(c[1], c[0]);
      final f = coin(funder, 30000);
      c.add(hop(c.last, 1, topUp: f));
      verify(c[2], c[1], topUp: f);
      expect(c[2].value, 2000 - 700 - 700 + 30000);
      for (var n = 3; n <= 6; n++) {
        c.add(hop(c.last, n - 1));
        verify(c.last, c[n - 1]);
      }
    });

    test('a funded issuance, and its first hops', () {
      final f = coin(funder, 40000);
      final t = issuance(fuel: 1000, fund: f);
      expect(t.value, 1000 + 40000);
      final h1 = hop(t, 0);
      verify(h1, t);
      verify(hop(h1, 1), h1);
    });

    test('a fee rate prices the transaction by its size, from the fuel', () {
      final c = chain(2);
      final t = b.transfer(from: c[2], ownerKey: key(2).lt, to: pkhOf(key(3)), satsPerKb: 100);
      expect(c[2].value - t.value, LtBuilder.feeFor(t.raw.length, 100));
      verify(t, c[2]);
    });

    test('running dry: no transfer is built; a top-up still moves it; the owner burns it and takes the value', () {
      final c = chain(1, fuel: 1500);
      verify(c[1], c[0]);
      expect(() => hop(c[1], 1, fee: 900), throwsArgumentError);
      final f = coin(funder, 5000);
      verify(hop(c[1], 1, topUp: f, fee: 900), c[1], topUp: f);
      final e = b.end(from: c[1], ownerKey: key(1).lt, payTo: pkhOf(key(1)), fee: 300);
      spend(e, 0, c[1].lock(code), c[1].value);
      final tx = Transaction.fromHex(hex.encode(e));
      expect(tx.inputs, hasLength(1));
      expect(tx.outputs.single.satoshis.toInt(), 800 - 300);
      final theirs = b.end(from: c[1], ownerKey: attacker.lt, payTo: pkhOf(attacker), fee: 300);
      expect(() => spend(theirs, 0, c[1].lock(code), c[1].value), refused());
    });
  });

  group('refuses', () {
    test('a transfer by anyone but the owner', () {
      final c = chain(1);
      final t = b.transfer(from: c[1], ownerKey: attacker.lt, to: pkhOf(attacker), fee: 700);
      expect(() => spend(t.raw, 0, c[1].lock(code), c[1].value), refused());
    });

    test('a relabelled token', () {
      final c = chain(1);
      final t = b.transfer(from: c[1], ownerKey: key(1).lt, to: pkhOf(key(2)), fee: 700, tokenIdOverride: sha256([7]));
      expect(() => spend(t.raw, 0, c[1].lock(code), c[1].value), refused());
    });

    test('a changed byte in either record level, and a false funded flag', () {
      final c = chain(3);
      FnftTx with_(List<int> rec) => b.transfer(from: c[3], ownerKey: key(3).lt, to: pkhOf(key(4)), fee: 700, recOverride: rec);
      final own = [...c[3].rec]..[5] ^= 1;
      expect(() => spend(with_(own).raw, 0, c[3].lock(code), c[3].value), refused());
      final deep = [...c[3].rec]..[FnftLayout.level(false) + 20] ^= 1;
      expect(() => spend(with_(deep).raw, 0, c[3].lock(code), c[3].value), refused());
      final flag = [...c[3].rec]..[0] = FnftLayout.flagFunded;
      expect(() => spend(with_(flag).raw, 0, c[3].lock(code), c[3].value), refused());
    });

    test('a child header with a stray funding outpoint, or flags other than 0 and 1', () {
      final c = chain(1);
      final stray = b.transfer(from: c[1], ownerKey: key(1).lt, to: pkhOf(key(2)), fee: 700,
          patchHeader: (h) => [...h.sublist(0, FnftLayout.fundIn), ...List.filled(36, 7)]);
      expect(() => spend(stray.raw, 0, c[1].lock(code), c[1].value), refused());
      final two = b.transfer(from: c[1], ownerKey: key(1).lt, to: pkhOf(key(2)), fee: 700,
          patchHeader: (h) => [...h.sublist(0, FnftLayout.flags), 2, ...h.sublist(FnftLayout.flags + 1)]);
      expect(() => spend(two.raw, 0, c[1].lock(code), c[1].value), refused());
    });

    test('an issuance attested by another key', () {
      final t = issuance();
      t.x = LtIssuer(Rabin.generateKeyPair(1024), sha256([1]), sha256([2])).attest(t.txid);
      expect(() => spend(hop(t, 0).raw, 0, t.lock(code), t.value), refused());
    });

    test('an input 0 that spent something else than the parent its record names; accepted once step B is removed', () {
      for (final strict in [true, false]) {
        final gen = strict ? code : const FnftScriptGen().code(stepB: false).buffer;
        final fb = FnftBuilder(gen);
        final t = fb.issue(first: coin(issuerKey, 50300), issuerPkh: issuer.pkh, owner: pkhOf(issuerKey), fee: 300);
        t.x = issuer.attest(t.txid);
        final c1 = fb.transfer(from: t, ownerKey: issuerKey.lt, to: pkhOf(key(1)), fee: 700);
        final f = fb.transfer(from: c1, ownerKey: key(1).lt, to: pkhOf(key(2)), fee: 700, in0Override: coin(attacker).out);
        final next = fb.transfer(from: f, ownerKey: key(2).lt, to: pkhOf(key(3)), fee: 700);
        if (strict) {
          expect(() => spend(next.raw, 0, f.lock(gen), f.value), refused());
        } else {
          spend(next.raw, 0, f.lock(gen), f.value);
        }
      }
    });
  });

  group('records', () {
    test('every transaction is its record rebuilt, and reads back from its raw bytes', () {
      final c = chain(3);
      final f = coin(funder, 9000);
      c.add(hop(c.last, 3, topUp: f));
      c.add(hop(c.last, 4));
      for (final t in c) {
        expect(b.fromRec(t.isIssuance ? t.headerAndSigs : t.rec, prefix: t.prefix).raw, t.raw);
        final r = b.fromRaw(t.raw);
        expect(r.raw, t.raw);
        expect(r.rec, t.isIssuance ? t.headerAndSigs : t.rec);
      }
      // fromRecOf recovers the token id from the record alone
      final last = c.last;
      final rebuilt = b.fromRecOf(last.rec, issuer: issuer.pkh, owner: pkhOf(key(6)));
      expect(rebuilt.tokenId, c[0].txid);
    });

    test('a plain level is 152 B; a top-up level 295 B', () {
      final c = chain(3);
      expect(c[3].rec.length - c[2].rec.length, FnftLayout.level(false));
      final d = hop(c[3], 3, topUp: coin(funder, 1000));
      expect(d.rec.length - c[3].rec.length, FnftLayout.level(true), reason: 'the top-up level is the topped-up transaction\'s own');
      final e = hop(d, 4);
      expect(e.rec.length - d.rec.length, FnftLayout.level(false));
      expect(FnftLayout.level(false), 152);
      expect(FnftLayout.level(true), 295);
    });
  });

  Future<FnftHolding> receive(List<int> raw, SVPrivateKey to, {List<LtLink> links = const []}) =>
      FnftReceive.check(b: b, raw: raw, ownerPkh: pkhOf(to), anchorTx: anchor, links: links);

  group('the payee', () {
    test('accepts a token paid to it, and holds what the next transfer needs', () async {
      final c = chain(3);
      final h = await receive(c[3].raw, key(3));
      expect(h.tokenId, c[0].txid);
      expect(h.value, c[3].value);
      final next = b.transfer(from: h.tx, ownerKey: key(3).lt, to: pkhOf(key(4)), fee: 700);
      verify(next, c[3]);
    });

    test('refuses: another key, a non-owner signer, an issuance, another anchor', () async {
      final c = chain(2);
      expect(() => receive(c[2].raw, key(9)), refusedBy('not paid to this key'));
      final theirs = b.transfer(from: c[2], ownerKey: attacker.lt, to: pkhOf(key(3)), fee: 700);
      expect(() => receive(theirs.raw, key(3)), refusedBy('input 0 does not spend the token output'));
      expect(() => receive(c[0].raw, issuerKey), refusedBy('an issuance comes with its issuer attestation'));
      final other = await anchorFor(Rabin.generateKeyPair(1024), seed: 3);
      expect(() => FnftReceive.check(b: b, raw: c[2].raw, ownerPkh: pkhOf(key(2)), anchorTx: other),
          refusedBy('issuer: the attestation names another anchor'));
    });
  });

  group('redeem and reissue', () {
    /// X: issued, 2 hops, redeemed to the issuer (G); E ends it; R reissues
    /// it to the issuer, fuelled by E's output 0.
    ({List<FnftTx> x, Uint8List e, FnftTx r}) lifecycle() {
      final c = chain(2);
      c.add(hop(c.last, 2, to: pkhOf(issuerKey)));
      final e = b.end(from: c.last, ownerKey: issuerKey.lt, payTo: pkhOf(issuerKey), fee: 200);
      final r = b.reissue(ended: e, endKey: issuerKey.lt, issuerPkh: issuer.pkh, fee: 300);
      r.x = issuer.attest(r.txid);
      return (x: c, e: e, r: r);
    }

    Future<String?> check(FnftTx r, List<int> pred, List<int> e, List<int> recG, {Transaction? anchorTx}) =>
        FnftSuccession.verify(b: b, r: r, predecessor: pred, ended: e, recG: recG, anchorTx: anchorTx ?? anchor);

    test('the end returns the fuel on output 0; the successor is fuelled by it; every spend verifies', () async {
      final l = lifecycle();
      final g = l.x.last;
      spend(l.e, 0, g.lock(code), g.value);
      final e0 = Transaction.fromHex(hex.encode(l.e)).outputs[0].satoshis.toInt();
      expect(e0, g.value - 200);
      spend(l.r.raw, 0, p2pkh(pkhOf(issuerKey)), e0);
      expect(l.r.value, e0 - 300);
      final r1 = hop(l.r, 0, to: pkhOf(key(5)));
      verify(r1, l.r);
      expect(await check(l.r, l.x[0].txid, l.e, g.rec), isNull);
    });

    test('the payee follows the link to the origin', () async {
      final l = lifecycle();
      final r1 = hop(l.r, 0, to: pkhOf(key(5)));
      final link = LtLink(l.e, l.x.last.rec);
      final h = await receive(r1.raw, key(5), links: LtLinks.decode(LtLinks.encode([link])));
      expect(h.tokenId, l.r.txid);
      expect(h.originId, l.x[0].txid);
    });

    test('refuses: the record of another transaction, a continued token, another predecessor, a tampered record, another issuer',
        () async {
      final l = lifecycle();
      final g = l.x.last;
      expect(await check(l.r, l.x[0].txid, l.e, l.x[1].rec), 'the record is not of the transaction the ended transaction spent');
      // E that continued the token on the normal path
      final cont = hop(g, 0, to: pkhOf(issuerKey));
      final rc = b.issue(first: LtCoin(outpoint(cont.txid, 0), issuerKey.lt, cont.value), issuerPkh: issuer.pkh,
          owner: pkhOf(issuerKey), fee: 300);
      rc.x = issuer.attest(rc.txid);
      expect(await check(rc, l.x[0].txid, cont.raw, g.rec), 'the ended transaction\'s input 0 is not a cheap-path spend');
      // another predecessor, a tampered record
      expect(await check(l.r, sha256([9]), l.e, g.rec), 'the ended token is not the predecessor');
      final bad = [...g.rec]..[10] ^= 1;
      expect(await check(l.r, l.x[0].txid, l.e, bad), 'the record is not of the transaction the ended transaction spent');
      // another issuer
      final otherRabin = Rabin.generateKeyPair(1024);
      final otherAnchor = await anchorFor(otherRabin, seed: 4);
      final other = LtIdentity.issuer(otherRabin, otherAnchor);
      final theirs = b.reissue(ended: l.e, endKey: issuerKey.lt, issuerPkh: other.pkh, fee: 300);
      theirs.x = other.attest(theirs.txid);
      expect(await check(theirs, l.x[0].txid, l.e, g.rec, anchorTx: otherAnchor),
          'the record is not of the transaction the ended transaction spent');
    });
  });

  test('sizes', () {
    final c = chain(21);
    print('code ${code.length} B, lock ${c[0].lock(code).length} B (header ${FnftLayout.size} B)');
    for (final n in [0, 1, 2, 10, 20]) {
      print('hop ${n.toString().padLeft(2)}: ${c[n].raw.length} B, value ${c[n].value}');
    }
    print('growth per plain hop: ${c[21].raw.length - c[20].raw.length} B (record level ${c[21].rec.length - c[20].rec.length} B)');
    expect(c[21].rec.length - c[20].rec.length, FnftLayout.level(false));
  });
}
