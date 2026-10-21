// TSL1_LT_FT through the interpreter: the fungible lineage token, its split,
// merge, reset, and the attacks each check refuses.
//
// Run: dart test test/lt_ft_test.dart
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_layout.dart';
import 'package:libtokensv/src/lt/lt_script_gen.dart';
import 'package:libtokensv/src/script_gen/stk.dart';

const L = LtLayout.ft;

final _builders = <String, LtBuilder>{};
LtBuilder bOf(List<int> code) => _builders.putIfAbsent(hex.encode(code), () => LtBuilder(L, code));

LtTx transferFt({
  required LtTx from,
  required int k,
  required LtKey ownerKey,
  required LtCoin fund,
  required List<LtOut> outs,
  required List<int> code,
  LtPassenger? passenger,
  List<int>? reset,
  bool cheap = false,
  int version = 1,
  List<int>? in0Override,
  List<int>? tokenIdOverride,
  List<int>? recPOverride,
  List<int>? passRecOverride,
  List<int> Function(List<int>)? patchH2,
}) => bOf(code).transfer(
  from: from,
  k: k,
  ownerKey: ownerKey,
  fund: fund,
  outs: outs,
  passenger: passenger,
  reset: reset,
  cheap: cheap,
  version: version,
  in0Override: in0Override,
  tokenIdOverride: tokenIdOverride,
  recPOverride: recPOverride,
  passRecOverride: passRecOverride,
  patchH2: patchH2,
);

LtTx issueFt(
  LtCoin first,
  LtCoin fund,
  List<int> issuerPkh,
  List<int> attesters,
  List<int> owner,
  int amount,
  List<int> code, {
  List<int> extra = const [],
}) => bOf(code).issue(
  first: first,
  fund: fund,
  issuerPkh: issuerPkh,
  attesters: attesters,
  owner: owner,
  amount: amount,
  extraOutputs: extra,
);

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
late List<LtAttester> attesters;
final funderLock = p2pkh(pkhOf(funder));

/// Verifies every input of [t], whose driver spends ([from], [k]) and whose
/// passenger, if any, is [p].
void verifyAll(LtTx t, LtTx from, int k, List<int> code, {LtPassenger? p}) {
  spend(t.raw, 0, from.lock(k, code), 1);
  if (p != null) spend(t.raw, 1, p.tx.lock(p.k, code), 1);
  spend(t.raw, p == null ? 1 : 2, funderLock, 100000);
}

/// An issuance of [amount] to key(0), attested by the issuer.
LtTx issuance(List<int> code, {int amount = 1000, LtIssuer? by, LtCoin? first}) {
  final iss = by ?? issuer;
  final t = issueFt(first ?? coin(key(0)), coin(funder), iss.pkh, attestersOf(attesters), pkhOf(key(0)), amount, code);
  t.x = iss.attest(t.txid);
  return t;
}

/// A single-output transfer of the whole amount from ([from], [k]), owned by key(n), to key(n + 1).
LtTx hop(LtTx from, int k, int n, List<int> code, {LtPassenger? p}) => transferFt(
  from: from,
  k: k,
  ownerKey: key(n).lt,
  fund: coin(funder),
  outs: [LtOut(pkhOf(key(n + 1)), from.amount(k) + (p == null ? 0 : p.tx.amount(p.k)))],
  code: code,
  passenger: p,
);

/// Issuance plus [hops] single-output transfers; hop n is owned by key(n).
List<LtTx> chain(int hops, List<int> code, {int amount = 1000}) {
  final out = [issuance(code, amount: amount)];
  for (var n = 1; n <= hops; n++) {
    out.add(hop(out.last, 1, n - 1, code));
  }
  return out;
}

void main() {
  final code = LtScriptGen.ft.code().buffer;

  setUpAll(() {
    issuer = LtIssuer(Rabin.generateKeyPair(1024), sha256([1]), sha256([2]));
    attesters = [
      LtAttester(issuer.key),
      LtAttester(Rabin.generateKeyPair(1024)),
      LtAttester(Rabin.generateKeyPair(1024)),
    ];
  });

  test('the script fits the 3-byte varint the preimage parse assumes', () {
    expect(code.length, inInclusiveRange(253, 0xffff));
  });

  test('an honest linear chain verifies on every input at every hop', () {
    final c = chain(8, code);
    for (var n = 1; n < c.length; n++) {
      verifyAll(c[n], c[n - 1], 1, code);
    }
    expect(c[1].tokenId, c[0].txid);
    expect(c[8].amount(1), 1000);
  });

  test('a split creates two token outputs, and both branches continue', () {
    final c = chain(2, code);
    final split = transferFt(
      from: c[2],
      k: 1,
      ownerKey: key(2).lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(key(3)), 300), LtOut(pkhOf(key(4)), 700)],
      code: code,
    );
    verifyAll(split, c[2], 1, code);
    final left = hop(split, 1, 3, code);
    verifyAll(left, split, 1, code);
    final right = hop(split, 2, 4, code);
    verifyAll(right, split, 2, code);
    expect(left.amount(1), 300);
    expect(right.amount(1), 700);
    final left2 = hop(left, 1, 4, code);
    verifyAll(left2, left, 1, code);
  });

  test('a merge: the driver absorbs the passenger and the amounts add', () {
    final c = chain(2, code);
    final split = transferFt(
      from: c[2],
      k: 1,
      ownerKey: key(2).lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(key(3)), 300), LtOut(pkhOf(key(4)), 700)],
      code: code,
    );
    final left = hop(split, 1, 3, code); // 300, owned by key(4)
    final right = hop(split, 2, 4, code); // 700, owned by key(5)
    final p = LtPassenger(right, 1, key(5).lt);
    final merged = hop(left, 1, 4, code, p: p);
    verifyAll(merged, left, 1, code, p: p);
    expect(merged.amount(1), 1000);
    final after = hop(merged, 1, 5, code);
    verifyAll(after, merged, 1, code);
    final after2 = hop(after, 1, 6, code);
    verifyAll(after2, after, 1, code);
  });

  test('the two outputs of a split can be merged straight back in one transaction', () {
    final c = chain(1, code);
    final s = transferFt(
      from: c[1],
      k: 1,
      ownerKey: key(1).lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(key(2)), 400), LtOut(pkhOf(key(2)), 600)],
      code: code,
    );
    final p = LtPassenger(s, 2, key(2).lt);
    final m = hop(s, 1, 2, code, p: p);
    verifyAll(m, s, 1, code, p: p);
    expect(m.amount(1), 1000);
    verifyAll(hop(m, 1, 3, code), m, 1, code);
  });

  test('a merge of merges carries the union of the lineages, once each', () {
    final c = chain(1, code);
    final s1 = transferFt(
      from: c[1],
      k: 1,
      ownerKey: key(1).lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(key(2)), 400), LtOut(pkhOf(key(2)), 600)],
      code: code,
    );
    verifyAll(s1, c[1], 1, code);
    final s2 = transferFt(
      from: s1,
      k: 1,
      ownerKey: key(2).lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(key(3)), 100), LtOut(pkhOf(key(3)), 300)],
      code: code,
    );
    verifyAll(s2, s1, 1, code);
    final s3 = transferFt(
      from: s1,
      k: 2,
      ownerKey: key(2).lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(key(3)), 200), LtOut(pkhOf(key(3)), 400)],
      code: code,
    );
    verifyAll(s3, s1, 2, code);
    // Four leaves: (s2,1)=100 (s2,2)=300 (s3,1)=200 (s3,2)=400, all key(3)'s.
    final pA = LtPassenger(s2, 2, key(3).lt);
    final mA = hop(s2, 1, 3, code, p: pA); // 400
    verifyAll(mA, s2, 1, code, p: pA);
    final pB = LtPassenger(s3, 2, key(3).lt);
    final mB = hop(s3, 1, 3, code, p: pB); // 600
    verifyAll(mB, s3, 1, code, p: pB);
    final pM = LtPassenger(mB, 1, key(4).lt);
    final m = hop(mA, 1, 4, code, p: pM); // 1000
    verifyAll(m, mA, 1, code, p: pM);
    expect(m.amount(1), 1000);
    final after = hop(m, 1, 5, code);
    verifyAll(after, m, 1, code);
    // Each merge's record is its own headers and signatures plus the two
    // parents' records: additive, not doubled.
    expect(mA.rec.length, L.size + LtLayout.sigsThree + s2.rec.length + s2.rec.length);
    expect(m.rec.length, L.size + LtLayout.sigsThree + mB.rec.length + mA.rec.length);
    final o = outpoint(after.txid, 1);
    final e = resetEvidence(
      c[0],
      attesters,
      attesters[0].attest(after.tokenId, o),
      attesters[1].attest(after.tokenId, o),
    );
    final r = transferFt(
      from: after,
      k: 1,
      ownerKey: key(6).lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(key(7)), 1000)],
      code: code,
      reset: e,
    );
    verifyAll(r, after, 1, code);
    // and each of them (issuance, split, merge with a passenger, reset) is
    // its record rebuilt
    final rb = LtBuilder(L, code);
    for (final t in [c[0], c[1], s1, s2, s3, mA, mB, m, after, r]) {
      expect(rb.fromRec(t.rec).raw, t.raw);
    }
    print(
      'merge of merges: leaf record ${s2.rec.length} B, first merge tx ${mA.raw.length} B, '
      'second merge tx ${m.raw.length} B, the hop after ${after.raw.length} B, a reset then ${r.raw.length} B',
    );
  });

  group('the passenger check', () {
    late List<LtTx> c;
    late LtCoin theirs;
    setUp(() {
      c = chain(3, code);
      theirs = coin(attacker);
    });

    /// A fabricated token transaction: input 0 is the attacker's own coin,
    /// output 1 holds the code with a header claiming a million, and its
    /// chain tail is a genuine record (so its own rebuild matches).
    LtTx fabricated(List<int> code) => transferFt(
      from: c[2],
      k: 1,
      ownerKey: attacker.lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(attacker), 1000000)],
      code: code,
      in0Override: theirs.out,
    );

    test('refuses a fabricated passenger, because its input 0 did not spend a token output (passenger step B)', () {
      final f = fabricated(code);
      final p = LtPassenger(f, 1, attacker.lt);
      final t = hop(c[3], 1, 3, code, p: p);
      expect(() => spend(t.raw, 0, c[3].lock(1, code), 1), refusedComparing(c[2].txid, theirs.out.sublist(0, 32)));
    });

    test('accepts it, and inflates the supply, once passenger step B is removed', () {
      final weak = LtScriptGen.ft.code(passengerB: false).buffer;
      final w = chain(3, weak);
      c = w;
      final f = fabricated(weak);
      final p = LtPassenger(f, 1, attacker.lt);
      final t = hop(w[3], 1, 3, weak, p: p);
      verifyAll(t, w[3], 1, weak, p: p);
      expect(t.amount(1), 1001000);
    });

    test('refuses a passenger created by a cheap-path spend (its rebuild cannot match)', () {
      // The owner of (c[3],1) spends it on the cheap path into a transaction
      // that claims a million. That spend is valid...
      final fund = coin(funder);
      final g = transferFt(
        from: c[3],
        k: 1,
        ownerKey: key(3).lt,
        fund: fund,
        outs: [LtOut(pkhOf(attacker), 1000000)],
        code: code,
        cheap: true,
      );
      spend(g.raw, 0, c[3].lock(1, code), 1);
      spend(g.raw, 1, funderLock, 100000);
      // ...but its output is no token: as a passenger it is refused, since the
      // rebuild assumes the normal path,
      final asIfNormal = transferFt(
        from: c[3],
        k: 1,
        ownerKey: key(3).lt,
        fund: fund,
        outs: [LtOut(pkhOf(attacker), 1000000)],
        code: code,
      );
      final d = chain(1, code);
      final p = LtPassenger(g, 1, attacker.lt);
      final t = hop(d[1], 1, 1, code, p: p);
      expect(() => spend(t.raw, 0, d[1].lock(1, code), 1), refusedComparing(asIfNormal.txid, g.txid));
      // and as a driver it is refused for the same reason (step A).
      final t2 = hop(g, 1, 9001, code);
      expect(() => spend(t2.raw, 0, g.lock(1, code), 1), refusedComparing(asIfNormal.txid, g.txid));
    });

    test('refuses a passenger of another token', () {
      final other = chain(1, code);
      final p = LtPassenger(other[1], 1, key(1).lt);
      final t = hop(c[3], 1, 3, code, p: p);
      expect(() => spend(t.raw, 0, c[3].lock(1, code), 1), refusedComparing(other[1].tokenId, c[3].tokenId));
    });

    test('refuses a passenger into the issuance\'s own output', () {
      final other = chain(1, code);
      final p = LtPassenger(other[1], 1, key(1).lt);
      final t = hop(c[0], 1, 0, code, p: p);
      expect(
        () => spend(t.raw, 0, c[0].lock(1, code), 1),
        anyOf(refusedWith(ScriptError.SCRIPT_ERR_VERIFY), refusedWith(ScriptError.SCRIPT_ERR_EQUALVERIFY)),
      );
    });

    test('a passenger cannot be absorbed without its owner\'s key', () {
      final other = hop(c[3], 1, 3, code); // owned by key(4)
      final split = transferFt(
        from: c[2],
        k: 1,
        ownerKey: key(2).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(5)), 500), LtOut(pkhOf(key(6)), 500)],
        code: code,
      );
      final p = LtPassenger(other, 1, attacker.lt);
      final t = hop(split, 1, 5, code, p: p);
      expect(
        () => spend(t.raw, 1, other.lock(1, code), 1),
        anyOf(refusedWith(ScriptError.SCRIPT_ERR_EQUALVERIFY), refusedWith(ScriptError.SCRIPT_ERR_SIG_NULLFAIL)),
      );
    });
  });

  group('the amounts', () {
    test('cannot be inflated', () {
      final c = chain(2, code);
      final t = transferFt(
        from: c[2],
        k: 1,
        ownerKey: key(2).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(3)), 1001)],
        code: code,
      );
      expect(() => spend(t.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY));
      final s = transferFt(
        from: c[2],
        k: 1,
        ownerKey: key(2).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(3)), 600), LtOut(pkhOf(key(4)), 600)],
        code: code,
      );
      expect(() => spend(s.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY));
    });

    test('cannot be negative', () {
      final c = chain(2, code);
      final s = transferFt(
        from: c[2],
        k: 1,
        ownerKey: key(2).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(3)), 1001), LtOut(pkhOf(key(4)), -1)],
        code: code,
      );
      expect(() => spend(s.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_VERIFY));
    });
  });

  group('a split', () {
    test('needs both headers to describe the same transaction', () {
      final c = chain(2, code);
      final s = transferFt(
        from: c[2],
        k: 1,
        ownerKey: key(2).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(3)), 500), LtOut(pkhOf(key(4)), 500)],
        code: code,
        patchH2: (h) => [...h]..setRange(L.in0, L.in0 + 32, sha256([9])),
      );
      expect(
        () => spend(s.raw, 0, c[2].lock(1, code), 1),
        refusedComparing(s.h1.sublist(L.shared2), s.h2!.sublist(L.shared2)),
      );
    });
  });

  group('the lineage', () {
    test('a fabricated driver parent is refused (step B), and accepted once step B is removed', () {
      final c = chain(3, code);
      final theirs = coin(attacker);
      final f = transferFt(
        from: c[2],
        k: 1,
        ownerKey: attacker.lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(attacker), 1000000)],
        code: code,
        in0Override: theirs.out,
      );
      final t = hop(f, 1, 9001, code);
      expect(() => spend(t.raw, 0, f.lock(1, code), 1), refusedComparing(c[2].txid, theirs.out.sublist(0, 32)));

      final weak = LtScriptGen.ft.code(stepB: false).buffer;
      final w = chain(3, weak);
      final fw = transferFt(
        from: w[2],
        k: 1,
        ownerKey: attacker.lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(attacker), 1000000)],
        code: weak,
        in0Override: theirs.out,
      );
      final tw = hop(fw, 1, 9001, weak);
      verifyAll(tw, fw, 1, weak);
    });

    test('a verbatim copy of a token output cannot be spent (step A)', () {
      final c = chain(2, code);
      final theirs = coin(attacker);
      final raw = Uint8List.fromList([
        ...le(1, 4), 1, ...theirs.out, 0, 0xff, 0xff, 0xff, 0xff, //
        1, ...bOf(code).tokenOut(c[2].h1), ...le(0, 4),
      ]);
      final clone = LtTx(L, c[2].h1, null, c[2].sigs, c[2].x, raw);
      final t = hop(clone, 1, 2, code);
      expect(() => spend(t.raw, 0, clone.lock(1, code), 1), refusedComparing(c[2].txid, clone.txid));
    });

    test('a token cannot be relabelled', () {
      final c = chain(2, code);
      final t = transferFt(
        from: c[2],
        k: 1,
        ownerKey: key(2).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(3)), 1000)],
        code: code,
        tokenIdOverride: sha256([7]),
      );
      expect(() => spend(t.raw, 0, c[2].lock(1, code), 1), refusedComparing(c[2].tokenId, sha256([7])));
    });

    test('a transfer cannot be made without the owner\'s key', () {
      final c = chain(2, code);
      final t = transferFt(
        from: c[2],
        k: 1,
        ownerKey: attacker.lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(attacker), 1000)],
        code: code,
      );
      expect(() => spend(t.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_EQUALVERIFY));
      final cheap = transferFt(
        from: c[2],
        k: 1,
        ownerKey: attacker.lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(attacker), 1000)],
        code: code,
        cheap: true,
      );
      expect(() => spend(cheap.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_EQUALVERIFY));
    });

    test('a version 2 transfer is refused', () {
      final c = chain(2, code);
      final t = transferFt(
        from: c[2],
        k: 1,
        ownerKey: key(2).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(3)), 1000)],
        code: code,
        version: 2,
      );
      expect(() => spend(t.raw, 0, c[2].lock(1, code), 1), refusedComparing([2, 0, 0, 0], [1, 0, 0, 0]));
    });

    test('a relayer cannot alter the child header: every signature covers it', () {
      final c = chain(2, code);
      final t = hop(c[2], 1, 2, code);
      final h = [...t.h1]..setRange(L.changePkh, L.in0, pkhOf(attacker));
      final body = t.raw.length - 4 - bOf(code).tokenOut(t.h1).length;
      final patched = [...t.raw.sublist(0, body), ...bOf(code).tokenOut(h), ...le(0, 4)];
      expect(
        () => spend(patched, 0, c[2].lock(1, code), 1),
        anyOf(refusedWith(ScriptError.SCRIPT_ERR_VERIFY), refusedWith(ScriptError.SCRIPT_ERR_SIG_NULLFAIL)),
      );
      expect(() => spend(patched, 1, funderLock, 100000), refusedWith(ScriptError.SCRIPT_ERR_SIG_NULLFAIL));
    });
  });

  group('the issuance', () {
    test('cannot be activated by anyone but the issuer', () {
      final c = chain(0, code);
      final other = LtIssuer(Rabin.generateKeyPair(1024), issuer.identityTxId, issuer.ed25519PubKey);
      c[0].x = other.attest(c[0].txid);
      final t = hop(c[0], 1, 0, code);
      expect(() => spend(t.raw, 0, c[0].lock(1, code), 1), refusedComparing(other.pkh, issuer.pkh));
    });

    test('cannot be activated with a replayed attestation', () {
      final genuine = chain(0, code);
      final counterfeit = chain(0, code);
      counterfeit[0].x = issuer.attest(genuine[0].txid);
      final t = hop(counterfeit[0], 1, 0, code);
      expect(
        () => spend(t.raw, 0, counterfeit[0].lock(1, code), 1),
        refusedWith(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY),
      );
    });

    test('is accepted with a foreign attestation once the Rabin check is removed', () {
      final weak = LtScriptGen.ft.code(issuerCheck: false).buffer;
      final c = chain(0, weak);
      final other = LtIssuer(Rabin.generateKeyPair(1024), issuer.identityTxId, issuer.ed25519PubKey);
      c[0].x = other.attest(c[0].txid);
      final t = hop(c[0], 1, 0, weak);
      verifyAll(t, c[0], 1, weak);
    });

    test('must have the shape later hops can rebuild', () {
      final malformed = issueFt(
        coin(key(0)),
        coin(funder),
        issuer.pkh,
        attestersOf(attesters),
        pkhOf(key(0)),
        1000,
        code,
        extra: [...le(1, 8), 0x19, ...p2pkh(pkhOf(key(0)))],
      );
      malformed.x = issuer.attest(malformed.txid);
      final t = hop(malformed, 1, 0, code);
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

  group('a reset', () {
    /// Evidence for ([t], [k]) of the token [iss] issued, signed by attesters [i] and [j].
    List<int> evidence(
      LtTx iss,
      LtTx t,
      int k, {
      int i = 0,
      int j = 1,
      List<LtAttester>? list,
      LtAttester? by,
      bool corrupt = false,
    }) {
      final o = outpoint(t.txid, k);
      return resetEvidence(
        iss,
        list ?? attesters,
        (by ?? attesters[i]).attest(t.tokenId, o, corrupt: corrupt),
        attesters[j].attest(t.tokenId, o),
      );
    }

    LtTx reset(LtTx from, int k, int n, List<int> code, List<int> e, {LtPassenger? p}) => transferFt(
      from: from,
      k: k,
      ownerKey: key(n).lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(key(n + 1)), from.amount(k) + (p == null ? 0 : p.tx.amount(p.k)))],
      code: code,
      passenger: p,
      reset: e,
    );

    test('drops the chain: the reset hop and the two after it verify, and the growth restarts', () {
      final c = chain(10, code);
      final r = reset(c[10], 1, 10, code, evidence(c[0], c[10], 1));
      verifyAll(r, c[10], 1, code);
      final r1 = hop(r, 1, 11, code);
      verifyAll(r1, r, 1, code);
      final r2 = hop(r1, 1, 12, code);
      verifyAll(r2, r1, 1, code);
      expect(r.rec.length, L.size + LtLayout.sigsTwo + L.resetEvidence);
      expect(r2.rec.length - r1.rec.length, L.size + LtLayout.sigsTwo);
      final normal = hop(c[10], 1, 10, code);
      print(
        'reset at hop 10: hop 10 ${c[10].raw.length} B, a normal hop 11 ${normal.raw.length} B, '
        'the reset hop ${r.raw.length} B, then ${r1.raw.length} B and ${r2.raw.length} B',
      );
    });

    test('accepts either pair of attesters', () {
      final c = chain(2, code);
      for (final pair in [(0, 2), (1, 2), (1, 0)]) {
        final r = reset(c[2], 1, 2, code, evidence(c[0], c[2], 1, i: pair.$1, j: pair.$2));
        verifyAll(r, c[2], 1, code);
      }
    });

    test('a reset transaction can be a passenger, and its reset is checked there', () {
      final c = chain(1, code);
      final s = transferFt(
        from: c[1],
        k: 1,
        ownerKey: key(1).lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(key(2)), 400), LtOut(pkhOf(key(2)), 600)],
        code: code,
      );
      final a = hop(s, 1, 2, code);
      final b = hop(s, 2, 2, code);
      final rb = reset(b, 1, 3, code, evidence(c[0], b, 1));
      final p = LtPassenger(rb, 1, key(4).lt);
      final m = hop(a, 1, 3, code, p: p);
      verifyAll(m, a, 1, code, p: p);
      expect(m.amount(1), 1000);
      expect(m.rec.length, L.size + LtLayout.sigsThree + rb.rec.length + a.rec.length);
      // A reset that consensus would have refused (corrupt evidence) is
      // refused again when its output is offered as a passenger.
      final rbBad = reset(b, 1, 3, code, evidence(c[0], b, 1, corrupt: true));
      final pBad = LtPassenger(rbBad, 1, key(4).lt);
      final bad = hop(a, 1, 3, code, p: pBad);
      expect(() => spend(bad.raw, 0, a.lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY));
    });

    test('refuses one attester twice', () {
      final c = chain(2, code);
      final r = reset(c[2], 1, 2, code, evidence(c[0], c[2], 1, i: 1, j: 1));
      expect(() => spend(r.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_VERIFY));
    });

    test('refuses a signer outside the list', () {
      final c = chain(2, code);
      final outsider = LtAttester(Rabin.generateKeyPair(1024));
      final r = reset(c[2], 1, 2, code, evidence(c[0], c[2], 1, by: outsider));
      expect(() => spend(r.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_VERIFY));
    });

    test('refuses a list other than the one the header commits to', () {
      final c = chain(2, code);
      final outsider = LtAttester(Rabin.generateKeyPair(1024));
      final list = [attesters[0], attesters[1], outsider];
      final r = reset(c[2], 1, 2, code, evidence(c[0], c[2], 1, list: list));
      expect(() => spend(r.raw, 0, c[2].lock(1, code), 1), refusedComparing(attestersOf(list), attestersOf(attesters)));
    });

    test('refuses a corrupted signature, and an attestation for another outpoint', () {
      final c = chain(2, code);
      final r = reset(c[2], 1, 2, code, evidence(c[0], c[2], 1, corrupt: true));
      expect(() => spend(r.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY));
      final other = reset(c[2], 1, 2, code, evidence(c[0], c[1], 1));
      expect(() => spend(other.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY));
    });

    test('refuses the reset flag over an ordinary record', () {
      final c = chain(2, code);
      final r = reset(c[2], 1, 2, code, c[2].rec);
      expect(() => spend(r.raw, 0, c[2].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_EQUALVERIFY));
    });

    test('refuses a reset of the issuance\'s output', () {
      final c = chain(0, code);
      final r = reset(c[0], 1, 0, code, evidence(c[0], c[0], 1));
      expect(() => spend(r.raw, 0, c[0].lock(1, code), 1), refusedWith(ScriptError.SCRIPT_ERR_VERIFY));
    });

    test('two dishonest attesters can duplicate the token: the trust cost', () {
      final c = chain(2, code);
      final theirs = coin(attacker);
      final f = transferFt(
        from: c[2],
        k: 1,
        ownerKey: attacker.lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(attacker), 1000000)],
        code: code,
        in0Override: theirs.out,
      );
      final r = reset(f, 1, 9001, code, evidence(c[0], f, 1));
      verifyAll(r, f, 1, code);
      expect(r.amount(1), 1000000);
      verifyAll(hop(r, 1, 9002, code), r, 1, code);
    });

    test('refuses a stranger with three keys of their own: the attesters come from the issuance, not the header', () {
      // Without the issuance in the evidence this passed (recorded 9.1): the
      // list was checked against the spent header, which a reset does not
      // verify. The stranger's header still names the issuer, but commits to
      // their own list, and the issuance it must rebuild commits to ours.
      final c = chain(2, code);
      final mine = [for (var i = 0; i < 3; i++) LtAttester(Rabin.generateKeyPair(1024))];
      final seed = issueFt(coin(attacker), coin(funder), issuer.pkh, attestersOf(mine), pkhOf(attacker), 1000, code);
      final f = transferFt(
        from: seed,
        k: 1,
        ownerKey: attacker.lt,
        fund: coin(funder),
        outs: [LtOut(pkhOf(attacker), 1000000)],
        code: code,
        in0Override: coin(attacker).out,
        tokenIdOverride: c[2].tokenId,
      );
      final o = outpoint(f.txid, 1);
      final e = resetEvidence(c[0], mine, mine[0].attest(f.tokenId, o), mine[1].attest(f.tokenId, o));
      final r = reset(f, 1, 9001, code, e);
      expect(
        () => spend(r.raw, 0, f.lock(1, code), 1),
        refusedComparing(c[0].h1.sublist(L.issuer, L.flags), f.h1.sublist(L.issuer, L.flags)),
      );
    });

    test('refuses evidence built on another issuance, even one with the same attesters', () {
      final c = chain(2, code);
      final other = chain(0, code)[0];
      final r = reset(c[2], 1, 2, code, evidence(other, c[2], 1));
      expect(() => spend(r.raw, 0, c[2].lock(1, code), 1), refusedComparing(other.txid, c[2].tokenId));
    });
  });

  test('sizes', () {
    final c = chain(20, code);
    print('script (after the separator): ${code.length} B');
    for (final iss in [true, false]) {
      final s = Stk(['rec', 'code']);
      LtScriptGen.ft.emitRebuild(s, 'rec', 'code', 'txid', issuance: iss);
      print('  one rebuild${iss ? ' (with the issuance branch)' : ''}: ${s.b.build().buffer.length} B');
    }
    {
      final s = Stk(['e', 'target', 'H', 'code']);
      LtScriptGen.ft.emitAttest(s, 'e', 'target');
      print('  one attestation check (two of three): ${s.b.build().buffer.length} B; evidence ${L.resetEvidence} B');
    }
    print('locking script: ${c[0].lock(1, code).length} B (header ${L.size} B)');
    for (final n in [0, 1, 2, 3, 10, 20]) {
      print('hop ${n.toString().padLeft(3)}: ${c[n].raw.length.toString().padLeft(6)} B');
    }
    print(
      'growth per hop: ${c[11].raw.length - c[10].raw.length} B (record: ${c[11].rec.length - c[10].rec.length} B)',
    );
    expect(c[11].rec.length - c[10].rec.length, L.size + LtLayout.sigsTwo);

    // Two lineages of ten hops each from one split, merged, then carried on.
    final root = chain(1, code, amount: 2000);
    final fork = transferFt(
      from: root[1],
      k: 1,
      ownerKey: key(1).lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(key(2)), 1000), LtOut(pkhOf(key(2)), 1000)],
      code: code,
    );
    List<LtTx> branch(int k) {
      final out = [hop(fork, k, 2, code)];
      for (var n = 3; n < 12; n++) {
        out.add(hop(out.last, 1, n, code));
      }
      return out;
    }

    final a = branch(1), b = branch(2);
    final split = transferFt(
      from: c[20],
      k: 1,
      ownerKey: key(20).lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(key(21)), 500), LtOut(pkhOf(key(22)), 500)],
      code: code,
    );
    final p = LtPassenger(b.last, 1, key(12).lt);
    final merged = transferFt(
      from: a.last,
      k: 1,
      ownerKey: key(12).lt,
      fund: coin(funder),
      outs: [LtOut(pkhOf(key(13)), 2000)],
      code: code,
      passenger: p,
    );
    verifyAll(merged, a.last, 1, code, p: p);
    final after = hop(merged, 1, 13, code);
    verifyAll(after, merged, 1, code);
    final alone = hop(a.last, 1, 12, code);
    print('split of hop 20: ${split.raw.length} B');
    print(
      'merge of two tokens ten hops past a split: ${merged.raw.length} B (one of them transferred alone: ${alone.raw.length} B); the hop after: ${after.raw.length} B',
    );
  });
}
