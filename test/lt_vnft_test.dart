// TSL1_LT_VNFT through the interpreter: the Voucher NFT, a Fuelled NFT with
// at most maxHops transfers, then only redemption to the issuer; a holder's
// redemption (fee capped) at any hop; the issuer's force-redemption after
// the expiry height; no burn. Reissue, succession, the payee, and the
// refusals.
//
// Run: dart test test/lt_vnft_test.dart
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

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x0f2e0000 + i));
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
  final b = FnftBuilder.voucher();
  final code = b.code;
  late RabinKeyPair rabin;
  late Transaction anchor;
  late LtIssuer issuer;
  setUpAll(() async {
    rabin = Rabin.generateKeyPair(1024);
    anchor = await anchorFor(rabin);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  VoucherTerms terms({int maxHops = 3, int expiry = 1000, int feeCap = 2000}) =>
      VoucherTerms(maxHops: maxHops, expiry: expiry, redeemTo: pkhOf(issuerKey), feeCap: feeCap);

  FnftTx issuance({int fuel = 50000, VoucherTerms? t}) {
    final i = b.issue(
        first: coin(issuerKey, fuel + 300), issuerPkh: issuer.pkh, owner: pkhOf(issuerKey), terms: t ?? terms(), fee: 300);
    i.x = issuer.attest(i.txid);
    return i;
  }

  SVPrivateKey ownerOf(int n) => n == 0 ? issuerKey : key(n);
  FnftTx hop(FnftTx from, int n, {LtCoin? topUp, List<int>? to, int? counter}) =>
      b.transfer(from: from, ownerKey: ownerOf(n).lt, to: to ?? pkhOf(key(n + 1)), fund: topUp, fee: 700, counterOverride: counter);

  void verify(FnftTx t, FnftTx from) => spend(t.raw, 0, from.lock(code), from.value);

  List<FnftTx> chain(int hops, {VoucherTerms? t}) {
    final c = [issuance(t: t)];
    for (var n = 1; n <= hops; n++) {
      c.add(hop(c.last, n - 1));
    }
    return c;
  }

  group('the hop limit', () {
    test('maxHops transfers verify, the counter counts them, then the builder refuses another', () {
      final c = chain(3);
      for (var n = 1; n <= 3; n++) {
        verify(c[n], c[n - 1]);
        expect(c[n].counter, n);
      }
      expect(c[3].hopsLeft, 0);
      expect(() => hop(c[3], 3), throwsArgumentError);
    });

    test('the script refuses a transfer past maxHops, a skipped count, and a repeated one', () {
      final c = chain(3);
      final past = hop(c[3], 3, counter: 4);
      expect(() => verify(past, c[3]), refused(), reason: 'the hop limit');
      final skip = hop(c[1], 1, counter: 3);
      expect(() => verify(skip, c[1]), refused());
      final same = hop(c[1], 1, counter: 1);
      expect(() => verify(same, c[1]), refused());
    });

    test('the script refuses a child with other terms', () {
      final c = chain(1);
      final longer = b.transfer(from: c[1], ownerKey: key(1).lt, to: pkhOf(key(2)), fee: 700,
          patchHeader: (h) => [...h.sublist(0, FuelLayout.vnft.maxHops), 200, ...h.sublist(FuelLayout.vnft.maxHops + 1)]);
      expect(() => verify(longer, c[1]), refused());
      final later = b.transfer(from: c[1], ownerKey: key(1).lt, to: pkhOf(key(2)), fee: 700,
          patchHeader: (h) => [...h.sublist(0, FuelLayout.vnft.expiry), ...le(999999, 4), ...h.sublist(FuelLayout.vnft.expiry + 4)]);
      expect(() => verify(later, c[1]), refused());
    });
  });

  group('the holder\'s redemption', () {
    test('at any hop, and forced at the limit: the issuer is paid, the fee within the cap', () {
      for (final hops in [1, 3]) {
        final c = chain(hops);
        final r = b.redeem(from: c[hops], ownerKey: key(hops).lt, fee: 400);
        spend(r, 0, c[hops].lock(code), c[hops].value);
        final out = Transaction.fromHex(hex.encode(r)).outputs.single;
        expect(hex.encode(out.script.buffer), hex.encode(p2pkh(pkhOf(issuerKey))));
        expect(out.satoshis.toInt(), c[hops].value - 400);
      }
    });

    test('a funding coin pays a fee beyond the cap; the token value goes to the issuer whole', () {
      final c = chain(2);
      expect(() => b.redeem(from: c[2], ownerKey: key(2).lt, fee: 2500), throwsArgumentError, reason: 'the cap is 2,000');
      final f = coin(funder, 5000);
      final r = b.redeem(from: c[2], ownerKey: key(2).lt, fund: f, fee: 2500);
      spend(r, 0, c[2].lock(code), c[2].value);
      spend(r, 1, p2pkh(f.pkh), f.sats);
    });

    test('refuses: a fee beyond the cap, a payment to anyone else, a non-owner, a burn', () {
      final c = chain(2);
      final greedy = b.redeem(from: c[2], ownerKey: key(2).lt, fee: 2500, checkCap: false);
      expect(() => spend(greedy, 0, c[2].lock(code), c[2].value), refused());
      final elsewhere = b.redeem(from: c[2], ownerKey: key(2).lt, fee: 400, payToOverride: pkhOf(key(2)));
      expect(() => spend(elsewhere, 0, c[2].lock(code), c[2].value), refused());
      final theirs = b.redeem(from: c[2], ownerKey: attacker.lt, fee: 400);
      expect(() => spend(theirs, 0, c[2].lock(code), c[2].value), refused());
      expect(() => b.end(from: c[2], ownerKey: key(2).lt, payTo: pkhOf(key(2))), throwsArgumentError);
      // a cheap-path spend (signature and key only), built as for the Fuelled NFT
      final burn = FnftBuilder(code).end(from: c[2], ownerKey: key(2).lt, payTo: pkhOf(key(2)), fee: 300);
      expect(() => spend(burn, 0, c[2].lock(code), c[2].value), refused());
    });
  });

  group('the issuer\'s force-redemption', () {
    test('after the expiry: the issuer\'s key, nLockTime at least the expiry, a non-final sequence', () {
      final c = chain(2);
      for (final lock in [1000, 5000]) {
        final f = b.forceRedeem(from: c[2], issuerKey: issuerKey.lt, lockHeight: lock, fee: 300);
        spend(f, 0, c[2].lock(code), c[2].value);
        final tx = Transaction.fromHex(hex.encode(f));
        expect(tx.nLockTime, lock);
        expect(tx.inputs.single.sequenceNumber, FnftBuilder.nonFinal);
        expect(tx.outputs.single.satoshis.toInt(), c[2].value - 300);
      }
    });

    test('refuses: before the expiry, a time instead of a height, a final sequence, another key, a wrong owner', () {
      final c = chain(2);
      final early = b.forceRedeem(from: c[2], issuerKey: issuerKey.lt, lockHeight: 999, fee: 300);
      expect(() => spend(early, 0, c[2].lock(code), c[2].value), refused());
      final time = b.forceRedeem(from: c[2], issuerKey: issuerKey.lt, lockHeight: 1700000000, fee: 300);
      expect(() => spend(time, 0, c[2].lock(code), c[2].value), refused());
      final finalSeq = b.forceRedeem(from: c[2], issuerKey: issuerKey.lt, fee: 300, sequence: 0xffffffff);
      expect(() => spend(finalSeq, 0, c[2].lock(code), c[2].value), refused());
      final theirs = b.forceRedeem(from: c[2], issuerKey: attacker.lt, fee: 300);
      expect(() => spend(theirs, 0, c[2].lock(code), c[2].value), refused());
      final wrongOwner = b.forceRedeem(from: c[2], issuerKey: issuerKey.lt, fee: 300, ownerOverride: pkhOf(attacker));
      expect(() => spend(wrongOwner, 0, c[2].lock(code), c[2].value), refused());
    });
  });

  group('records, the payee, reissue', () {
    test('every transaction is its record rebuilt; fromRecOf recovers the token from the record and the terms', () {
      final c = chain(3);
      for (final t in c) {
        expect(b.fromRec(t.isIssuance ? t.headerAndSigs : t.rec, prefix: t.prefix).raw, t.raw);
        expect(b.fromRaw(t.raw).raw, t.raw);
      }
      final g = b.fromRecOf(c[3].rec, issuer: issuer.pkh, owner: pkhOf(key(3)), terms: terms());
      expect(g.raw, c[3].raw);
      expect(c[3].rec.length - c[2].rec.length, FnftLayout.level(false), reason: 'terms and counter cost no growth');
    });

    test('the payee accepts a voucher and sees its hops left; refuses a non-owner signer', () async {
      final c = chain(2);
      final h = await FnftReceive.check(b: b, raw: c[2].raw, ownerPkh: pkhOf(key(2)), anchorTx: anchor);
      expect(h.tx.hopsLeft, 1);
      expect(h.tx.terms.expiry, 1000);
      final theirs = b.transfer(from: c[2], ownerKey: attacker.lt, to: pkhOf(key(3)), fee: 700);
      expect(() => FnftReceive.check(b: b, raw: theirs.raw, ownerPkh: pkhOf(key(3)), anchorTx: anchor),
          throwsA(isA<LtRefused>()));
    });

    test('redeemed or force-redeemed: the reissue (new terms) succeeds it; the payee follows the link', () async {
      for (final forced in [false, true]) {
        final c = chain(3);
        final e = forced
            ? b.forceRedeem(from: c[3], issuerKey: issuerKey.lt, fee: 300)
            : b.redeem(from: c[3], ownerKey: key(3).lt, fee: 300);
        spend(e, 0, c[3].lock(code), c[3].value);
        final next = terms(maxHops: 5, expiry: 2000);
        final r = b.reissue(ended: e, endKey: issuerKey.lt, issuerPkh: issuer.pkh, terms: next, fee: 300);
        r.x = issuer.attest(r.txid);
        spend(r.raw, 0, p2pkh(pkhOf(issuerKey)), Transaction.fromHex(hex.encode(e)).outputs[0].satoshis.toInt());
        expect(r.value, c[3].value - 300 - 300);
        expect(
            await FnftSuccession.verify(
                b: b, r: r, predecessor: c[0].txid, ended: e, recG: c[3].rec, anchorTx: anchor, terms: terms().bytes),
            isNull,
            reason: forced ? 'force-redeemed' : 'redeemed');
        final r1 = hop(r, 0, to: pkhOf(key(7)));
        verify(r1, r);
        final link = LtLink(e, c[3].rec, terms().bytes);
        final held = await FnftReceive.check(
            b: b, raw: r1.raw, ownerPkh: pkhOf(key(7)), anchorTx: anchor, links: LtLinks.decode(LtLinks.encode([link])));
        expect(held.originId, c[0].txid);
        expect(held.tx.terms.maxHops, 5);
        // without the predecessor's terms the record does not rebuild
        expect(
            await FnftSuccession.verify(
                b: b, r: r, predecessor: c[0].txid, ended: e, recG: c[3].rec, anchorTx: anchor, terms: next.bytes),
            isNotNull);
      }
    });
  });

  test('sizes', () {
    final c = chain(3);
    print('code ${code.length} B (Fuelled NFT ${const FnftScriptGen().code().buffer.length} B), '
        'lock ${c[0].lock(code).length} B (header ${FuelLayout.vnft.size} B)');
    print('issue ${c[0].raw.length} B, hop 1 ${c[1].raw.length} B, hop 3 ${c[3].raw.length} B, '
        'growth ${c[3].raw.length - c[2].raw.length} B');
    print('redeem ${b.redeem(from: c[3], ownerKey: key(3).lt, fee: 300).length} B, '
        'force-redeem ${b.forceRedeem(from: c[3], issuerKey: issuerKey.lt, fee: 300).length} B');
  });
}
