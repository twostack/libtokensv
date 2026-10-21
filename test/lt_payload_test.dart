// The payload transaction (WITNESS_LINEAGE_RESEARCH.md 9.11): content bound
// to a token through its issuance's input 1, in the covenant, Fuelled and
// Voucher NFT, with no script change. Also gate G3 (a funded Fuelled or
// Voucher issuance on a payload coin) and gate G4 (an 8-byte all-ones
// amount is a negative script number) of docs/RUGGERBOT_TOKENS_PLAN.md.
//
// Run: dart test test/lt_payload_test.dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_fnft_builder.dart';
import 'package:libtokensv/src/lt/lt_fnft_wallet.dart';
import 'package:libtokensv/src/lt/lt_identity.dart';
import 'package:libtokensv/src/lt/lt_layout.dart';
import 'package:libtokensv/src/lt/lt_payload.dart';
import 'package:libtokensv/src/lt/lt_script_gen.dart';
import 'package:libtokensv/src/lt/lt_wallet.dart';

import 'lt_nft_test.dart' as nft show anchorFor;

final flags = {
  VerifyFlag.SIGHASH_FORKID,
  VerifyFlag.LOW_S,
  VerifyFlag.NULLFAIL,
  VerifyFlag.MINIMALDATA,
  VerifyFlag.MINIMALIF,
  VerifyFlag.SIGPUSHONLY,
  VerifyFlag.UTXO_AFTER_GENESIS,
};

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x9a710000 + i));
var _coin = 0;
LtCoin coin(SVPrivateKey k, [int sats = 100000]) => LtCoin(outpoint(sha256(le(++_coin, 4)), _coin % 3), k.lt, sats);

void spend(List<int> raw, int i, List<int> lock, int sats) {
  final tx = Transaction.fromHex(hex.encode(raw));
  Interpreter().correctlySpends(
      tx.inputs[i].script!, SVScript.fromByteArray(Uint8List.fromList(lock)), tx, i, flags, Coin.valueOf(BigInt.from(sats)));
}

Matcher refused(String why) => throwsA(isA<LtRefused>().having((e) => e.reason, 'reason', contains(why)));

void main() {
  late Transaction anchor;
  late LtIssuer issuer;
  final issuerKey = key(1), funder = key(9);
  final content = utf8.encode('{"name":"Ruggerbot Badge #1","image":"sha256:00ff"}');

  setUpAll(() async {
    final rabin = Rabin.generateKeyPair(1024);
    anchor = await nft.anchorFor(rabin, seed: 21);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  group('the covenant NFT', () {
    final code = LtScriptGen.nft.code().buffer;
    final b = LtBuilder(LtLayout.nft, code);

    /// An issuance whose input 1 is a payload transaction's output 1.
    (List<int>, LtTx) issued(List<int> payload) {
      final (pRaw, pCoin) = LtPayload.build(coin: coin(issuerKey), payload: payload, fundSats: 5000);
      final iss = b.issue(first: coin(issuerKey), fund: pCoin, issuerPkh: issuer.pkh, owner: pkhOf(issuerKey));
      iss.x = issuer.attest(iss.txid);
      return (pRaw, iss);
    }

    List<LtTx> hops(LtTx iss, int n) {
      final c = [iss];
      for (var i = 1; i <= n; i++) {
        final owner = i == 1 ? issuerKey : key(100 + i - 1);
        c.add(b.transfer(from: c.last, k: 1, ownerKey: owner.lt, fund: coin(funder), outs: [LtOut(pkhOf(key(100 + i)))]));
      }
      return c;
    }

    test('the payload reads back at hop 1 and hop 20 from the token\'s transaction and the payload transaction', () async {
      final (pRaw, iss) = issued(content);
      spend(iss.raw, 1, p2pkh(pkhOf(issuerKey)), 5000);
      final c = hops(iss, 20);
      for (final n in [1, 20]) {
        spend(c[n].raw, 0, c[n - 1].lock(1, code), 1);
        final held = await LtReceive.check(b: b, raw: c[n].raw, ownerPkh: pkhOf(key(100 + n)), anchorTx: anchor, payloadTx: pRaw);
        expect(utf8.decode(held.payload!), utf8.decode(content));
      }
      final plain = await LtReceive.check(b: b, raw: c[1].raw, ownerPkh: pkhOf(key(101)), anchorTx: anchor);
      expect(plain.payload, isNull, reason: 'without the payload transaction the holding is valid and has no payload');
    });

    test('refuses: a changed byte, another transaction, an output 0 that is not data, an ordinary coin', () {
      final (pRaw, iss) = issued(content);
      final changed = [...pRaw]..[pRaw.length - 60] ^= 1;
      expect(() => LtPayload.of(iss.raw, changed), refused('not the one the issuance\'s input 1 spends'));
      final (otherRaw, _) = LtPayload.build(coin: coin(issuerKey), payload: content, fundSats: 5000);
      expect(() => LtPayload.of(iss.raw, otherRaw), refused('not the one the issuance\'s input 1 spends'));

      // a "payload" transaction whose output 0 is a P2PKH coin
      final c0 = coin(issuerKey);
      final outs = cat([
        [...le(1000, 8), 0x19, ...p2pkh(pkhOf(issuerKey))],
        [...le(5000, 8), 0x19, ...p2pkh(pkhOf(issuerKey))],
      ]);
      final sig = signInput(c0.key, prevouts: c0.out, input: 0, scriptCode: p2pkh(c0.pkh), sats: c0.sats, outputs: outs, nOut: 2);
      final ss = [...push(sig), ...push(c0.pub)];
      final notData = cat([le(1, 4), [1], c0.out, varint(ss.length), ss, le(0xffffffff, 4), [2], outs, le(0, 4)]);
      final iss2 = b.issue(
          first: coin(issuerKey), fund: LtCoin(outpoint(h256(notData), 1), issuerKey.lt, 5000), issuerPkh: issuer.pkh,
          owner: pkhOf(issuerKey));
      expect(() => LtPayload.of(iss2.raw, notData), refused('not OP_FALSE OP_RETURN'));

      // an issuance funded by an ordinary coin carries no payload; the token is valid
      final plain = b.issue(first: coin(issuerKey), fund: coin(funder), issuerPkh: issuer.pkh, owner: pkhOf(issuerKey));
      expect(() => LtPayload.of(plain.raw, pRaw), refused('not the one the issuance\'s input 1 spends'));
    });

    test('a reissue on a new payload: the link verifies and the holding carries the new payload', () async {
      final (_, iss) = issued(content);
      final c = hops(iss, 2);
      // back to the issuer, ended, reissued on a new payload
      final back = b.transfer(from: c.last, k: 1, ownerKey: key(102).lt, fund: coin(funder), outs: [LtOut(pkhOf(issuerKey))]);
      final ended = b.end(from: back, k: 1, ownerKey: issuerKey.lt, fund: coin(funder), changePkh: pkhOf(issuerKey));
      final next = utf8.encode('{"name":"Ruggerbot Badge #1, season 2"}');
      final (p2Raw, p2Coin) = LtPayload.build(coin: coin(issuerKey), payload: next, fundSats: 5000);
      final r = b.reissue(ended: ended, endKey: issuerKey.lt, fund: p2Coin, issuerPkh: issuer.pkh, owner: pkhOf(issuerKey));
      r.x = issuer.attest(r.txid);
      final d = b.transfer(from: r, k: 1, ownerKey: issuerKey.lt, fund: coin(funder), outs: [LtOut(pkhOf(key(300)))]);
      final held = await LtReceive.check(
          b: b, raw: d.raw, ownerPkh: pkhOf(key(300)), anchorTx: anchor, links: [LtLink(ended, back.rec)], payloadTx: p2Raw);
      expect(hex.encode(held.originId), hex.encode(iss.txid));
      expect(utf8.decode(held.payload!), utf8.decode(next));
    });

    test('the builder refuses an empty or oversized payload and an unfunded coin', () {
      expect(() => LtPayload.build(coin: coin(issuerKey), payload: const [], fundSats: 5000), throwsArgumentError);
      expect(() => LtPayload.build(coin: coin(issuerKey), payload: List.filled(LtPayload.maxPayload + 1, 1), fundSats: 5000),
          throwsArgumentError);
      expect(() => LtPayload.build(coin: coin(issuerKey, 5500), payload: content, fundSats: 5000), throwsArgumentError);
    });
  });

  group('gate G3: the Fuelled and the Voucher NFT', () {
    for (final (name, b, terms) in [
      ('Fuelled', FnftBuilder.standard(), null),
      ('Voucher', FnftBuilder.voucher(), VoucherTerms(maxHops: 3, expiry: 1000, redeemTo: pkhOf(key(1)), feeCap: 500)),
    ]) {
      test('$name: a funded issuance on a payload coin verifies, transfers, and reads back', () async {
        final (pRaw, pCoin) = LtPayload.build(coin: coin(issuerKey), payload: content, fundSats: 20000);
        final iss = b.issue(first: coin(issuerKey), fund: pCoin, issuerPkh: issuer.pkh, owner: pkhOf(issuerKey), terms: terms);
        iss.x = issuer.attest(iss.txid);
        spend(iss.raw, 1, p2pkh(pkhOf(issuerKey)), 20000);
        final t1 = b.transfer(from: iss, ownerKey: issuerKey.lt, to: pkhOf(key(200)), satsPerKb: 1);
        spend(t1.raw, 0, iss.lock(b.code), iss.value);
        final t2 = b.transfer(from: t1, ownerKey: key(200).lt, to: pkhOf(key(201)), satsPerKb: 1);
        spend(t2.raw, 0, t1.lock(b.code), t1.value);
        final held = await FnftReceive.check(b: b, raw: t2.raw, ownerPkh: pkhOf(key(201)), anchorTx: anchor, payloadTx: pRaw);
        expect(utf8.decode(held.payload!), utf8.decode(content));
        expect(iss.value, 100000 + 20000 - 1000, reason: 'the payload coin is fuel like any other');
      });
    }
  });

  test('gate G4: an 8-byte all-ones amount is a negative script number', () {
    final allOnes = List<int>.filled(8, 0xff);
    // PUSH(ff*8) OP_0 OP_LESSTHAN: true when the number is negative
    final lock = SVScript.fromByteArray(Uint8List.fromList([8, ...allOnes, OpCodes.OP_0, OpCodes.OP_LESSTHAN]));
    final tx = Transaction.fromHex(hex.encode(cat([
      le(1, 4), [1], List.filled(36, 0), [0], le(0xffffffff, 4), [1], le(0, 8), [1], [OpCodes.OP_TRUE], le(0, 4),
    ])));
    Interpreter().correctlySpends(SVScript(), lock, tx, 0, flags, Coin.valueOf(BigInt.zero));
  });
}
