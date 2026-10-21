// Research spike (docs/RUGGERBOT_TOKENS_PLAN.md, P6; WITNESS_LINEAGE_RESEARCH.md
// 9.14): TSL1_LT_LNFT, the covenant NFT with a price anyone may pay. The
// owner lists by a signed hop that sets the price; anyone buys by spending
// it with no signature (PUSH(pre) OP_0 OP_0 PUSH(C)), paying the owner at
// least the price at output 0, the token to whom the buyer names, unlisted.
//
// Run: dart test test/lt_lnft_test.dart
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:test/test.dart';
import 'package:libtokensv/src/crypto/rabin.dart';
import 'package:libtokensv/src/lt/lt_builder.dart';
import 'package:libtokensv/src/lt/lt_identity.dart';
import 'package:libtokensv/src/lt/lt_layout.dart';
import 'package:libtokensv/src/lt/lt_script_gen.dart';
import 'package:libtokensv/src/lt/lt_swap.dart';
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

SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x11570000 + i));
var _coin = 0;
LtCoin coin(SVPrivateKey k, [int sats = 100000]) => LtCoin(outpoint(sha256(le(++_coin, 4)), _coin % 3), k.lt, sats);

void spend(List<int> raw, int i, List<int> lock, int sats) {
  final tx = Transaction.fromHex(hex.encode(raw));
  Interpreter().correctlySpends(
      tx.inputs[i].script!, SVScript.fromByteArray(Uint8List.fromList(lock)), tx, i, flags, Coin.valueOf(BigInt.from(sats)));
}

Matcher refused() => throwsA(isA<ScriptException>());

void main() {
  final code = LtScriptGen.lnft.code().buffer;
  final b = LtBuilder(LtLayout.lnft, code);
  late Transaction anchor;
  late LtIssuer issuer;
  final funder = key(9), owner = key(1), stranger = key(2);
  const price = 25000;

  setUpAll(() async {
    final rabin = Rabin.generateKeyPair(1024);
    anchor = await nft.anchorFor(rabin, seed: 51);
    issuer = LtIdentity.issuer(rabin, anchor);
  });

  /// An issuance, distributed to the owner, and listed by the owner at
  /// [at] (a transfer to its own key with a price).
  List<LtTx> listed({int at = price, LtBuilder? builder}) {
    final bb = builder ?? b;
    final iss = bb.issue(first: coin(key(0)), fund: coin(funder), issuerPkh: issuer.pkh, owner: pkhOf(key(0)));
    iss.x = issuer.attest(iss.txid);
    final t1 = bb.transfer(from: iss, k: 1, ownerKey: key(0).lt, fund: coin(funder), outs: [LtOut(pkhOf(owner))]);
    final l = bb.transfer(from: t1, k: 1, ownerKey: owner.lt, fund: coin(funder), outs: [LtOut(pkhOf(owner))], price: at);
    spend(l.raw, 0, t1.lock(1, bb.code), 1);
    return [iss, t1, l];
  }

  test('the code: the NFT and FT code unchanged beside it', () {
    expect(code.length, 2417);
    expect(LtScriptGen.nft.code().buffer.length, 2231);
    expect(LtLayout.lnft.size, 180);
  });

  test('list, a stranger buys, the buyer moves it on: every input verifies; a purchase rebuilds two hops later', () async {
    final c = listed();
    expect(c.last.price, price);
    final buy = b.buy(from: c.last, fund: coin(stranger, price + 400), newOwner: pkhOf(stranger));
    spend(buy.raw, 0, c.last.lock(1, code), 1);
    spend(buy.raw, 1, p2pkh(pkhOf(stranger)), price + 400);
    final tx = Transaction.fromHex(hex.encode(buy.raw));
    expect((tx.outputs[0].satoshis.toInt(), hex.encode(tx.outputs[0].script.buffer)), (price, hex.encode(p2pkh(pkhOf(owner)))));
    expect(buy.bought, isTrue);
    expect(hex.encode(b.fromRaw(buy.raw).raw), hex.encode(buy.raw), reason: 'a purchase reads back');
    final n1 = b.transfer(from: buy, k: 1, ownerKey: stranger.lt, fund: coin(funder), outs: [LtOut(pkhOf(key(5)))]);
    spend(n1.raw, 0, buy.lock(1, code), 1);
    final n2 = b.transfer(from: n1, k: 1, ownerKey: key(5).lt, fund: coin(funder), outs: [LtOut(pkhOf(key(6)))]);
    spend(n2.raw, 0, n1.lock(1, code), 1);
    final held = await LtReceive.check(b: b, raw: n2.raw, ownerPkh: pkhOf(key(6)), anchorTx: anchor);
    expect(hex.encode(held.tokenId), hex.encode(c.first.txid));
    print('sizes: listing ${c.last.raw.length} B, purchase ${buy.raw.length} B, next hop ${n1.raw.length} B; '
        'growth ${n1.rec.length - buy.rec.length} B per hop');
  });

  test('refused: one sat under the price, another payee, an unlisted token, a buyer leaving it listed', () {
    final c = listed();
    for (final buy in [
      b.buy(from: c.last, fund: coin(stranger, price + 400), newOwner: pkhOf(stranger), pay: price - 1),
      b.buy(from: c.last, fund: coin(stranger, price + 400), newOwner: pkhOf(stranger), payToOverride: pkhOf(stranger)),
      b.buy(from: c.last, fund: coin(stranger, price + 400), newOwner: pkhOf(stranger), childPrice: price),
    ]) {
      expect(() => spend(buy.raw, 0, c.last.lock(1, code), 1), refused());
    }
    final unlisted = listed(at: 0);
    final free = b.buy(from: unlisted.last, fund: coin(stranger, 400), newOwner: pkhOf(stranger), pay: 1);
    expect(() => spend(free.raw, 0, unlisted.last.lock(1, code), 1), refused());
  });

  test('with the unlisted-child rule removed, a buyer\'s leftover listing lets the next stranger take it', () {
    final weak = LtScriptGen.weakened(LtLayout.lnft, childUnlisted: false).code().buffer;
    final wb = LtBuilder(LtLayout.lnft, weak);
    final c = listed(builder: wb);
    final careless = wb.buy(from: c.last, fund: coin(stranger, price + 400), newOwner: pkhOf(stranger), childPrice: price);
    spend(careless.raw, 0, c.last.lock(1, weak), 1);
    final taken = wb.buy(from: careless, fund: coin(key(7), price + 400), newOwner: pkhOf(key(7)));
    spend(taken.raw, 0, careless.lock(1, weak), 1);
  });

  test('a counterfeit listing written by a stranger cannot be bought (step B)', () {
    final c = listed();
    final theirs = coin(stranger);
    final fake = b.transfer(
        from: c[1], k: 1, ownerKey: stranger.lt, fund: coin(funder), outs: [LtOut(pkhOf(stranger))], in0Override: theirs.out, price: 1);
    final buy = b.buy(from: fake, fund: coin(key(8), 400), newOwner: pkhOf(key(8)));
    expect(() => spend(buy.raw, 0, fake.lock(1, code), 1), refused());
  });

  test('a withdrawal and a purchase of one outpoint both verify alone (the network takes one); a swap ignores the price', () {
    final c = listed();
    final withdraw = b.transfer(from: c.last, k: 1, ownerKey: owner.lt, fund: coin(funder), outs: [LtOut(pkhOf(owner))]);
    spend(withdraw.raw, 0, c.last.lock(1, code), 1);
    expect(withdraw.price, 0);
    final buy = b.buy(from: c.last, fund: coin(stranger, price + 400), newOwner: pkhOf(stranger));
    spend(buy.raw, 0, c.last.lock(1, code), 1);

    final swap = LtSwap(b);
    final fund = coin(stranger, 10400);
    final t = LtSwapTerms(
        tokenTx: c.last.raw, payTo: pkhOf(owner), price: 10000, fundOut: fund.out, fundSats: fund.sats, fundPub: fund.pub,
        newOwner: pkhOf(stranger));
    final s = swap.assemble(t, seller: owner.lt, buyer: stranger.lt);
    spend(s.raw, 0, c.last.lock(1, code), 1);
  });
}
