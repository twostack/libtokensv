@Tags(['localnet'])
library;

// The sale versions (WITNESS_LINEAGE_RESEARCH.md 9.13) on a real node:
// TSL1_LT_FNFT_S, _VNFT_S and _NOTE_S. A token issued, distributed, sold for
// 30,000 sats in its own transfer (the buyer's coin pays the price and the
// fee), and moved on by the buyer; the Voucher then redeemed and the Note
// exited by the next holder: every transaction mined.
//
//   LT_LOCALNET=1 dart test test/lt_fnft_sale_localnet_test.dart
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
import 'localnet.dart';

final env = Platform.environment;
SVPrivateKey key(int i) => SVPrivateKey.fromBigInt(BigInt.from(0x5a1f0000 + i));
Address addressOf(SVPrivateKey k) => Address.fromPublicKey(k.publicKey, NetworkType.TEST);
Transaction txOf(List<int> raw) => Transaction.fromHex(hex.encode(raw));

void main() {
  final skip = env['LT_LOCALNET'] == null ? 'set LT_LOCALNET=1 with ../localnet running' : false;
  const t = Timeout(Duration(minutes: 10));
  test('a Fuelled NFT sold in its own transfer, on localnet', () => run(FnftBuilder.saleable(), null, 0), skip: skip, timeout: t);
  test(
    'a Voucher NFT sold, then redeemed by the next holder, on localnet',
    () => run(FnftBuilder.saleableVoucher(), (pkh) => VoucherTerms(maxHops: 5, expiry: 100000, redeemTo: pkh, feeCap: 2000), 10),
    skip: skip,
    timeout: t,
  );
  test(
    'an issuer\'s early forced redemption blocks a voucher\'s sale; a transfer to self clears it, then the sale is mined',
    () => run(FnftBuilder.saleableVoucher(), (pkh) => VoucherTerms(maxHops: 5, expiry: 100000, redeemTo: pkh, feeCap: 2000), 30,
        early: true),
    skip: skip,
    timeout: t,
  );
  test(
    'a Note NFT sold, then exited by the next holder, on localnet',
    () => run(FnftBuilder.saleableNote(), (pkh) => NoteTerms.deposit(payTo: pkh, feeCap: 500, at: 100000, early: 1000), 20),
    skip: skip,
    timeout: t,
  );
}

Future<void> run(FnftBuilder b, FuelTerms Function(List<int> issuerPkh)? termsFor, int k, {bool early = false}) async {
  final net = Localnet(viaRpc: env['LT_BROADCAST'] == 'rpc');
  await net.ready();
  final issuerKey = key(100 + k), seller = key(1 + k), buyer = key(2 + k);
  final rabin = Rabin.generateKeyPair(1024);

  Future<LtCoin> coinFor(SVPrivateKey k, int sats) async {
    final tx = await net.fund(addressOf(k), BigInt.from(sats));
    final vout = tx.outputs.indexWhere((o) => hex.encode(o.script.buffer) == hex.encode(p2pkh(pkhOf(k))));
    return LtCoin(outpoint(h256(hex.decode(tx.serialize())), vout), k.lt, tx.outputs[vout].satoshis.toInt());
  }

  final sigHashAll = SighashType.SIGHASH_ALL.value | SighashType.SIGHASH_FORKID.value;
  final iAddr = addressOf(issuerKey);
  final seed = await net.fund(iAddr, BigInt.from(100000));
  final seedVout = seed.outputs.indexWhere((o) => hex.encode(o.script.buffer) == hex.encode(p2pkh(pkhOf(issuerKey))));
  final anchorFunding = TransactionBuilder()
      .spendFromTxnWithSigner(
        DefaultTransactionSigner(sigHashAll, issuerKey),
        seed,
        seedVout,
        TransactionInput.MAX_SEQ_NUMBER,
        P2PKHUnlockBuilder(issuerKey.publicKey),
      )
      .spendToLockBuilder(P2PKHLockBuilder.fromAddress(iAddr), BigInt.from(546))
      .spendToLockBuilder(P2PKHLockBuilder.fromAddress(iAddr), BigInt.from(99000))
      .sendChangeToPKH(iAddr)
      .withFeePerKb(1)
      .build(false);
  await net.submit('fund anchor', anchorFunding);
  final ed = Ed25519();
  final wand = await ed.newSignatureWandFromKeyPair(await ed.newKeyPairFromSeed(List<int>.generate(32, (i) => 0xa0 + i)));
  final anchorTx = await IdentityAnchorBuilder(
    LtIdentity.anchorMetadata(rabin, {'name': 'Localnet Sale Issuer'}),
  ).buildTransaction(anchorFunding, DefaultTransactionSigner(sigHashAll, issuerKey), issuerKey.publicKey, iAddr, wand);
  await net.submit('anchor', anchorTx);
  final issuer = LtIdentity.issuer(rabin, anchorTx);

  final iss = b.issue(
    first: await coinFor(issuerKey, 5000),
    issuerPkh: issuer.pkh,
    owner: pkhOf(issuerKey),
    terms: termsFor?.call(pkhOf(issuerKey)),
    satsPerKb: 1,
  );
  iss.x = issuer.attest(iss.txid);
  await net.submit('issue', txOf(iss.raw));
  final t1 = b.transfer(from: iss, ownerKey: issuerKey.lt, to: pkhOf(seller), satsPerKb: 1);
  await net.submit('distribute', txOf(t1.raw));

  const price = 30000, fee = 20;
  final buyerCoin = await coinFor(buyer, price + fee);
  var from = t1;
  if (early) {
    Future<String> send(List<int> raw) =>
        net.rpc('sendrawtransaction', [hex.encode(raw)]).then((_) => 'accepted', onError: (e) => '$e'.split('\n').first);
    // the issuer sends a forced redemption long before the expiry
    final f = b.forceRedeem(from: t1, issuerKey: issuerKey.lt, fee: 300);
    print('early forced redemption: ${await send(f)}');
    final blocked = b.transfer(from: t1, ownerKey: seller.lt, to: pkhOf(buyer), fund: buyerCoin, fee: fee, pay: (pkhOf(seller), price));
    final refused = await send(blocked.raw);
    print('the sale while it waits: $refused');
    expect(refused, contains('txn-mempool-conflict'));
    from = b.transfer(from: t1, ownerKey: seller.lt, to: pkhOf(seller), satsPerKb: 1);
    await net.submit('transfer to self', txOf(from.raw));
    print('the early forced redemption sent again: ${await send(f)}');
  }
  final sale = b.transfer(
    from: from,
    ownerKey: seller.lt,
    to: pkhOf(buyer),
    fund: buyerCoin,
    fee: fee,
    pay: (pkhOf(seller), price),
  );
  await net.submit('sale', txOf(sale.raw));
  expect(txOf(sale.raw).outputs[1].satoshis.toInt(), price);
  expect(sale.value, from.value);
  final holder = key(3 + k);
  final next = b.transfer(from: sale, ownerKey: buyer.lt, to: pkhOf(holder), satsPerKb: 1);
  await net.submit('hop after the sale', txOf(next.raw));
  final held = await FnftReceive.check(b: b, raw: next.raw, ownerPkh: pkhOf(holder), anchorTx: anchorTx);
  expect(hex.encode(held.tokenId), hex.encode(iss.txid));
  var end = '';
  if (b.L.voucher) {
    final r = b.redeem(from: next, ownerKey: holder.lt, fee: 300);
    await net.submit('redeem', txOf(r));
    end = ', redemption ${r.length} B';
  } else if (b.L.isNote) {
    final x = b.exit(from: next, ownerKey: holder.lt, fee: 300);
    await net.submit('exit', txOf(x));
    end = ', exit ${x.length} B';
  }
  print('${b.L.name}: code ${b.code.length} B; sale ${sale.raw.length} B, the next hop ${next.raw.length} B$end');
}
