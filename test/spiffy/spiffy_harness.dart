// A real libspiffy wallet for the plugin tests: the actor system on a
// temporary Isar store, ARC stubbed (it takes every transaction and mines
// nothing), and the steps a host takes: create a wallet, give it coins, make
// a plugin payment, settle it. Every input of every transaction the tests see
// is run through the script interpreter (checkInputs).
// ignore_for_file: implementation_imports
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dactor/dactor.dart';
import 'package:dartsv/dartsv.dart' as dartsv;
import 'package:isar_community/isar.dart';
import 'package:libspiffy/coordinator.dart' as coord;
import 'package:libspiffy/libspiffy.dart';
// ignore: implementation_imports
import 'package:libspiffy/src/utils/extended_format.dart';
import 'package:libspiffy/src/core/wallet_commands.dart';
import 'package:test/test.dart';

const testXpriv =
    'tprv8ZgxMBicQKsPeMiDjtXBGAyFY1wEMGgomjwf54ZmiZfKTNYvVdBa6GqWUwnvtHm6NKVkQkhCKxaobd9JPxNEXgDfVgJ5RNHJ3ivogSG3V1R';

/// ARC with no network behind it: publishes a 100 sat/kB policy, takes
/// every transaction, and knows the ones it took.
class StubArc extends ArcService {
  final submitted = <String>[];
  StubArc() : super(baseUrl: 'fake://arc');

  @override
  Future<ArcPolicyResponse> getPolicy() async => ArcPolicyResponse(
        timestamp: DateTime.now().toIso8601String(),
        maxScriptSize: 500000,
        maxTxSigopsCount: 4294967295,
        maxTxSize: 10000000,
        miningFee: const FeeRate(satoshis: 100, bytes: 1000),
        standardFormatSupported: true,
      );

  @override
  Future<ArcSubmitResponse> submitTransaction(String rawTx, {String? callbackUrl}) async {
    // libspiffy submits the extended form (BRC-30) when it has the parents
    final id = dartsv.Transaction.fromHex(ExtendedFormat.rawHexOf(rawTx)).id;
    submitted.add(id);
    return ArcSubmitResponse(txid: id, status: ArcTransactionStatus.seenOnNetwork, timestamp: DateTime.now().toIso8601String());
  }

  // Nothing is mined here: no proofs. (Unstubbed, these go over HTTP to a
  // URL nothing serves, and the ARC actor waits for the timeout.)
  @override
  Future<ArcMerkleProofResponse?> getMerkleProof(String txid) async => null;
  @override
  Future<List<ArcMerkleProofResponse>> getBatchMerkleProofs(List<String> txids) async => const [];

  /// Seen on the network once submitted; unknown (404) before, as ARC
  /// answers: a half-signed swap, never broadcast, is not on the network.
  @override
  Future<ArcTransactionResponse> getTransaction(String txid) async {
    if (!submitted.contains(txid)) throw ArcException('Transaction not found', statusCode: 404);
    return ArcTransactionResponse.fromJson(
        {'timestamp': DateTime.now().toIso8601String(), 'txid': txid, 'txStatus': 'SEEN_ON_NETWORK'});
  }
}

class _Receiver<T> extends Actor {
  final Completer<T> completer;
  _Receiver(this.completer);
  @override
  Future<void> onMessage(dynamic message) async {
    final payload = message is LocalMessage ? message.payload : message;
    if (payload is T && !completer.isCompleted) completer.complete(payload);
  }
}

final _flags = {dartsv.VerifyFlag.SIGHASH_FORKID, dartsv.VerifyFlag.UTXO_AFTER_GENESIS};

class SpiffyHarness {
  late Directory _dir;
  late Isar _isar;
  late LocalActorSystem actors;
  late LibSpiffyActorSystem spiffy;
  final String wallet;

  /// Every output the tests know, by txid:vout: its script and value.
  final outputs = <String, ({String script, int sats})>{};
  late String root;
  late String second;

  SpiffyHarness({this.wallet = 'w'});

  static Future<void> initIsar() async {
    try {
      await Isar.initializeIsarCore(download: true);
    } catch (e) {
      if (!'$e'.contains('already initialized')) rethrow;
    }
  }

  Future<void> start() async {
    _dir = await Directory.systemTemp.createTemp('lt_spiffy_');
    _isar = await Isar.open(LibSpiffySchemas.allSchemas, directory: _dir.path, name: 'lt_${DateTime.now().microsecondsSinceEpoch}');
    actors = LocalActorSystem(ActorSystemConfig());
    spiffy = LibSpiffyActorSystem();
    await spiffy.initialize(
      actorSystem: actors,
      isar: _isar,
      dataDirectory: _dir.path,
      enableP2P: false,
      arcService: StubArc(),
      secureStorage: InMemorySecureStorage(),
    );
  }

  Future<void> stop() async {
    await spiffy.shutdown();
    await _isar.close();
    if (await _dir.exists()) await _dir.delete(recursive: true);
  }

  Future<T> ask<T>(ActorRef target, Message message, {Duration timeout = const Duration(seconds: 30)}) async {
    final completer = Completer<T>();
    final receiver = await actors.spawn('ask-$T-${DateTime.now().microsecondsSinceEpoch}', () => _Receiver<T>(completer));
    try {
      target.tell(message, sender: receiver);
      return await completer.future.timeout(timeout, onTimeout: () => throw TimeoutException('No $T within $timeout'));
    } finally {
      await actors.stop(receiver);
    }
  }

  Future<void> eventually(Future<bool> Function() condition, String what) async {
    final deadline = DateTime.now().add(const Duration(seconds: 10));
    while (!await condition()) {
      if (DateTime.now().isAfter(deadline)) fail('Timed out waiting for $what');
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  }

  /// The wallet, with its root address and a second address, and [coins]
  /// coins of 60,000 sats at the root. [xpriv] gives a second wallet keys of
  /// its own.
  Future<void> createWallet({int coins = 8, String xpriv = testXpriv}) async {
    final created = await ask<WalletCreatedMessage>(spiffy.walletManager, CreateWalletMessage(wallet, 'Test', xpriv: xpriv));
    expect(created.success, isTrue, reason: created.error);
    root = created.rootAddress;
    await eventually(() async => await spiffy.walletStorage.getAddressMetadata(wallet, root) != null, 'the root address');
    second = (await ask<AddressGeneratedResponse>(spiffy.walletManager, WalletCommandMessage(wallet, GenerateAddressCommand(walletId: wallet))))
        .address;
    await eventually(() async => await spiffy.walletStorage.getAddressMetadata(wallet, second) != null, 'the second address');
    for (var i = 0; i < coins; i++) {
      final txid = hex.encode(dartsv.sha256([i, 7, ...xpriv.codeUnits]));
      final script = dartsv.P2PKHLockBuilder.fromAddress(dartsv.Address.fromBase58(root)).getScriptPubkey().toHex();
      final r = await ask<UTXOReceivedResponse>(
        spiffy.walletManager,
        WalletCommandMessage(
          wallet,
          ReceiveUTXOCommand(
            walletId: wallet,
            txid: txid,
            vout: 0,
            satoshis: BigInt.from(60000),
            scriptPubKey: script,
            address: root,
            blockHeight: 1239645,
            confirmations: 10,
            initialStatus: UTXOStatus.available,
          ),
        ),
      );
      expect(r.success, isTrue, reason: r.error);
      outputs['$txid:0'] = (script: script, sats: 60000);
    }
    await eventually(() async => (await spiffy.walletStorage.getPaymentUTXOs(wallet)).length == coins, 'the funding');
  }

  static String pkhOfAddress(String a) => dartsv.Address.fromBase58(a).pubkeyHash160;

  /// Runs every input of [tx] through the interpreter against the output it
  /// spends, then learns [tx]'s outputs.
  void checkInputs(dartsv.Transaction tx) {
    for (var i = 0; i < tx.inputs.length; i++) {
      final input = tx.inputs[i];
      final spent = outputs['${input.prevTxnId}:${input.prevTxnOutputIndex}'] ??
          (throw StateError('input $i of ${tx.id} spends an output this test does not know'));
      dartsv.Interpreter().correctlySpends(
          input.script!, dartsv.SVScript.fromHex(spent.script), tx, i, _flags, dartsv.Coin.ofSat(BigInt.from(spent.sats)));
    }
    for (var v = 0; v < tx.outputs.length; v++) {
      outputs['${tx.id}:$v'] = (script: tx.outputs[v].script.toHex(), sats: tx.outputs[v].satoshis.toInt());
    }
  }

  /// The BEEF's subject, its last transaction. The ones before it (funding
  /// the payment auto-provisioned) are checked first.
  dartsv.Transaction subject(Uint8List beef) {
    final txs = [for (final raw in BEEF.parse(beef).txs) dartsv.Transaction.fromHex(hex.encode(raw))];
    for (final a in txs.sublist(0, txs.length - 1)) {
      if (!outputs.containsKey('${a.id}:0')) checkInputs(a);
    }
    return txs.last;
  }

  /// The sender settles its own plugin payment: ARC takes it, and its
  /// outputs (the token's included) become spendable.
  Future<void> settle(Uint8List beef, String txid) async {
    final done = Completer<coord.BEEFSettledEvent>();
    final sub = spiffy.coordinatorEvents!.listen((e) {
      if (e is coord.BEEFSettledEvent && e.txid == txid && !done.isCompleted) done.complete(e);
    });
    spiffy.coordinator.tell(coord.SettleBEEFCommand(walletId: wallet, beefHex: hex.encode(beef), txid: txid));
    final settled = await done.future.timeout(const Duration(seconds: 10));
    await sub.cancel();
    expect(settled.success, isTrue, reason: settled.error);
    // libspiffy records the paired transaction of a result (a reissue's
    // successor) as an ordinary outgoing transaction, not a deferred
    // payment: there is no deferred status to ask for; settling it is enough
    if (await spiffy.walletStorage.getDeferredPayment(wallet, txid) == null) return;
    // ARC's status scan makes the outputs spendable; ask for it now
    final checked = Completer<coord.DeferredPaymentStatusEvent>();
    final sub2 = spiffy.coordinatorEvents!.listen((e) {
      if (e is coord.DeferredPaymentStatusEvent && e.txid == txid && !checked.isCompleted) checked.complete(e);
    });
    spiffy.coordinator.tell(coord.CheckDeferredPaymentStatusCommand(walletId: wallet, txid: txid));
    // (answers in under a second since libspiffy 46f98b5; before that about
    // 20 s, see AGENTS.md, "Run the tests")
    final st = await checked.future.timeout(const Duration(seconds: 60));
    await sub2.cancel();
    expect(st.networkStatus, 'SEEN_ON_NETWORK');
    expect(st.error, isNull, reason: 'every input of $txid is spent in the wallet');
  }

  /// A plugin payment of [pluginId]; [settleIt] settles it (and its paired
  /// transaction) as the sender would.
  Future<BEEFPaymentResponse> pay(String pluginId, String scriptType, Map<String, dynamic> params,
      {int amount = 1, bool settleIt = true}) async {
    final r = await ask<BEEFPaymentResponse>(
      spiffy.paymentCoordinator,
      PayInvoiceMessage(
        walletId: wallet,
        invoiceId: 'lt-${params['action']}-${DateTime.now().microsecondsSinceEpoch}',
        addresses: const [],
        amount: BigInt.from(amount),
        outputs: [PluginOutputSpec(pluginId: pluginId, pluginScriptType: scriptType, params: params, amount: BigInt.from(amount))],
      ),
    );
    if (r.success && settleIt) {
      await settle(r.beefBytes, r.txid);
      if (r.witnessTxid != null) await settle(r.witnessBeefBytes!, r.witnessTxid!);
    }
    return r;
  }

  /// A coin of exactly [sats] at [address], received as a confirmed
  /// payment: a real transaction (its raw bytes stored, so a plugin can look
  /// it up and a counterparty can check it) whose output 0 is the coin.
  Future<dartsv.Transaction> receiveCoin(String address, int sats) async {
    final script = dartsv.P2PKHLockBuilder.fromAddress(dartsv.Address.fromBase58(address)).getScriptPubkey();
    final tx = dartsv.Transaction()
      ..addInput(dartsv.TransactionInput(hex.encode(dartsv.sha256([sats, ...address.codeUnits])), 0, dartsv.TransactionInput.MAX_SEQ_NUMBER))
      ..addOutput(dartsv.TransactionOutput(BigInt.from(sats), script));
    final now = DateTime.now();
    await spiffy.walletStorage.storeTransaction(
      wallet,
      BitcoinTransaction(
        walletId: wallet,
        txid: tx.id,
        rawHex: tx.serialize(),
        status: TransactionStatus.confirmed,
        blockHeight: 1239645,
        inputValue: BigInt.from(sats),
        outputValue: BigInt.from(sats),
        fee: BigInt.zero,
        receivingAddresses: [address],
        sendingAddresses: const [],
        netAmount: BigInt.from(sats),
        createdAt: now,
        updatedAt: now,
      ),
    );
    final r = await ask<UTXOReceivedResponse>(
      spiffy.walletManager,
      WalletCommandMessage(
        wallet,
        ReceiveUTXOCommand(
          walletId: wallet,
          txid: tx.id,
          vout: 0,
          satoshis: BigInt.from(sats),
          scriptPubKey: script.toHex(),
          address: address,
          blockHeight: 1239645,
          confirmations: 10,
          initialStatus: UTXOStatus.available,
        ),
      ),
    );
    expect(r.success, isTrue, reason: r.error);
    outputs['${tx.id}:0'] = (script: script.toHex(), sats: sats);
    await spendable(tx.id, 0);
    return tx;
  }

  /// An ordinary payment of [sats] to [address] (no plugin), settled.
  Future<dartsv.Transaction> payPlain(String address, int sats) async {
    final r = await ask<BEEFPaymentResponse>(
      spiffy.paymentCoordinator,
      PayInvoiceMessage(
        walletId: wallet,
        invoiceId: 'plain-${DateTime.now().microsecondsSinceEpoch}',
        addresses: [address],
        amount: BigInt.from(sats),
      ),
    );
    expect(r.success, isTrue, reason: r.error);
    await settle(r.beefBytes, r.txid);
    return subject(r.beefBytes);
  }

  /// Sends [message] to the coordinator and waits for the first coordinator
  /// event [match] accepts.
  Future<E> command<E>(Message message, bool Function(E) match, {Duration timeout = const Duration(seconds: 30)}) async {
    final done = Completer<E>();
    final sub = spiffy.coordinatorEvents!.listen((e) {
      if (e is E && match(e as E) && !done.isCompleted) done.complete(e as E);
    });
    spiffy.coordinator.tell(message);
    try {
      return await done.future.timeout(timeout);
    } finally {
      await sub.cancel();
    }
  }

  Future<bool> available(String txid, int vout) async => (await spiffy.walletStorage.getUTXO(wallet, txid, vout))?.isAvailable ?? false;

  Future<void> spendable(String txid, int vout) => eventually(() => available(txid, vout), 'the token at $txid:$vout spendable');
}
