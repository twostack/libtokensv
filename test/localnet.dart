// The regtest node and ARC of ../localnet, for the tests tagged `localnet`.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';

final _env = Platform.environment;

/// The regtest node's RPC and ARC, as ../localnet runs them.
class Localnet {
  final bool viaRpc;
  final rpcUri = Uri.parse(_env['LOCALNET_RPC'] ?? 'http://localhost:18332');
  final arcUri = Uri.parse(_env['LOCALNET_ARC'] ?? 'http://localhost:9090');
  final _http = HttpClient();
  final _known = <String, Transaction>{};

  Localnet({this.viaRpc = false});

  Future<dynamic> rpc(String method, [List<dynamic> params = const []]) async {
    final req = await _http.postUrl(rpcUri);
    req.headers.set('Authorization', 'Basic ${base64.encode(utf8.encode('bitcoin:bitcoin'))}');
    req.headers.contentType = ContentType.json;
    // The node closes idle connections, and proving can idle this client
    // for minutes, so a pooled connection may be dead when reused.
    req.persistentConnection = false;
    req.write(jsonEncode({'jsonrpc': '1.0', 'id': method, 'method': method, 'params': params}));
    final res = await req.close();
    final body = await res.transform(utf8.decoder).join();
    final json = jsonDecode(body) as Map<String, dynamic>;
    if (json['error'] != null) throw StateError('$method: ${json['error']}');
    return json['result'];
  }

  Future<int> height() async => await rpc('getblockcount') as int;

  Future<void> mine([int n = 1]) async => rpc('generatetoaddress', [n, await rpc('getnewaddress')]);

  /// Checks the node answers and ARC is healthy, and matures coinbase.
  Future<void> ready() async {
    try {
      await height();
    } catch (e) {
      throw StateError('No regtest node at $rpcUri ($e). Start ../localnet (docker compose up -d).');
    }
    if (!viaRpc) {
      final res = await (await _http.getUrl(arcUri.resolve('/v1/health'))).close();
      final body = await res.transform(utf8.decoder).join();
      if (res.statusCode != 200) throw StateError('ARC at $arcUri is not healthy: ${res.statusCode} $body');
    }
    if ((await rpc('getbalance') as num) < 2) await mine(101);
  }

  /// Sends [sats] from the node's wallet to [to], mines it, and returns the
  /// transaction.
  Future<Transaction> fund(Address to, BigInt sats) async {
    final txid = await rpc('sendtoaddress', [to.toBase58(), sats.toInt() / 1e8]) as String;
    await mine();
    final tx = Transaction.fromHex(await rpc('getrawtransaction', [txid, 0]) as String);
    _known[tx.id] = tx;
    return tx;
  }

  /// Registers a transaction sent outside [submit] (by raw RPC), so a later
  /// [submit] can price and extend a spend of its outputs.
  void know(Transaction tx) => _known[tx.id] = tx;

  /// Broadcasts [tx], mines a block, and checks the block took it.
  Future<void> submit(String name, Transaction tx) async {
    final size = hex.decode(tx.serialize()).length;
    var fee = BigInt.zero;
    for (final i in tx.inputs) {
      fee += _known[i.prevTxnId]!.outputs[i.prevTxnOutputIndex].satoshis;
    }
    for (final o in tx.outputs) {
      fee -= o.satoshis;
    }
    final sw = Stopwatch()..start();
    final status = viaRpc ? await _sendRpc(name, tx) : await _sendArc(name, tx);
    final accepted = sw.elapsedMilliseconds;
    await mine();
    final info = await rpc('getrawtransaction', [tx.id, 1]) as Map<String, dynamic>;
    if ((info['confirmations'] ?? 0) < 1) {
      throw StateError('$name ${tx.id} was accepted ($status) but not mined');
    }
    _known[tx.id] = tx;
    final row = '${name.padRight(6)} ${size.toString().padLeft(9)} B  fee ${fee.toString().padLeft(7)}  '
        '${(fee.toInt() * 1000 / size).toStringAsFixed(2).padLeft(7)} sat/kB  $status in $accepted ms  ${tx.id}';
    print(row);
  }

  Future<String> _sendRpc(String name, Transaction tx) async {
    try {
      await rpc('sendrawtransaction', [tx.serialize()]);
      return 'node';
    } catch (e) {
      throw StateError('node refused $name: $e');
    }
  }

  Future<String> _sendArc(String name, Transaction tx) async {
    final req = await _http.postUrl(arcUri.resolve('/v1/tx'));
    req.headers.contentType = ContentType.json;
    req.headers.set('X-WaitFor', 'SEEN_ON_NETWORK');
    req.headers.set('X-MaxTimeout', '30');
    req.write(jsonEncode({'rawTx': hex.encode(_extended(tx))}));
    final res = await req.close();
    final body = await res.transform(utf8.decoder).join();
    Map<String, dynamic> json;
    try {
      json = jsonDecode(body) as Map<String, dynamic>;
    } catch (_) {
      throw StateError('ARC answered $name with ${res.statusCode}: $body');
    }
    final txStatus = json['txStatus'] as String?;
    // Anything short of a node holding it is not acceptance: ARC with no
    // connected peers stores the transaction and answers STORED.
    const good = {'SEEN_ON_NETWORK', 'ACCEPTED_BY_NETWORK', 'MINED'};
    if (res.statusCode != 200 || txStatus == null || !good.contains(txStatus)) {
      throw StateError('ARC refused $name (${res.statusCode}): ${json['title'] ?? ''} ${json['detail'] ?? ''} '
          '${json['extraInfo'] ?? ''} txStatus=$txStatus');
    }
    return txStatus;
  }

  /// [tx] in Extended Format (BRC-30): each input followed by the value and
  /// locking script it spends, so ARC can validate it without the parents.
  List<int> _extended(Transaction tx) {
    final raw = hex.decode(tx.serialize());
    final out = <int>[...raw.sublist(0, 4), 0, 0, 0, 0, 0, 0xef, ..._varint(tx.inputs.length)];
    for (final i in tx.inputs) {
      final spent = _known[i.prevTxnId]?.outputs[i.prevTxnOutputIndex];
      if (spent == null) throw StateError('input spends ${i.prevTxnId}:${i.prevTxnOutputIndex}, which this run did not make');
      final value = ByteData(8)..setUint64(0, spent.satoshis.toInt(), Endian.little);
      out
        ..addAll(i.serialize())
        ..addAll(value.buffer.asUint8List())
        ..addAll(_varint(spent.script.buffer.length))
        ..addAll(spent.script.buffer);
    }
    out.addAll(_varint(tx.outputs.length));
    for (final o in tx.outputs) {
      out.addAll(o.serialize());
    }
    out.addAll(raw.sublist(raw.length - 4));
    return out;
  }

}

List<int> _varint(int n) {
  if (n < 0xfd) return [n];
  if (n <= 0xffff) return [0xfd, n & 0xff, n >> 8];
  return [0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
}
