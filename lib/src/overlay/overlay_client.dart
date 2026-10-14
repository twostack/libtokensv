import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:http/http.dart' as http;
import 'package:libspiffy/libspiffy.dart' show Brc95;

import 'overlay_admin_token.dart';

/// The SLAP trackers each network starts from, as `@bsv/sdk`'s
/// LookupResolver ships them.
enum OverlayNetwork {
  mainnet([
    'https://overlay-us-1.bsvb.tech',
    'https://overlay-eu-1.bsvb.tech',
    'https://overlay-ap-1.bsvb.tech',
    'https://users.bapp.dev',
  ]),
  testnet(['https://testnet-users.bapp.dev']);

  final List<String> slapTrackers;
  const OverlayNetwork(this.slapTrackers);
}

/// One output a lookup service answered with: the transaction (from the
/// BEEF it came in) and which of its outputs.
class LookupOutput {
  final Uint8List beef;
  final Transaction transaction;
  final int outputIndex;

  LookupOutput({required this.beef, required this.transaction, required this.outputIndex});

  String get txid => transaction.id;
  TransactionOutput get output => transaction.outputs[outputIndex];
  SVScript get lockingScript => output.script;
  String get outpoint => '$txid.$outputIndex';
}

/// What one overlay host said to a submitted transaction: per topic, the
/// outputs it admitted and the coins it retained or removed (a STEAK).
class TopicAdmittance {
  final List<int> outputsToAdmit;
  final List<int> coinsToRetain;
  final List<String> coinsRemoved;

  const TopicAdmittance({this.outputsToAdmit = const [], this.coinsToRetain = const [], this.coinsRemoved = const []});

  /// Whether the host took anything from the transaction into the topic.
  bool get acknowledged => outputsToAdmit.isNotEmpty || coinsToRetain.isNotEmpty || coinsRemoved.isNotEmpty;

  factory TopicAdmittance.fromJson(Map<String, dynamic> json) => TopicAdmittance(
        outputsToAdmit: [for (final i in (json['outputsToAdmit'] as List? ?? const [])) (i as num).toInt()],
        coinsToRetain: [for (final i in (json['coinsToRetain'] as List? ?? const [])) (i as num).toInt()],
        coinsRemoved: [for (final c in (json['coinsRemoved'] as List? ?? const [])) '$c'],
      );
}

/// The outcome of [OverlayClient.submit]: each interested host's answer,
/// or why it gave none.
class SubmitResult {
  final Map<String, Map<String, TopicAdmittance>> answers;
  final Map<String, String> failures;

  const SubmitResult({required this.answers, required this.failures});

  /// Whether at least one host acknowledged the transaction in [topic].
  bool acknowledgedIn(String topic) => answers.values.any((steak) => steak[topic]?.acknowledged ?? false);
}

/// Thrown when an overlay operation cannot be done at all: no host found
/// for a service or topic, or none answered.
class OverlayException implements Exception {
  final String message;
  const OverlayException(this.message);
  @override
  String toString() => 'OverlayException: $message';
}

/// A client for BSV overlay services (BRC-22 submit, BRC-24 lookup), finding
/// hosts the way `@bsv/sdk` does: the hosts of a lookup service through the
/// SLAP trackers (`ls_slap`), the hosts of a topic through SHIP
/// advertisements (`ls_ship`).
class OverlayClient {
  final List<String> slapTrackers;

  /// Hosts to use for a service instead of asking the trackers.
  final Map<String, List<String>> hostOverrides;
  final Duration timeout;
  final http.Client _http;
  final Map<String, ({DateTime at, List<String> hosts})> _competent = {};

  /// How long the hosts found for a service are kept.
  static const _cacheFor = Duration(minutes: 5);

  OverlayClient({
    required this.slapTrackers,
    this.hostOverrides = const {},
    this.timeout = const Duration(seconds: 5),
    http.Client? httpClient,
  }) : _http = httpClient ?? http.Client();

  OverlayClient.forNetwork(OverlayNetwork network,
      {Map<String, List<String>> hostOverrides = const {}, Duration timeout = const Duration(seconds: 5), http.Client? httpClient})
      : this(slapTrackers: network.slapTrackers, hostOverrides: hostOverrides, timeout: timeout, httpClient: httpClient);

  void close() => _http.close();

  /// Asks lookup [service] [query] at every host that runs it, and merges
  /// the answers (one entry per outpoint, in the order they came). Throws
  /// [OverlayException] when no host runs it, or none answered.
  Future<List<LookupOutput>> lookup(String service, Map<String, dynamic> query) async {
    final hosts = await hostsFor(service);
    if (hosts.isEmpty) throw OverlayException('No overlay host runs the lookup service $service');
    final answers = await Future.wait([for (final host in hosts) _lookupAt(host, service, query)]);
    if (answers.every((a) => a == null)) throw OverlayException('No overlay host answered the lookup service $service');
    final seen = <String>{};
    return [
      for (final answer in answers)
        for (final output in answer ?? const <LookupOutput>[])
          if (seen.add(output.outpoint)) output,
    ];
  }

  /// The hosts that run lookup [service]: [hostOverrides], the trackers
  /// themselves for `ls_slap`, else the SLAP advertisements the trackers
  /// hold for it.
  Future<List<String>> hostsFor(String service) async {
    if (hostOverrides[service] case final hosts?) return hosts;
    if (service == 'ls_slap') return slapTrackers;
    final cached = _competent[service];
    if (cached != null && DateTime.now().difference(cached.at) < _cacheFor) return cached.hosts;
    final hosts = <String>{
      for (final output in await lookup('ls_slap', {'service': service}))
        if (OverlayAdminToken.decode(output.lockingScript) case final token?
            when token.protocol == 'SLAP' && token.topicOrService == service && _isHttps(token.domain))
          token.domain,
    }.toList();
    _competent[service] = (at: DateTime.now(), hosts: hosts);
    return hosts;
  }

  /// The hosts that take transactions for [topic]: its SHIP advertisements.
  Future<List<String>> hostsInterestedIn(String topic) async => {
        for (final output in await lookup('ls_ship', {
          'topics': [topic]
        }))
          if (OverlayAdminToken.decode(output.lockingScript) case final token?
              when token.protocol == 'SHIP' && token.topicOrService == topic && _isHttps(token.domain))
            token.domain,
      }.toList();

  /// Submits [beef] (the transaction, with its ancestry) to every host
  /// interested in [topics]. Throws [OverlayException] when no host is.
  Future<SubmitResult> submit(List<int> beef, List<String> topics) async {
    final hosts = <String>{for (final topic in topics) ...await hostsInterestedIn(topic)};
    if (hosts.isEmpty) throw OverlayException('No overlay host takes transactions for ${topics.join(', ')}');
    final answers = <String, Map<String, TopicAdmittance>>{};
    final failures = <String, String>{};
    await Future.wait([
      for (final host in hosts)
        () async {
          try {
            final response = await _http
                .post(Uri.parse('$host/submit'),
                    headers: {'Content-Type': 'application/octet-stream', 'X-Topics': topics.join(',')},
                    body: Uint8List.fromList(beef))
                .timeout(timeout);
            if (response.statusCode != 200) {
              failures[host] = 'HTTP ${response.statusCode}: ${response.body}';
              return;
            }
            final steak = jsonDecode(response.body) as Map<String, dynamic>;
            answers[host] = {
              for (final entry in steak.entries)
                if (entry.value is Map) entry.key: TopicAdmittance.fromJson(Map<String, dynamic>.from(entry.value as Map)),
            };
          } catch (e) {
            failures[host] = '$e';
          }
        }(),
    ]);
    return SubmitResult(answers: answers, failures: failures);
  }

  Future<List<LookupOutput>?> _lookupAt(String host, String service, Map<String, dynamic> query) async {
    try {
      final response = await _http
          .post(Uri.parse('$host/lookup'),
              headers: {'Content-Type': 'application/json'}, body: jsonEncode({'service': service, 'query': query}))
          .timeout(timeout);
      if (response.statusCode != 200) return null;
      return parseOutputList(jsonDecode(response.body));
    } catch (_) {
      return null;
    }
  }

  /// A lookup answer (`{"type": "output-list", "outputs": [{"beef": [...],
  /// "outputIndex": n}]}`) read into outputs; outputs that cannot be read
  /// are left out. Throws [FormatException] for an answer of another type.
  static List<LookupOutput> parseOutputList(Object? json) {
    if (json is! Map || json['type'] != 'output-list') throw const FormatException('Not an output-list answer');
    final outputs = <LookupOutput>[];
    for (final o in (json['outputs'] as List? ?? const [])) {
      try {
        final beef = Uint8List.fromList([for (final b in (o['beef'] as List)) (b as num).toInt()]);
        final index = (o['outputIndex'] as num).toInt();
        final read = Brc95.read(beef);
        final subject = read.subjectTxid;
        final Uint8List? raw;
        if (subject != null) {
          final found = read.beef.findTransactionByTxid(Uint8List.fromList(hex.decode(subject)));
          raw = found == null ? null : found['txData'] as Uint8List;
        } else {
          raw = read.beef.txs.last;
        }
        if (raw == null) continue;
        final tx = Transaction.fromHex(hex.encode(raw));
        if (index < 0 || index >= tx.outputs.length) continue;
        outputs.add(LookupOutput(beef: beef, transaction: tx, outputIndex: index));
      } catch (_) {
        continue;
      }
    }
    return outputs;
  }

  /// Only HTTPS hosts are asked, as the SDK does.
  static bool _isHttps(String domain) => Uri.tryParse(domain)?.scheme == 'https';
}
