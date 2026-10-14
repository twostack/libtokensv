import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:libtoken/libtoken.dart';
import 'package:test/test.dart';

/// Answers recorded from https://overlay-us-1.bsvb.tech on 2026-10-14.
Object? _fixture(String name) => jsonDecode(File('test/fixtures/$name.json').readAsStringSync());

void main() {
  test('reads recorded SHIP and SLAP answers into admin tokens', () {
    final shipHosts = OverlayClient.parseOutputList(_fixture('ls_slap_ls_ship'));
    expect(shipHosts.map((o) => OverlayAdminToken.decode(o.lockingScript)?.topicOrService).toSet(), {'ls_ship'});
    final ship = OverlayClient.parseOutputList(_fixture('ls_ship_tm_messagebox'));
    final slap = OverlayClient.parseOutputList(_fixture('ls_slap_ls_messagebox'));
    final shipTokens = [for (final o in ship) OverlayAdminToken.decode(o.lockingScript)!];
    final slapTokens = [for (final o in slap) OverlayAdminToken.decode(o.lockingScript)!];
    expect([for (final t in shipTokens) t.domain], ['https://overlay-us-1.bsvb.tech', 'https://overlay-ap-1.bsvb.tech']);
    expect(shipTokens, hasLength(2));
    expect(shipTokens.every((t) => t.protocol == 'SHIP' && t.topicOrService == 'tm_messagebox'), isTrue);
    expect(slapTokens, hasLength(3));
    expect(slapTokens.every((t) => t.protocol == 'SLAP' && t.topicOrService == 'ls_messagebox'), isTrue);
  });

  group('against overlay hosts', () {
    late List<String> asked;

    /// Two trackers; SLAP names us-1 and ap-1 for ls_messagebox, SHIP names
    /// them for tm_messagebox.
    OverlayClient client(Future<http.Response> Function(http.Request request) answer) {
      asked = [];
      return OverlayClient(
        slapTrackers: const ['https://tracker-a.example', 'https://tracker-b.example'],
        httpClient: MockClient((request) {
          asked.add('${request.url.host}${request.url.path}');
          return answer(request);
        }),
      );
    }

    http.Response json(Object? body) => http.Response(jsonEncode(body), 200);

    Future<http.Response> standard(http.Request request) async {
      final body = request.url.path == '/lookup' ? jsonDecode(request.body) as Map<String, dynamic> : const {};
      return switch ((request.url.host, request.url.path, body['service'])) {
        (_, '/lookup', 'ls_slap') when body['query']['service'] == 'ls_messagebox' => json(_fixture('ls_slap_ls_messagebox')),
        (_, '/lookup', 'ls_slap') when body['query']['service'] == 'ls_ship' => json(_fixture('ls_slap_ls_ship')),
        (_, '/lookup', 'ls_ship') => json(_fixture('ls_ship_tm_messagebox')),
        ('overlay-us-1.bsvb.tech', '/lookup', 'ls_messagebox') => json({'type': 'output-list', 'outputs': []}),
        ('overlay-ap-1.bsvb.tech', '/lookup', 'ls_messagebox') => http.Response('down', 503),
        _ => http.Response('not found', 404),
      };
    }

    test('finds the hosts of a lookup service through the SLAP trackers, once', () async {
      final c = client(standard);
      expect(await c.hostsFor('ls_messagebox'), ['https://overlay-us-1.bsvb.tech', 'https://overlay-ap-1.bsvb.tech']);
      expect(asked, ['tracker-a.example/lookup', 'tracker-b.example/lookup']);
      await c.hostsFor('ls_messagebox');
      expect(asked, hasLength(2), reason: 'the hosts found are kept for a while');
    });

    test('a lookup asks every host and gets by with one answering', () async {
      final c = client(standard);
      expect(await c.lookup('ls_messagebox', {'identityKey': '02' * 33}), isEmpty);
      expect(asked, containsAll(['overlay-us-1.bsvb.tech/lookup', 'overlay-ap-1.bsvb.tech/lookup']));
    });

    test('merges answers by outpoint', () async {
      final c = client((request) async => json(_fixture('ls_ship_tm_messagebox')));
      final outputs = await c.lookup('ls_slap', {'service': 'anything'});
      expect(outputs, hasLength(2), reason: 'both trackers gave the same two outputs');
    });

    test('a lookup nobody answers, or nobody runs, fails', () async {
      final down = client((request) async => http.Response('down', 503));
      await expectLater(down.lookup('ls_slap', {'service': 'x'}), throwsA(isA<OverlayException>()));
      final none = client((request) async => json({'type': 'output-list', 'outputs': []}));
      await expectLater(none.lookup('ls_messagebox', {}), throwsA(isA<OverlayException>()));
    });

    test('submits to the hosts SHIP names for the topic, and reads their STEAKs', () async {
      String? topics;
      final c = client((request) async {
        if (request.url.path != '/submit') return standard(request);
        topics = request.headers['X-Topics'];
        expect(request.headers['Content-Type'], 'application/octet-stream');
        expect(request.bodyBytes, [1, 2, 3]);
        return request.url.host == 'overlay-us-1.bsvb.tech'
            ? json({
                'tm_messagebox': {'outputsToAdmit': [0], 'coinsToRetain': []}
              })
            : http.Response('busy', 500);
      });
      final result = await c.submit([1, 2, 3], ['tm_messagebox']);
      expect(topics, 'tm_messagebox');
      expect(result.acknowledgedIn('tm_messagebox'), isTrue);
      expect(result.answers.keys, ['https://overlay-us-1.bsvb.tech']);
      expect(result.failures.keys, ['https://overlay-ap-1.bsvb.tech']);
      expect(result.acknowledgedIn('tm_other'), isFalse);
    });

    test('a STEAK that admits nothing is no acknowledgment', () async {
      final c = client((request) async => request.url.path == '/submit'
          ? json({
              'tm_messagebox': {'outputsToAdmit': [], 'coinsToRetain': []}
            })
          : standard(request));
      expect((await c.submit([1], ['tm_messagebox'])).acknowledgedIn('tm_messagebox'), isFalse);
    });

    test('host overrides skip the trackers', () async {
      asked = [];
      final c = OverlayClient(
        slapTrackers: const ['https://tracker-a.example'],
        hostOverrides: const {
          'ls_messagebox': ['https://local.example']
        },
        httpClient: MockClient((request) async {
          asked.add(request.url.host);
          return json({'type': 'output-list', 'outputs': []});
        }),
      );
      await c.lookup('ls_messagebox', {});
      expect(asked, ['local.example']);
    });
  });
}
