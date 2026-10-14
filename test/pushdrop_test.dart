import 'dart:convert';
import 'dart:io';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';
import 'package:libspiffy/libspiffy.dart' show Brc100Counterparty, Brc100Keys, Brc43Protocol;
import 'package:libtokensv/libtokensv.dart';
import 'package:test/test.dart';

/// Vectors written by @bsv/sdk 2.2.0's PushDrop template and ProtoWallet
/// (test/fixtures/pushdrop_vectors.json).
final _vectors = jsonDecode(File('test/fixtures/pushdrop_vectors.json').readAsStringSync()) as Map<String, dynamic>;

void main() {
  group('the reference SDK\'s scripts', () {
    final encodings = (_vectors['encodings'] as List).cast<Map<String, dynamic>>();
    for (final (i, v) in encodings.indexed) {
      final fields = [for (final f in (v['fields'] as List).cast<String>()) hex.decode(f)];
      test('encoding $i (${fields.map((f) => '${f.length} bytes').join(', ')}): read and written as the SDK does', () {
        final script = SVScript.fromHex(v['scriptHex'] as String);
        final token = PushDrop.decode(script)!;
        expect([for (final f in token.fields) hex.encode(f)], v['decoded']);
        // and written back the same, from the key and fields
        expect(PushDrop.lock(lockingPublicKey: token.lockingPublicKey, fields: fields).toHex(), v['scriptHex']);
      });
    }

    for (final v in (_vectors['advertisements'] as List).cast<Map<String, dynamic>>()) {
      test('message box advertisement for ${v['host']}: same key, signature and script', () {
        final keys = Brc100Keys(SVPrivateKey.fromHex(v['privateKey'] as String, NetworkType.MAIN));
        expect(keys.identityKey, v['identityKey']);
        final protocol = Brc43Protocol(1, 'messagebox advertisement');
        final lockingKey = keys.derivePublicKey(protocol, '1', Brc100Counterparty.anyone, forSelf: true).toHex();
        expect(lockingKey, v['lockingKey']);
        final fields = [hex.decode(v['identityKey'] as String), utf8.encode(v['host'] as String)];
        final signature = keys.createSignature(protocol, '1', fields.expand((f) => f).toList(),
            counterparty: Brc100Counterparty.anyone);
        expect(hex.encode(signature), v['signature']);
        final script = PushDrop.lock(lockingPublicKey: lockingKey, fields: [...fields, signature]);
        expect(script.toHex(), v['scriptHex']);
      });
    }
  });

  group('decode', () {
    const key = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';

    test('reads the lock after the fields when asked', () {
      final script = PushDrop.lock(lockingPublicKey: key, fields: [
        [1, 2, 3],
        [4]
      ], position: LockPosition.after);
      expect(PushDrop.decode(script), isNull);
      final token = PushDrop.decode(script, position: LockPosition.after)!;
      expect(token.lockingPublicKey, key);
      expect(token.fields, [
        [1, 2, 3],
        [4]
      ]);
    });

    test('refuses scripts that are not PushDrop tokens', () {
      SVScript asm(String s) => SVScript.fromASM(s);
      // P2PK: no fields
      expect(PushDrop.decode(asm('$key OP_CHECKSIG')), isNull);
      // fields not all dropped
      expect(PushDrop.decode(asm('$key OP_CHECKSIG 010203 040506 OP_DROP')), isNull);
      // dropped twice over
      expect(PushDrop.decode(asm('$key OP_CHECKSIG 010203 OP_2DROP')), isNull);
      // something after the drops
      expect(PushDrop.decode(asm('$key OP_CHECKSIG 010203 OP_DROP OP_1')), isNull);
      // no checksig
      expect(PushDrop.decode(asm('$key OP_CHECKSIGVERIFY 010203 OP_DROP')), isNull);
      // P2PKH
      expect(PushDrop.decode(SVScript.fromHex('76a914f4c03610e60ad15100929cc23da2f3a799af172588ac')), isNull);
    });

    test('lock refuses no fields', () {
      expect(() => PushDrop.lock(lockingPublicKey: key, fields: const []), throwsArgumentError);
    });
  });
}
