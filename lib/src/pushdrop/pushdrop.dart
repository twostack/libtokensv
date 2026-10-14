import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';

/// Where a PushDrop script puts its lock: before the fields (the default,
/// and what BRC-100 overlays use) or after them.
enum LockPosition { before, after }

/// A PushDrop output read back: the key it is locked to and its fields.
class PushDropToken {
  /// The compressed public key the output is locked to, lower-case hex.
  final String lockingPublicKey;

  /// The fields, in order; the last is the signature when the token was
  /// made with one.
  final List<Uint8List> fields;

  const PushDropToken({required this.lockingPublicKey, required this.fields});
}

/// PushDrop scripts, as the TypeScript `@bsv/sdk` template writes them: data
/// fields kept in a spendable output.
///
///     <lockingPublicKey> OP_CHECKSIG <field 1> ... <field n> OP_2DROP ... [OP_DROP]
///
/// Each field is pushed in its minimal encoding, and dropped again (OP_2DROP
/// for each pair, OP_DROP for an odd one out), so spending the output takes
/// only a signature by the locking key. With [LockPosition.after] the lock
/// goes after the drops.
abstract final class PushDrop {
  /// The locking script holding [fields], locked to [lockingPublicKey]
  /// (compressed, hex).
  static SVScript lock({
    required String lockingPublicKey,
    required List<List<int>> fields,
    LockPosition position = LockPosition.before,
  }) {
    if (fields.isEmpty) throw ArgumentError.value(fields, 'fields', 'a PushDrop token holds at least one field');
    final key = SVPublicKey.fromHex(lockingPublicKey);
    final lock = <int>[...pushData(hex.decode(key.toHex())), OpCodes.OP_CHECKSIG];
    final drops = <int>[
      for (final field in fields) ...pushData(field),
      for (var i = 0; i < fields.length ~/ 2; i++) OpCodes.OP_2DROP,
      if (fields.length.isOdd) OpCodes.OP_DROP,
    ];
    return SVScript.fromBuffer(position == LockPosition.before ? [...lock, ...drops] : [...drops, ...lock]);
  }

  /// [script] read as a PushDrop token, or null when it is not one: a lock,
  /// one or more pushed fields, and drops that take exactly those fields off
  /// the stack, nothing else.
  static PushDropToken? decode(SVScript script, {LockPosition position = LockPosition.before}) {
    final chunks = script.chunks;
    if (chunks.length < 4) return null;
    final ScriptChunk keyChunk;
    final List<ScriptChunk> body;
    if (position == LockPosition.before) {
      keyChunk = chunks[0];
      if (chunks[1].opcodenum != OpCodes.OP_CHECKSIG) return null;
      body = chunks.sublist(2);
    } else {
      keyChunk = chunks[chunks.length - 2];
      if (chunks.last.opcodenum != OpCodes.OP_CHECKSIG) return null;
      body = chunks.sublist(0, chunks.length - 2);
    }
    final key = keyChunk.buf;
    if (key == null || key.length != 33 || (key[0] != 2 && key[0] != 3)) return null;

    final fields = <Uint8List>[];
    var i = 0;
    for (; i < body.length; i++) {
      final field = _fieldOf(body[i]);
      if (field == null) break;
      fields.add(field);
    }
    if (fields.isEmpty) return null;
    var dropped = 0;
    for (; i < body.length; i++) {
      final op = body[i].opcodenum;
      if (op == OpCodes.OP_2DROP && dropped + 2 <= fields.length) {
        dropped += 2;
      } else if (op == OpCodes.OP_DROP && dropped + 1 == fields.length) {
        dropped += 1;
      } else {
        return null;
      }
    }
    if (dropped != fields.length) return null;
    try {
      return PushDropToken(lockingPublicKey: SVPublicKey.fromBuffer(key).toHex().toLowerCase(), fields: fields);
    } catch (_) {
      return null; // not a point on the curve
    }
  }

  /// The minimal push of [data]: OP_0, OP_1..OP_16 or OP_1NEGATE for the one
  /// byte values they stand for, else a direct push or OP_PUSHDATA1/2/4.
  static List<int> pushData(List<int> data) {
    if (data.isEmpty || (data.length == 1 && data[0] == 0)) return [OpCodes.OP_0];
    if (data.length == 1 && data[0] >= 1 && data[0] <= 16) return [OpCodes.OP_1 + data[0] - 1];
    if (data.length == 1 && data[0] == 0x81) return [OpCodes.OP_1NEGATE];
    final n = data.length;
    if (n <= 75) return [n, ...data];
    if (n <= 0xff) return [OpCodes.OP_PUSHDATA1, n, ...data];
    if (n <= 0xffff) return [OpCodes.OP_PUSHDATA2, n & 0xff, n >> 8, ...data];
    return [OpCodes.OP_PUSHDATA4, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, n >> 24, ...data];
  }

  /// The value [chunk] pushes, or null when it is not a push.
  static Uint8List? _fieldOf(ScriptChunk chunk) {
    final op = chunk.opcodenum;
    if (op == OpCodes.OP_0) return Uint8List.fromList(const [0]);
    if (op == OpCodes.OP_1NEGATE) return Uint8List.fromList(const [0x81]);
    if (op >= OpCodes.OP_1 && op <= OpCodes.OP_16) return Uint8List.fromList([op - OpCodes.OP_1 + 1]);
    if (op > 0 && op <= OpCodes.OP_PUSHDATA4) return Uint8List.fromList(chunk.buf ?? const []);
    return null;
  }
}

/// The locking script of a PushDrop token, for a [TransactionBuilder].
class PushDropLockBuilder extends LockingScriptBuilder {
  String? lockingPublicKey;
  List<List<int>> fields = const [];
  LockPosition position;

  PushDropLockBuilder({required String this.lockingPublicKey, required this.fields, this.position = LockPosition.before});

  PushDropLockBuilder.fromScript(super.script, {this.position = LockPosition.before}) : super.fromScript();

  @override
  SVScript getScriptPubkey() => lockingPublicKey == null
      ? SVScript()
      : PushDrop.lock(lockingPublicKey: lockingPublicKey!, fields: fields, position: position);

  @override
  void parse(SVScript script) {
    final token = PushDrop.decode(script, position: position) ??
        (throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, ' - Not a PushDrop locking script'));
    lockingPublicKey = token.lockingPublicKey;
    fields = token.fields;
  }
}

/// The unlocking script of a PushDrop token: the locking key's signature
/// alone.
class PushDropUnlockBuilder extends UnlockingScriptBuilder {
  PushDropUnlockBuilder();

  PushDropUnlockBuilder.fromScript(super.script) : super.fromScript();

  @override
  SVScript getScriptSig() {
    if (signatures.isEmpty) return SVScript();
    return SVScript.fromBuffer(PushDrop.pushData(hex.decode(signatures.first.toTxFormat())));
  }

  @override
  void parse(SVScript script) {
    final chunks = script.chunks;
    if (chunks.length != 1 || chunks.first.buf == null) {
      throw ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, ' - Not a PushDrop unlocking script');
    }
    addSignature(SVSignature.fromTxFormat(hex.encode(chunks.first.buf!)));
  }
}
