// A script builder that tracks the main stack by name, and the small
// serialisation emitters the lineage-token scripts share.
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'opcode_helpers.dart';

/// A script builder that tracks the main stack by name, so that a value is
/// fetched by what it is rather than by a hand-counted depth. Names starting
/// with `~` are, by convention, intermediates.
class Stk {
  final ScriptBuilder b = ScriptBuilder();
  final List<String> names;
  Stk(List<String> initial) : names = List.of(initial);

  int _depth(String n) {
    final i = names.lastIndexOf(n);
    if (i < 0) throw StateError('"$n" is not on the stack: $names');
    return names.length - 1 - i;
  }

  void op(int opcode, {int pops = 0, List<String> pushes = const []}) {
    if (names.length < pops) throw StateError('opcode $opcode pops $pops from $names');
    names.removeRange(names.length - pops, names.length);
    names.addAll(pushes);
    b.opCode(opcode);
  }

  /// Applies an emitter that replaces the top item with one other item.
  void map(void Function(ScriptBuilder) emit, String as) {
    emit(b);
    names[names.length - 1] = as;
  }

  void bytes(String name, List<int> v) {
    if (v.isEmpty) {
      b.opCode(OpCodes.OP_0);
    } else if (v.length == 1 && v[0] >= 1 && v[0] <= 16) {
      b.smallNum(v[0]);
    } else {
      b.addData(Uint8List.fromList(v));
    }
    names.add(name);
  }

  void num(String name, int v) {
    OpcodeHelpers.pushInt(b, v);
    names.add(name);
  }

  void pick(String n, String as) {
    final d = _depth(n);
    if (d == 0) {
      b.opCode(OpCodes.OP_DUP);
    } else if (d == 1) {
      b.opCode(OpCodes.OP_OVER);
    } else {
      OpcodeHelpers.pushInt(b, d);
      b.opCode(OpCodes.OP_PICK);
    }
    names.add(as);
  }

  void roll(String n) {
    final d = _depth(n);
    if (d == 0) return;
    if (d == 1) {
      b.opCode(OpCodes.OP_SWAP);
    } else if (d == 2) {
      b.opCode(OpCodes.OP_ROT);
    } else {
      OpcodeHelpers.pushInt(b, d);
      b.opCode(OpCodes.OP_ROLL);
    }
    names.removeAt(names.length - 1 - d);
    names.add(n);
  }

  void swap() {
    final top = names.removeLast(), second = names.removeLast();
    names
      ..add(top)
      ..add(second);
    b.opCode(OpCodes.OP_SWAP);
  }

  void rot() {
    final third = names.removeAt(names.length - 3);
    names.add(third);
    b.opCode(OpCodes.OP_ROT);
  }

  void nip() {
    names.removeAt(names.length - 2);
    b.opCode(OpCodes.OP_NIP);
  }

  /// Renames the top item; emits nothing.
  void rename(String as) => names[names.length - 1] = as;

  /// Drops the [n] items under the top one, keeping the top.
  void dropBelowTop(int n) {
    if (n == 0) return;
    final top = names.removeLast();
    if (names.length < n) throw StateError('cannot drop $n below $top from $names');
    names.removeRange(names.length - n, names.length);
    names.add(top);
    b.opCode(OpCodes.OP_TOALTSTACK);
    for (var i = 0; i + 1 < n; i += 2) {
      b.opCode(OpCodes.OP_2DROP);
    }
    if (n.isOdd) b.opCode(OpCodes.OP_DROP);
    b.opCode(OpCodes.OP_FROMALTSTACK);
  }

  void drop() => op(OpCodes.OP_DROP, pops: 1);
  void cat(String as) => op(OpCodes.OP_CAT, pops: 2, pushes: [as]);
  void hash256(String as) => op(OpCodes.OP_HASH256, pops: 1, pushes: [as]);
  void equalVerify() => op(OpCodes.OP_EQUALVERIFY, pops: 2);

  /// x -> x[0:at] x[at:]
  void split(int at, String head, String tail) {
    OpcodeHelpers.pushInt(b, at);
    op(OpCodes.OP_SPLIT, pops: 1, pushes: [head, tail]);
  }

  /// Pushes a copy of src[from:to]; [total] is src's length.
  void slice(String src, int from, int to, String as, {required int total}) {
    pick(src, as);
    if (from > 0) {
      split(from, '~', as);
      nip();
    }
    if (to < total) {
      split(to - from, as, '~');
      drop();
    }
  }

  /// flag -> ; both branches must leave the same stack.
  void ifElse(void Function() then, void Function() otherwise) {
    names.removeLast();
    b.opCode(OpCodes.OP_IF);
    final before = List.of(names);
    then();
    final after = List.of(names);
    names
      ..clear()
      ..addAll(before);
    b.opCode(OpCodes.OP_ELSE);
    otherwise();
    if (after.join(',') != names.join(',')) {
      throw StateError('branches disagree:\n  then $after\n  else $names');
    }
    b.opCode(OpCodes.OP_ENDIF);
  }

  /// flag -> ; the body runs when the flag is false and must be stack-neutral.
  void notIf(void Function() body) {
    names.removeLast();
    b.opCode(OpCodes.OP_NOTIF);
    final before = names.join(',');
    body();
    if (before != names.join(',')) throw StateError('NOTIF body is not stack-neutral: $names');
    b.opCode(OpCodes.OP_ENDIF);
  }
}

/// Emitters for transaction serialisation in script.
class ScriptEmit {
  /// n -> n as [k] bytes, unsigned little-endian.
  static void uintLE(ScriptBuilder b, int k) {
    OpcodeHelpers.pushInt(b, k + 1);
    b.opCode(OpCodes.OP_NUM2BIN);
    OpcodeHelpers.pushInt(b, k);
    b.opCode(OpCodes.OP_SPLIT);
    b.opCode(OpCodes.OP_DROP);
  }

  static void _prefixed(ScriptBuilder b, int marker, int k) {
    uintLE(b, k);
    b.addData(Uint8List.fromList([marker]));
    b.opCode(OpCodes.OP_SWAP);
    b.opCode(OpCodes.OP_CAT);
  }

  static void _below(ScriptBuilder b, int limit) {
    b.opCode(OpCodes.OP_DUP);
    OpcodeHelpers.pushInt(b, limit);
    b.opCode(OpCodes.OP_LESSTHAN);
    b.opCode(OpCodes.OP_IF);
  }

  /// n -> the transaction varint of n (1, 3 or 5 bytes).
  static void varint(ScriptBuilder b) {
    _below(b, 253);
    uintLE(b, 1);
    b.opCode(OpCodes.OP_ELSE);
    _below(b, 65536);
    _prefixed(b, 0xfd, 2);
    b.opCode(OpCodes.OP_ELSE);
    _prefixed(b, 0xfe, 4);
    b.opCode(OpCodes.OP_ENDIF);
    b.opCode(OpCodes.OP_ENDIF);
  }

  /// n -> the minimal push opcode bytes for a data item of length n.
  static void pushPrefix(ScriptBuilder b) {
    _below(b, 76);
    uintLE(b, 1);
    b.opCode(OpCodes.OP_ELSE);
    _below(b, 256);
    _prefixed(b, 0x4c, 1);
    b.opCode(OpCodes.OP_ELSE);
    _below(b, 65536);
    _prefixed(b, 0x4d, 2);
    b.opCode(OpCodes.OP_ELSE);
    _prefixed(b, 0x4e, 4);
    b.opCode(OpCodes.OP_ENDIF);
    b.opCode(OpCodes.OP_ENDIF);
    b.opCode(OpCodes.OP_ENDIF);
  }

  /// slot pub -> the P2PKH unlocking script  PUSH(sig) PUSH(pub).
  /// The slot's first 1 + len bytes are already the signature's push.
  static void p2pkhUnlock(Stk s, String as) {
    s.swap();
    s.split(1, '~len', '~padded');
    s.op(OpCodes.OP_OVER, pushes: ['~n']);
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~n']);
    s.op(OpCodes.OP_SPLIT, pops: 2, pushes: ['~sig', '~pad']);
    s.drop();
    s.cat('~sigpush');
    s.swap();
    s.bytes('~21', [0x21]);
    s.swap();
    s.cat('~pubpush');
    s.cat(as);
  }
}
