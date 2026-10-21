// The Fuelled NFT, TSL1_LT_FNFT: a covenant NFT whose token output carries
// the satoshis that pay its own fees. A transfer spends the token alone, or
// with one funding input swept whole into the token (a top-up); there is no
// change output. The owner can always end it on the cheap path and take its
// value. Records leave out what the script derives (as docs/
// WITNESS_LINEAGE_RESEARCH.md 9.6-9.7 describe); the issuance is anchored as
// for TSL1_LT_NFT, by the issuer's Rabin attestation at the first spend.
//
// Transaction shape, version 1, locktime 0, all sequences 0xffffffff:
//   in 0    the token                PUSH(pre) PUSH(sig) PUSH(pub) PUSH(C)
//   in 1    funding, P2PKH           PUSH(sig) PUSH(pub)          (top-up only)
//   out 0   the token                PUSH(h) OP_CODESEPARATOR code
// The issuance: in 0 a P2PKH coin, in 1 optional funding, out 0 the token.
//
// Header (153 B): tokenId 32, issuer 20, owner 20, flags 1 (bit 0: input 1
// funds this transaction), value 8 (this output's), in0 36, fundIn 36 (zero
// when unfunded).
//
// A record level leaves out the derived 72 bytes and, when unfunded, the
// funding outpoint and its signature:
//   Rec(T) = flags ‖ value ‖ in0 ‖ [fundIn] ‖ sigSlot sigPub ‖ [fSlot fPub] ‖ X(T)
//   X(T)   = Rec(T's parent), or the issuer's attestation for the issuance.
// The script splices the derived bytes back in: for its own transaction from
// its own header; for the parent the token id (zero when input 0 spends the
// issuance, whose txid is the token id), the issuer, and as owner HASH160 of
// the key that signed input 0. Rebuilding a transaction needs the value of
// the output its input 0 spent: the value field of X(T)'s first level, at
// bytes 1..9.
//
// Value is conserved by consensus (outputs cannot exceed inputs), so the
// covenant has no value rule: whatever the token does not keep goes to the
// miners as fee.
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import 'lt_layout.dart';
import '../script_gen/check_preimage_ocs.dart';
import '../script_gen/opcode_helpers.dart';
import '../script_gen/stk.dart';

/// Byte layout of the Fuelled NFT's header and record.
class FnftLayout {
  static const name = 'TSL1_LT_FNFT';
  static const size = 153;
  static const tokenId = 0, issuer = 32, owner = 52, flags = 72, value = 73, in0 = 81, fundIn = 117;
  static const derived = 72;
  static const flagFunded = 1;

  /// The record header of a level: flags, value, in0, [fundIn].
  static int recHeader(bool funded) => funded ? 81 : 45;

  /// A whole level without its X.
  static int level(bool funded) => recHeader(funded) + (funded ? 214 : 107);

  static const slot = 74;

  /// The issuer's attestation the issuance's record ends with.
  static const attestation = 326;
}

/// The header layout of a fuelled token: the Fuelled NFT ([fnft]); the
/// Voucher NFT ([vnft]), a Fuelled NFT with a hop limit, a forced
/// redemption to the issuer and an expiry after which the issuer can force
/// it; or the Note NFT ([note]), whose terms split the fuel between the
/// holder and the issuer on each way it can end. The derived bytes come
/// first (a record leaves them out); the record header (flags, value, in0,
/// fundIn) follows, the same for all.
class FuelLayout {
  final String name;

  /// 0 the Fuelled NFT, 1 the Voucher NFT, 2 the Note NFT.
  final int kind;

  /// A transfer may carry a pay output (flags bit 1): output 1, P2PKH to the
  /// header's pay key hash for its pay amount. The sale versions of the
  /// three (WITNESS_LINEAGE_RESEARCH.md 9.13), each an archetype of its own:
  /// other code, another code hash.
  final bool payable;
  const FuelLayout._(this.name, this.kind, [this.payable = false]);

  static const fnft = FuelLayout._('TSL1_LT_FNFT', 0);
  static const vnft = FuelLayout._('TSL1_LT_VNFT', 1);
  static const note = FuelLayout._('TSL1_LT_NOTE', 2);

  /// The Fuelled NFT with a pay output, so that it can be sold in its own
  /// transfer.
  static const fnftSale = FuelLayout._('TSL1_LT_FNFT_S', 0, true);

  /// The Voucher NFT with a pay output. A sale is a transfer: it counts
  /// against the hop limit.
  static const vnftSale = FuelLayout._('TSL1_LT_VNFT_S', 1, true);

  /// The Note NFT with a pay output. A sale is a transfer: it counts against
  /// the hop limit when there is one.
  static const noteSale = FuelLayout._('TSL1_LT_NOTE_S', 2, true);

  /// Flags bit 1: the transfer has a pay output.
  static const flagPaid = 2;

  bool get voucher => kind == 1;
  bool get isNote => kind == 2;

  /// Terms in the header, a counter after the owner, four pushes on every
  /// path, and no cheap path: the Voucher NFT and the Note NFT.
  bool get termed => kind == 1 || kind == 2;

  int get tokenId => 0; // 32
  int get issuer => 32; // 20

  /// The terms, fixed at issuance and copied unchanged. Both kinds start
  /// with maxHops 1.
  ///
  /// Voucher: expiry 4 (a block height, LE), redeemTo 20 (the issuer's
  /// wallet key hash, which redemptions pay), feeCap 8 (the most a holder's
  /// redemption may leave for the fee): 33 bytes.
  ///
  /// Note: payTo 20 (the issuer's wallet key hash: paid the issuer's share,
  /// its key signs a call), feeCap 8, exit 8 (the holder's amount when the
  /// holder ends it before maturity), maturity 4 (a height), mature 8 (the
  /// holder's amount from maturity on), callAt 4 (a height from which the
  /// issuer may end it), call 8 (the holder's amount then): 61 bytes. An
  /// amount of at least the value less feeCap pays the holder everything.
  int get maxHops => 52;
  int get expiry => 53;
  int get redeemTo => 57;
  int get payTo => 53;
  int get feeCap => isNote ? 73 : 77;
  int get exit => 81;
  int get maturity => 89;
  int get mature => 93;
  int get callAt => 101;
  int get call => 105;
  int get terms => isNote ? 61 : 33;

  int get owner => termed ? 52 + terms : 52; // 20
  int get counter => owner + 20; // termed only: 1, the hops since issuance
  int get derived => termed ? counter + 1 : 72;
  int get flags => derived;
  int get value => derived + 1;
  int get in0 => derived + 9;
  int get fundIn => derived + 45;
  int get pay => derived + 81; // payable only: amount 8, key hash 20
  int get size => derived + 81 + (payable ? 28 : 0); // 153 (FNFT), 187 (VNFT), 215 (Note); + 28 for each _S
}

class FnftScriptGen {
  final FuelLayout L;
  final bool _noteIssuerShare, _noteLock, _payRules;
  const FnftScriptGen([this.L = FuelLayout.fnft])
      : _noteIssuerShare = true,
        _noteLock = true,
        _payRules = true;

  /// The Note NFT's code with one clause removed ([noteIssuerShare]: the
  /// issuer's share in a two-output ending; [noteLock]: the lock-time rule),
  /// for tests that show the clause is what refuses an attack. (Terms are
  /// copied unchanged by the forward check on the header from the issuer to
  /// the owner, which spans them, as for the Voucher NFT.) [payRules]: a
  /// sale version's rules on the child's flags and pay field.
  const FnftScriptGen.weakened(this.L, {bool noteIssuerShare = true, bool noteLock = true, bool payRules = true})
      : _noteIssuerShare = noteIssuerShare,
        _noteLock = noteLock,
        _payRules = payRules;

  static final zero32 = List<int>.filled(32, 0);
  static final zero36 = List<int>.filled(36, 0);
  static final zero28 = List<int>.filled(28, 0);
  static final hashSequence1 = sha256Twice(List<int>.filled(4, 0xff));
  static final hashSequence2 = sha256Twice(List<int>.filled(8, 0xff));

  void _h(Stk s, String src, int from, int to, String as) => s.slice(src, from, to, as, total: L.size);

  /// h code -> value ‖ varint(len) ‖ PUSH(h) OP_CODESEPARATOR code
  void _tokenOutput(Stk s, String h, String code, String as) {
    s.pick(code, '~code');
    s.pick(h, '~h');
    s.bytes('~pfx', [0x4c, L.size]);
    s.swap();
    s.cat('~ph');
    s.bytes('~sep', [OpCodes.OP_CODESEPARATOR]);
    s.cat('~phs');
    s.swap();
    s.cat('~lock');
    s.op(OpCodes.OP_SIZE, pushes: ['~n']);
    s.map(ScriptEmit.varint, '~vi');
    s.swap();
    s.cat('~vlock');
    _h(s, h, L.value, L.in0, '~v');
    s.swap();
    s.cat(as);
  }

  /// -> amount ‖ 0x19 ‖ P2PKH(pkh), from [src]'s pay field (amount 8, key
  /// hash 20) at its last 28 bytes ([total] its length).
  void _payOutput(Stk s, String src, int total, String as) {
    s.slice(src, total - 28, total - 20, '~amt', total: total);
    s.bytes('~p', [0x19, 0x76, 0xa9, 0x14]);
    s.cat('~ap');
    s.slice(src, total - 20, total, '~pkh', total: total);
    s.cat('~app');
    s.bytes('~q', [0x88, 0xac]);
    s.cat(as);
  }

  /// slot pub -> varint(len) ‖ PUSH(sig) PUSH(pub) ‖ sequence
  void _sigInputTail(Stk s, String as) {
    ScriptEmit.p2pkhUnlock(s, '~ss');
    s.op(OpCodes.OP_SIZE, pushes: ['~n']);
    s.map((b) => ScriptEmit.uintLE(b, 1), '~n');
    s.swap();
    s.cat('~lss');
    s.bytes('~seq', [0xff, 0xff, 0xff, 0xff]);
    s.cat(as);
  }

  /// rec -> 1 when its first level is funded, else 0 (flags must be 0 or 1).
  void _funded(Stk s, String rec, String as) {
    s.pick(rec, '~r');
    s.split(1, '~f', '~');
    s.drop();
    s.bytes('~one', [FnftLayout.flagFunded]);
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: [as]);
  }

  /// rec -> the length of its first level's record header, or of the level.
  void _len(Stk s, String rec, String as, {required bool whole}) {
    if (L.payable) {
      // 45, + 36 when funded, + 28 when paid; the whole level adds a
      // signature pair per input
      s.pick(rec, '~r');
      s.split(1, '~f', '~');
      s.drop();
      s.op(OpCodes.OP_DUP, pushes: ['~f2']);
      s.bytes('~1', [1]);
      s.op(OpCodes.OP_AND, pops: 2, pushes: ['~fb']);
      s.bytes('~1', [1]);
      s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~fd']);
      s.ifElse(() => s.num('~a', whole ? 36 + 214 : 36), () => s.num('~a', whole ? 107 : 0));
      s.swap();
      s.bytes('~2', [2]);
      s.op(OpCodes.OP_AND, pops: 2, pushes: ['~pb']);
      s.bytes('~2', [2]);
      s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~pd']);
      s.ifElse(() => s.num('~b', 28 + 45), () => s.num('~b', 45));
      s.op(OpCodes.OP_ADD, pops: 2, pushes: [as]);
      return;
    }
    _funded(s, rec, '~fd');
    s.ifElse(() => s.num(as, whole ? FnftLayout.level(true) : FnftLayout.recHeader(true)),
        () => s.num(as, whole ? FnftLayout.level(false) : FnftLayout.recHeader(false)));
  }

  /// rec prefix code -> the txid of the transaction whose record is rec,
  /// given the 72 derived header bytes named by [prefix].
  void emitRebuild(Stk s, String rec, String prefix, String code, String as) {
    s.pick(rec, '~rec');
    s.split(1, 'fl', '~r');
    s.pick('fl', '~f');
    if (L.payable) {
      s.bytes('~one', [FnftLayout.flagFunded]);
      s.op(OpCodes.OP_AND, pops: 2, pushes: ['~fb']);
    }
    s.bytes('~one', [FnftLayout.flagFunded]);
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['fund']);
    s.roll('~r');
    s.split(44, 'vin', '~r'); // value 8, in0 36
    s.pick('fund', '~g');
    s.ifElse(() {
      s.roll('~r');
      s.split(36, 'fIn', '~r');
    }, () {
      s.bytes('fIn', zero36);
      s.roll('~r');
    });
    if (L.payable) {
      s.pick('fl', '~f');
      s.bytes('~two', [2]);
      s.op(OpCodes.OP_AND, pops: 2, pushes: ['~pb']);
      s.bytes('~two', [2]);
      s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['paid']);
      s.pick('paid', '~g');
      s.ifElse(() {
        s.roll('~r');
        s.split(28, 'pay', '~r');
      }, () {
        s.bytes('pay', zero28);
        s.roll('~r');
      });
    }
    s.split(FnftLayout.slot, 'sSlot', '~r');
    s.split(33, 'sPub', '~r');
    s.pick('fund', '~g');
    s.ifElse(() {
      s.roll('~r');
      s.split(FnftLayout.slot, 'fSlot', '~r');
      s.split(33, 'fPub', 'X');
    }, () {
      s.bytes('fSlot', []);
      s.bytes('fPub', []);
      s.roll('~r');
      s.rename('X');
    });

    // The full header: prefix ‖ flags ‖ value ‖ in0 ‖ fundIn.
    s.pick(prefix, '~h');
    s.pick('fl', '~a');
    s.cat('~h');
    s.pick('vin', '~a');
    s.cat('~h');
    s.pick('fIn', '~a');
    if (L.payable) {
      s.cat('~h');
      s.pick('pay', '~a');
    }
    s.cat('h1');

    _tokenOutput(s, 'h1', code, 'outs');
    if (L.payable) {
      s.pick('paid', '~g');
      s.ifElse(() {
        _payOutput(s, 'pay', 28, '~po');
        s.cat('outs');
      }, () {});
    }

    // Input 0's unlocking script: P2PKH in the issuance, else the token's.
    _h(s, 'h1', L.tokenId, L.issuer, '~t');
    s.bytes('~z', zero32);
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~iss']);
    s.ifElse(() {
      s.pick('sSlot', '~slot');
      s.pick('sPub', '~pub');
      ScriptEmit.p2pkhUnlock(s, 'ss0');
    }, () {
      _h(s, 'h1', L.in0, L.fundIn, '~o');
      s.pick('fund', '~g');
      s.ifElse(() {
        s.pick('fIn', '~f');
        s.cat('~o');
      }, () {});
      s.hash256('~hashPrevouts');
      s.bytes('~ver', [1, 0, 0, 0]);
      s.swap();
      s.cat('~p');
      s.pick('fund', '~g');
      s.ifElse(() => s.bytes('~hs', hashSequence2), () => s.bytes('~hs', hashSequence1));
      s.cat('~p');
      _h(s, 'h1', L.in0, L.fundIn, '~o');
      s.cat('~p');
      s.pick(code, '~code');
      s.op(OpCodes.OP_SIZE, pushes: ['~n']);
      s.map(ScriptEmit.varint, '~vi');
      s.swap();
      s.cat('~vcode');
      s.cat('~p');
      // the value of the output input 0 spent: the parent level's value
      s.pick('X', '~x');
      s.split(1, '~', '~x');
      s.nip();
      s.split(8, '~pv', '~');
      s.drop();
      s.cat('~p');
      s.bytes('~seq', [0xff, 0xff, 0xff, 0xff]);
      s.cat('~p');
      s.pick('outs', '~o');
      s.hash256('~ho');
      s.cat('~p');
      s.bytes('~lt', [0, 0, 0, 0, 0x41, 0, 0, 0]);
      s.cat('~pre');
      s.op(OpCodes.OP_SIZE, pushes: ['~n']);
      s.map(ScriptEmit.pushPrefix, '~pp');
      s.swap();
      s.cat('~pushPre');
      s.pick('sSlot', '~slot');
      s.pick('sPub', '~pub');
      ScriptEmit.p2pkhUnlock(s, '~sigpub');
      s.cat('~u');
      s.pick('h1', '~c');
      s.pick('X', '~x');
      s.cat('~c');
      s.op(OpCodes.OP_SIZE, pushes: ['~n']);
      s.map(ScriptEmit.pushPrefix, '~pp');
      s.swap();
      s.cat('~pushC');
      s.cat('ss0');
    });
    s.op(OpCodes.OP_SIZE, pushes: ['~n']);
    s.map(ScriptEmit.varint, '~vi');
    s.swap();
    s.cat('vss0');

    s.bytes('tx', [1, 0, 0, 0]);
    s.pick('fund', '~g');
    s.ifElse(() => s.bytes('~n', [2]), () => s.bytes('~n', [1]));
    s.cat('tx');
    _h(s, 'h1', L.in0, L.fundIn, '~o');
    s.cat('tx');
    s.roll('vss0');
    s.cat('tx');
    s.bytes('~seq', [0xff, 0xff, 0xff, 0xff]);
    s.cat('tx');
    s.pick('fund', '~g');
    s.ifElse(() {
      s.pick('fIn', '~fi');
      s.cat('tx');
      s.pick('fSlot', '~slot');
      s.pick('fPub', '~pub');
      _sigInputTail(s, '~inF');
      s.cat('tx');
    }, () {});
    if (L.payable) {
      s.pick('paid', '~g');
      s.ifElse(() => s.bytes('~nout', [2]), () => s.bytes('~nout', [1]));
    } else {
      s.bytes('~nout', [1]);
    }
    s.cat('tx');
    s.roll('outs');
    s.cat('tx');
    s.bytes('~lock', [0, 0, 0, 0]);
    s.cat('tx');
    s.hash256(as);
    // fl fund vin fIn [paid pay] sSlot sPub fSlot fPub X h1 remain underneath
    s.dropBelowTop(L.payable ? 12 : 10);
  }

  /// blob -> ; the issuer's Rabin signature over SHA256(identity ‖ ed25519 ‖
  /// this issuance's txid), by the key whose hash is H's issuer.
  void _issuerAttestation(Stk s) {
    s.split(LtIssuerBlob.padding, '~idEd', '~r');
    s.swap();
    s.slice('ownOut', 0, 32, '~txid', total: 36);
    s.cat('~msg');
    s.op(OpCodes.OP_SHA256, pops: 1, pushes: ['~h']);
    s.bytes('~00', [0]);
    s.cat('~h');
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~h']);
    s.swap();
    s.split(4, '~pad', '~r');
    s.swap();
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~pad']);
    s.rot();
    s.op(OpCodes.OP_ADD, pops: 2, pushes: ['~hp']);
    s.swap();
    s.split(LtResetEvidence.numLen, '~s', '~n');
    s.op(OpCodes.OP_DUP, pushes: ['~n2']);
    s.op(OpCodes.OP_HASH160, pops: 1, pushes: ['~nh']);
    _h(s, 'H', L.issuer, L.issuer + 20, '~issuer');
    s.equalVerify();
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~n']);
    s.swap();
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~s']);
    s.op(OpCodes.OP_DUP, pushes: ['~s2']);
    s.op(OpCodes.OP_MUL, pops: 2, pushes: ['~ss']);
    s.swap();
    s.op(OpCodes.OP_MOD, pops: 2, pushes: ['~ssn']);
    s.op(OpCodes.OP_NUMEQUALVERIFY, pops: 2);
  }

  /// The code after the separator. Normal path: PUSH(pre) PUSH(sig)
  /// PUSH(pub) PUSH(C), C = h1c ‖ Rec(this transaction). Cheap path: PUSH(sig)
  /// PUSH(pub), the owner's signature only (ends the token; any value).
  SVScript code({bool stepB = true, bool issuerCheck = true}) {
    final s = Stk(['pre', 'sig', 'pub', 'C', 'H']);
    final b = s.b;

    if (!L.termed) {
      // Cheap path: sig pub H.
      b.opCode(OpCodes.OP_DEPTH);
      b.smallNum(3);
      b.opCode(OpCodes.OP_NUMEQUAL);
      b.opCode(OpCodes.OP_IF);
      OpcodeHelpers.pushInt(b, L.owner);
      b.opCode(OpCodes.OP_SPLIT);
      b.opCode(OpCodes.OP_NIP);
      OpcodeHelpers.pushInt(b, 20);
      b.opCode(OpCodes.OP_SPLIT);
      b.opCode(OpCodes.OP_DROP);
      b.opCode(OpCodes.OP_OVER);
      b.opCode(OpCodes.OP_HASH160);
      b.opCode(OpCodes.OP_EQUALVERIFY);
      b.opCode(OpCodes.OP_CHECKSIG);
      b.opCode(OpCodes.OP_ELSE);
    } else {
      // Every path of the Voucher and Note NFT pushes four items: depth 5 with H.
      b.opCode(OpCodes.OP_DEPTH);
      b.smallNum(5);
      b.opCode(OpCodes.OP_NUMEQUALVERIFY);
    }

    // The preimage is this spend's.
    s.pick('pre', '~pre');
    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    s.op(OpCodes.OP_VERIFY, pops: 1);

    // version, hashPrevouts, own outpoint, own code, hashOutputs
    s.pick('pre', '~pre');
    s.split(104, 'head', '~r');
    s.split(3, '~', '~r');
    s.nip();
    s.op(OpCodes.OP_SIZE, pushes: ['~n']);
    s.num('~52', 52);
    s.op(OpCodes.OP_SUB, pops: 2, pushes: ['~at']);
    s.op(OpCodes.OP_SPLIT, pops: 2, pushes: ['code', '~tail']);
    if (L.termed) {
      // keep the tail: value 8, nSequence 4, hashOutputs 32, nLockTime 4, sighash 4
      s.op(OpCodes.OP_DUP, pushes: ['tail']);
      s.swap();
    }
    s.split(12, '~', '~r');
    s.nip();
    s.split(32, 'hashOutputs', '~');
    s.drop();
    s.roll('head');
    s.split(4, '~ver', '~r');
    s.swap();
    s.bytes('~one', [1, 0, 0, 0]);
    s.equalVerify();
    s.split(32, 'hashPrevouts', '~r');
    s.split(32, '~', 'ownOut');
    s.nip();

    if (!L.termed) {
      _transferPath(s, stepB: stepB, issuerCheck: issuerCheck);
      while (s.names.isNotEmpty) {
        s.drop();
      }
      b.opCode(OpCodes.OP_1);
      b.opCode(OpCodes.OP_ENDIF);
      return b.build();
    }

    void dropAll() {
      while (s.names.isNotEmpty) {
        s.drop();
      }
    }

    if (L.isNote) {
      // The Note NFT: the fourth item selects the path by its size. 29 or 37
      // bytes (3, the owner's key hash, one or two output values): the
      // issuer's call. 9 or 17 (1 or 2, one or two output values): the
      // holder's exit or mature exit. Else a transfer (C).
      _size(s, 'C', '~n');
      s.op(OpCodes.OP_DUP, pushes: ['~n2']);
      s.num('~29', 29);
      s.op(OpCodes.OP_NUMEQUAL, pops: 2, pushes: ['~c1']);
      s.swap();
      s.num('~37', 37);
      s.op(OpCodes.OP_NUMEQUAL, pops: 2, pushes: ['~c2']);
      s.op(OpCodes.OP_BOOLOR, pops: 2, pushes: ['~isCall']);
      s.ifElse(() {
        _noteEnding(s, 3);
        dropAll();
      }, () {
        _size(s, 'C', '~n');
        s.op(OpCodes.OP_DUP, pushes: ['~n2']);
        s.num('~9', 9);
        s.op(OpCodes.OP_NUMEQUAL, pops: 2, pushes: ['~e1']);
        s.swap();
        s.num('~17', 17);
        s.op(OpCodes.OP_NUMEQUAL, pops: 2, pushes: ['~e2']);
        s.op(OpCodes.OP_BOOLOR, pops: 2, pushes: ['~isExit']);
        s.ifElse(() {
          s.slice('C', 0, 1, '~path', total: 9);
          s.bytes('~1', [1]);
          s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~isEarly']);
          s.ifElse(() {
            _noteEnding(s, 1);
            dropAll();
          }, () {
            _noteEnding(s, 2);
            dropAll();
          });
        }, () {
          _transferPath(s, stepB: stepB, issuerCheck: issuerCheck);
          dropAll();
        });
      });
      b.opCode(OpCodes.OP_1);
      return b.build();
    }

    // The Voucher NFT: the fourth item selects the path by its size: 8 bytes
    // (the redemption's output value) a holder's redemption, 20 (the owner's
    // key hash) the issuer's force-redemption, else a transfer (C).

    _size(s, 'C', '~n');
    s.num('~8', 8);
    s.op(OpCodes.OP_NUMEQUAL, pops: 2, pushes: ['~isR']);
    s.ifElse(() {
      _redeemPath(s);
      dropAll();
    }, () {
      _size(s, 'C', '~n');
      s.num('~20', 20);
      s.op(OpCodes.OP_NUMEQUAL, pops: 2, pushes: ['~isX']);
      s.ifElse(() {
        _reclaimPath(s);
        dropAll();
      }, () {
        _transferPath(s, stepB: stepB, issuerCheck: issuerCheck);
        dropAll();
      });
    });
    b.opCode(OpCodes.OP_1);
    return b.build();
  }

  /// The normal path: a transfer, its child header and this transaction's
  /// record in C.
  void _transferPath(Stk s, {required bool stepB, required bool issuerCheck}) {
    // C: the child's header, then this transaction's record.
    s.pick('C', '~c');
    s.split(L.size, 'h1c', 'RecP');

    // Forward: the child carries this token, from this outpoint.
    _h(s, 'H', L.tokenId, L.issuer, '~t');
    s.bytes('~z', zero32);
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['hop0']);
    s.pick('hop0', '~g');
    s.ifElse(() => s.slice('ownOut', 0, 32, '~a', total: 36), () => _h(s, 'H', L.tokenId, L.issuer, '~a'));
    _h(s, 'h1c', L.tokenId, L.issuer, '~b');
    s.equalVerify();
    _h(s, 'h1c', L.issuer, L.owner, '~a');
    _h(s, 'H', L.issuer, L.owner, '~b');
    s.equalVerify();
    if (L.payable) {
      // flags: bit 0 funded, bit 1 paid, nothing else; unpaid: a zero pay
      // field (the one the rebuild assumes)
      if (_payRules) {
        _h(s, 'h1c', L.flags, L.value, '~fl');
        s.bytes('~fc', [0xfc]);
        s.op(OpCodes.OP_AND, pops: 2, pushes: ['~hi']);
        s.bytes('~0', [0]);
        s.equalVerify();
      }
      _h(s, 'h1c', L.flags, L.value, '~fl');
      s.bytes('~1', [FnftLayout.flagFunded]);
      s.op(OpCodes.OP_AND, pops: 2, pushes: ['~fb']);
      s.bytes('~1', [FnftLayout.flagFunded]);
      s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['fundC']);
      _h(s, 'h1c', L.flags, L.value, '~fl');
      s.bytes('~2', [2]);
      s.op(OpCodes.OP_AND, pops: 2, pushes: ['~pb']);
      s.bytes('~2', [2]);
      s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['paidC']);
      if (_payRules) {
        s.pick('paidC', '~g');
        s.notIf(() {
          _h(s, 'h1c', L.pay, L.size, '~pf');
          s.bytes('~z28', zero28);
          s.equalVerify();
        });
      }
    } else {
      // flags 0 or 1; unfunded: a zero funding outpoint (the one the rebuild assumes)
      _h(s, 'h1c', L.flags, L.value, '~fl');
      s.op(OpCodes.OP_DUP, pushes: ['~fl2']);
      s.bytes('~1', [FnftLayout.flagFunded]);
      s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['fundC']);
      s.swap();
      s.bytes('~0', [0]);
      s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~unf']);
      s.pick('fundC', '~fc');
      s.op(OpCodes.OP_BOOLOR, pops: 2, pushes: ['~ok']);
      s.op(OpCodes.OP_VERIFY, pops: 1);
    }
    s.pick('fundC', '~g');
    s.notIf(() {
      _h(s, 'h1c', L.fundIn, L.fundIn + 36, '~fi');
      s.bytes('~z36', zero36);
      s.equalVerify();
    });
    _h(s, 'h1c', L.in0, L.fundIn, '~a');
    s.pick('ownOut', '~b');
    s.equalVerify();
    _h(s, 'h1c', L.in0, L.fundIn, '~o');
    s.roll('fundC');
    s.ifElse(() {
      _h(s, 'h1c', L.fundIn, L.fundIn + 36, '~fi');
      s.cat('~o');
    }, () {});
    s.hash256('~a');
    s.pick('hashPrevouts', '~b');
    s.equalVerify();

    // The owner authorises it.
    s.pick('pub', '~pub');
    s.op(OpCodes.OP_HASH160, pops: 1, pushes: ['~pkh']);
    _h(s, 'H', L.owner, L.owner + 20, '~owner');
    s.equalVerify();
    s.pick('sig', '~sig');
    s.pick('pub', '~pub');
    s.op(OpCodes.OP_CHECKSIGVERIFY, pops: 2);

    if (L.voucher) {
      // The hop limit: this output's counter is below maxHops, and the
      // child's is one more.
      _byte(s, 'H', L.counter, '~hc');
      s.op(OpCodes.OP_DUP, pushes: ['~hc2']);
      _byte(s, 'H', L.maxHops, '~mh');
      s.op(OpCodes.OP_LESSTHAN, pops: 2, pushes: ['~below']);
      s.op(OpCodes.OP_VERIFY, pops: 1);
      s.op(OpCodes.OP_1ADD, pops: 1, pushes: ['~next']);
      _byte(s, 'h1c', L.counter, '~cc');
      s.op(OpCodes.OP_NUMEQUALVERIFY, pops: 2);
    }
    if (L.isNote) {
      // The hop limit when maxHops is not zero: as for the voucher. With no
      // limit the counter is not kept: the child's equals this one's (zero).
      _byte(s, 'H', L.maxHops, '~mh');
      s.op(OpCodes.OP_0NOTEQUAL, pops: 1, pushes: ['~limited']);
      s.ifElse(() {
        _byte(s, 'H', L.counter, '~hc');
        s.op(OpCodes.OP_DUP, pushes: ['~hc2']);
        _byte(s, 'H', L.maxHops, '~mh');
        s.op(OpCodes.OP_LESSTHAN, pops: 2, pushes: ['~below']);
        s.op(OpCodes.OP_VERIFY, pops: 1);
        s.op(OpCodes.OP_1ADD, pops: 1, pushes: ['~next']);
        _byte(s, 'h1c', L.counter, '~cc');
        s.op(OpCodes.OP_NUMEQUALVERIFY, pops: 2);
      }, () {
        _h(s, 'h1c', L.counter, L.counter + 1, '~cc');
        _h(s, 'H', L.counter, L.counter + 1, '~hc');
        s.equalVerify();
      });
    }


    // The child's one output is the token (and, paid, the pay output).
    _tokenOutput(s, 'h1c', 'code', '~out');
    if (L.payable) {
      s.roll('paidC');
      s.ifElse(() {
        _h(s, 'h1c', L.pay, L.size, '~pf');
        _payOutput(s, '~pf', 28, '~po');
        s.nip();
        s.cat('~out');
      }, () {});
    }
    s.hash256('~a');
    s.pick('hashOutputs', '~b');
    s.equalVerify();

    // Step A: this transaction is what its record says.
    _h(s, 'H', 0, L.derived, 'pfxA');
    emitRebuild(s, 'RecP', 'pfxA', 'code', '~txid');
    s.slice('ownOut', 0, 32, '~own', total: 36);
    s.equalVerify();
    s.roll('pfxA');
    s.drop();

    // Step B: at hop 0 the issuer attested this issuance; otherwise the
    // output it spent held this script.
    s.roll('hop0');
    s.ifElse(() {
      if (issuerCheck) {
        s.pick('RecP', '~r');
        _len(s, 'RecP', '~off', whole: true);
        s.op(OpCodes.OP_SPLIT, pops: 2, pushes: ['~', '~blob']);
        s.nip();
        _issuerAttestation(s);
      }
    }, () {
      if (stepB) {
        // the parent's derived bytes: its token id (zero for the issuance),
        // the issuer, and its owner, the key that signed input 0 here
        _h(s, 'H', L.in0, L.in0 + 32, '~i');
        _h(s, 'H', L.tokenId, L.issuer, '~t');
        s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~isIss']);
        s.ifElse(() => s.bytes('~tid', zero32), () => _h(s, 'H', L.tokenId, L.issuer, '~tid'));
        _h(s, 'H', L.issuer, L.owner, '~iss');
        s.cat('~p');
        s.pick('RecP', '~r');
        _len(s, 'RecP', '~c', whole: false);
        s.num('~s', FnftLayout.slot);
        s.op(OpCodes.OP_ADD, pops: 2, pushes: ['~at']);
        s.op(OpCodes.OP_SPLIT, pops: 2, pushes: ['~', '~r2']);
        s.nip();
        s.split(33, '~spub', '~');
        s.drop();
        s.op(OpCodes.OP_HASH160, pops: 1, pushes: ['~own']);
        if (L.voucher) {
          // and its counter, one less than this output's
          s.cat('~p');
          _byte(s, 'H', L.counter, '~hc');
          s.op(OpCodes.OP_1SUB, pops: 1, pushes: ['~pc']);
          s.map((b) => ScriptEmit.uintLE(b, 1), '~pcb');
        }
        if (L.isNote) {
          // and its counter: one less than this output's when counted, else
          // the same
          s.cat('~p');
          _byte(s, 'H', L.counter, '~hc');
          _byte(s, 'H', L.maxHops, '~mh');
          s.op(OpCodes.OP_0NOTEQUAL, pops: 1, pushes: ['~limited']);
          s.op(OpCodes.OP_SUB, pops: 2, pushes: ['~pc']);
          s.map((b) => ScriptEmit.uintLE(b, 1), '~pcb');
        }
        s.cat('pfxB');
        s.pick('RecP', '~r');
        _len(s, 'RecP', '~off', whole: true);
        s.op(OpCodes.OP_SPLIT, pops: 2, pushes: ['~', 'recB']);
        s.nip();
        emitRebuild(s, 'recB', 'pfxB', 'code', '~txidB');
        _h(s, 'H', L.in0, L.in0 + 32, '~expect');
        s.equalVerify();
        s.roll('recB');
        s.drop();
        s.roll('pfxB');
        s.drop();
      }
    });

  }

  /// x -> the byte of [src] at [at] as an unsigned number.
  void _byte(Stk s, String src, int at, String as) {
    _h(s, src, at, at + 1, '~b1');
    s.bytes('~00', [0]);
    s.cat('~b2');
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: [as]);
  }

  /// -> the little-endian unsigned number in [src][from:to].
  void _uint(Stk s, String src, int from, int to, String as, {int? total}) {
    s.slice(src, from, to, '~u', total: total ?? L.size);
    s.bytes('~00', [0]);
    s.cat('~u2');
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: [as]);
  }

  /// -> the size of [src].
  void _size(Stk s, String src, String as) {
    s.pick(src, '~sz');
    s.op(OpCodes.OP_SIZE, pushes: [as]);
    s.nip();
  }

  /// The holder's redemption (Voucher NFT): the owner signs; the one output
  /// pays the issuer's redeemTo the value C (8 bytes, LE), at least this
  /// output's value less the feeCap.
  void _redeemPath(Stk s) {
    s.pick('pub', '~pub');
    s.op(OpCodes.OP_HASH160, pops: 1, pushes: ['~pkh']);
    _h(s, 'H', L.owner, L.owner + 20, '~owner');
    s.equalVerify();
    s.pick('sig', '~sig');
    s.pick('pub', '~pub');
    s.op(OpCodes.OP_CHECKSIGVERIFY, pops: 2);
    // C >= value - feeCap
    s.pick('C', '~o');
    s.bytes('~00', [0]);
    s.cat('~o2');
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~out']);
    _uint(s, 'tail', 0, 8, '~val', total: 52);
    _uint(s, 'H', L.feeCap, L.feeCap + 8, '~cap');
    s.op(OpCodes.OP_SUB, pops: 2, pushes: ['~floor']);
    s.op(OpCodes.OP_GREATERTHANOREQUAL, pops: 2, pushes: ['~ok']);
    s.op(OpCodes.OP_VERIFY, pops: 1);
    // the outputs are C ‖ P2PKH(redeemTo)
    s.pick('C', '~v');
    s.bytes('~p', [0x19, 0x76, 0xa9, 0x14]);
    s.cat('~vp');
    _h(s, 'H', L.redeemTo, L.redeemTo + 20, '~rt');
    s.cat('~vpr');
    s.bytes('~q', [0x88, 0xac]);
    s.cat('~out1');
    s.hash256('~a');
    s.pick('hashOutputs', '~b');
    s.equalVerify();
  }

  /// The issuer's force-redemption (Voucher NFT): the key whose hash is
  /// redeemTo signs, C names the owner it takes the token from, and the
  /// transaction cannot be mined before the expiry height: its nLockTime is
  /// a height at least the expiry and this input's sequence is not final,
  /// which is what makes the network enforce the nLockTime. Its outputs are
  /// the issuer's to choose.
  void _reclaimPath(Stk s) {
    s.pick('pub', '~pub');
    s.op(OpCodes.OP_HASH160, pops: 1, pushes: ['~pkh']);
    _h(s, 'H', L.redeemTo, L.redeemTo + 20, '~rt');
    s.equalVerify();
    s.pick('sig', '~sig');
    s.pick('pub', '~pub');
    s.op(OpCodes.OP_CHECKSIGVERIFY, pops: 2);
    s.pick('C', '~c');
    _h(s, 'H', L.owner, L.owner + 20, '~owner');
    s.equalVerify();
    // nLockTime: a block height (below 500,000,000), at least the expiry
    _uint(s, 'tail', 44, 48, '~lt', total: 52);
    s.op(OpCodes.OP_DUP, pushes: ['~lt2']);
    s.num('~500m', 500000000);
    s.op(OpCodes.OP_LESSTHAN, pops: 2, pushes: ['~height']);
    s.op(OpCodes.OP_VERIFY, pops: 1);
    _uint(s, 'H', L.expiry, L.expiry + 4, '~exp');
    s.op(OpCodes.OP_GREATERTHANOREQUAL, pops: 2, pushes: ['~late']);
    s.op(OpCodes.OP_VERIFY, pops: 1);
    // this input's nSequence is not final
    s.slice('tail', 8, 12, '~sq', total: 52);
    s.bytes('~ff', [0xff, 0xff, 0xff, 0xff]);
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~final']);
    s.op(OpCodes.OP_NOT, pops: 1, pushes: ['~nonFinal']);
    s.op(OpCodes.OP_VERIFY, pops: 1);
  }

  /// nLockTime is a block height (below 500,000,000) of at least the 4-byte
  /// height at H[[at]], and this input's sequence is not final, which makes
  /// the network enforce the nLockTime.
  void _lockRule(Stk s, int at) {
    _uint(s, 'tail', 44, 48, '~lt', total: 52);
    s.op(OpCodes.OP_DUP, pushes: ['~lt2']);
    s.num('~500m', 500000000);
    s.op(OpCodes.OP_LESSTHAN, pops: 2, pushes: ['~height']);
    s.op(OpCodes.OP_VERIFY, pops: 1);
    _uint(s, 'H', at, at + 4, '~at');
    s.op(OpCodes.OP_GREATERTHANOREQUAL, pops: 2, pushes: ['~late']);
    s.op(OpCodes.OP_VERIFY, pops: 1);
    s.slice('tail', 8, 12, '~sq', total: 52);
    s.bytes('~ff', [0xff, 0xff, 0xff, 0xff]);
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~final']);
    s.op(OpCodes.OP_NOT, pops: 1, pushes: ['~nonFinal']);
    s.op(OpCodes.OP_VERIFY, pops: 1);
  }

  /// A Note NFT ending ([path] 1 the holder's exit, 2 the holder's mature
  /// exit, 3 the issuer's call). C is the path byte, for a call the owner's
  /// key hash, then one or two 8-byte output values. With `a` the terms'
  /// holder amount for the path, `v` this output's value and
  /// `floor = v - feeCap`, the outputs are exactly:
  ///  * one value x0 >= floor, to payTo when a is 0, else to the owner,
  ///    which needs a >= floor (the holder gets everything);
  ///  * two values, a > 0: x0 >= floor - a to payTo and x1 >= a to the
  ///    owner: neither side can take the other's share.
  /// Output 0 pays payTo whenever the issuer is paid: the coin a successor's
  /// issuance spends.
  void _noteEnding(Stk s, int path) {
    final call = path == 3;
    final who = call ? L.payTo : L.owner;
    s.pick('pub', '~pub');
    s.op(OpCodes.OP_HASH160, pops: 1, pushes: ['~pkh']);
    _h(s, 'H', who, who + 20, '~who');
    s.equalVerify();
    s.pick('sig', '~sig');
    s.pick('pub', '~pub');
    s.op(OpCodes.OP_CHECKSIGVERIFY, pops: 2);

    // the path byte, then for a call the owner it ends, then the values
    s.pick('C', '~c');
    s.split(1, '~path', '~rest');
    s.swap();
    s.bytes('~p', [path]);
    s.equalVerify();
    if (call) {
      s.split(20, '~own', 'body');
      s.swap();
      _h(s, 'H', L.owner, L.owner + 20, '~ho');
      s.equalVerify();
    } else {
      s.rename('body');
    }
    if (path == 2 && _noteLock) _lockRule(s, L.maturity);
    if (call && _noteLock) _lockRule(s, L.callAt);

    final amountAt = switch (path) { 1 => L.exit, 2 => L.mature, _ => L.call };
    _uint(s, 'H', amountAt, amountAt + 8, 'amt');
    _uint(s, 'tail', 0, 8, '~v', total: 52);
    _uint(s, 'H', L.feeCap, L.feeCap + 8, '~cap');
    s.op(OpCodes.OP_SUB, pops: 2, pushes: ['floor']);

    void p2pkhOut(String bodyName, int from, int to, int total, int pkhAt, String as) {
      s.slice(bodyName, from, to, '~val', total: total);
      s.bytes('~p', [0x19, 0x76, 0xa9, 0x14]);
      s.cat('~vp');
      _h(s, 'H', pkhAt, pkhAt + 20, '~pkh');
      s.cat('~vpp');
      s.bytes('~q', [0x88, 0xac]);
      s.cat(as);
    }

    _size(s, 'body', '~bn');
    s.num('~8', 8);
    s.op(OpCodes.OP_NUMEQUAL, pops: 2, pushes: ['~one']);
    s.ifElse(() {
      // one output of x0 >= floor
      _uint(s, 'body', 0, 8, '~x0', total: 8);
      s.pick('floor', '~f');
      s.op(OpCodes.OP_GREATERTHANOREQUAL, pops: 2, pushes: ['~ok']);
      s.op(OpCodes.OP_VERIFY, pops: 1);
      // to payTo when a is 0; to the owner only when a >= floor
      s.pick('amt', '~a');
      s.op(OpCodes.OP_NOT, pops: 1, pushes: ['~zero']);
      s.pick('amt', '~a');
      s.pick('floor', '~f');
      s.op(OpCodes.OP_GREATERTHANOREQUAL, pops: 2, pushes: ['~all']);
      s.op(OpCodes.OP_BOOLOR, pops: 2, pushes: ['~ok']);
      s.op(OpCodes.OP_VERIFY, pops: 1);
      s.pick('amt', '~a');
      s.op(OpCodes.OP_0NOTEQUAL, pops: 1, pushes: ['~toOwner']);
      s.ifElse(() => p2pkhOut('body', 0, 8, 8, L.owner, '~outs'), () => p2pkhOut('body', 0, 8, 8, L.payTo, '~outs'));
    }, () {
      // two outputs: a > 0; the holder gets x1 >= a, and the issuer
      // x0 >= floor - a (each side's share is protected from the other)
      s.pick('amt', '~a');
      s.op(OpCodes.OP_0NOTEQUAL, pops: 1, pushes: ['~pos']);
      s.op(OpCodes.OP_VERIFY, pops: 1);
      _uint(s, 'body', 8, 16, '~x1', total: 16);
      s.pick('amt', '~a');
      s.op(OpCodes.OP_GREATERTHANOREQUAL, pops: 2, pushes: ['~ok']);
      s.op(OpCodes.OP_VERIFY, pops: 1);
      if (_noteIssuerShare) {
        _uint(s, 'body', 0, 8, '~x0', total: 16);
        s.pick('floor', '~f');
        s.pick('amt', '~a');
        s.op(OpCodes.OP_SUB, pops: 2, pushes: ['~share']);
        s.op(OpCodes.OP_GREATERTHANOREQUAL, pops: 2, pushes: ['~ok']);
        s.op(OpCodes.OP_VERIFY, pops: 1);
      }
      p2pkhOut('body', 0, 8, 16, L.payTo, '~o0');
      p2pkhOut('body', 8, 16, 16, L.owner, '~o1');
      s.cat('~outs');
    });
    s.hash256('~a');
    s.pick('hashOutputs', '~b');
    s.equalVerify();
  }

  /// PUSH(header) OP_CODESEPARATOR code
  Uint8List lock(List<int> header, List<int> code) {
    if (header.length != L.size) throw ArgumentError('header is ${header.length} bytes');
    return Uint8List.fromList([0x4c, L.size, ...header, OpCodes.OP_CODESEPARATOR, ...code]);
  }
}
