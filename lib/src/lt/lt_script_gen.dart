// The lineage-token scripts, TSL1_LT_FT and TSL1_LT_NFT.
//
// A token output is  PUSH(header) OP_CODESEPARATOR code.  The header holds
// the input side of its OWN transaction; when the output is spent, the script
// reassembles that transaction byte for byte from the header and the unlock,
// hashes it natively and compares with the txid in its own outpoint (step A),
// then does the same for the transaction it spent, from a record supplied in
// the unlock, so that consensus ran these same checks one hop earlier (step
// B). The induction closes at the issuance, whose first spend carries the
// issuer's Rabin attestation over the issuance txid. A forward covenant
// (OCS, SIGHASH_ALL) fixes the successor outputs. The unlock therefore
// carries one record per ancestor transaction; a reset (two of the three
// attesters the issuance names signing for an outpoint, with the issuance's
// record so that the script can rebuild it and read them from it) drops that
// history.
//
// The fungible archetype adds amounts, a split into two token outputs, and a
// merge with one PASSENGER: input 1, whose script runs a cheap path (the
// owner's signature only) while the DRIVER at input 0 rebuilds the
// passenger's transaction and its parent. A transaction's token outputs are
// genuine iff its input 0 is a normal-path spend of a token output.
//
// Transaction shape, version 1, locktime 0, all sequences 0xffffffff:
//   in 0    driver token input      PUSH(pre) PUSH(sig) PUSH(pub) PUSH(C)
//   in 1    passenger token input   PUSH(sig) PUSH(pub)           (FT, optional)
//   in last funding, P2PKH          PUSH(sig) PUSH(pub)
//   out 0   change, P2PKH
//   out 1   token, 1 sat            PUSH(h1) OP_CODESEPARATOR code
//   out 2   token, 1 sat            PUSH(h2) OP_CODESEPARATOR code   (FT, optional)
// The issuance is an ordinary transaction: in 0 a P2PKH coin, in 1 funding.
//
// A transaction's RECORD is everything a script needs to rebuild it:
//   Rec(T) = h1 ‖ [h2] ‖ senderSlot senderPub [passSlot passPub] fundSlot fundPub ‖ X(T)
//   X(T)   = Pass(T) ‖ Rec(driver parent of T)     Pass(T) = Rec(passenger's tx), or empty
//          = Pass(T) ‖ E                            when T's input 0 was a reset
//   X(T0)  = R, the issuer's attestation            (the issuance)
// and the driver's unlock pushes C(T) = h1 ‖ [h2] ‖ X(T).
//
// Every signature is pushed in an unlocking script and none sits in a header,
// so every input signs SIGHASH_ALL and every output is covered by every
// signature. The transaction must stay version 1: Chronicle relaxes the
// malleability rules for higher versions, and a relayer who could re-encode
// an unlock would change the txid and kill the token at the next hop.
import 'dart:typed_data';
import 'package:dartsv/dartsv.dart';
import '../script_gen/check_preimage_ocs.dart';
import '../script_gen/opcode_helpers.dart';
import '../script_gen/stk.dart';
import 'lt_layout.dart';

class LtScriptGen {
  final LtLayout L;
  final bool _childUnlisted;
  const LtScriptGen(this.L) : _childUnlisted = true;

  /// TSL1_LT_LNFT without the rule that a purchase leaves the child
  /// unlisted, for the test that shows what the rule stops.
  const LtScriptGen.weakened(this.L, {bool childUnlisted = true}) : _childUnlisted = childUnlisted;

  static const ft = LtScriptGen(LtLayout.ft);
  static const nft = LtScriptGen(LtLayout.nft);
  static const lnft = LtScriptGen(LtLayout.lnft);
  static final zero33 = List<int>.filled(33, 0);
  static final zero8 = List<int>.filled(8, 0);

  static final List<int> hashSequence2 = sha256Twice(List<int>.filled(8, 0xff));
  static final List<int> hashSequence3 = sha256Twice(List<int>.filled(12, 0xff));
  static final List<int> zero32 = List<int>.filled(32, 0);

  void _h(Stk s, String src, int from, int to, String as) => s.slice(src, from, to, as, total: L.size);

  /// h -> h.flags & [bit], as a boolean.
  void _flag(Stk s, String h, int bit, String as) {
    _h(s, h, L.flags, L.flags + 1, as);
    s.bytes('~m', [bit]);
    s.op(OpCodes.OP_AND, pops: 2, pushes: [as]);
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: [as]);
    s.op(OpCodes.OP_0NOTEQUAL, pops: 1, pushes: [as]);
  }

  /// h -> whether h's transaction has two token outputs (FT; NFT: false).
  void _split(Stk s, String h, String as) {
    if (L.fungible) {
      _flag(s, h, LtLayout.flagSplit, as);
    } else {
      s.bytes(as, []);
    }
  }

  /// h -> whether h's transaction's input 0 was a reset.
  void _reset(Stk s, String h, String as) => _flag(s, h, LtLayout.flagReset, as);

  /// h -> h.passLen, as a number (FT; NFT: 0).
  void _passLen(Stk s, String h, String as) {
    if (L.fungible) {
      _h(s, h, L.passLen, L.passLen + 4, as);
      s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: [as]);
    } else {
      s.num(as, 0);
    }
  }

  /// Branches on a runtime flag the FT script has; the NFT script takes the
  /// [otherwise] branch at generation time.
  void _when(Stk s, String flag, void Function() then, void Function() otherwise) {
    if (L.fungible) {
      s.pick(flag, '~f');
      s.ifElse(then, otherwise);
    } else {
      otherwise();
    }
  }

  /// h -> the offset of Rec(driver parent) within Rec(h's transaction):
  /// headers + signatures + passenger record.
  void emitParentOffset(Stk s, String h, String as) {
    if (!L.fungible) {
      s.num(as, L.size + LtLayout.sigsTwo);
      return;
    }
    _split(s, h, '~sp');
    s.ifElse(() => s.num('~hl', 2 * L.size), () => s.num('~hl', L.size));
    _passLen(s, h, '~pl');
    s.op(OpCodes.OP_DUP, pushes: ['~pl2']);
    s.op(OpCodes.OP_0NOTEQUAL, pops: 1, pushes: ['~p']);
    s.ifElse(() => s.num('~sl', LtLayout.sigsThree), () => s.num('~sl', LtLayout.sigsTwo));
    s.op(OpCodes.OP_ADD, pops: 2, pushes: ['~x']);
    s.op(OpCodes.OP_ADD, pops: 2, pushes: [as]);
  }

  /// rec -> rec[offset(rec's first header):], the driver parent's record.
  void emitParentRec(Stk s, String rec, String as) {
    s.pick(rec, '~rec');
    if (L.fungible) {
      s.op(OpCodes.OP_DUP, pushes: ['~rec2']);
      s.split(L.size, '~h', '~');
      s.drop();
      emitParentOffset(s, '~h', '~off');
      s.nip();
    } else {
      emitParentOffset(s, rec, '~off');
    }
    s.op(OpCodes.OP_SPLIT, pops: 2, pushes: ['~', as]);
    s.nip();
  }

  /// h code -> the serialised token output holding h.
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
    s.bytes('~one', [1, 0, 0, 0, 0, 0, 0, 0]);
    s.swap();
    s.cat(as);
  }

  /// Pushes the serialised outputs: change, token h1, and token h2 when [split].
  void emitOutputs(Stk s, String h1, String h2, String split, String code, String as) {
    _h(s, h1, L.changeAmt, L.changePkh, '~amt');
    s.bytes('~p', [0x19, 0x76, 0xa9, 0x14]);
    s.cat('~p');
    _h(s, h1, L.changePkh, L.in0, '~pkh');
    s.cat('~p');
    s.bytes('~q', [0x88, 0xac]);
    s.cat('~change');
    _tokenOutput(s, h1, code, '~t1');
    s.cat('~outs');
    _when(
      s,
      split,
      () {
        _tokenOutput(s, h2, code, '~t2');
        s.cat(as);
      },
      () {
        s.rename(as);
      },
    );
  }

  /// slot pub -> P2PKH-style input tail: varint(len) ‖ PUSH(sig) PUSH(pub) ‖ sequence.
  void _sigInputTail(Stk s, String as) {
    ScriptEmit.p2pkhUnlock(s, '~ss');
    s.op(OpCodes.OP_SIZE, pushes: ['~n']);
    s.map((b) => ScriptEmit.uintLE(b, 1), '~n');
    s.swap();
    s.cat('~lss');
    s.bytes('~seq', [0xff, 0xff, 0xff, 0xff]);
    s.cat(as);
  }

  /// slot pub -> PUSH(sig) PUSH(pub), or OP_0 OP_0 for a purchase (a zero
  /// key in the record: nobody signed input 0).
  void _listedUnlock(Stk s, String as) {
    s.pick('~pub', '~p');
    s.bytes('~z33', zero33);
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~bought']);
    s.ifElse(() {
      s.op(OpCodes.OP_2DROP, pops: 2);
      s.bytes('~00', [0, 0]);
      s.rename(as);
    }, () {
      ScriptEmit.p2pkhUnlock(s, as);
    });
  }

  /// rec code -> the txid of the transaction whose record is rec. With
  /// [issuance] the routine can also rebuild an issuance (input 0 a P2PKH
  /// coin); a passenger's own transaction is never one, so that rebuild
  /// leaves the branch out.
  void emitRebuild(Stk s, String rec, String code, String as, {bool issuance = true}) {
    s.pick(rec, '~rec');
    s.split(L.size, 'h1', '~r');
    _split(s, 'h1', 'split');
    _when(
      s,
      'split',
      () {
        s.roll('~r');
        s.split(L.size, 'h2', '~r');
      },
      () {
        s.bytes('h2', []);
        s.roll('~r');
      },
    );
    s.split(LtLayout.slot, 'sSlot', '~r');
    s.split(33, 'sPub', '~r');
    _passLen(s, 'h1', '~pl');
    s.op(OpCodes.OP_0NOTEQUAL, pops: 1, pushes: ['pass']);
    _when(
      s,
      'pass',
      () {
        s.roll('~r');
        s.split(LtLayout.slot, 'pSlot', '~r');
        s.split(33, 'pPub', '~r');
      },
      () {
        s.bytes('pSlot', []);
        s.bytes('pPub', []);
        s.roll('~r');
      },
    );
    s.split(LtLayout.slot, 'fSlot', '~r');
    s.split(33, 'fPub', 'X');

    emitOutputs(s, 'h1', 'h2', 'split', code, 'outs');

    // Input 0's unlocking script.
    if (issuance) {
      _h(s, 'h1', L.tokenId, L.issuer, '~t');
      s.bytes('~z', zero32);
      s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~hop0']);
    } else {
      s.bytes('~hop0', []);
    }
    s.ifElse(
      () {
        s.pick('sSlot', '~slot');
        s.pick('sPub', '~pub');
        ScriptEmit.p2pkhUnlock(s, 'ss0');
      },
      () {
        // The sighash preimage that transaction pushed, SIGHASH_ALL|FORKID.
        _h(s, 'h1', L.in0, L.in0 + 36, '~o');
        _when(s, 'pass', () {
          _h(s, 'h1', L.passIn, L.fundIn, '~pi');
          s.cat('~o');
        }, () {});
        _h(s, 'h1', L.fundIn, L.size, '~fi');
        s.cat('~outpoints');
        s.hash256('~hashPrevouts');
        s.bytes('~ver', [1, 0, 0, 0]);
        s.swap();
        s.cat('~p');
        _when(s, 'pass', () => s.bytes('~hs', hashSequence3), () => s.bytes('~hs', hashSequence2));
        s.cat('~p');
        _h(s, 'h1', L.in0, L.in0 + 36, '~o');
        s.cat('~p');
        s.pick(code, '~code');
        s.op(OpCodes.OP_SIZE, pushes: ['~n']);
        s.map(ScriptEmit.varint, '~vi');
        s.swap();
        s.cat('~vcode');
        s.cat('~p');
        s.bytes('~vs', [1, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        s.cat('~p');
        s.pick('outs', '~o');
        s.hash256('~hashOutputs');
        s.cat('~p');
        s.bytes('~lt', [0, 0, 0, 0, 0x41, 0, 0, 0]);
        s.cat('~pre');
        s.op(OpCodes.OP_SIZE, pushes: ['~n']);
        s.map(ScriptEmit.pushPrefix, '~pp');
        s.swap();
        s.cat('~pushPre');
        s.pick('sSlot', '~slot');
        s.pick('sPub', '~pub');
        if (L.listed) {
          _listedUnlock(s, '~sigpub');
        } else {
          ScriptEmit.p2pkhUnlock(s, '~sigpub');
        }
        s.cat('~u');
        // Then C = h1 ‖ [h2] ‖ X.
        s.pick('h1', '~c');
        s.pick('h2', '~h2');
        s.cat('~c');
        s.pick('X', '~x');
        s.cat('~c');
        s.op(OpCodes.OP_SIZE, pushes: ['~n']);
        s.map(ScriptEmit.pushPrefix, '~pp');
        s.swap();
        s.cat('~pushC');
        s.cat('ss0');
      },
    );
    s.op(OpCodes.OP_SIZE, pushes: ['~n']);
    s.map(ScriptEmit.varint, '~vi');
    s.swap();
    s.cat('vss0');

    // version ‖ input count ‖ input 0 ‖ [passenger] ‖ funding ‖ output count ‖ outputs ‖ locktime
    s.bytes('tx', [1, 0, 0, 0]);
    _when(s, 'pass', () => s.bytes('~n', [3]), () => s.bytes('~n', [2]));
    s.cat('tx');
    _h(s, 'h1', L.in0, L.in0 + 36, '~o');
    s.cat('tx');
    s.roll('vss0');
    s.cat('tx');
    s.bytes('~seq', [0xff, 0xff, 0xff, 0xff]);
    s.cat('tx');
    _when(s, 'pass', () {
      _h(s, 'h1', L.passIn, L.fundIn, '~pi');
      s.cat('tx');
      s.pick('pSlot', '~slot');
      s.pick('pPub', '~pub');
      _sigInputTail(s, '~in1');
      s.cat('tx');
    }, () {});
    _h(s, 'h1', L.fundIn, L.size, '~fi');
    s.cat('tx');
    s.pick('fSlot', '~slot');
    s.pick('fPub', '~pub');
    _sigInputTail(s, '~inF');
    s.cat('tx');
    _when(s, 'split', () => s.bytes('~n', [3]), () => s.bytes('~n', [2]));
    s.cat('tx');
    s.roll('outs');
    s.cat('tx');
    s.bytes('~locktime', [0, 0, 0, 0]);
    s.cat('tx');
    s.hash256(as);
    // h1 h2 split sSlot sPub pass pSlot pPub fSlot fPub X remain underneath.
    s.dropBelowTop(11);
  }

  /// blob hm -> nh: checks s² ≡ hm + padding (mod n) and leaves HASH160(n).
  void _attestOne(Stk s, String blob, String hm, String as) {
    s.roll(blob);
    s.split(4, '~pad', '~r');
    s.swap();
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~pad']);
    s.pick(hm, '~h');
    s.op(OpCodes.OP_ADD, pops: 2, pushes: ['~hp']);
    s.swap();
    s.split(LtResetEvidence.numLen, '~s', '~n');
    s.op(OpCodes.OP_DUP, pushes: ['~n2']);
    s.op(OpCodes.OP_HASH160, pops: 1, pushes: [as]);
    s.roll('~n');
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~n']);
    s.roll('~s');
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~s']);
    s.op(OpCodes.OP_DUP, pushes: ['~s2']);
    s.op(OpCodes.OP_MUL, pops: 2, pushes: ['~ss']);
    s.swap();
    s.op(OpCodes.OP_MOD, pops: 2, pushes: ['~ssn']);
    s.roll('~hp');
    s.op(OpCodes.OP_NUMEQUALVERIFY, pops: 2);
  }

  /// nh list -> ; nh must be one of the three hashes in the list.
  void _member(Stk s, String nh, String list) {
    s.pick(list, '~l');
    s.split(20, '~a1', '~r');
    s.split(20, '~a2', '~a3');
    s.pick(nh, '~x');
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~e3']);
    s.swap();
    s.pick(nh, '~x');
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~e2']);
    s.op(OpCodes.OP_BOOLOR, pops: 2, pushes: ['~e']);
    s.swap();
    s.pick(nh, '~x');
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~e1']);
    s.op(OpCodes.OP_BOOLOR, pops: 2, pushes: ['~e']);
    s.op(OpCodes.OP_VERIFY, pops: 1);
  }

  /// rec [E] expect index [target doAttest] -> ; one rebuild for step B and for
  /// the issuance binding of a reset. The transaction whose record is rec is
  /// rebuilt and must have the txid expect, index must be positive (the
  /// output index named alongside expect: a token output's, never the
  /// change's), and the rebuilt first header's issuer and attesters must be
  /// H's; then, if doAttest, E is checked as reset evidence for the outpoint
  /// target. On the normal path rec is the parent's record
  /// and expect the txid its input 0 names; on a reset rec is the issuance's
  /// record and expect is H.tokenId, so the keys a reset trusts come from the
  /// issuance, which a reset cannot invent, rather than from the spent
  /// header, which it does not verify.
  void emitRebuildAndAttest(Stk s) {
    emitRebuild(s, 'rec', 'code', '~txid');
    s.roll('expect');
    s.equalVerify();
    s.roll('index');
    _positive(s);
    s.roll('rec');
    s.split(L.size, '~h', '~');
    s.drop();
    _h(s, '~h', L.issuer, L.flags, '~a');
    _h(s, 'H', L.issuer, L.flags, '~b');
    s.equalVerify();
    s.drop();
    if (L.resettable) {
      s.roll('doAttest');
      s.ifElse(() => emitAttest(s, 'E', 'target'), () => s.op(OpCodes.OP_2DROP, pops: 2));
    }
  }

  /// e -> rec E expect: splits reset evidence into the issuance's record and
  /// the attestation, with H.tokenId as the txid the issuance must have.
  void _resetEvidence(Stk s, String e) {
    s.roll(e);
    s.split(L.issuanceRec, 'rec', 'E');
    _h(s, 'H', L.tokenId, L.issuer, 'expect');
  }

  /// e target -> ; e is a reset's attestation: two distinct attesters from
  /// the list H commits to (and, by [emitRebuildAndAttest], the issuance
  /// commits to) signed SHA256(tag ‖ H.tokenId ‖ target).
  void emitAttest(Stk s, String e, String target) {
    s.roll(e);
    s.split(LtResetEvidence.blob + 60, '~lb1', '~b2');
    s.swap();
    s.split(60, 'L', '~b1');
    s.swap();
    s.op(OpCodes.OP_DUP, pushes: ['~l2']);
    s.op(OpCodes.OP_HASH160, pops: 1, pushes: ['~lh']);
    _h(s, 'H', L.attesters, L.flags, '~a');
    s.equalVerify();
    s.bytes('~tag', LtResetEvidence.tag);
    _h(s, 'H', L.tokenId, L.issuer, '~t');
    s.cat('~m');
    s.roll(target);
    s.cat('~m');
    s.op(OpCodes.OP_SHA256, pops: 1, pushes: ['~m']);
    s.bytes('~00', [0]);
    s.cat('~m');
    s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['hm']);
    _attestOne(s, '~b1', 'hm', 'nh1');
    _attestOne(s, '~b2', 'hm', 'nh2');
    s.pick('nh1', '~x');
    s.pick('nh2', '~y');
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~same']);
    s.op(OpCodes.OP_NOT, pops: 1, pushes: ['~ok']);
    s.op(OpCodes.OP_VERIFY, pops: 1);
    _member(s, 'nh1', 'L');
    _member(s, 'nh2', 'L');
    s.op(OpCodes.OP_2DROP, pops: 2);
    s.op(OpCodes.OP_2DROP, pops: 2);
  }

  /// blob -> ; checks the issuer's Rabin signature over
  /// SHA256(identityTxId ‖ ed25519PubKey ‖ own txid) against H.issuer.
  void emitIssuerAttestation(Stk s) {
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
    _h(s, 'H', L.issuer, L.attesters, '~issuer');
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

  /// n -> ; n must be positive.
  void _positive(Stk s) {
    s.num('~0', 0);
    s.op(OpCodes.OP_GREATERTHAN, pops: 2, pushes: ['~ok']);
    s.op(OpCodes.OP_VERIFY, pops: 1);
  }

  /// The code after the separator.
  ///
  /// Normal path (unlock PUSH(pre) PUSH(sig) PUSH(pub) PUSH(C)): the forward
  /// covenant, the passenger check (FT), step A and step B, or the reset.
  /// Cheap path (unlock PUSH(sig) PUSH(pub)): the owner's signature only.
  ///
  /// [stepB], [passengerB] and [issuerCheck] false leave out one check each;
  /// they exist only for the tests' mutation checks.
  SVScript code({bool stepB = true, bool passengerB = true, bool issuerCheck = true}) {
    final s = Stk(['pre', 'sig', 'pub', 'C', 'H']);
    final b = s.b;

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

    // The preimage is this spend's.
    s.pick('pre', '~pre');
    CheckPreimageOCS.emitCheckPreimageOCS(b, useCodeSeparator: false);
    s.op(OpCodes.OP_VERIFY, pops: 1);

    // Read it: version, hashPrevouts, own outpoint, own code, hashOutputs.
    s.pick('pre', '~pre');
    s.split(104, 'head', '~r');
    s.split(3, '~', '~r');
    s.nip();
    s.op(OpCodes.OP_SIZE, pushes: ['~n']);
    s.num('~52', 52);
    s.op(OpCodes.OP_SUB, pops: 2, pushes: ['~at']);
    s.op(OpCodes.OP_SPLIT, pops: 2, pushes: ['code', '~tail']);
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

    // C: the child's header(s), the passenger's record, this transaction's record.
    s.pick('C', '~c');
    s.split(L.size, 'h1c', '~r');
    _split(s, 'h1c', 'splitC');
    _when(
      s,
      'splitC',
      () {
        s.roll('~r');
        s.split(L.size, 'h2c', '~r');
      },
      () {
        s.bytes('h2c', []);
        s.roll('~r');
      },
    );
    _passLen(s, 'h1c', 'plC');
    s.roll('~r');
    if (L.fungible) {
      s.pick('plC', '~n');
      s.op(OpCodes.OP_SPLIT, pops: 2, pushes: ['PassC', 'RecP']);
    } else {
      s.bytes('PassC', []);
      s.swap();
      s.rename('RecP');
    }

    // Forward: the child carries this token, from this outpoint, with these inputs.
    _h(s, 'H', L.tokenId, L.issuer, '~t');
    s.bytes('~z', zero32);
    s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['hop0']);
    s.pick('hop0', '~g');
    s.ifElse(() => s.slice('ownOut', 0, 32, '~a', total: 36), () => _h(s, 'H', L.tokenId, L.issuer, '~a'));
    _h(s, 'h1c', L.tokenId, L.issuer, '~b');
    s.equalVerify();
    _h(s, 'h1c', L.issuer, L.flags, '~a');
    _h(s, 'H', L.issuer, L.flags, '~b');
    s.equalVerify();
    if (L.fungible) {
      // No passenger into the issuance's output.
      s.pick('plC', '~p');
      s.op(OpCodes.OP_0NOTEQUAL, pops: 1, pushes: ['~p']);
      s.pick('hop0', '~g');
      s.op(OpCodes.OP_BOOLAND, pops: 2, pushes: ['~bad']);
      s.op(OpCodes.OP_NOT, pops: 1, pushes: ['~ok']);
      s.op(OpCodes.OP_VERIFY, pops: 1);
      // A split's two headers describe the same transaction.
      _when(s, 'splitC', () {
        _h(s, 'h1c', 0, L.shared1, '~a');
        _h(s, 'h2c', 0, L.shared1, '~b');
        s.equalVerify();
        _h(s, 'h1c', L.shared2, L.size, '~a');
        _h(s, 'h2c', L.shared2, L.size, '~b');
        s.equalVerify();
      }, () {});
    }
    _h(s, 'h1c', L.in0, L.in0 + 36, '~a');
    s.pick('ownOut', '~b');
    s.equalVerify();
    _h(s, 'h1c', L.in0, L.in0 + 36, '~o');
    if (L.fungible) {
      s.pick('plC', '~p');
      s.op(OpCodes.OP_0NOTEQUAL, pops: 1, pushes: ['~p']);
      s.ifElse(() {
        _h(s, 'h1c', L.passIn, L.fundIn, '~pi');
        s.cat('~o');
      }, () {});
    }
    _h(s, 'h1c', L.fundIn, L.size, '~fi');
    s.cat('~o');
    s.hash256('~a');
    s.pick('hashPrevouts', '~b');
    s.equalVerify();

    void ownerSigns() {
      s.pick('pub', '~pub');
      s.op(OpCodes.OP_HASH160, pops: 1, pushes: ['~pkh']);
      _h(s, 'H', L.owner, L.owner + 20, '~owner');
      s.equalVerify();
      s.pick('sig', '~sig');
      s.pick('pub', '~pub');
      s.op(OpCodes.OP_CHECKSIGVERIFY, pops: 2);
    }

    if (!L.listed) {
      // The owner authorises it.
      ownerSigns();
    } else {
      // The owner authorises it, or (an empty key) anyone buys it: the
      // output is listed (a price that is not zero), not the issuance's,
      // the child pays this owner at least the price at output 0, and the
      // child is not listed.
      s.pick('pub', '~pub');
      s.op(OpCodes.OP_SIZE, pushes: ['~n']);
      s.nip();
      s.op(OpCodes.OP_0NOTEQUAL, pops: 1, pushes: ['~signed']);
      s.ifElse(ownerSigns, () {
        s.pick('hop0', '~g');
        s.op(OpCodes.OP_NOT, pops: 1, pushes: ['~notIss']);
        s.op(OpCodes.OP_VERIFY, pops: 1);
        _h(s, 'H', L.price, L.price + 8, '~pr');
        s.bytes('~z8', zero8);
        s.op(OpCodes.OP_EQUAL, pops: 2, pushes: ['~unlisted']);
        s.op(OpCodes.OP_NOT, pops: 1, pushes: ['~listed']);
        s.op(OpCodes.OP_VERIFY, pops: 1);
        _h(s, 'h1c', L.changePkh, L.changePkh + 20, '~payee');
        _h(s, 'H', L.owner, L.owner + 20, '~owner');
        s.equalVerify();
        _h(s, 'h1c', L.changeAmt, L.changeAmt + 8, '~paid');
        s.bytes('~00', [0]);
        s.cat('~paid');
        s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~paid']);
        _h(s, 'H', L.price, L.price + 8, '~pr');
        s.bytes('~00', [0]);
        s.cat('~pr');
        s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~pr']);
        s.op(OpCodes.OP_GREATERTHANOREQUAL, pops: 2, pushes: ['~enough']);
        s.op(OpCodes.OP_VERIFY, pops: 1);
        if (_childUnlisted) {
          _h(s, 'h1c', L.price, L.price + 8, '~cp');
          s.bytes('~z8', zero8);
          s.equalVerify();
        }
      });
    }

    if (L.fungible) {
      // The passenger, if any: a token output of the same id, in a transaction
      // that is what its record says (step A) and whose input 0 spent a token
      // output on the normal path, or was a reset (step B). Its amount joins
      // this one.
      s.pick('plC', '~p');
      s.op(OpCodes.OP_0NOTEQUAL, pops: 1, pushes: ['~p']);
      s.ifElse(
        () {
          emitRebuild(s, 'PassC', 'code', '~txidB', issuance: false);
          _h(s, 'h1c', L.passIn, L.passIn + 32, '~b');
          s.equalVerify();
          s.pick('PassC', '~pc');
          s.split(L.size, 'hb1', '~r');
          _h(s, 'h1c', L.passIn + 32, L.passIn + 36, '~k');
          s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~k']);
          s.op(OpCodes.OP_DUP, pushes: ['~k2']);
          s.num('~2', 2);
          s.op(OpCodes.OP_NUMEQUAL, pops: 2, pushes: ['~is2']);
          s.ifElse(
            () {
              s.drop();
              s.split(L.size, 'hb', '~');
              s.drop();
            },
            () {
              s.num('~1', 1);
              s.op(OpCodes.OP_NUMEQUALVERIFY, pops: 2);
              s.drop();
              s.pick('hb1', 'hb');
            },
          );
          _h(s, 'hb', L.tokenId, L.issuer, '~a');
          _h(s, 'H', L.tokenId, L.issuer, '~b');
          s.equalVerify();
          _h(s, 'hb', L.amount, L.amount + 8, 'hbAmt');
          s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['hbAmt']);
          if (passengerB) {
            emitParentRec(s, 'PassC', '~recBp');
            _reset(s, 'hb1', '~rb');
            s.ifElse(
              () {
                _resetEvidence(s, '~recBp');
                s.num('index', 1);
                _h(s, 'hb1', L.in0, L.in0 + 36, 'target');
                s.num('doAttest', 1);
              },
              () {
                s.rename('rec');
                s.bytes('E', []);
                _h(s, 'hb1', L.in0, L.in0 + 32, 'expect');
                _h(s, 'hb1', L.in0 + 32, L.in0 + 36, 'index');
                s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['index']);
                s.bytes('target', []);
                s.num('doAttest', 0);
              },
            );
            emitRebuildAndAttest(s);
          }
          s.roll('hb');
          s.drop();
          s.roll('hb1');
          s.drop();
        },
        () {
          s.num('hbAmt', 0);
        },
      );

      // Amounts: the children's, all positive, sum to this output's plus the passenger's.
      _h(s, 'h1c', L.amount, L.amount + 8, '~a1');
      s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~a1']);
      s.op(OpCodes.OP_DUP, pushes: ['~a']);
      _positive(s);
      _when(
        s,
        'splitC',
        () {
          _h(s, 'h2c', L.amount, L.amount + 8, '~a2');
          s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~a2']);
          s.op(OpCodes.OP_DUP, pushes: ['~a']);
          _positive(s);
          s.op(OpCodes.OP_ADD, pops: 2, pushes: ['outSum']);
        },
        () {
          s.rename('outSum');
        },
      );
      _h(s, 'H', L.amount, L.amount + 8, '~in');
      s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['~in']);
      s.roll('hbAmt');
      s.op(OpCodes.OP_ADD, pops: 2, pushes: ['~inSum']);
      s.op(OpCodes.OP_NUMEQUALVERIFY, pops: 2);
    }

    // The child's outputs are exactly the successor's.
    emitOutputs(s, 'h1c', 'h2c', 'splitC', 'code', '~outs');
    s.hash256('~a');
    s.pick('hashOutputs', '~b');
    s.equalVerify();

    if (L.resettable) {
      _stepsAB(s, stepB: stepB, issuerCheck: issuerCheck);
    } else {
      // Step A: this transaction is what its record says.
      emitRebuild(s, 'RecP', 'code', '~txid');
      s.slice('ownOut', 0, 32, '~own', total: 36);
      s.equalVerify();

      // Step B: the output it spent held this script; at hop 0, instead, the
      // issuer attested this issuance, which is rebuilt in its place.
      s.pick('hop0', '~g');
      s.ifElse(
        () {
          if (issuerCheck) {
            emitParentRec(s, 'RecP', '~blob');
            emitIssuerAttestation(s);
          }
          s.pick('RecP', 'rec');
          s.slice('ownOut', 0, 32, 'expect', total: 36);
          s.num('index', 1);
        },
        () {
          if (stepB) {
            emitParentRec(s, 'RecP', 'rec');
            _h(s, 'H', L.in0, L.in0 + 32, 'expect');
            _h(s, 'H', L.in0 + 32, L.in0 + 36, 'index');
            s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['index']);
          } else {
            s.pick('RecP', 'rec');
            s.slice('ownOut', 0, 32, 'expect', total: 36);
            s.num('index', 1);
          }
        },
      );
    }
    emitRebuildAndAttest(s);

    while (s.names.isNotEmpty) {
      s.drop();
    }
    b.opCode(OpCodes.OP_1);
    b.opCode(OpCodes.OP_ENDIF);
    return b.build();
  }

  /// Steps A and B of a token that can be reset: the child's reset flag
  /// selects the path. Leaves rec E expect index target doAttest.
  void _stepsAB(Stk s, {required bool stepB, required bool issuerCheck}) {
    // Step A: this transaction is what its record says. Not on a reset: the
    // child's reset flag selects the path, and then the tail of C is the
    // attestation for this outpoint rather than this transaction's record.
    _reset(s, 'h1c', 'resetC');
    s.pick('resetC', '~r');
    s.pick('hop0', '~g');
    s.op(OpCodes.OP_BOOLAND, pops: 2, pushes: ['~bad']);
    s.op(OpCodes.OP_NOT, pops: 1, pushes: ['~ok']);
    s.op(OpCodes.OP_VERIFY, pops: 1);
    s.pick('resetC', '~r');
    s.notIf(() {
      emitRebuild(s, 'RecP', 'code', '~txid');
      s.slice('ownOut', 0, 32, '~own', total: 36);
      s.equalVerify();
    });

    // Step B: the output it spent held this script. At hop 0, instead, the
    // issuer attested this issuance. On a reset, the attesters attested this
    // outpoint; and if this transaction's own input 0 was a reset, they
    // attested the outpoint it spent. Each branch names one transaction to
    // rebuild (the parent, the issuance a reset's evidence carries, or at hop
    // 0 this issuance again) so that the rebuild is emitted once.
    s.pick('hop0', '~g');
    s.ifElse(
      () {
        if (issuerCheck) {
          emitParentRec(s, 'RecP', '~blob');
          emitIssuerAttestation(s);
        }
        s.pick('RecP', 'rec');
        s.bytes('E', []);
        s.slice('ownOut', 0, 32, 'expect', total: 36);
        s.num('index', 1);
        s.bytes('target', []);
        s.num('doAttest', 0);
      },
      () {
        s.pick('resetC', '~r');
        s.ifElse(
          () {
            s.pick('RecP', '~e');
            _resetEvidence(s, '~e');
            s.num('index', 1);
            s.pick('ownOut', 'target');
            s.num('doAttest', 1);
          },
          () {
            _reset(s, 'H', '~ro');
            s.ifElse(
              () {
                emitParentRec(s, 'RecP', '~e');
                _resetEvidence(s, '~e');
                s.num('index', 1);
                _h(s, 'H', L.in0, L.in0 + 36, 'target');
                s.num('doAttest', 1);
              },
              () {
                if (stepB) {
                  emitParentRec(s, 'RecP', 'rec');
                  s.bytes('E', []);
                  _h(s, 'H', L.in0, L.in0 + 32, 'expect');
                  _h(s, 'H', L.in0 + 32, L.in0 + 36, 'index');
                  s.op(OpCodes.OP_BIN2NUM, pops: 1, pushes: ['index']);
                } else {
                  s.pick('RecP', 'rec');
                  s.bytes('E', []);
                  s.slice('ownOut', 0, 32, 'expect', total: 36);
                  s.num('index', 1);
                }
                s.bytes('target', []);
                s.num('doAttest', 0);
              },
            );
          },
        );
      },
    );
  }

  /// PUSH(header) OP_CODESEPARATOR code
  Uint8List lock(List<int> header, List<int> code) {
    if (header.length != L.size) throw ArgumentError('header is ${header.length} bytes, ${L.name} needs ${L.size}');
    return Uint8List.fromList([0x4c, L.size, ...header, OpCodes.OP_CODESEPARATOR, ...code]);
  }
}
