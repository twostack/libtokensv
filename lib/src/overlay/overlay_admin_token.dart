import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:dartsv/dartsv.dart';

import '../pushdrop/pushdrop.dart';

/// A SHIP or SLAP advertisement: the PushDrop token by which an overlay host
/// says it hosts a topic (SHIP) or a lookup service (SLAP), as the TypeScript
/// `OverlayAdminTokenTemplate` writes it.
///
/// Fields: protocol ('SHIP' or 'SLAP'), the host's identity key, its domain,
/// the topic or service, and a signature.
class OverlayAdminToken {
  final String protocol;
  final String identityKey;
  final String domain;
  final String topicOrService;

  const OverlayAdminToken({
    required this.protocol,
    required this.identityKey,
    required this.domain,
    required this.topicOrService,
  });

  /// [script] read as an admin token, or null when it is not one.
  static OverlayAdminToken? decode(SVScript script) {
    final token = PushDrop.decode(script);
    if (token == null || token.fields.length < 4) return null;
    try {
      final protocol = utf8.decode(token.fields[0]);
      if (protocol != 'SHIP' && protocol != 'SLAP') return null;
      return OverlayAdminToken(
        protocol: protocol,
        identityKey: hex.encode(token.fields[1]),
        domain: utf8.decode(token.fields[2]),
        topicOrService: utf8.decode(token.fields[3]),
      );
    } on FormatException {
      return null;
    }
  }
}
