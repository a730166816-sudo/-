// ============================================================================
// BMS Pro Mobile v2.0 (Flutter)
// Includes: Hive Offline Sync + Rank Priority Resolution + 60s Dynamic TOTP QR
// ============================================================================
import 'dart:async';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:http/http.dart' as http;

class BmsOfflineSyncEngine extends ChangeNotifier {
  static const String personnelBoxName = 'bms_personnel_box';
  static const String syncQueueBoxName = 'bms_sync_queue_box';
  final String apiBaseUrl;
  final String currentOfficerRole;
  bool isOnline = true;

  BmsOfflineSyncEngine({
    required this.apiBaseUrl,
    this.currentOfficerRole = 'BATTALION_CMD',
  });

  Future<void> initHiveBoxes() async {
    await Hive.initFlutter();
    await Hive.openBox(personnelBoxName);
    await Hive.openBox(syncQueueBoxName);
  }

  // Generates a 60-second rotating TOTP token for the soldier's smart military card
  String generateRotatingMilitaryQrToken(String militaryId, String secretKey) {
    final int timeWindow = DateTime.now().millisecondsSinceEpoch ~/ 60000;
    final hmac = Hmac(sha256, utf8.encode(secretKey));
    final digest = hmac.convert(utf8.encode('$militaryId:$timeWindow')).toString();
    return 'TOTP-$militaryId-${digest.substring(0, 8).toUpperCase()}';
  }

  Future<void> recordAttendanceOfflineFirst({
    required String personnelId,
    required String date,
    required String shift,
    required String status,
    required String totpToken,
  }) async {
    final queueBox = Hive.box(syncQueueBoxName);
    final op = {
      'id': 'OP-${DateTime.now().millisecondsSinceEpoch}',
      'entity': 'attendance',
      'action': 'UPSERT',
      'actorRole': currentOfficerRole,
      'data': {
        'personnelId': personnelId,
        'date': date,
        'shift': shift,
        'status': status,
        'method': 'QR_TOTP:$totpToken',
      },
      'createdAt': DateTime.now().toIso8601String(),
    };

    await queueBox.add(op);
    notifyListeners();

    if (isOnline) {
      await flushSyncQueue();
    }
  }

  Future<void> flushSyncQueue() async {
    final queueBox = Hive.box(syncQueueBoxName);
    if (queueBox.isEmpty) return;

    final operations = queueBox.values.toList();
    try {
      final response = await http.post(
        Uri.parse('$apiBaseUrl/api/v1/sync/batch'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'clientId': 'FLUTTER_TACTICAL_TERMINAL',
          'actorRole': currentOfficerRole,
          'operations': operations,
        }),
      );
      if (response.statusCode == 200) {
        await queueBox.clear();
        notifyListeners();
      }
    } catch (_) {
      // Remains safely queued in Hive until network restoration
    }
  }
}
