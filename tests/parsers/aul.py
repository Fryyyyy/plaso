#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Apple Unified Logging parser."""

import unittest

from plaso.parsers import aul

from tests.parsers import test_lib


class AULParserTest(test_lib.ParserTestCase):
  """Tests for the AUL parser."""

  def testParse(self):
    """Tests the Parse function."""
    parser = aul.AULParser()
    storage_writer = self._ParseFile([
      'AUL', 'private', 'var', 'db', 'diagnostics', 'Special',
      '0000000000000346.tracev3'
    ], parser)

    number_of_events = storage_writer.GetNumberOfAttributeContainers('event')
    self.assertEqual(number_of_events, 8)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    events = list(storage_writer.GetEvents())

    expected_event_values = {
        'data_type': 'mac:aul:event',
        'date_time': '2022-08-28T09:02:09.099778189+00:00',
        'level': 'Default',
        'subsystem': 'com.apple.sbd',
        'thread_id': 1941589,
        'pid': 823,
        'euid': 802300,
        'library': '/System/Library/PrivateFrameworks/CloudServices.framework/Helpers/com.apple.sbd',
        'library_uuid': '1F58234E37DD3B3789213BCD74F49AC6',
        'activity_id': 2747488,
        'category': 'daemon',
        'message': 'sbd listener begin from pid 2115 ((null)) [com.apple.SecureBackupDaemon]'
        }

    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_event_values = {
        'data_type': 'mac:aul:event',
        'date_time': '2022-08-28T09:02:09.205599969+00:00',
        'level': 'Error',
        'subsystem': 'com.apple.sbd',
        'thread_id': 1941589,
        'pid': 823,
        'euid': 802300,
        'library': '/System/Library/PrivateFrameworks/CloudServices.framework/Helpers/com.apple.sbd',
        'library_uuid': '1F58234E37DD3B3789213BCD74F49AC6',
        'activity_id': 2747488,
        'category': 'daemon',
        'message': 'No iCloud account yet'
        }

    self.CheckEventValues(storage_writer, events[1], expected_event_values)


if __name__ == '__main__':
  unittest.main()
