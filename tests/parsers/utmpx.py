#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for UTMPX file parser."""

import unittest

from plaso.parsers import utmpx

from tests.parsers import test_lib


class UtmpxParserTest(test_lib.ParserTestCase):
  """Tests for utmpx file parser."""

  def testParse(self):
    """Tests the Parse function."""
    parser = utmpx.UtmpxParser()
    storage_writer = self._ParseFile(['utmpx_mac'], parser)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 6)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
<<<<<<< HEAD
        'data_type': 'mac:utmpx:event',
        'date_time': '2013-11-13T17:52:34.000000+00:00',
        'hostname': 'localhost',
        'pid': 1,
        'terminal_identifier': 0,
        'type': 2}

    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_event_values = {
        'data_type': 'mac:utmpx:event',
        'date_time': '2013-11-13T17:52:41.736713+00:00',
=======
        'data_type': 'macos:utmpx:entry',
>>>>>>> origin/main
        'hostname': 'localhost',
        'pid': 67,
        'terminal': 'console',
        'terminal_identifier': 65583,
        'type': 7,
        'username': 'moxilo',
        'written_time': '2013-11-13T17:52:41.736713+00:00'}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[1], expected_event_values)

    expected_event_values = {
        'data_type': 'mac:utmpx:event',
        'date_time': '2013-11-14T04:32:56.641464+00:00',
        'hostname': 'localhost',
        'pid': 6899,
        'terminal': 'ttys002',
        'terminal_identifier': 842018931,
        'type': 8,
        'username': 'moxilo'}

    self.CheckEventValues(storage_writer, events[4], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 1)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
