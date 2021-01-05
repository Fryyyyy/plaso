#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the MacOS Knowledge C db."""

import unittest

from plaso.lib import definitions
from plaso.parsers.sqlite_plugins import mac_knowledgec

from tests.parsers.sqlite_plugins import test_lib


class MacKnowledgecTest(test_lib.SQLitePluginTestCase):
  """Tests for the MacOS KnowledgeC database."""

  def testProcessHighSierra(self):
    """Tests the Process function on a MacOS 10.13 database."""
    plugin = mac_knowledgec.MacKnowledgeCPlugin()
    storage_writer = self._ParseDatabaseFileWithPlugin(
        ['mac_knowledgec-10.13.db'], plugin)

    self.assertEqual(0, storage_writer.number_of_warnings)
    self.assertEqual(51, storage_writer.number_of_events)
    events = list(storage_writer.GetEvents())

    expected_event_values = {
        'bundle_identifier': 'com.apple.Installer-Progress',
        'timestamp': '2019-02-10 16:59:58.860665',
        'timestamp_desc': definitions.TIME_DESCRIPTION_CREATION}

    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_message = (
        'Application com.apple.Installer-Progress executed for 1 seconds')
    expected_short_message = 'Application com.apple.Installer-Progress'

    event_data = self._GetEventDataOfEvent(storage_writer, events[0])
    self._TestGetMessageStrings(
        event_data, expected_message, expected_short_message)

  def testProcessMojave(self):
    """Tests the Process function on a MacOS 10.14 database."""
    plugin = mac_knowledgec.MacKnowledgeCPlugin()
    storage_writer = self._ParseDatabaseFileWithPlugin(
        ['mac_knowledgec-10.14.db'], plugin)

    self.assertEqual(0, storage_writer.number_of_warnings)
    self.assertEqual(231, storage_writer.number_of_events)
    events = list(storage_writer.GetEvents())

    expected_event_values = {
        'bundle_identifier': 'com.apple.Terminal',
        'timestamp': '2019-05-08 13:57:30.668998',
        'timestamp_desc': definitions.TIME_DESCRIPTION_CREATION}

    self.CheckEventValues(storage_writer, events[225], expected_event_values)

    expected_message = (
        'Application com.apple.Terminal executed for 1041 seconds')
    expected_short_message = 'Application com.apple.Terminal'

    event_data = self._GetEventDataOfEvent(storage_writer, events[225])
    self._TestGetMessageStrings(
        event_data, expected_message, expected_short_message)

    expected_event_values = {
        'timestamp': '2019-05-08 13:57:20.000000',
        'timestamp_desc': definitions.TIME_DESCRIPTION_END,
        'title': 'Instagram',
        'url': 'https://www.instagram.com/'}

    self.CheckEventValues(storage_writer, events[212], expected_event_values)

    expected_message = (
        'Visited: https://www.instagram.com/ (Instagram) Duration: 0')
    expected_short_message = 'Safari: https://www.instagram.com/'

    event_data = self._GetEventDataOfEvent(storage_writer, events[212])
    self._TestGetMessageStrings(
        event_data, expected_message, expected_short_message)


if __name__ == '__main__':
  unittest.main()
