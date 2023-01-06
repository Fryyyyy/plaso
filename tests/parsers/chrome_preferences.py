#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Chrome Preferences file parser."""

import unittest

from plaso.parsers import chrome_preferences

from tests.parsers import test_lib


class ChromePreferencesParserTest(test_lib.ParserTestCase):
  """Tests for the Google Chrome Preferences file parser."""

  def testParseFile(self):
    """Tests parsing a default profile Preferences file."""
    parser = chrome_preferences.ChromePreferencesParser()
    storage_writer = self._ParseFile(['Preferences'], parser)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 30)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
        'data_type': 'chrome:preferences:extensions_autoupdater',
        'message': 'Chrome extensions autoupdater last run',
        'recorded_time': '2014-11-12T13:01:43.926143+00:00'}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)

    expected_event_values = {
        'data_type': 'chrome:preferences:extensions_autoupdater',
<<<<<<< HEAD
        'date_time': '2014-11-12T13:01:43.926143+00:00',
        'message': 'Chrome extensions autoupdater last run'}
=======
        'message': 'Chrome extensions autoupdater next run',
        'recorded_time': '2014-11-12T18:20:21.519200+00:00'}
>>>>>>> origin/main

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 1)
    self.CheckEventData(event_data, expected_event_values)

    expected_event_values = {
        'data_type': 'chrome:preferences:extensions_autoupdater',
<<<<<<< HEAD
        'date_time': '2014-11-12T18:20:21.519200+00:00',
        'message': 'Chrome extensions autoupdater next run'}

    self.CheckEventValues(storage_writer, events[18], expected_event_values)

    expected_event_values = {
        'data_type': 'chrome:preferences:extensions_autoupdater',
        'date_time': '2016-06-08T16:17:47.453766+00:00',
        'message': 'Chrome history was cleared by user'}

    self.CheckEventValues(storage_writer, events[22], expected_event_values)

    expected_event_values = {
        'data_type': 'chrome:preferences:extension_installation',
        'date_time': '2014-11-05T18:31:24.154837+00:00',
        'extension_id': 'mgndgikekgjfcpckkfioiadnlibdjbkf',
=======
        'message': 'Chrome history was cleared by user',
        'recorded_time': '2016-06-08T16:17:47.453766+00:00'}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 2)
    self.CheckEventData(event_data, expected_event_values)

    expected_event_values = {
        'data_type': 'chrome:preferences:extension_installation',
        'extension_identifier': 'mgndgikekgjfcpckkfioiadnlibdjbkf',
>>>>>>> origin/main
        'extension_name': 'Chrome',
        'installation_time': '2014-11-05T18:31:24.154837+00:00',
        'path': (
            'C:\\Program Files\\Google\\Chrome\\Application\\38.0.2125.111\\'
            'resources\\chrome_app')}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 17)
    self.CheckEventData(event_data, expected_event_values)

    expected_event_values = {
        'data_type': 'chrome:preferences:content_settings:exceptions',
<<<<<<< HEAD
        'date_time': '2016-11-14T14:12:50.588974+00:00',
        'permission': 'geolocation',
        'primary_url': ''}

    self.CheckEventValues(storage_writer, events[25], expected_event_values)

    expected_event_values = {
        'data_type': 'chrome:preferences:content_settings:exceptions',
        'date_time': '2016-11-11T16:20:09.866137+00:00',
        'permission': 'midi_sysex',
        'primary_url': 'https://rawgit.com:443'}

    self.CheckEventValues(storage_writer, events[23], expected_event_values)

    expected_event_values = {
        'data_type': 'chrome:preferences:content_settings:exceptions',
        'date_time': '2016-11-14T14:13:00.639332+00:00',
        'permission': 'notifications',
        'primary_url': 'https://rawgit.com:443'}

    self.CheckEventValues(storage_writer, events[29], expected_event_values)

    expected_event_values = {
        'data_type': 'chrome:preferences:content_settings:exceptions',
        'date_time': '2016-11-14T14:13:00.627093+00:00',
        'permission': 'notifications',
        'primary_url': 'https://rawgit.com:443'}

    self.CheckEventValues(storage_writer, events[28], expected_event_values)

    expected_event_values = {
        'data_type': 'chrome:preferences:content_settings:exceptions',
        'date_time': '2016-11-14T14:12:54.899474+00:00',
        'permission': 'media_stream_mic',
        'primary_url': ''}

    self.CheckEventValues(storage_writer, events[27], expected_event_values)

    expected_event_values = {
        'data_type': 'chrome:preferences:content_settings:exceptions',
        'date_time': '2016-11-14T14:12:53.667838+00:00',
        'permission': 'media_stream_mic',
        'primary_url': 'https://rawgit.com:443'}

    self.CheckEventValues(storage_writer, events[26], expected_event_values)
=======
        'last_visited_time': '2016-11-11T16:20:09.866137+00:00',
        'permission': 'midi_sysex',
        'primary_url': 'https://rawgit.com:443'}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 27)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
