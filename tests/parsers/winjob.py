#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Windows Scheduled Task job file parser."""

import unittest

from plaso.parsers import winjob

from tests.parsers import test_lib


class WinJobTest(test_lib.ParserTestCase):
  """Tests for the Windows Scheduled Task job file parser."""

  def testParse(self):
    """Tests the Parse function."""
    parser = winjob.WinJobParser()
    storage_writer = self._ParseFile(['wintask.job'], parser)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 2)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
        'application': (
            'C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe'),
        'comment': (
            'Keeps your Google software up to date. If this task is disabled '
            'or stopped, your Google software will not be kept up to date, '
            'meaning security vulnerabilities that may arise cannot be fixed '
            'and features may not work. This task uninstalls itself when there '
            'is no Google software using it.'),
        'data_type': 'windows:tasks:job',
        'parameters': '/ua /installsource scheduler',
        'last_run_time': '2013-08-24T12:42:00.112+00:00',
        'username': 'Brian',
        'working_directory': None}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)

    expected_event_values = {
        'application': (
            'C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe'),
<<<<<<< HEAD
        'date_time': '2013-08-24T12:42:00.112+00:00',
        'data_type': 'windows:tasks:job',
        'comment': expected_comment,
        'parameters': '/ua /installsource scheduler',
        'timestamp_desc': definitions.TIME_DESCRIPTION_LAST_RUN,
        'username': 'Brian'}

    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_event_values = {
        'application': (
            'C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe'),
        'date_time': '2013-07-12T15:42:00',
        'data_type': 'windows:tasks:job',
        'parameters': '/ua /installsource scheduler',
        'timestamp': '2013-07-12 15:42:00.000000',
        'timestamp_desc': 'Scheduled to start',
=======
        'comment': (
            'Keeps your Google software up to date. If this task is disabled '
            'or stopped, your Google software will not be kept up to date, '
            'meaning security vulnerabilities that may arise cannot be fixed '
            'and features may not work. This task uninstalls itself when there '
            'is no Google software using it.'),
        'data_type': 'windows:tasks:trigger',
        'end_time': None,
        'parameters': '/ua /installsource scheduler',
        'start_time': '2013-07-12T15:42:00',
>>>>>>> origin/main
        'trigger_type': 1,
        'username': 'Brian',
        'working_directory': None}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[1], expected_event_values)

  def testParseWithTimeZone(self):
    """Tests the Parse function with a time zone."""
    parser = winjob.WinJobParser()
    storage_writer = self._ParseFile(['wintask.job'], parser, timezone='CET')

    number_of_events = storage_writer.GetNumberOfAttributeContainers('event')
    self.assertEqual(number_of_events, 2)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    events = list(storage_writer.GetEvents())

    expected_event_values = {
        'application': (
            'C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe'),
        'date_time': '2013-07-12T15:42:00',
        'data_type': 'windows:tasks:job',
        'parameters': '/ua /installsource scheduler',
        'timestamp': '2013-07-12 13:42:00.000000',
        'timestamp_desc': 'Scheduled to start',
        'trigger_type': 1,
        'username': 'Brian'}

    self.CheckEventValues(storage_writer, events[1], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 1)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
