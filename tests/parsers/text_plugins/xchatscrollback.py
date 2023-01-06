#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the xchatscrollback log parser."""

import unittest

from dfvfs.file_io import fake_file_io
from dfvfs.path import fake_path_spec
from dfvfs.resolver import context as dfvfs_context

from plaso.parsers import text_parser
from plaso.parsers.text_plugins import xchatscrollback

from tests.parsers.text_plugins import test_lib


class XChatScrollbackLogTextPluginTest(test_lib.TextPluginTestCase):
  """Tests for the xchatscrollback log parser."""

  def testCheckRequiredFormat(self):
    """Tests for the CheckRequiredFormat method."""
    plugin = xchatscrollback.XChatScrollbackLogTextPlugin()

    resolver_context = dfvfs_context.Context()
    test_path_spec = fake_path_spec.FakePathSpec(location='/file.txt')

    file_object = fake_file_io.FakeFile(resolver_context, test_path_spec, (
        b'T 1232315916 Python interface unloaded\n'))
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(file_object)
    text_reader.ReadLines()

    result = plugin.CheckRequiredFormat(None, text_reader)
    self.assertTrue(result)

    file_object = fake_file_io.FakeFile(resolver_context, test_path_spec, (
        b'T1232315916 Python interface unloaded\n'))
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(file_object)
    text_reader.ReadLines()

    result = plugin.CheckRequiredFormat(None, text_reader)
    self.assertFalse(result)

    file_object = fake_file_io.FakeFile(resolver_context, test_path_spec, (
        b'T 1232315916Python interface unloaded\n'))
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(file_object)
    text_reader.ReadLines()

    result = plugin.CheckRequiredFormat(None, text_reader)
    self.assertFalse(result)

    file_object = fake_file_io.FakeFile(resolver_context, test_path_spec, (
        b'T 12323159160 Python interface unloaded\n'))
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(file_object)
    text_reader.ReadLines()

    result = plugin.CheckRequiredFormat(None, text_reader)
    self.assertFalse(result)

    file_object = fake_file_io.FakeFile(resolver_context, test_path_spec, (
        b'.TH MT 1 \" -*- nroff -*-\n'))
    file_object.Open()

    text_reader = text_parser.EncodedTextReader(file_object)
    text_reader.ReadLines()

    result = plugin.CheckRequiredFormat(None, text_reader)
    self.assertFalse(result)

  def testProcess(self):
    """Tests the Process function."""
    plugin = xchatscrollback.XChatScrollbackLogTextPlugin()
    storage_writer = self._ParseTextFileWithPlugin(
        ['xchatscrollback.log'], plugin)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 10)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 1)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_event_values = {
<<<<<<< HEAD
=======
        'added_time': '2009-01-16T02:56:19+00:00',
>>>>>>> origin/main
        'data_type': 'xchat:scrollback:line',
        'date_time': '2009-01-16T02:56:19+00:00',
        'text': '* Speaking now on ##plaso##'}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_event_values = {
        'data_type': 'xchat:scrollback:line',
        'date_time': '2009-01-16T02:56:27+00:00',
        'text': '* Joachim \xe8 uscito (Client exited)'}

    self.CheckEventValues(storage_writer, events[1], expected_event_values)

    expected_event_values = {
        'data_type': 'xchat:scrollback:line',
        'date_time': '2009-01-18T21:58:36+00:00',
        'text': 'Tcl interface unloaded'}

    self.CheckEventValues(storage_writer, events[2], expected_event_values)

    expected_event_values = {
        'data_type': 'xchat:scrollback:line',
        'date_time': '2009-01-18T21:58:36+00:00',
        'text': 'Python interface unloaded'}

    self.CheckEventValues(storage_writer, events[3], expected_event_values)

    # TODO: change parser to return NotSet semantic time.
    expected_event_values = {
        'data_type': 'xchat:scrollback:line',
        'date_time': '1970-01-01T00:00:00+00:00',
        'nickname': 'fpi',
        'text': '0 is a good timestamp',
        'timestamp': 0}

    self.CheckEventValues(storage_writer, events[5], expected_event_values)

    expected_event_values = {
        'data_type': 'xchat:scrollback:line',
        'date_time': '2009-01-26T08:50:56+00:00',
        'text': '* Topic of #plasify \xe8: .'}

    self.CheckEventValues(storage_writer, events[6], expected_event_values)

    expected_event_values = {
        'data_type': 'xchat:scrollback:line',
        'date_time': '2009-01-26T08:51:02+00:00'}

    self.CheckEventValues(storage_writer, events[7], expected_event_values)

    expected_event_values = {
        'data_type': 'xchat:scrollback:line',
        'date_time': '2009-01-26T08:52:12+00:00',
        'nickname': 'fpi',
        'text': 'Hi Kristinn!'}

    self.CheckEventValues(storage_writer, events[8], expected_event_values)

    expected_event_values = {
        'data_type': 'xchat:scrollback:line',
        'date_time': '2009-01-26T08:53:13+00:00',
        'nickname': 'Kristinn',
        'text': 'GO AND WRITE PARSERS!!! O_o'}

    self.CheckEventValues(storage_writer, events[9], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


if __name__ == '__main__':
  unittest.main()
