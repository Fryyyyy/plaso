#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for Basic Security Module (BSM) file parser."""

import unittest

from plaso.parsers import bsm

from tests.parsers import test_lib


class MacOSBSMParserTest(test_lib.ParserTestCase):
  """Tests for Basic Security Module (BSM) file parser."""

  def testParse(self):
    """Tests the Parse function on a MacOS BSM file."""
    parser = bsm.BSMParser()
    storage_writer = self._ParseFile(['apple.bsm'], parser)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 54)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_extra_tokens = [
        {'AUT_TEXT': {
            'text': 'launchctl::Audit recovery'}},
        {'AUT_PATH': {
            'path': '/var/audit/20131104171720.crash_recovery'}},
        {'AUT_RETURN32': {
            'call_status': 0,
            'error': 'Success',
            'token_status': 0}}]

    expected_event_values = {
<<<<<<< HEAD
        'data_type': 'bsm:event',
        'date_time': '2013-11-04T18:36:20.000381+00:00',
=======
        'data_type': 'bsm:entry',
>>>>>>> origin/main
        'event_type': 45029,
        'extra_tokens': expected_extra_tokens,
        'return_value': (
            '{\'error\': \'Success\', \'token_status\': 0, '
            '\'call_status\': 0}'),
        'written_time': '2013-11-04T18:36:20.000381+00:00'}

<<<<<<< HEAD
    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_extra_tokens = [
        {'AUT_SUBJECT32': {
            'aid': -1,
            'egid': 92,
            'euid': 92,
            'gid': 92,
            'pid': 143,
            'session_id': 100004,
            'terminal_ip': '0.0.0.0',
            'terminal_port': 143,
            'uid': 92}},
        {'AUT_TEXT': {
            'text': ('Verify password for record type Users \'moxilo\' node '
                     '\'/Local/Default\'')}},
        {'AUT_RETURN32': {
            'call_status': 5000,
            'error': 'UNKNOWN',
            'token_status': 255}}]

    expected_return_value = (
        '{\'error\': \'UNKNOWN\', \'token_status\': 255, '
        '\'call_status\': 5000}')

    expected_event_values = {
        'data_type': 'bsm:event',
        'date_time': '2013-11-04T18:36:26.000171+00:00',
        'event_type': 45023,
        'extra_tokens': expected_extra_tokens,
        'return_value': expected_return_value}

    self.CheckEventValues(storage_writer, events[15], expected_event_values)

    expected_extra_tokens = [
        {'AUT_SUBJECT32': {
            'aid': -1,
            'egid': 0,
            'euid': 0,
            'gid': 0,
            'pid': 67,
            'session_id': 100004,
            'terminal_ip': '0.0.0.0',
            'terminal_port': 67,
            'uid': 0}},
        {'AUT_TEXT': {
            'text': 'system.login.done'}},
        {'AUT_TEXT': {
            'text': 'system.login.done'}},
        {'AUT_RETURN32': {
            'call_status': 0,
            'error': 'Success',
            'token_status': 0}}]

    expected_return_value = (
        '{\'error\': \'Success\', \'token_status\': 0, \'call_status\': 0}')

    expected_event_values = {
        'data_type': 'bsm:event',
        'date_time': '2013-11-04T18:36:26.000530+00:00',
        'event_type': 45025,
        'extra_tokens': expected_extra_tokens,
        'return_value': expected_return_value}

    self.CheckEventValues(storage_writer, events[31], expected_event_values)

    expected_extra_tokens = [
        {'AUT_ARG64': {
            'is': 0,
            'num_arg': 1,
            'string': 'sflags'}},
        {'AUT_ARG32': {
            'is': 12288,
            'num_arg': 2,
            'string': 'am_success'}},
        {'AUT_ARG32': {
            'is': 12288,
            'num_arg': 3,
            'string': 'am_failure'}},
        {'AUT_SUBJECT32': {
            'aid': -1,
            'egid': 0,
            'euid': 0,
            'gid': 0,
            'pid': 0,
            'session_id': 100015,
            'terminal_ip': '0.0.0.0',
            'terminal_port': 0,
            'uid': 0}},
        {'AUT_RETURN32': {
            'call_status': 0,
            'error': 'Success',
            'token_status': 0}}]

    expected_return_value = (
        '{\'error\': \'Success\', \'token_status\': 0, \'call_status\': 0}')

    expected_event_values = {
        'data_type': 'bsm:event',
        'date_time': '2013-11-04T18:37:36.000399+00:00',
        'event_type': 44903,
        'extra_tokens': expected_extra_tokens,
        'return_value': expected_return_value}

    self.CheckEventValues(storage_writer, events[50], expected_event_values)
=======
    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)
>>>>>>> origin/main


class OpenBSMParserTest(test_lib.ParserTestCase):
  """Tests for Basic Security Module (BSM) file parser."""

  def testParse(self):
    """Tests the Parse function on a "generic" BSM file."""
    parser = bsm.BSMParser()
    storage_writer = self._ParseFile(['openbsm.bsm'], parser)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 50)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    expected_extra_tokens = [{
        'AUT_ARG32': {
            'is': 2882400000,
            'num_arg': 3,
            'string': 'test_arg32_token'}}]

    expected_event_values = {
        'data_type': 'bsm:entry',
        'event_type': 0,
        'extra_tokens': expected_extra_tokens,
        'return_value': None,
        'written_time': '2008-12-28T15:12:18.000131+00:00'}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 0)
    self.CheckEventData(event_data, expected_event_values)


if __name__ == '__main__':
  unittest.main()
