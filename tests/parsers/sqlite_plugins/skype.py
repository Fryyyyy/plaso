#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Skype main.db history database plugin."""

import unittest

from plaso.parsers.sqlite_plugins import skype

from tests.parsers.sqlite_plugins import test_lib


class SkypePluginTest(test_lib.SQLitePluginTestCase):
  """Tests for the Skype main.db history database plugin."""

  def testProcess(self):
    """Tests the Process function."""
    plugin = skype.SkypePlugin()
    storage_writer = self._ParseDatabaseFileWithPlugin(
        ['skype_main.db'], plugin)

    number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
        'event_data')
    self.assertEqual(number_of_event_data, 20)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

    # Test transfer file entry.
    expected_event_values = {
        'accept_time': None,
        'data_type': 'skype:event:transferfile',
<<<<<<< HEAD
        'date_time': '2013-10-24T21:49:32+00:00',
=======
        'end_time': None,
>>>>>>> origin/main
        'destination': 'european.bbq.competitor <European BBQ>',
        'source': 'gen.beringer <Gen Beringer>',
        'start_time': '2013-10-24T21:49:32+00:00',
        'transfer_status': 2,
        'transferred_filename': 'secret-project.pdf'}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 17)
    self.CheckEventData(event_data, expected_event_values)

    # Test SMS entry.
    expected_event_values = {
        'data_type': 'skype:event:sms',
<<<<<<< HEAD
        'date_time': '2013-07-01T22:14:22+00:00',
=======
>>>>>>> origin/main
        'number': '+34123456789',
        'recorded_time': '2013-07-01T22:14:22+00:00',
        'text': ('If you want I can copy some documents for you, if you can '
                 'pay it... ;)')}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 16)
    self.CheckEventData(event_data, expected_event_values)

<<<<<<< HEAD
    # Test file event.
    expected_event_values = {
        'action_type': 'GETSOLICITUDE',
        'data_type': 'skype:event:transferfile',
        'date_time': '2013-10-24T21:49:35+00:00',
        'destination': 'european.bbq.competitor <European BBQ>',
        'source': 'gen.beringer <Gen Beringer>',
        'transferred_filename': 'secret-project.pdf',
        'transferred_filepath': '/Users/gberinger/Desktop/secret-project.pdf',
        'transferred_filesize': 69986}

    self.CheckEventValues(storage_writer, events[18], expected_event_values)

    # Test chat event.
    expected_event_values = {
        'data_type': 'skype:event:chat',
        'date_time': '2013-07-30T21:27:11+00:00',
=======
    # Test chat entry.
    expected_event_values = {
        'data_type': 'skype:event:chat',
>>>>>>> origin/main
        'from_account': 'Gen Beringer <gen.beringer>',
        'recorded_time': '2013-07-30T21:27:11+00:00',
        'text': 'need to know if you got it this time.',
        'title': 'European Competitor | need to know if you got it..',
        'to_account': 'european.bbq.competitor'}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 1)
    self.CheckEventData(event_data, expected_event_values)

<<<<<<< HEAD
    # Test chat room event.
    expected_event_values = {
        'data_type': 'skype:event:chat',
        'date_time': '2013-10-27T15:29:19+00:00',
        'from_account': 'European Competitor <european.bbq.competitor>',
        'text': 'He is our new employee',
        'title': 'European Competitor, Echo123',
        'to_account': 'gen.beringer, echo123'}

    self.CheckEventValues(storage_writer, events[14], expected_event_values)

    # Test call event.
=======
    # Test call entry.
>>>>>>> origin/main
    expected_event_values = {
        'attempt_time': '2013-07-01T22:12:17+00:00',
        'data_type': 'skype:event:call',
<<<<<<< HEAD
        'date_time': '2013-07-01T22:12:17+00:00',
=======
>>>>>>> origin/main
        'dst_call': 'european.bbq.competitor',
        'end_time': '2013-07-01T22:23:03+00:00',
        'src_call': 'gen.beringer',
        'start_time': '2013-07-01T22:12:17+00:00',
        'user_start_call': False,
        'video_conference': False}

    event_data = storage_writer.GetAttributeContainerByIndex('event_data', 19)
    self.CheckEventData(event_data, expected_event_values)


if __name__ == '__main__':
  unittest.main()
