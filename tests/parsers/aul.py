#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the Apple Unified Logging parser."""

import csv
import glob
import logging
import tempfile
import os
import subprocess
import unittest

from pathlib import Path

from plaso.parsers import aul

from tests.parsers import test_lib


class AULParserTest(test_lib.ParserTestCase):
  """Tests for the AUL parser."""
  def setUp(self) -> None:
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    return super().setUp()

  def testParseBasic(self):
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
        'thread_id': '0x1da055',
        'pid': 823,
        'euid': 802300,
        'library': '/System/Library/PrivateFrameworks/CloudServices.framework/Helpers/com.apple.sbd',
        'library_uuid': '1F58234E37DD3B3789213BCD74F49AC6',
        'activity_id': '0x29ec60',
        'category': 'daemon',
        'message': 'sbd listener begin from pid 2115 ((null)) [com.apple.SecureBackupDaemon]'
        }

    self.CheckEventValues(storage_writer, events[0], expected_event_values)

    expected_event_values = {
        'data_type': 'mac:aul:event',
        'date_time': '2022-08-28T23:28:16.834004518+00:00',
        'level': 'Error',
        'subsystem': 'com.apple.sbd',
        'thread_id': '0x2349fa',
        'pid': 823,
        'euid': 802300,
        'library': '/System/Library/PrivateFrameworks/CloudServices.framework/Helpers/com.apple.sbd',
        'library_uuid': '1F58234E37DD3B3789213BCD74F49AC6',
        'activity_id': '0x29ec68',
        'category': 'daemon',
        'message': 'No iCloud account yet'
        }

    self.CheckEventValues(storage_writer, events[3], expected_event_values)

  def testParseAdvanced(self):
    """Tests the Parse function."""
    parser = aul.AULParser()
    storage_writer = self._ParseFile([
      'AUL', 'private', 'var', 'db', 'diagnostics', 'Special',
      '000000000000034f.tracev3'
    ], parser)

    number_of_events = storage_writer.GetNumberOfAttributeContainers('event')
    self.assertEqual(number_of_events, 51867)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'extraction_warning')
    self.assertEqual(number_of_warnings, 0)

    number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
        'recovery_warning')
    self.assertEqual(number_of_warnings, 0)

  def testParseAdvancedLoop(self):
    """Tests the Parse function."""
    files = [
    #  "33a",
    #  "33b",
    #  "33c",
    #  "33d",
    #  "33e",
    #  "33f",
    #  "34a",
    #  "34b",
    #  "34c",
    #  "34d",
    #  "34e",
      "34f"
    ]
    for filename in files:
      cmd = "echo -n > /tmp/fryoutput.csv && echo -n > /tmp/logs.rust"
      subprocess.run(cmd, shell=True, check=True)

      parser = aul.AULParser()
      storage_writer = self._ParseFile([
        'AUL', 'private', 'var', 'db', 'diagnostics', 'Special',
        '0000000000000{0:s}.tracev3'.format(filename)
      ], parser)

      cmd = "rm /home/fryy/AUL/RUST_TEST/Special/*"
      subprocess.run(cmd, shell=True, check=True)
      cmd = ["cp", "/home/fryy/AUL/private/var/db/diagnostics/Special/0000000000000{0:s}.tracev3".format(filename), "/home/fryy/AUL/RUST_TEST/Special/"]
      subprocess.run(cmd, check=True)
      cmd = ["/home/fryy/Code/macos-UnifiedLogs/examples/target/debug/unifiedlog_parser", "-i", "/home/fryy/AUL/RUST_TEST", "-o", "/tmp/logs.rust"]
      result = subprocess.run(cmd, capture_output=True, check=True)
      number_results = int((str(result.stdout).split('\\n')[-4]).split(" ")[1])

      number_of_events = storage_writer.GetNumberOfAttributeContainers('event')
      self.assertEqual(number_of_events, number_results)

      number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
          'extraction_warning')
      self.assertEqual(number_of_warnings, 0)

      number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
          'recovery_warning')
      self.assertEqual(number_of_warnings, 0)

      rustlines = []
      with open('/tmp/logs.rust', 'r', encoding="utf-8") as rustcsv:
        rustcsvreader = csv.DictReader(rustcsv)
        for line in rustcsvreader:
          rustlines.append(line)

      endlines = []
      i = 0
      with open('/tmp/fryoutput.csv', 'r', encoding="utf-8") as frycsv:
        frycsvreader = csv.reader(frycsv)
        for line in frycsvreader:
          rust = rustlines[i]['Message']
          while 'decode' in rust or \
            'openOptions' in rust or \
            'title: ' in rust or \
            '_CLL' in rust or \
            '_CLD' in rust or \
            '_CLC' in rust or \
            'Downloaded Resources' in rust:
            i += 1
            rust = rustlines[i]['Message']
          while rust in endlines:
            endlines = [x for x in endlines if x[1] != rust]
            i += 1
            rust = rustlines[i]['Message']
          rust = rust.replace("00000000-0000-0000-0000-000000000000 +0x0\n", "")
          if "has compatibility score" in line[1]:
            line[1] = line[1].replace("-1.0", "-1")
          if line[1] == rust or \
            line[1].replace(".0", "") == rust or \
            line[1].upper() == rust.replace("#FFFFFFFF", "#").upper() or \
            line[1].upper() == rust.replace("0xFFFFFFFF", "0x").upper() or \
            line[1].upper() == rust.upper() or \
            line[1].replace('(null)', "") == rust:
            i += 1
            continue
          if 'decode' in line[1] or \
            'battery_saver' in line[1] or \
            'vehicle_speed' in line[1] or \
            'location_enabled' in line[1] or \
            'openOptions' in line[1] or \
            'Downloaded Resources' in line[1]:
            continue

          endlines.append((line[1], rust))
      self.assertLessEqual(len(endlines), 5)

  def testMandiantTests(self):
    """Tests the Parse function."""
    for operating_system in glob.glob("/home/fryy/AUL/Mandiant/test_data/*logarchive*"):
      # Clean output files
      cmd = "echo -n > /tmp/fryoutput.csv && echo -n > /tmp/logs.rust"
      subprocess.run(cmd, shell=True, check=True)

      # Set up directory structure
      with tempfile.TemporaryDirectory(dir="/home/fryy/Code/plaso/test_data/AUL/MANDIANT/") as t:
        uuidpath = os.path.join(t, "private/var/db/uuidtext")
        diagpath = os.path.join(t, "private/var/db/diagnostics")
        Path(diagpath).mkdir(parents=True, exist_ok=True)
        Path(uuidpath).mkdir(parents=True, exist_ok=True)
        subprocess.run("cp -r {0:s}/* {1:s}/".format(operating_system, uuidpath), shell=True, check=True)
        subprocess.run("mv {}/Extra {}/Special {}/HighVolume {}/Persist {}/Signpost {}/timesync {}/".format(uuidpath, uuidpath, uuidpath, uuidpath, uuidpath, uuidpath, diagpath), shell=True, check=True)

        # Run full Mandiant command
        cmd = ["/home/fryy/Code/macos-UnifiedLogs/examples/target/debug/unifiedlog_parser", "-i", operating_system, "-o", "/tmp/logs.rust"]
        subprocess.run(cmd, check=True)
      
        # Sort resultant CSV
        subprocess.run(r"cat /tmp/logs.rust | (read -r; printf \"%s\n\" \"$REPLY\"; sort > /tmp/rust.csv)", shell=True, check=True)

        # Run on each of the files
        for f in glob.glob(os.path.join(diagpath, "Special")):
          parser = aul.AULParser()
          storage_writer = self._ParseFile([f], parser)

          number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
              'extraction_warning')
          self.assertEqual(number_of_warnings, 0)

          number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
              'recovery_warning')
          self.assertEqual(number_of_warnings, 0)
        pass

if __name__ == '__main__':
  unittest.main()
