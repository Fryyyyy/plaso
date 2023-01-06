# -*- coding: utf-8 -*-
"""The Apple Unified Logging (AUL) Statedump file parser."""
import csv
import os
import plistlib

from dfdatetime import apfs_time as dfdatetime_apfs_time

from plaso.containers import time_events

from plaso.lib.aul import time as aul_time

from plaso.lib import definitions as plaso_definitions
from plaso.lib import dtfabric_helper
from plaso.lib import errors

from plaso.parsers import aul
from plaso.parsers import logger

class StatedumpParser(dtfabric_helper.DtFabricHelper):
  """StateDump data chunk parser"""

  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), '..', '..', 'parsers', 'aul.yaml')

  def ReadStatedumpChunkData(self, tracev3, parser_mediator, chunk_data,
                              data_offset):
    """Parses the Statedump Chunk and adds a DateTimeEvent.

    Args:
      tracev3 (TraceV3FileParser): TraceV3 File Parser.
      parser_mediator (ParserMediator): a parser mediator.
      chunk_data (bytes): oversize chunk data.
      data_offset (int): offset of the oversize chunk relative to the start
        of the chunk set.

    Raises:
      ParseError: if the records cannot be parsed.
    """
    logger.info("Reading Statedump")
    data_type_map = self._GetDataTypeMap('tracev3_statedump')

    statedump_structure = self._ReadStructureFromByteStream(
        chunk_data, data_offset, data_type_map)
    logger.info(
        ("Statedump data: ProcID 1 {0:d} // ProcID 2 {1:d} // "
        "TTL {2:d} // CT {3:d} // String Name {4:s}")
        .format(statedump_structure.first_number_proc_id,
                statedump_structure.second_number_proc_id,
                statedump_structure.ttl, statedump_structure.continuous_time,
                statedump_structure.string_name))

    try:
      statedump_structure.string1 = self._ReadStructureFromByteStream(
        statedump_structure.string1, 0, self._GetDataTypeMap('cstring'))
    except errors.ParseError:
      statedump_structure.string1 = ''

    try:
      statedump_structure.string2 = self._ReadStructureFromByteStream(
        statedump_structure.string2, 0, self._GetDataTypeMap('cstring'))
    except errors.ParseError:
      statedump_structure.string2 = ''

    proc_id = statedump_structure.second_number_proc_id | (
        statedump_structure.first_number_proc_id << 32)
    proc_info = [
        c for c in tracev3.catalog.process_entries
        if c.second_number_proc_id | (c.first_number_proc_id << 32) == proc_id
    ]
    if len(proc_info) == 0:
      raise errors.ParseError(
          "Could not find Process Info block for ID: {0:d}".format(proc_id))
    else:
      proc_info = proc_info[0]

    event_data = aul.AULEventData()
    try:
      uuid_file = tracev3.catalog.files[proc_info.main_uuid_index]
      event_data.process_uuid = uuid_file.uuid
      event_data.process = uuid_file.library_path
    except IndexError:
      pass
    event_data.boot_uuid = tracev3.header.generation_subchunk.generation_subchunk_data.boot_uuid.hex
    event_data.level = "StateDump"

    ct = statedump_structure.continuous_time
    ts = aul_time.FindClosestTimesyncItemInList(
      tracev3.boot_uuid_ts_list.sync_records, ct)
    time = ts.wall_time + ct - ts.kernel_continuous_timestamp

    if statedump_structure.data_type == aul.TraceV3FileParser.STATETYPE_PLIST:
      try:
        event_data.message = str(plistlib.loads(statedump_structure.data))
      except plistlib.InvalidFileException:
        logger.warning("Statedump PList not valid")
        return
    elif statedump_structure.data_type == aul.TraceV3FileParser.STATETYPE_PROTOBUF:
      event_data.message  = "Statedump Protocol Buffer"
      logger.error("Statedump Protobuf not supported")
    elif statedump_structure.data_type == aul.TraceV3FileParser.STATETYPE_CUSTOM:
      if statedump_structure.string1 == "location":
        state_tracker_structure = {}
        extra_state_tracker_structure = {}

        if statedump_structure.string_name == "CLDaemonStatusStateTracker":
          state_tracker_structure = self._ReadStructureFromByteStream(
              statedump_structure.data, 0,
              self._GetDataTypeMap('location_tracker_daemon_data')).__dict__

          if state_tracker_structure['reachability'] == 0x2:
            state_tracker_structure['reachability'] = "kReachabilityLarge"
          else:
            state_tracker_structure['reachability'] = "Unknown"

          if state_tracker_structure['charger_type'] == 0x0:
            state_tracker_structure['charger_type'] = "kChargerTypeUnknown"
          else:
            state_tracker_structure['charger_type'] = "Unknown"
        elif statedump_structure.string_name == "CLClientManagerStateTracker":
          state_tracker_structure = self._ReadStructureFromByteStream(
              statedump_structure.data, 0,
              self._GetDataTypeMap('location_tracker_client_data')).__dict__
        elif statedump_structure.string_name == "CLLocationManagerStateTracker":
          if statedump_structure.data_size not in [64, 72]:
            raise errors.ParseError(
              "Possibly corrupted CLLocationManagerStateTracker block")
          state_tracker_structure = self._ReadStructureFromByteStream(
              statedump_structure.data, 0,
              self._GetDataTypeMap('location_manager_state_data')).__dict__
          if len(statedump_structure.data) == 72:
            extra_state_tracker_structure = self._ReadStructureFromByteStream(
                statedump_structure.data[64:], 64,
                self._GetDataTypeMap(
                    'location_manager_state_data_extra')).__dict__
        else:
          raise errors.ParseError(
            "Unknown location Statedump Custom object not supported")

        event_data.message = str({
            **state_tracker_structure,
            **extra_state_tracker_structure
        })
      else:
        logger.error("Non-location Statedump Custom object not supported")
        event_data.message = "Unsupported Statedump object: {}".format(
            statedump_structure.string_name)
    else:
      raise errors.ParseError("Unknown Statedump data type {0:d}".format(
          statedump_structure.data_type))

    event_data.activity_id = hex(statedump_structure.activity_id)
    event_data.pid = statedump_structure.first_number_proc_id
    logger.info("Log line: {0!s}".format(event_data.message))

    with open('/tmp/fryoutput.csv', 'a') as f:
      csv.writer(f).writerow([
          dfdatetime_apfs_time.APFSTime(
            timestamp=time).CopyToDateTimeString(), event_data.level,
          event_data.message
      ])
    event = time_events.DateTimeValuesEvent(
        dfdatetime_apfs_time.APFSTime(timestamp=time),
        plaso_definitions.TIME_DESCRIPTION_RECORDED)
    parser_mediator.ProduceEventWithEventData(event, event_data)
