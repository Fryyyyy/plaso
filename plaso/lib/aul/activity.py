# -*- coding: utf-8 -*-
"""The Apple Unified Logging (AUL) Activity chunk parser."""

import base64
import csv
import os

from dfdatetime import apfs_time as dfdatetime_apfs_time

from plaso.containers import time_events

from plaso.lib.aul import constants
from plaso.lib.aul import formatter
from plaso.lib.aul import dsc

from plaso.lib import definitions as plaso_definitions
from plaso.lib import dtfabric_helper
from plaso.lib import errors

from plaso.parsers import aul
from plaso.parsers import logger


class ActivityParser(dtfabric_helper.DtFabricHelper):
  """Activity data chunk parser"""

  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), "..", "..", "parsers", "aul.yaml")

  _USER_ACTION_ACTIVITY_TYPE = 0x3

  def ParseActivity(self, tracev3, parser_mediator, tracepoint, proc_info,
                     time):
    """Processes an Activity chunk.

    Args:
      tracev3 (TraceV3FileParser): TraceV3 File Parser.
      parser_mediator (ParserMediator): a parser mediator.
      tracepoint (tracev3_firehose_tracepoint): Firehose tracepoint chunk.
      proc_info (tracev3_catalog_process_information_entry): Process Info entry.
      time (int): Log timestamp.

    Raises:
      ParseError: if the non-activity chunk cannot be parsed.
    """
    logger.info("Parsing activity")

    log_data = []
    offset = 0
    data = tracepoint.data
    flags = tracepoint.flags

    fmt = None
    private_string = None
    activity_id = None
    dsc_range = dsc.DSCRange()

    event_data = aul.AULEventData()
    event_data.boot_uuid = tracev3.header.generation_subchunk.generation_subchunk_data.boot_uuid.hex

    try:
      dsc_file = tracev3.catalog.files[proc_info.catalog_dsc_index]
    except IndexError:
      dsc_file = None

    try:
      uuid_file = tracev3.catalog.files[proc_info.main_uuid_index]
      event_data.process_uuid = uuid_file.uuid
      event_data.process = uuid_file.library_path
    except IndexError:
      uuid_file = None

    uint32_data_type_map = self._GetDataTypeMap("uint32")
    uint64_data_type_map = self._GetDataTypeMap("uint64")

    if tracepoint.log_type != self._USER_ACTION_ACTIVITY_TYPE:
      activity_id = self._ReadStructureFromByteStream(data, offset,
                                                      uint32_data_type_map)
      offset += 4
      sentinel = self._ReadStructureFromByteStream(data[offset:], offset,
                                                   uint32_data_type_map)
      offset += 4

    if flags & constants.UNIQUE_PID:
      unique_pid = self._ReadStructureFromByteStream(data[offset:], offset,
                                                     uint64_data_type_map)
      offset += 8
      logger.info("Signpost has unique_pid: {0:d}".format(unique_pid))

    if flags & constants.CURRENT_AID:
      logger.info("Activity has current_aid")
      activity_id = self._ReadStructureFromByteStream(data, offset,
                                                      uint32_data_type_map)
      offset += 4
      sentinel = self._ReadStructureFromByteStream(data[offset:], offset,
                                                   uint32_data_type_map)
      offset += 4

    if flags & constants.HAS_SUBSYSTEM:
      logger.info("Activity has has_other_current_aid")
      activity_id = self._ReadStructureFromByteStream(data, offset,
                                                      uint32_data_type_map)
      offset += 4
      sentinel = self._ReadStructureFromByteStream(data[offset:], offset,
                                                   uint32_data_type_map)
      offset += 4

    message_string_reference = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
    offset += 4
    logger.info("Unknown PCID: {0:d}".format(message_string_reference))

    ffh = formatter.FormatterFlagsHelper()
    formatter_flags = ffh.FormatFlags(tracev3, flags, data, offset)
    offset = formatter_flags.offset

    if flags & constants.PRIVATE_STRING_RANGE:
      raise errors.ParseError("Activity with Private String Range")

    # If there's data...
    if tracepoint.data_size - offset >= 6:
      data_meta = self._ReadStructureFromByteStream(
          data[offset:], offset,
          self._GetDataTypeMap("tracev3_firehose_tracepoint_data"))
      offset += 2

      logger.info(
          "After activity data: Unknown {0:d} // Number of Items {1:d}".format(
              data_meta.unknown1, data_meta.num_items))
      (log_data, deferred_data_items,
       offset) = tracev3.ReadItems(data_meta, data, offset)

      if flags & constants.HAS_CONTEXT_DATA != 0:
        raise errors.ParseError("Backtrace data in Activity log chunk")

      if flags & constants.HAS_DATA_REF:
        raise errors.ParseError("Activity log chunk with Data Ref")

      #TODO(fryy): Functionise this
      for item in deferred_data_items:
        if item[2] == 0:
          result = ""
        elif item[0] in constants.FIREHOSE_ITEM_PRIVATE_STRING_TYPES:
          if not private_string:
            raise errors.ParseError("Trying to read from empty Private String")
          try:
            result = self._ReadStructureFromByteStream(
                private_string[item[1]:], 0, self._GetDataTypeMap("cstring"))
            logger.info("End result: {0:s}".format(result))
          except errors.ParseError:
            result = ""  # Private
        else:
          if item[0] in constants.FIREHOSE_ITEM_STRING_ARBITRARY_DATA_TYPES:
            result = data[offset + item[1]:offset + item[1] + item[2]]
          elif item[0] == constants.FIREHOSE_ITEM_STRING_BASE64_TYPE:
            result = base64.encodebytes(data[offset + item[1]:offset + item[1] +
                                             item[2]]).strip()
          else:
            result = self._ReadStructureFromByteStream(
                data[offset + item[1]:], 0, self._GetDataTypeMap("cstring"))
            logger.info("End result: {0:s}".format(result))
        log_data.insert(item[3], (item[0], item[2], result))

    if formatter_flags.shared_cache or formatter_flags.large_shared_cache != 0:
      if formatter_flags.large_offset_data != 0:
        raise errors.ParseError(
            "Large offset Activity not supported - activity.rs:140")
      extra_offset_value_result = tracepoint.format_string_location
      (fmt, dsc_range) = tracev3.ExtractSharedStrings(
          tracepoint.format_string_location, extra_offset_value_result,
          dsc_file)
    else:
      if formatter_flags.absolute:
        raise errors.ParseError(
            "Absolute Activity not supported - signpost.rs:224")
      elif formatter_flags.uuid_relative:
        uuid_file = tracev3.ExtractAltUUID(formatter_flags.uuid_relative)
        fmt = uuid_file.ReadFormatString(tracepoint.format_string_location)
      else:
        fmt = tracev3.ExtractFormatStrings(tracepoint.format_string_location,
                                           uuid_file)

    event_data.level = constants.LOG_TYPES.get(tracepoint.log_type, "Default")

    # Info is 'Create' when it's an Activity
    if tracepoint.log_type == 0x1:
      event_data.level = "Create"

    if activity_id:
      event_data.activity_id = hex(activity_id)
    event_data.library = dsc_range.path if dsc_range.path else uuid_file.library_path
    event_data.library_uuid = dsc_range.uuid.hex if dsc_range.uuid else uuid_file.uuid
    event_data.thread_id = hex(tracepoint.thread_identifier)
    event_data.pid = proc_info.pid
    event_data.euid = proc_info.euid
    event_data.library = dsc_range.path if dsc_range.path else uuid_file.library_path
    event_data.library_uuid = dsc_range.uuid.hex if dsc_range.uuid else uuid_file.uuid
    event_data.message = tracev3.FormatString(fmt, log_data)

    with open("/tmp/fryoutput.csv", "a") as f:
      csv.writer(f).writerow([
          dfdatetime_apfs_time.APFSTime(timestamp=time).CopyToDateTimeString(),
          event_data.level, event_data.message
      ])

    event = time_events.DateTimeValuesEvent(
        dfdatetime_apfs_time.APFSTime(timestamp=time),
        plaso_definitions.TIME_DESCRIPTION_RECORDED)
    parser_mediator.ProduceEventWithEventData(event, event_data)
