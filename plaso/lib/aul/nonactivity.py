# -*- coding: utf-8 -*-
"""The Apple Unified Logging (AUL) Non-activity chunk parser."""
import base64
import csv
import os

from dfdatetime import apfs_time as dfdatetime_apfs_time
from plaso.containers import time_events
from plaso.lib import definitions as plaso_definitions
from plaso.lib import dtfabric_helper
from plaso.lib import errors
from plaso.lib.aul import constants
from plaso.lib.aul import dsc
from plaso.lib.aul import formatter
from plaso.parsers import aul
from plaso.parsers import logger


class NonactivityParser(dtfabric_helper.DtFabricHelper):
  """Non-activity data chunk parser"""

  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), "..", "..", "parsers", "aul.yaml")

  _NON_ACTIVITY_SENINTEL = 0x80000000

  def ParseNonActivity(self, tracev3, parser_mediator, tracepoint, proc_info,
                       time, private_strings):
    """Processes a Non Activity chunk.

    Args:
      tracev3 (TraceV3FileParser): TraceV3 File Parser.
      parser_mediator (ParserMediator): a parser mediator.
      tracepoint (tracev3_firehose_tracepoint): Firehose tracepoint chunk.
      proc_info (tracev3_catalog_process_information_entry): Process Info entry.
      time (int): Log timestamp.
      private_strings (tuple[int, bytes]): Offset and data of the private
        strings, or None.

    Raises:
      ParseError: if the non-activity chunk cannot be parsed.
    """
    logger.info("Parsing non-activity")

    log_data = []
    offset = 0
    data = tracepoint.data
    flags = tracepoint.flags

    activity_id = None
    data_ref_id = 0
    fmt = None
    private_string = None
    ttl_value = None

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

    uint8_data_type_map = self._GetDataTypeMap("uint8")
    uint16_data_type_map = self._GetDataTypeMap("uint16")
    uint32_data_type_map = self._GetDataTypeMap("uint32")

    if flags & constants.CURRENT_AID:
      logger.info("Non-activity has current_aid")

      activity_id = self._ReadStructureFromByteStream(data, offset,
                                                      uint32_data_type_map)
      offset += 4
      sentinel = self._ReadStructureFromByteStream(data[offset:], offset,
                                                   uint32_data_type_map)
      offset += 4
      if sentinel != self._NON_ACTIVITY_SENINTEL:
        raise errors.ParseError("Incorrect sentinel value for Non-Activity")

    if flags & constants.PRIVATE_STRING_RANGE:
      logger.info(
          "Non-activity has private_string_range (has_private_data flag)")

      private_strings_offset = self._ReadStructureFromByteStream(
          data[offset:], offset, uint16_data_type_map)
      offset += 2
      private_strings_size = self._ReadStructureFromByteStream(
          data[offset:], offset, uint16_data_type_map)
      offset += 2

    message_string_reference = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
    offset += 4
    logger.info("Unknown PCID: {0:d}".format(message_string_reference))

    if flags & constants.HAS_ALTERNATE_UUID:
      if flags & constants.HAS_MESSAGE_IN_UUIDTEXT:
        logger.info("Non-activity: Has Alternate UUID & Message in UUIDText")
      else:
        logger.info(
            "Non-activity: Has Alternate UUID & _NO_ Message in UUIDText")

    ffh = formatter.FormatterFlagsHelper()
    formatter_flags = ffh.FormatFlags(tracev3, flags, data, offset)
    offset = formatter_flags.offset

    subsystem_value = ""
    if flags & constants.HAS_SUBSYSTEM:
      subsystem_value = self._ReadStructureFromByteStream(
          data[offset:], offset, uint16_data_type_map)
      offset += 2
      logger.info("Non-activity has subsystem: {0:d}".format(subsystem_value))

    if flags & constants.HAS_TTL:
      ttl_value = self._ReadStructureFromByteStream(data[offset:], offset,
                                                    uint8_data_type_map)
      offset += 1
      logger.info("Non-activity has TTL: {0:d}".format(ttl_value))

    if flags & constants.HAS_DATA_REF:
      data_ref_id = self._ReadStructureFromByteStream(data[offset:], offset,
                                                      uint16_data_type_map)
      offset += 1
      logger.info("Non-activity with data reference: {0:d}".format(data_ref_id))

    if flags & constants.HAS_SIGNPOST_NAME:
      raise errors.ParseError("Non-activity signpost not supported")

    if flags & constants.HAS_MESSAGE_IN_UUIDTEXT:
      logger.info("Non-activity has message in UUID Text file")
      if flags & constants.HAS_ALTERNATE_UUID and \
        flags & constants.HAS_SIGNPOST_NAME:
        raise errors.ParseError(
            "Non-activity with Alternate UUID and Signpost not supported")
      else:
        if not uuid_file:
          raise errors.ParseError(
              "Unable to continue without matching UUID file")
        if flags & constants.HAS_SIGNPOST_NAME:
          raise errors.ParseError("Non-activity signpost not supported (2)")

    if flags & constants.PRIVATE_STRING_RANGE:
      if private_strings:
        string_start = private_strings_offset - private_strings[0]
        if string_start > len(private_strings[1] or string_start < 0):
          raise errors.ParseError("Error with private string offset")
        private_string = private_strings[1][string_start:string_start +
                                            private_strings_size]
      else:
        raise errors.ParseError("Private strings wanted but not supplied")

    if tracepoint.log_activity_type == constants.FIREHOSE_LOG_ACTIVITY_TYPE_LOSS:
      raise errors.ParseError("Loss Type not supported")

    data_meta = self._ReadStructureFromByteStream(
        data[offset:], offset,
        self._GetDataTypeMap("tracev3_firehose_tracepoint_data"))
    offset += 2

    logger.info(
        "After activity data: Unknown {0:d} // Number of Items {1:d}".format(
            data_meta.unknown1, data_meta.num_items))
    (log_data, deferred_data_items,
     offset) = tracev3.ReadItems(data_meta, data, offset)

    backtrace_strings = []
    if flags & constants.HAS_CONTEXT_DATA != 0 and len(data[offset:]) >= 6:
      logger.info("Backtrace data in Firehose log chunk")
      backtrace_strings = ["Backtrace:\n"]
      backtrace_data = self._ReadStructureFromByteStream(
          data[offset:], offset, self._GetDataTypeMap("tracev3_backtrace"))
      for count, idx in enumerate(backtrace_data.indices):
        try:
          backtrace_strings.append("{0:s} +0x{1:d}\n".format(
              backtrace_data.uuids[idx].hex.upper(),
              backtrace_data.offsets[count]))
        except IndexError:
          pass
    elif len(data[offset:]) > 3:
      if data[offset:offset + 3] == r"\x01\x00\x18":
        raise errors.ParseError(
            "Backtrace signature without context -- firehose_logs.rs:330")

    #TODO(fryy): Turn item tuple into an object with names
    for item in deferred_data_items:
      if item[2] == 0:
        result = ""
      elif item[0] in constants.FIREHOSE_ITEM_PRIVATE_STRING_TYPES:
        if not private_string:
          raise errors.ParseError("Trying to read from empty Private String")
        if item[0] in constants.FIREHOSE_ITEM_STRING_ARBITRARY_DATA_TYPES:
          result = private_string[item[1]:item[1] + item[2]]
        else:
          result = self._ReadStructureFromByteStream(
              private_string[item[1]:], 0, self._GetDataTypeMap("cstring"))
          logger.info("End result: {0:s}".format(result))
      elif item[0] == constants.FIREHOSE_ITEM_STRING_PRIVATE:
        result = private_string[item[1]:item[1] + item[2]]
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

    if tracepoint.log_activity_type == constants.FIREHOSE_LOG_ACTIVITY_TYPE_LOSS:
      raise errors.ParseError("Loss Type not supported")

    dsc_range = dsc.DSCRange()
    extra_offset_value_result = tracepoint.format_string_location
    if formatter_flags.shared_cache or formatter_flags.large_shared_cache != 0:
      if formatter_flags.large_offset_data != 0:
        if formatter_flags.large_offset_data != formatter_flags.large_shared_cache / 2 and \
          not formatter_flags.shared_cache:
          formatter_flags.large_offset_data = formatter_flags.large_shared_cache / 2
          extra_offset_value = "{0:X}{1:08x}".format(
              formatter_flags.large_offset_data,
              tracepoint.format_string_location)
        elif formatter_flags.shared_cache:
          formatter_flags.large_offset_data = 8
          extra_offset_value = "{0:X}{1:07x}".format(
              formatter_flags.large_offset_data,
              tracepoint.format_string_location)
        else:
          extra_offset_value = "{0:X}{1:08x}".format(
              formatter_flags.large_offset_data,
              tracepoint.format_string_location)
        extra_offset_value_result = int(extra_offset_value, 16)
      (fmt, dsc_range) = tracev3.ExtractSharedStrings(
          tracepoint.format_string_location, extra_offset_value_result,
          dsc_file)
    else:
      if formatter_flags.absolute:
        uuid_file = tracev3.ExtractAbsoluteStrings(
            tracepoint.format_string_location, formatter_flags.uuid_file_index,
            proc_info, message_string_reference)
        fmt = uuid_file.ReadFormatString(tracepoint.format_string_location)
      elif formatter_flags.uuid_relative:
        uuid_file = tracev3.ExtractAltUUID(formatter_flags.uuid_relative)
        fmt = uuid_file.ReadFormatString(tracepoint.format_string_location)
      else:
        fmt = tracev3.ExtractFormatStrings(tracepoint.format_string_location,
                                           uuid_file)

    found = False
    if data_ref_id != 0:
      for oversize_data in tracev3.oversize_data:
        if oversize_data.first_proc_id == proc_info.first_number_proc_id and \
          oversize_data.second_proc_id == proc_info.second_number_proc_id and \
          oversize_data.data_ref_index == data_ref_id:
          log_data = oversize_data.strings
          found = True
          break
      if not found:
        logger.info(
            "Did not find any oversize log entries from Data Ref ID: {0:d}"
            ", First Proc ID: {1:d}, and Second Proc ID: {2:d}"
            .format(data_ref_id, proc_info.first_number_proc_id,
                    proc_info.second_number_proc_id))

    if fmt:
      event_data.message = "".join(backtrace_strings) + tracev3.FormatString(
          fmt, log_data)
    elif not fmt and not log_data:
      return  # Nothing to do ??
    else:
      event_data.message = "UNKNOWN"
      raise errors.ParseError("UNKNOWN")
    event_data.thread_id = hex(tracepoint.thread_identifier)
    event_data.level = constants.LOG_TYPES.get(tracepoint.log_type, "Default")
    if activity_id:
      event_data.activity_id = hex(activity_id)
    if ttl_value:
      event_data.ttl = ttl_value
    event_data.pid = proc_info.pid
    event_data.euid = proc_info.euid
    event_data.subsystem = (proc_info.items.get(subsystem_value, ("", "")))[0]
    event_data.category = (proc_info.items.get(subsystem_value, ("", "")))[1]
    event_data.library = dsc_range.path if dsc_range.path else uuid_file.library_path
    event_data.library_uuid = dsc_range.uuid.hex if dsc_range.uuid else uuid_file.uuid

    logger.info("Log line: {0!s}".format(event_data.message))
    with open("/tmp/fryoutput.csv", "a") as f:
      csv.writer(f).writerow([
          dfdatetime_apfs_time.APFSTime(timestamp=time).CopyToDateTimeString(),
          event_data.level, event_data.message
      ])

    event = time_events.DateTimeValuesEvent(
        dfdatetime_apfs_time.APFSTime(timestamp=time),
        plaso_definitions.TIME_DESCRIPTION_RECORDED)
    parser_mediator.ProduceEventWithEventData(event, event_data)
