# -*- coding: utf-8 -*-
"""The Apple Unified Logging (AUL) file parser."""

import datetime
import os
import re

import lz4.block

from dfdatetime import apfs_time as dfdatetime_apfs_time

from dfvfs.helpers import file_system_searcher
from dfvfs.lib import definitions
from dfvfs.resolver import resolver as path_spec_resolver
from dfvfs.path import factory as path_spec_factory

from plaso.containers import events
from plaso.containers import time_events
from plaso.lib import definitions as plaso_definitions
from plaso.lib import dtfabric_helper
from plaso.lib import errors
from plaso.lib import specification
from plaso.parsers import interface
from plaso.parsers import logger
from plaso.parsers import manager


class UUIDText(dtfabric_helper.DtFabricHelper):
  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), 'aul.yaml')

  def __init__(self, library_path, library_name, uuid, data, entries):
    super(UUIDText, self).__init__()
    self.library_path = library_path
    self.library_name = library_name
    self.UUID = uuid
    self.data = data
    self.entries = entries

  def ReadFormatString(self, offset):
    #TODO(fryy): Verify this?
    if offset & 0x80000000:
      return '%s'

    negative_start_offset = 16 + (8 * len(self.entries))
    for range_start_offset, data_offset, data_len in self.entries:
      range_end_offset = range_start_offset + data_len
      if range_start_offset <= offset < range_end_offset:
        rel_offset = offset - range_start_offset
        return self._ReadStructureFromByteStream(
          self.data[data_offset + rel_offset - negative_start_offset:],
          0, self._GetDataTypeMap('cstring'))

class UUIDFileParser(
  interface.FileObjectParser, dtfabric_helper.DtFabricHelper):
  """UUID file parser
  """
  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), 'aul.yaml')

  def __init__(self, file_entry, file_system):
    super(UUIDFileParser, self).__init__()
    self.uuid = None
    self.file_entry = file_entry
    self.file_system = file_system
    path_segments = file_system.SplitPath(file_entry.path_spec.location)
    self.uuidtext_location = file_system.JoinPath(path_segments[:-3] + ['uuidtext'])
    if not os.path.exists(self.uuidtext_location):
      raise errors.ParseError(
        "Invalid UUIDText location: {0:s}".format(self.uuidtext_location))

  def FindFile(self, parser_mediator, uuid):
    self.uuid = uuid
    kwargs = {}
    kwargs['location'] = self.file_system.JoinPath([self.uuidtext_location] + [uuid[0:2]] + [uuid[2:]])
    uuid_file_path_spec = path_spec_factory.Factory.NewPathSpec(
        self.file_entry.path_spec.TYPE_INDICATOR, **kwargs)

    uuid_file_entry = path_spec_resolver.Resolver.OpenFileEntry(uuid_file_path_spec)

    if not uuid_file_entry:
      return None

    uuid_file_object = uuid_file_entry.GetFileObject()
    try:
      return self.ParseFileObject(parser_mediator, uuid_file_object)
    except (IOError, errors.ParseError) as exception:
      message = (
          'Unable to parse UUID file: {0:s} with error: '
          '{1!s}').format(uuid, exception)
      logger.warning(message)
      parser_mediator.ProduceExtractionWarning(message)
    return None

  def ParseFileObject(self, parser_mediator, file_object):
    """Parses a UUID file-like object.

    Args:
      parser_mediator (ParserMediator): a parser mediator.
      file_object (dfvfs.FileIO): a file-like object to parse.

    Raises:
      ParseError: if the records cannot be parsed.
    """
    offset = 0
    entries = []

    uuid_header_data_map = self._GetDataTypeMap('uuidtext_file_header')
    uuid_header, size = self._ReadStructureFromFileObject(
      file_object, offset, uuid_header_data_map)
    format_version = (
        uuid_header.major_format_version, uuid_header.minor_format_version)
    if format_version != (2, 1):
      raise errors.ParseError(
        'Unsupported format version: {0:d}.{1:d}.'.format(
            uuid_header.major_format_version,
            uuid_header.minor_format_version))
    data_size = 0
    for entry in uuid_header.entry_descriptors:
      entry_tuple = (entry.offset, data_size+32, entry.data_size)
      data_size += entry.data_size
      entries.append(entry_tuple)
    data = file_object.read(data_size)
    offset = size + data_size
    uuid_footer, _ = self._ReadStructureFromFileObject(
      file_object, offset, self._GetDataTypeMap('uuidtext_file_footer')
    )
    return UUIDText(
      library_path=uuid_footer.library_path,
      library_name=os.path.basename(uuid_footer.library_path),
      uuid=self.uuid,
      data=data,
      entries=entries)


class TimesyncParser(
  interface.FileObjectParser, dtfabric_helper.DtFabricHelper):
  """Timesync record file parser
  """
  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), 'aul.yaml')

  def __init__(self):
    super(TimesyncParser, self).__init__()
    self.records = []

  def ParseAll(self, parser_mediator, file_entry, file_system):
    """Finds and parses all the timesync files

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      file_system (dfvfs.FileSystem): file system.
      file_entry (dfvfs.FileEntry): file entry.
    """
    path_segments = file_system.SplitPath(file_entry.path_spec.location)
    timesync_location = file_system.JoinPath(path_segments[:-2] + ['timesync'])
    kwargs = {}
    if file_entry.path_spec.parent:
      kwargs['parent'] = file_entry.path_spec.parent
    kwargs['location'] = timesync_location
    timesync_file_path_spec = path_spec_factory.Factory.NewPathSpec(
        file_entry.path_spec.TYPE_INDICATOR, **kwargs)

    find_spec = file_system_searcher.FindSpec(
        file_entry_types=[definitions.FILE_ENTRY_TYPE_FILE])

    path_spec_generator = file_system_searcher.FileSystemSearcher(
      file_system, timesync_file_path_spec).Find(
        find_specs=[find_spec])

    for path_spec in path_spec_generator:
      try:
        timesync_file_entry = path_spec_resolver.Resolver.OpenFileEntry(
            path_spec)

      except RuntimeError as exception:
        message = (
            'Unable to open timesync file: {0:s} with error: '
            '{1!s}'.format(path_spec, exception))
        parser_mediator.ProduceExtractionWarning(message)
        continue
      try:
        timesync_file_object = timesync_file_entry.GetFileObject()
        self.ParseFileObject(parser_mediator, timesync_file_object)
      except (IOError, errors.ParseError) as exception:
        message = (
          'Unable to parse data block file: {0:s} with error: '
          '{1!s}').format(path_spec, exception)
        parser_mediator.ProduceExtractionWarning(message)
        continue

  def ParseFileObject(self, parser_mediator, file_object):
    """Parses a shared-cache strings (dsc) file-like object.

    Args:
      parser_mediator (ParserMediator): a parser mediator.
      file_object (dfvfs.FileIO): a file-like object to parse.

    Raises:
      ParseError: if the records cannot be parsed.
    """
    boot_record_data_map = self._GetDataTypeMap('timesync_boot_record')
    sync_record_data_map = self._GetDataTypeMap('timesync_sync_record')

    file_size = file_object.get_size()
    offset = 0
    current_boot_record = None
    while offset < file_size:
      try:
        boot_record, size = self._ReadStructureFromFileObject(
            file_object, offset, boot_record_data_map)
        offset += size
        if current_boot_record is not None:
          self.records.append(current_boot_record)
        current_boot_record = boot_record
        current_boot_record.sync_records = []
        continue
      except errors.ParseError:
        pass

      try:
        sync_record, size = self._ReadStructureFromFileObject(
            file_object, offset, sync_record_data_map)
        offset += size
        current_boot_record.sync_records.append(sync_record)
      except errors.ParseError as exception:
        raise errors.ParseError(
            'Unable to parse time sync file with error: {0!s}'.format(
                exception))
    self.records.append(current_boot_record)

class DSCRange(object):
  """Shared-Cache Strings (dsc) range.

  Attributes:
    path (str): path.
    range_offset (int): the offset of the range.
    range_sizes (int): the size of the range.
    data_offset (int): the offset of the data.
    uuid (uuid.UUID): the UUID.
  """

  def __init__(self):
    """Initializes a Shared-Cache Strings (dsc) range."""
    super(DSCRange, self).__init__()
    self.path = None
    self.range_offset = None
    self.range_size = None
    self.data_offset = None
    self.uuid = None
    self.uuid_index = None
    self.string = None


class DSCUUID(object):
  """Shared-Cache Strings (dsc) UUID.

  Attributes:
    path (str): path.
    sender_identifier (uuid.UUID): the sender identifier.
    text_offset (int): the offset of the text.
    text_sizes (int): the size of the text.
  """

  def __init__(self):
    """Initializes a Shared-Cache Strings (dsc) UUID."""
    super(DSCUUID, self).__init__()
    self.path = None
    self.sender_identifier = None
    self.text_offset = None
    self.text_size = None


class DSCFile(object):
  def __init__(self):
    super(DSCFile, self).__init__()
    self.ranges = []
    self.uuids = []

  def ReadFormatString(self, offset):
    #TODO(fryy): Verify this?
    for range in self.ranges:
      if offset >= range.range_offset and offset < (range.range_offset + range.range_size):
        return range

class DSCFileParser(
    interface.FileObjectParser, dtfabric_helper.DtFabricHelper):
  """Shared-Cache Strings (dsc) file parser.

  Attributes:
    ranges (list[DSCRange]): the ranges.
    uuids (list[DSCUUID]): the UUIDs.
  """

  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), 'aul.yaml')

  def __init__(self, file_entry, file_system):
    """Initializes a dsc file.
    """
    super(DSCFileParser, self).__init__()
    self.file_entry = file_entry
    self.file_system = file_system
    path_segments = file_system.SplitPath(file_entry.path_spec.location)
    self.dsc_location = file_system.JoinPath(path_segments[:-3] + ['uuidtext', 'dsc'])
    if not os.path.exists(self.dsc_location):
      raise errors.ParseError(
        "Invalid UUIDText location: {0:s}".format(self.dsc_location))

  def FindFile(self, parser_mediator, uuid):
    kwargs = {}
    kwargs['location'] = self.file_system.JoinPath([self.dsc_location] + [uuid])
    dsc_file_path_spec = path_spec_factory.Factory.NewPathSpec(
        self.file_entry.path_spec.TYPE_INDICATOR, **kwargs)

    dsc_file_entry = path_spec_resolver.Resolver.OpenFileEntry(dsc_file_path_spec)

    if not dsc_file_entry:
      return None

    dsc_file_object = dsc_file_entry.GetFileObject()
    try:
      return self.ParseFileObject(parser_mediator, dsc_file_object)
    except (IOError, errors.ParseError) as exception:
      message = (
          'Unable to parse DSC file: {0:s} with error: '
          '{1!s}').format(uuid, exception)
      logger.warning(message)
      parser_mediator.ProduceExtractionWarning(message)
    return None

  def _ReadFileHeader(self, file_object):
    """Reads a dsc file header.

    Args:
      file_object (file): file-like object.

    Returns:
      dsc_file_header: a file header.

    Raises:
      ParseError: if the file header cannot be read.
    """
    data_type_map = self._GetDataTypeMap('dsc_file_header')

    file_header, _ = self._ReadStructureFromFileObject(
        file_object, 0, data_type_map)

    format_version = (
        file_header.major_format_version, file_header.minor_format_version)
    if format_version not in [(1, 0), (2, 0)]:
      raise errors.ParseError(
          'Unsupported format version: {0:d}.{1:d}.'.format(
              file_header.major_format_version,
              file_header.minor_format_version))

    return file_header

  def _ReadRangeDescriptors(
      self, file_object, file_offset, version, number_of_ranges):
    """Reads the range descriptors.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the start of range descriptors data relative
          to the start of the file.
      version (int): major version of the file.
      number_of_ranges (int): the number of range descriptions to retrieve.

    Yields:
      DSCRange: a range.

    Raises:
      ParseError: if the file cannot be read.
    """
    if version not in (1, 2):
      raise errors.ParseError('Unsupported format version: {0:d}.'.format(
          version))

    if version == 1:
      data_type_map_name = 'dsc_range_descriptor_v1'
    else:
      data_type_map_name = 'dsc_range_descriptor_v2'

    data_type_map = self._GetDataTypeMap(data_type_map_name)

    for _ in range(number_of_ranges):
      range_descriptor, record_size = self._ReadStructureFromFileObject(
          file_object, file_offset, data_type_map)

      file_offset += record_size

      dsc_range = DSCRange()
      dsc_range.range_offset = range_descriptor.range_offset
      dsc_range.range_size = range_descriptor.range_size
      dsc_range.data_offset = range_descriptor.data_offset
      dsc_range.uuid_index = range_descriptor.uuid_descriptor_index
      yield dsc_range

  def _ReadUUIDDescriptors(
      self, file_object, file_offset, version, number_of_uuids):
    """Reads the UUID descriptors.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the start of UUID descriptors data relative
          to the start of the file.
      version (int): major version of the file
      number_of_uuids (int): the number of UUID descriptions to retrieve.

    Yields:
      DSCUUId: an UUID.

    Raises:
      ParseError: if the file cannot be read.
    """
    if version not in (1, 2):
      raise errors.ParseError('Unsupported format version: {0:d}.'.format(
          version))

    if version == 1:
      data_type_map_name = 'dsc_uuid_descriptor_v1'
    else:
      data_type_map_name = 'dsc_uuid_descriptor_v2'

    data_type_map = self._GetDataTypeMap(data_type_map_name)

    for _ in range(number_of_uuids):
      uuid_descriptor, record_size = self._ReadStructureFromFileObject(
          file_object, file_offset, data_type_map)

      file_offset += record_size

      dsc_uuid = DSCUUID()
      dsc_uuid.sender_identifier = uuid_descriptor.sender_identifier
      dsc_uuid.text_offset = uuid_descriptor.text_offset
      dsc_uuid.text_size = uuid_descriptor.text_size

      dsc_uuid.path = self._ReadUUIDPath(
          file_object, uuid_descriptor.path_offset)

      yield dsc_uuid

  def _ReadUUIDPath(self, file_object, file_offset):
    """Reads an UUID path.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the UUID path data relative to the start of
          the file.

    Returns:
      str: UUID path.

    Raises:
      ParseError: if the file cannot be read.
    """
    data_type_map = self._GetDataTypeMap('cstring')

    uuid_path, _ = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map)

    return uuid_path

  def ParseFileObject(self, parser_mediator, file_object):
    """Parses a shared-cache strings (dsc) file-like object.

    Args:
      parser_mediator (ParserMediator): a parser mediator.
      file_object (dfvfs.FileIO): a file-like object to parse.

    Raises:
      WrongParser: when the file cannot be parsed.
    """
    ret = DSCFile()
    file_header = self._ReadFileHeader(file_object)

    file_offset = file_object.tell()

    ret.ranges = list(self._ReadRangeDescriptors(
        file_object, file_offset, file_header.major_format_version,
        file_header.number_of_ranges))

    file_offset = file_object.tell()

    ret.uuids = list(self._ReadUUIDDescriptors(
        file_object, file_offset, file_header.major_format_version,
        file_header.number_of_uuids))

    #TODO(fryy): can we do this on demand?
    for dsc_range in ret.ranges:
      dsc_uuid = ret.uuids[dsc_range.uuid_index]

      dsc_range.path = dsc_uuid.path
      dsc_range.uuid = dsc_uuid.sender_identifier
    
    #TODO(fryy) : Can we do this?
    del ret.uuids

    file_offset = file_object.tell()

    # Fill in strings
    for dsc_range in ret.ranges:
      file_object.seek(dsc_range.data_offset, os.SEEK_SET)
      dsc_range.string = file_object.read(dsc_range.range_size)

    return ret


class OversizeData(object):
  def __init__(self, first_proc_id, second_proc_id, data_ref_index):
    super(OversizeData, self).__init__()
    self.first_proc_id = first_proc_id
    self.second_proc_id = second_proc_id
    self.data_ref_index = data_ref_index
    self.strings = []


class TraceV3FileParser(interface.FileObjectParser,
                        dtfabric_helper.DtFabricHelper):
  """Apple Unified Logging and Activity Tracing (tracev3) file."""

  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), 'aul.yaml')

  _CATALOG_LZ4_COMPRESSION = 0x100

  # Chunk Tags
  _CHUNK_TAG_HEADER = 0x1000
  _CHUNK_TAG_FIREHOSE = 0x6001
  _CHUNK_TAG_OVERSIZE = 0x6002
  _CHUNK_TAG_STATEDUMP = 0x6003
  _CHUNK_TAG_CATALOG = 0x600B
  _CHUNK_TAG_CHUNKSET = 0x600D

  # Activity Types
  _FIREHOSE_LOG_ACTIVITY_TYPE_ACTIVITY = 0x2
  _FIREHOSE_LOG_ACTIVITY_TYPE_TRACE = 0x3
  _FIREHOSE_LOG_ACTIVITY_TYPE_NONACTIVITY = 0x4
  _FIREHOSE_LOG_ACTIVITY_TYPE_SIGNPOST = 0x6
  _FIREHOSE_LOG_ACTIVITY_TYPE_LOSS = 0x7

  # Item Types
  _FIREHOSE_ITEM_NUMBER_TYPES = [0x0, 0x2]
  _FIREHOSE_ITEM_STRING_PRIVATE = 0x1
  _FIREHOSE_ITEM_PRIVATE_STRING_TYPES = [
    0x21, 0x25, 0x31, 0x35, 0x41
  ]
  _FIREHOSE_ITEM_STRING_TYPES = [
    0x20, 0x22, 0x30, 0x32, 0x40, 0x42, 0xf2
  ]
  _FIREHOSE_ITEM_STRING_ARBITRARY_DATA_TYPES = [
    0x30, 0x31, 0x32
  ]
  _FIREHOSE_ITEM_STRING_BASE64_TYPE = 0xf2
  _FIREHOSE_ITEM_PRECISION_TYPES = [0x10, 0x12]
  _FIREHOSE_ITEM_SENSITIVE = 0x45

  # Log Types
  _LOG_TYPES = {
    0x01: "Info",
    0x02: "Debug",
    0x10: "Error",
    0x11: "Fault"
  }

  # Taken from https://github.com/mandiant/macos-UnifiedLogs/blob/main/src/unified_log.rs#L203
  format_strings_re = re.compile(r"(%(?:(?:\{[^}]+}?)(?:[-+0#]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l|ll|w|I|z|t|q|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@}]|(?:[-+0 #]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l||q|t|ll|w|I|z|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@%]))")

  def __init__(self, timesync_parser, uuid_parser, dsc_parser):
    """Initializes a tracev3 file parser.
    """
    super(TraceV3FileParser, self).__init__()
    self.boot_uuid_ts_list = None
    self.catalog = None
    self.chunksets = []
    self.dsc_parser = dsc_parser
    self.header = None
    self.logs = []
    self.oversize_data = []
    self.timesync_parser = timesync_parser
    self.uuid_parser = uuid_parser

  # TODO(fryy): Rewrite
  def _ReadAPFSTime(self, mac_apfs_time):
    '''Returns datetime object, or empty string upon error
      Mac APFS timestamp is nano second time epoch beginning 1970/1/1
    '''
    if mac_apfs_time not in ( 0, None, ''):
      try:
        if isinstance(mac_apfs_time, str):
          mac_apfs_time = float(mac_apfs_time)
        return datetime.datetime(1970, 1, 1) + datetime.timedelta(
            seconds=mac_apfs_time / 1000000000.)
      except (ValueError, UnicodeDecodeError, TypeError):
        logger.error(
            "ReadAPFSTime() Failed to convert timestamp from value %s",
            str(mac_apfs_time),
            exc_info=1)
    return ''

  def _GetBootUuidTimeSyncList(self, uuid):
    '''Retrieves the timesync for a specific boot identifier.

    Args:
        uuid (uuid): boot identifier.

    Returns:
      Timesync: timesync or None if not available.
    '''
    for ts in self.timesync_parser.records:
      if ts.boot_uuid == uuid:
        return ts.sync_records
    logger.error("Could not find boot uuid {} in Timesync!".format(uuid))
    return None

  def _FindClosestTimesyncItemInList(self, sync_records, continuous_time):
    '''Returns the closest timesync item from the provided list'''
    if not sync_records:
      return None

    closest_tsi = sync_records[0]
    for item in sync_records:
      if item.kernel_continuous_timestamp > continuous_time:
        break
      closest_tsi = item
    return closest_tsi

  def _TimestampFromContTime(self, ct):
    ts = self._FindClosestTimesyncItemInList(self.boot_uuid_ts_list, ct)
    time_string = 'N/A'
    if ts is not None:
      time = ts.wall_time + ct - ts.kernel_continuous_timestamp
      time_string = dfdatetime_apfs_time.APFSTime(timestamp=time).CopyToDateTimeString()
    return time_string

  def _FormatString(self, format_string, data):
    if len(format_string) == 0:
      if len(data) == 0:
        return ''
      else:
        return data[0][2]

    output = ""
    i = 0
    last_start_index = 0
    replacements = []
    for match in self.format_strings_re.finditer(format_string):
      output = format_string[last_start_index:match.start()]
      last_start_index = match.end()
      if match.group().startswith("% "):
        continue
        
      if match == "%%":
        output += "%"
        continue

      if i > len(data):
        output += "<decode: missing data>"
        continue

      if match.group().startswith("%{") and match.group().endswith("}"):
        output += match[1:]
        continue
      
      # Item type, Item Size, Item
      if (data[i][0] in self._FIREHOSE_ITEM_PRIVATE_STRING_TYPES) and len(data[i][2]) == 0 and data[i][1] == 0 or (data[i][0] == self._FIREHOSE_ITEM_STRING_PRIVATE and data[i][1] == 0x8000):
        output += "<private>"
      if match.group().startswith("%{"):
        (format, format_type) = match.group().split("}", 1)
        self._ParseFormatter("}"+format_type, data, i)
        # parse_type_formatter
        raise errors.ParseError("parse_type_formatter not supported")
      else:
        # parse_formatter
        raise errors.ParseError("parse_formatter not supported")
      
      if data[i][0] in self._FIREHOSE_ITEM_PRECISION_TYPES:
        i += 1

#    data_items = []
#    new_format_string = format_string.replace('%@', '%s').replace("%hh", "%")
#    for item in data:
#      if item[0] == 0x2: # Number ?
#        data_items.append(int.from_bytes(item[2], 'little'))
#      else:
#        data_items.append(item[2])
#    x = new_format_string # % tuple(data_items)
    return output

  def _ParseFormatter(self, format, data, index):
    ret = data[2]
    precision_value = 0
    if data[0] in self._FIREHOSE_ITEM_PRECISION_TYPES:
      precision_value = data[1]
      index += 1
    
    # TODO(fryy): Do we need this?
    #if format.lower().endswith('c') and data[0] in self._FIREHOSE_ITEM_NUMBER_TYPES + [self._FIREHOSE_ITEM_STRING_PRIVATE]:
    #  data[2] = str(data[2])
    width_index = 1

    for (i, char) in enumerate(format):
      if i == 0:
        continue
      
      left_justify, hashtag, pad_zero, plus_minus = False
      if char == "-":
        left_justify = True
        continue
      if char == "+":
        plus_minus = True
        continue
      if char == "#":
        hashtag = True
        continue
      if char == "0":
        pad_zero = True
        continue
      width_index = i
      break

    # Split into numbers / letters
    width = ""
    results = re.findall(r'(\d*)(\D*)', format[width_index:])
    if len(results) != 2:
      formatter = format[width_index:]
    else:
      (width, formatter) = results[0]

    if formatter.startswith('*'):
      if data[0] == 0x0 and data[1] == 0:
        precision_value = data[1]
        index += 1
      
      width_value = 

  def _ReadHeader(self, file_object, file_offset):
    """Reads a Header.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the catalog data relative to the start
          of the file.

    Raises:
      ParseError: if the chunk header cannot be read.
    """
    data_type_map = self._GetDataTypeMap('tracev3_header')

    self.header, _ = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map)

    logger.warning('Header data: CT {0:d} // Bias {1:d}'.format(self.header.continuous_time, self.header.bias_in_minutes))
    logger.warning('SI Info: BVS: {0:s} // HMS: {1:s}'.format(self.header.systeminfo_subchunk.systeminfo_subchunk_data.build_version_string, self.header.systeminfo_subchunk.systeminfo_subchunk_data.hardware_model_string))
    logger.warning('Boot UUID: {0:s}'.format(self.header.generation_subchunk.generation_subchunk_data.boot_uuid.hex))
    logger.warning('TZ Info: {0:s}'.format(self.header.timezone_subchunk.timezone_subchunk_data.path_to_tzfile))

    self.boot_uuid_ts_list = self._GetBootUuidTimeSyncList(
        self.header.generation_subchunk.generation_subchunk_data.boot_uuid)
    logger.error('Tracev3 Header Timestamp: %s', self._TimestampFromContTime(
          self.header.continuous_time_subchunk.continuous_time_data))

  def _ReadCatalog(self, parser_mediator, file_object, file_offset):
    """Reads a catalog.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the catalog data relative to the start
          of the file.

    Raises:
      ParseError: if the chunk header cannot be read.
    """
    data_type_map = self._GetDataTypeMap('tracev3_catalog')

    catalog, offset_bytes = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map)

    logger.warning("Catalog data: NumProcs {0:d} // NumSubChunks {1:d} // EarliestFirehoseTS {2:d}".format(catalog.number_of_process_information_entries, catalog.number_of_sub_chunks, catalog.earliest_firehose_timestamp))
    logger.warning("Num UUIDS: {0:d} // Num SubSystemStrings {1:d}".format(len(catalog.uuids), len(catalog.sub_system_strings)))

    catalog.files = []

    #TODO(fryy): Cache these so we don't have to reparse them
    for uuid in catalog.uuids:
      filename = uuid.hex.upper()
      logger.warning("Encountered UUID {0:s} in Catalog.".format(filename))
      found = self.dsc_parser.FindFile(parser_mediator, filename)
      if not found:
        found = self.uuid_parser.FindFile(parser_mediator, filename)
        if not found:
          raise errors.ParseError('Neither UUID nor DSC file found for UUID: {0:s}'.format(uuid.hex))
      catalog.files.append(found)

    data_type_map = self._GetDataTypeMap(
      'tracev3_catalog_process_information_entry')
    catalog.process_entries = []

    for _ in range(catalog.number_of_process_information_entries):
      process_entry, new_bytes = self._ReadStructureFromFileObject(
        file_object, file_offset+offset_bytes, data_type_map)
      process_entry.main_uuid = catalog.uuids[process_entry.main_uuid_index]
      process_entry.dsc_uuid = catalog.uuids[process_entry.catalog_dsc_index]
      process_entry.items = {}
      logger.warning("Process Entry data: PID {0:d} // EUID {1:d}".format(process_entry.pid, process_entry.euid))
      for subsystem in process_entry.subsystems:
        offset = 0
        subsystem_string = None
        category_string = None
        for string in catalog.sub_system_strings:
          if subsystem_string is None:
            if offset >= subsystem.subsystem_offset:
              subsystem_string = string
              offset += len(string) + 1
              continue
            else:
              offset += len(string) + 1
          if category_string is None:
            if offset >= subsystem.category_offset:
              category_string = string
              break
            offset += len(string) + 1
        process_entry.items[subsystem.identifier] = (subsystem_string, category_string)
        logger.warning("Process Entry coalesce: Subsystem {0:s} // Category {1:s}".format(subsystem_string, category_string))
      catalog.process_entries.append(process_entry)
      offset_bytes += new_bytes

    data_type_map = self._GetDataTypeMap(
      'tracev3_catalog_subchunk')
    catalog.subchunks = []

    for _ in range(catalog.number_of_sub_chunks):
      subchunk, new_bytes = self._ReadStructureFromFileObject(
        file_object, file_offset+offset_bytes, data_type_map)
      logger.warning("Catalog Subchunk data: Size {0:d}".format(subchunk.uncompressed_size))
      catalog.subchunks.append(subchunk)
      offset_bytes += new_bytes

    return catalog

  def _ReadChunkHeader(self, file_object, file_offset):
    """Reads a chunk header.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the chunk header relative to the start
          of the file.

    Returns:
      tracev3_chunk_header: a chunk header.

    Raises:
      ParseError: if the chunk header cannot be read.
    """
    data_type_map = self._GetDataTypeMap('tracev3_chunk_header')

    chunk_header, _ = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map)

    return chunk_header

  def _ReadChunkSet(self, parser_mediator, file_object, file_offset, chunk_header,
                        chunkset_index):
    """Reads a chunk set.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the chunk set data relative to the start
          of the file.
      chunk_header (tracev3_chunk_header): the chunk header of the chunk set.
      chunkset_index (int): What number chunk this is in the catalog.

    Raises:
      ParseError: if the chunk header cannot be read.
    """
    if self.catalog.subchunks[
            chunkset_index].compression_algorithm != self._CATALOG_LZ4_COMPRESSION:
      raise errors.ParseError(
        "Unknown compression algorithm : {0:s}".format(self.catalog.compression_algorithm))

    chunk_data = file_object.read(chunk_header.chunk_data_size)

    data_type_map = self._GetDataTypeMap('tracev3_lz4_block_header')

    lz4_block_header, _ = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map)
    logger.warning("Read LZ4 block: Compressed size {0:d} // Uncompressed size {1:d}".format(lz4_block_header.compressed_data_size, lz4_block_header.uncompressed_data_size))

    end_of_compressed_data_offset = 12 + lz4_block_header.compressed_data_size

    if lz4_block_header.signature == b'bv41':
      uncompressed_data = lz4.block.decompress(
          chunk_data[12:end_of_compressed_data_offset],
          uncompressed_size=lz4_block_header.uncompressed_data_size)

    elif lz4_block_header.signature == b'bv4-':
      logger.warning("It was already uncompressed!")
      uncompressed_data = chunk_data[12:end_of_compressed_data_offset]

    else:
      raise errors.ParseError('Unsupported start of compressed data marker')

    end_of_compressed_data_identifier = chunk_data[
        end_of_compressed_data_offset:end_of_compressed_data_offset + 4]

    if end_of_compressed_data_identifier != b'bv4$':
      raise errors.ParseError('Unsupported end of compressed data marker')

    data_type_map = self._GetDataTypeMap('tracev3_chunk_header')

    data_offset = 0
    while data_offset < lz4_block_header.uncompressed_data_size:
      chunkset_chunk_header = self._ReadStructureFromByteStream(
          uncompressed_data[data_offset:], data_offset, data_type_map)
      data_offset += 16
      logger.warning("Reading Decompressed Chunk: Size {0:d}".format(chunkset_chunk_header.chunk_data_size))

      data_end_offset = data_offset + chunkset_chunk_header.chunk_data_size
      chunkset_chunk_data = uncompressed_data[data_offset:data_end_offset]

      if chunkset_chunk_header.chunk_tag == self._CHUNK_TAG_FIREHOSE:
        logger.warning("Processing a Firehose Chunk (0x6001)")
        self._ReadFirehoseChunkData(
            parser_mediator, chunkset_chunk_data, chunkset_chunk_header.chunk_data_size,
            data_offset)
      elif chunkset_chunk_header.chunk_tag == self._CHUNK_TAG_OVERSIZE:
        logger.warning("Processing an Oversize Chunk (0x6002) -- not supported")
        self._ReadOversizeChunkData(
          parser_mediator, chunkset_chunk_data, chunkset_chunk_header.chunk_data_size,
          data_offset
        )
      else:
        raise errors.ParseError(
          "Unsupported Chunk Type: {0:d}".format(
            chunkset_chunk_header.chunk_tag))

      data_offset = data_end_offset

      _, alignment = divmod(data_offset, 8)
      if alignment > 0:
        alignment = 8 - alignment

      data_offset += alignment

  def _ParseNonActivity(self, parser_mediator, tracepoint, proc_info, time):
    logger.warning("Parsing non-activity")
    offset = 0
    flags = tracepoint.flags
    data = tracepoint.data

    # Event data initialisation
    # TODO(fryy): Can we put these directly into event_data?
    fmt = None
    activity_id = 0

    event_data = AULEventData()
    event_data.boot_uuid = self.header.generation_subchunk.generation_subchunk_data.boot_uuid.hex

    try:
      dsc_file = self.catalog.files[proc_info.catalog_dsc_index]
    except IndexError:
      dsc_file = None
    try:
      uuid_file = self.catalog.files[proc_info.main_uuid_index]
      event_data.process_uuid = uuid_file.UUID
      event_data.process = uuid_file.library_path
    except IndexError:
      uuid_file = None

    _NON_ACTIVITY_SENINTEL = 0x80000000

    # Flags
    _CURRENT_AID = 0x1
    _PRIVATE_STRING_RANGE = 0x100
    _HAS_MESSAGE_IN_UUIDTEXT = 0x0002
    _HAS_ALTERNATE_UUID = 0x0008
    _HAS_SUBSYSTEM = 0x0200
    _HAS_TTL = 0x0400
    _HAS_DATA_REF = 0x0800
    _HAS_CONTEXT_DATA = 0x1000
    _HAS_SIGNPOST_NAME = 0x8000

    uint8_data_type_map = self._GetDataTypeMap('uint8')
    uint16_data_type_map = self._GetDataTypeMap('uint16')
    uint32_data_type_map = self._GetDataTypeMap('uint32')
    uint64_data_type_map = self._GetDataTypeMap('uint64')

    if flags & _CURRENT_AID:
      logger.warning("Non-activity has current_aid")
      
      activity_id = self._ReadStructureFromByteStream(
        data, offset, uint32_data_type_map)
      offset += 4
      sentinel = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
      offset += 4
      if sentinel != _NON_ACTIVITY_SENINTEL:
        raise errors.ParseError("Incorrect sentinel value for Non-Activity")
    
    if flags & _PRIVATE_STRING_RANGE:
      logger.warning("Non-activity has private_string_range (has_private_data flag)")
      
      private_strings_offset = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      private_strings_size = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      
    # Mandiant: unknown_pc_id
    unknown_message_string_reference  = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
    offset += 4
    logger.warning("Unknown PCID: {0:d}".format(unknown_message_string_reference))
  
    if flags & _HAS_ALTERNATE_UUID:
      if flags & _HAS_MESSAGE_IN_UUIDTEXT:
        logger.warning("Non-activity: Has Alternate UUID & Message in UUIDText")

      else:
        logger.warning("Non-activity: Has Alternate UUID & _NO_ Message in UUIDText")
#        uuid_file_id = self._ReadStructureFromByteStream(
#          data[offset:], offset, uint8_data_type_map)
#        for extra_uuid in proc_info.uuids:
#            logger.warning("Doing tha thing")
            # if extra_uuid.
#        offset += 1

    large_shared_cache = 0
    large_offset_data = 0
    uuid_file_index = -1
    data_ref_id = 0
    shared_cache = False
    absolute = False
    uuid_relative = False
    # Flags ??
    if flags & 0xe == 0x20:
      large_offset_data = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      logger.warning('Has large offset: {0:d}'.format(large_offset_data))
      if flags & 0xc:
        large_shared_cache = self._ReadStructureFromByteStream(
          data[offset:], offset, uint16_data_type_map)
        offset += 2
        logger.warning('Has large shared cache: {0:d}'.format(large_shared_cache))
    elif flags & 0xe == 0xc:
      if flags & 0x20:
        large_offset_data = self._ReadStructureFromByteStream(
          data[offset:], offset, uint16_data_type_map)
        offset += 2
        logger.warning('Has large offset: {0:d}'.format(large_offset_data))
      large_shared_cache = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      logger.warning('Has large shared cache: {0:d}'.format(large_shared_cache))
    elif flags & 0xe == 0x8:
      logger.warning('Absolute')
      absolute = True
      if flags & 0x2 == 0:
        logger.warning('Alt index')
        uuid_file_index = self._ReadStructureFromByteStream(
          data[offset:], offset, uint16_data_type_map)
        offset += 2
    elif flags & 0xe == 0x2:
      logger.warning('main_exe')
    elif flags & 0xe == 0x4:
      logger.warning('shared_cache')
      shared_cache = True
      if flags & 0x20:
        large_offset_data = self._ReadStructureFromByteStream(
          data[offset:], offset, uint16_data_type_map)
        offset += 2
        logger.warning('Has large offset: {0:d}'.format(large_offset_data))
    elif flags & 0xe == 0xa:
      logger.warning('uuid_relative')
      uuid_relative = self._ReadStructureFromByteStream(
          data[offset:], offset, uint64_data_type_map)
      offset += 8

    # Yes has subsys (1)
    if flags & _HAS_SUBSYSTEM:
      subsystem_value = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      logger.warning("Non-activity has subsystem: {0:d}".format(subsystem_value))
    
    # Yes has TTL (30)
    if flags & _HAS_TTL:
      ttl_value = self._ReadStructureFromByteStream(
        data[offset:], offset, uint8_data_type_map)
      offset += 1
      logger.warning("Non-activity has TTL: {0:d}".format(ttl_value))

    if flags & _HAS_DATA_REF:
      # UnifiedLogReader: This is a ref to an object stored as type 0x0602 blob
      data_ref_id = self._ReadStructureFromByteStream(
        data[offset:], offset, uint8_data_type_map)
      offset += 1
      logger.warning("Non-activity with data reference: {0:d}".format(data_ref_id))


    if flags & _HAS_SIGNPOST_NAME:
      raise errors.ParseError("Non-activity signpost not supported")

    if flags & _HAS_MESSAGE_IN_UUIDTEXT:
      logger.warning("Non-activity has message in UUID Text file")
      if flags & _HAS_ALTERNATE_UUID:
        raise errors.ParseError("Non-activity with Alternate UUID not supported")
        if flags & _HAS_SIGNPOST_NAME:
          raise errors.ParseError("Non-activity signpost not supported")
      else:
        if not uuid_file:
          # raise errors.ParseError("Unable to continue without matching UUID file")
          return
        fmt = uuid_file.ReadFormatString(tracepoint.format_string_location)
        # log_data_len = tracepoint.data_size
        if flags & _HAS_SIGNPOST_NAME:
          raise errors.ParseError("Non-activity signpost not supported")

    # Read log data
    log_data = []

    if flags & _PRIVATE_STRING_RANGE:
      raise errors.ParseError("Private strings not supported")

    if tracepoint.log_activity_type == self._FIREHOSE_LOG_ACTIVITY_TYPE_LOSS:
      raise errors.ParseError("Loss Type not supported")

    # TODO(fryy): Check for len(data[offset:] minimums)
    data_meta = self._ReadStructureFromByteStream(
      data[offset:], offset, self._GetDataTypeMap('tracev3_firehose_tracepoint_data'))
    offset += 2

    logger.warning("After activity data: Unknown {0:d} // Number of Items {1:d}".format(data_meta.unknown1, data_meta.num_items))
    (log_data, deferred_data_items, offset) = self._ReadItems(data_meta, data, offset)

    if flags & _HAS_CONTEXT_DATA != 0:
      raise errors.ParseError("Backtrace data in Firehose log chunk unsupported")

    for item in deferred_data_items:
      result = self._ReadStructureFromByteStream(
        data[offset + item[1]:], 0, self._GetDataTypeMap('cstring'))
      logger.warning("End result: {0:s}".format(result))
      log_data.append((item[0], item[2], result))

    if flags & _HAS_DATA_REF:
      logger.warning("Data Ref Not Supported")
    
    if tracepoint.log_activity_type == self._FIREHOSE_LOG_ACTIVITY_TYPE_LOSS:
      raise errors.ParseError("Loss Type not supported")
    
    dsc_range = DSCRange()
    extra_offset_value_result = -1
    if shared_cache or large_shared_cache != 0:
      if large_offset_data is not None:
        if large_offset_data != large_shared_cache / 2 and not shared_cache:
          large_offset_data = large_shared_cache / 2
          extra_offset_value = "{0:X}{1:08x}".format(large_offset_data, tracepoint.format_string_location)
        elif shared_cache:
          large_offset_data = 8
          extra_offset_value = "{0:X}{1:07x}".format(large_offset_data, tracepoint.format_string_location)
        else:
          extra_offset_value = "{0:X}{1:08x}".format(large_offset_data, tracepoint.format_string_location)
      extra_offset_value_result = int(extra_offset_value, 16)
      (fmt, dsc_range) = self._ExtractSharedStrings(tracepoint.format_string_location, extra_offset_value_result, dsc_file)
    else:
      if absolute:
        extra_offset_value = "{0:X}{1:08X}".format(uuid_file_index, unknown_message_string_reference)
        extra_offset_value_result = int(extra_offset_value, 16)
        # extract_absolute_strings()
        raise errors.ParseError("Absolute not supported")
      if uuid_relative:
        # extract_alt_uuid_strings
        raise errors.ParseError("Alt UUID not supported")
        pass
      self._ExtractFormatStrings(tracepoint.format_string_location)

    found = False
    if data_ref_id != 0:
      for oversize in self.oversize_data:
        if oversize.first_proc_id == proc_info.first_number_proc_id and oversize.second_proc_id == proc_info.second_number_proc_id and oversize.data_ref == data_ref_id:
          log_data = oversize.strings
          found = True
          break
    if not found:
      logger.warning("Did not find any oversize log entries from Data Ref ID: {0:d}, First Proc ID: {1:d}, and Second Proc ID: {2:d}".format(data_ref_id, proc_info.first_number_proc_id, proc_info.second_number_proc_id))

    if fmt:
      event_data.message = self._FormatString(fmt, log_data)
    else:
      event_data.message = "UNKNOWN"
    event_data.thread_id = hex(tracepoint.thread_identifier)
    event_data.level = self._LOG_TYPES.get(tracepoint.log_type, "Default")
    event_data.activity_id = hex(activity_id)
    event_data.pid = proc_info.pid
    event_data.euid = proc_info.euid
    event_data.subsystem = (proc_info.items.get(subsystem_value, ('', '')))[0]
    event_data.category = (proc_info.items.get(subsystem_value, ('', '')))[1]
    event_data.library = dsc_range.path
    event_data.library_uuid = dsc_range.uuid.hex
    logger.warning("Log line: {0!s}".format(event_data.message))
    # 'signpost_name': '',
    # 'signpost_string': '',
    # 'ttl'

    event = time_events.DateTimeValuesEvent(dfdatetime_apfs_time.APFSTime(timestamp=time), plaso_definitions.TIME_DESCRIPTION_RECORDED)
    parser_mediator.ProduceEventWithEventData(event, event_data)

  #TODO(fryy): Move
  def _ExtractFormatStrings(self, original_offset):
    logger.warning("Extracting format string from UUID file")
    if original_offset & 0x80000000 != 0:
      raise errors.ParseError("Dynamic offset not supported")

    raise errors.ParseError("UUID not done yet")

  def _ExtractSharedStrings(self, original_offset, extra_offset, dsc_file):
    logger.warning("Extracting format string from shared cache file (DSC)")
    if original_offset & 0x80000000 != 0:
      raise errors.ParseError("Dynamic offset not supported")

    range = dsc_file.ReadFormatString(extra_offset)
    format_string = self._ReadStructureFromByteStream(
      range.string[extra_offset - range.range_offset:], 0, self._GetDataTypeMap('cstring'))

    logger.warning("Fmt string: {0:s}".format(format_string))
    return (format_string, range)

  def _ReadItems(self, data_meta, data, offset):
    log_data = []
    deferred_data_items = []
    for _ in range(data_meta.num_items):
      data_item = self._ReadStructureFromByteStream(
        data[offset:], offset, self._GetDataTypeMap('tracev3_firehose_tracepoint_data_item'))
      offset += 2 + data_item.item_size
      logger.warning("Item data: Type {0:d}".format(data_item.item_type))
      if data_item.item_type in self._FIREHOSE_ITEM_NUMBER_TYPES:
        logger.warning("Number: {0!s}".format(data_item.item))
        log_data.append((data_item.item_type, data_item.item_size, data_item.item))
      if data_item.item_type == self._FIREHOSE_ITEM_STRING_PRIVATE or data_item.item_type in self._FIREHOSE_ITEM_PRIVATE_STRING_TYPES + self._FIREHOSE_ITEM_STRING_TYPES:
        offset -= data_item.item_size
        string_message = self._ReadStructureFromByteStream(
          data[offset:], offset, self._GetDataTypeMap('tracev3_firehose_tracepoint_data_item_string_type'))
        offset += data_item.item_size
        if string_message.message_data_size == 0:
          if data_item.item_type == 0x21 or data_item.item_type == 0x41:
            logger.warning("<private>")
            log_data.append((data_item.item_type, data_item.item_size, "<private>"))
          else:
            logger.warning("(null)")
            log_data.append((data_item.item_type, data_item.item_size, "(null)"))
        else:
          deferred_data_items.append((data_item.item_type, string_message.offset, string_message.message_data_size))
        if data_item.item_type in self._FIREHOSE_ITEM_STRING_ARBITRARY_DATA_TYPES:
          logger.warning("Unsupported arbitrary type -- firehose_log.rs:790")
        if data_item.item_type == self._FIREHOSE_ITEM_STRING_BASE64_TYPE:
          logger.warning("Unsupported base64 type -- firehose_log.rs:797")
      if data_item.item_type in self._FIREHOSE_ITEM_PRECISION_TYPES:
        raise errors.ParseError("Precision types not supported -- firehose_log.rs:759")
      if data_item.item_type == self._FIREHOSE_ITEM_SENSITIVE:
        raise errors.ParseError("Sensitive types not supported -- firehose_log.rs:764")
      if data_item.item_type & 0xF0 == 0x10:
        logger.warning("Unsupported special case?? tracev3_file.py:479")
    return (log_data, deferred_data_items, offset)

  def _ParseTracepointData(self, parser_mediator, tracepoint, proc_info, time):
    """Parses a log line"""

    logger.warning("Parsing log line")
    log_type = self._LOG_TYPES.get(tracepoint.log_type, "Default")
    if tracepoint.log_activity_type == self._FIREHOSE_LOG_ACTIVITY_TYPE_NONACTIVITY:
      if log_type == 0x80:
        raise errors.ParseError("Non Activity Signpost ??")
      self._ParseNonActivity(parser_mediator, tracepoint, proc_info, time)
    return

  def _ReadOversizeChunkData(self, parser_mediator, chunk_data, chunk_data_size, data_offset):
    logger.warning("Reading Oversize")
    data_type_map = self._GetDataTypeMap('tracev3_oversize_header')

    oversize_header = self._ReadStructureFromByteStream(
        chunk_data, data_offset, data_type_map)
    logger.warning("Oversize Header data: ProcID 1 {0:d} // ProcID 2 {1:d} // TTL {2:d} // CT {3:d}".format(oversize_header.first_number_proc_id, oversize_header.second_number_proc_id, oversize_header.ttl, oversize_header.continuous_time))

    offset = 0
    data_meta = self._ReadStructureFromByteStream(
      oversize_header.data, offset, self._GetDataTypeMap('tracev3_firehose_tracepoint_data'))
    offset += 2

    logger.warning("After activity data: Unknown {0:d} // Number of Items {1:d}".format(data_meta.unknown1, data_meta.num_items))
    (log_data, deferred_data_items, offset) = self._ReadItems(data_meta, oversize_header.data, offset)

    # Check for backtrace
    if oversize_header.data[offset:offset+3] == [0x01, 0x00, 0x18]:
      raise errors.ParseError("Backtrace !?")

    oversize_strings = []
    for item in deferred_data_items:
      oversize_strings.append((item[0], item[2], self._ReadStructureFromByteStream(
        oversize_header.data[offset + item[1]:], 0, self._GetDataTypeMap('cstring'))))
    
    oversize = OversizeData(oversize_header.first_number_proc_id, oversize_header.second_number_proc_id, oversize_header.data_ref_index)
    oversize.strings = oversize_strings
    self.oversize_data.append(oversize)
    logger.debug("Oversize Data: {0!s}".format(oversize_strings))
    
  def _ReadFirehoseChunkData(self, parser_mediator, chunk_data, chunk_data_size, data_offset):
    """Reads firehose chunk data.

    Args:
      chunk_data (bytes): firehose chunk data.
      chunk_data_size (int): size of the firehose chunk data.
      data_offset (int): offset of the firehose chunk relative to the start
          of the chunk set.

    Raises:
      ParseError: if the firehose chunk cannot be read.
    """
    logger.warning("Reading Firehose")
    data_type_map = self._GetDataTypeMap('tracev3_firehose_header')

    firehose_header = self._ReadStructureFromByteStream(
        chunk_data, data_offset, data_type_map)
    
    logger.warning("Firehose Header data: ProcID 1 {0:d} // ProcID 2 {1:d} // TTL {2:d} // CT {3:d}".format(firehose_header.first_number_proc_id, firehose_header.second_number_proc_id, firehose_header.ttl, firehose_header.base_continuous_time))

    proc_id = firehose_header.second_number_proc_id | (firehose_header.first_number_proc_id << 32)
    proc_info = [c for c in self.catalog.process_entries if c.second_number_proc_id | (c.first_number_proc_id << 32) == proc_id]
    if len(proc_info) == 0:
      logger.warning("Could not find Process Info block for ID: %d", proc_id)
    else:
      proc_info = proc_info[0]

    if firehose_header.private_data_virtual_offset < 4096:
      raise errors.ParseError(
        "Something to do with private strings - tracev3_file.py:794")

    logger.warning("Firehose Header Timestamp: %s", self._TimestampFromContTime(
          firehose_header.base_continuous_time))

    tracepoint_map = self._GetDataTypeMap('tracev3_firehose_tracepoint')
    chunk_data_offset = 32
    while chunk_data_offset < chunk_data_size:
      firehose_tracepoint = self._ReadStructureFromByteStream(
          chunk_data[chunk_data_offset:], data_offset + chunk_data_offset, tracepoint_map)
      logger.warning("Firehose Tracepoint data: ActivityType {0:d} // Flags {1:d} // ThreadID {2:d} // Datasize {3:d}".format(firehose_tracepoint.log_activity_type, firehose_tracepoint.flags, firehose_tracepoint.thread_identifier, firehose_tracepoint.data_size))

      ct = firehose_header.base_continuous_time + (firehose_tracepoint.continuous_time_lower | (firehose_tracepoint.continuous_time_upper << 32))
      ts = self._FindClosestTimesyncItemInList(self.boot_uuid_ts_list, ct)
      time = ts.wall_time + ct - ts.kernel_continuous_timestamp
      self._ParseTracepointData(parser_mediator, firehose_tracepoint, proc_info, time)

      chunk_data_offset += 24 + firehose_tracepoint.data_size
      _, alignment = divmod(chunk_data_offset, 8)
      if alignment > 0:
        alignment = 8 - alignment

      chunk_data_offset += alignment

  def ParseFileObject(self, parser_mediator, file_object):
    """Parses a timezone information file-like object.

    Args:
      parser_mediator (ParserMediator): a parser mediator.
      file_object (dfvfs.FileIO): a file-like object to parse.

    Raises:
      WrongParser: when the file cannot be parsed.
    """
    file_offset = 0
    file_size = file_object.get_size()

    chunkset_index = 0

    while file_offset < file_size:
      chunk_header = self._ReadChunkHeader(file_object, file_offset)
      file_offset += 16

      if chunk_header.chunk_tag == self._CHUNK_TAG_HEADER:
        logger.warning("Processing a HEADER (0x1000)")
        self._ReadHeader(file_object, file_offset)

      if chunk_header.chunk_tag == self._CHUNK_TAG_CATALOG:
        logger.warning("Processing a CATALOG (0x600B)")
        self.catalog = self._ReadCatalog(parser_mediator, file_object, file_offset)
        chunkset_index = 0

      if chunk_header.chunk_tag == self._CHUNK_TAG_CHUNKSET:
        logger.warning("Processing a CHUNKSET (0x600D)")
        self._ReadChunkSet(
          parser_mediator, file_object, file_offset, chunk_header, chunkset_index)
        chunkset_index += 1

      file_offset += chunk_header.chunk_data_size

      _, alignment = divmod(file_offset, 8)
      if alignment > 0:
        alignment = 8 - alignment

      file_offset += alignment


class AULEventData(events.EventData):
  DATA_TYPE = 'mac:aul:event'

  def __init__(self):
    """Initializes event data."""
    super(AULEventData, self).__init__(data_type=self.DATA_TYPE)
    self.activity_id = None
    self.category = None
    self.euid = None
    self.level = None
    self.library = None
    self.message = None
    self.pid = None
    self.subsystem = None
    self.thread_id = None


class AULParser(interface.FileEntryParser, dtfabric_helper.DtFabricHelper):
  """Parser for Apple Unified Logging (AUL) files."""

  NAME = 'aul_log'
  DATA_FORMAT = 'Apple Unified Log (AUL) file'

  def __init__(self):
    """Initializes an Apple Unified Logging parser."""
    super(AULParser, self).__init__()
    self.timesync_parser = TimesyncParser()
    self.tracev3_parser = None
    self.uuid_parser = None
    self.dsc_parser = None

  @classmethod
  def GetFormatSpecification(cls):
    """Retrieves the format specification.

    Returns:
      FormatSpecification: format specification.
    """
    format_specification = specification.FormatSpecification(cls.NAME)
    format_specification.AddNewSignature(
        b'\x00\x10\x00\x00', offset=0)
    return format_specification

  def ParseFileEntry(self, parser_mediator, file_entry):
    """Parses an Apple Unified Logging file.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      file_entry (dfvfs.FileEntry): file entry.

    Raises:
      WrongParser: when the file cannot be parsed.
    """
    file_object = file_entry.GetFileObject()
    if not file_object:
      display_name = parser_mediator.GetDisplayName()
      raise errors.WrongParser(
          '[{0:s}] unable to parse tracev3 file {1:s}'.format(
              self.NAME, display_name))

    # Parse timesync files
    file_system = file_entry.GetFileSystem()
    self.timesync_parser.ParseAll(parser_mediator, file_entry, file_system)

    self.uuid_parser = UUIDFileParser(file_entry, file_system)
    self.dsc_parser = DSCFileParser(file_entry, file_system)

    self.tracev3_parser = TraceV3FileParser(self.timesync_parser, self.uuid_parser, self.dsc_parser)

    try:
      self.tracev3_parser.ParseFileObject(parser_mediator, file_object)
    except (IOError, errors.ParseError) as exception:
      display_name = parser_mediator.GetDisplayName()
      raise errors.WrongParser(
          '[{0:s}] unable to parse tracev3 file {1:s} with error: {2!s}'.format(
              self.NAME, display_name, exception))


manager.ParsersManager.RegisterParser(AULParser)
