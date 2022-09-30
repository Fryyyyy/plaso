# -*- coding: utf-8 -*-
"""The Apple Unified Logging (AUL) file parser."""

import datetime
import os

import lz4.block

from dfvfs.helpers import file_system_searcher
from dfvfs.lib import definitions
from dfvfs.resolver import resolver as path_spec_resolver
from dfvfs.path import factory as path_spec_factory

from plaso.containers import events
from plaso.containers import time_events
from plaso.lib import dtfabric_helper
from plaso.lib import errors
from plaso.lib import specification
from plaso.parsers import interface
from plaso.parsers import logger
from plaso.parsers import manager


class TimesyncParser(
  interface.FileObjectParser, dtfabric_helper.DtFabricHelper):
  """Timesync record file parser
  """
  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), 'aul.yaml')

  def __init__(self):
    super(TimesyncParser, self).__init__()
    self.records = []

  def parseAll(self, parser_mediator, file_entry, file_system):
    """Finds and parses all the timesync files

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      file_system (dfvfs.FileSystem): file system.
      file_entry (dfvfs.FileEntry): file entry.
    """
    path_segments = file_system.SplitPath(file_entry.path_spec.location)
    timesync_location = file_system.JoinPath(path_segments[:-2] + ["timesync"])
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
      except errors.ParseError as e:
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
    uuid (uuid.UUID): the UUID.
    uuid_index (int): index of the UUID.
  """

  def __init__(self):
    """Initializes a Shared-Cache Strings (dsc) range."""
    super(DSCRange, self).__init__()
    self.path = None
    self.range_offset = None
    self.range_size = None
    self.uuid = None
    self.uuid_index = None


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


class DSCFileParser(
    interface.FileObjectParser, dtfabric_helper.DtFabricHelper):
  """Shared-Cache Strings (dsc) file parser.

  Attributes:
    ranges (list[DSCRange]): the ranges.
    uuids (list[DSCUUID]): the UUIDs.
  """

  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), 'aul.yaml')

  def __init__(self):
    """Initializes a dsc file.
    """
    super(DSCFileParser, self).__init__()
    self.ranges = []
    self.uuids = []

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

    if file_header.signature != b'hcsd':
      raise errors.ParseError('Unsupported signature.')

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
    file_header = self._ReadFileHeader(file_object)

    file_offset = file_object.tell()

    self.ranges = list(self._ReadRangeDescriptors(
        file_object, file_offset, file_header.major_format_version,
        file_header.number_of_ranges))

    file_offset = file_object.tell()

    self.uuids = list(self._ReadUUIDDescriptors(
        file_object, file_offset, file_header.major_format_version,
        file_header.number_of_uuids))

    for dsc_range in self.ranges:
      dsc_uuid = self.uuids[dsc_range.uuid_index]

      dsc_range.path = dsc_uuid.path
      dsc_range.uuid = dsc_uuid.sender_identifier

class TraceV3FileParser(interface.FileObjectParser,
                        dtfabric_helper.DtFabricHelper):
  """Apple Unified Logging and Activity Tracing (tracev3) file."""

  _DEFINITION_FILE = os.path.join(
      os.path.dirname(__file__), 'aul.yaml')

  _CHUNK_TAG_HEADER = 0x1000
  _CHUNK_TAG_CATALOG = 0x600b
  _CHUNK_TAG_CHUNKSET = 0x600d
  _CHUNK_TAG_FIREHOSE = 0x00006001

  def __init__(self, timesync_parser):
    """Initializes a tracev3 file parser.
    """
    super(TraceV3FileParser, self).__init__()
    self.timesync_parser = timesync_parser
    self.header = None
    self.catalogs = []
    self.chunksets = []
    self.boot_uuid_ts_list = None

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
      if ts.boot_uuid[0] == uuid:
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
      time_string = self._ReadAPFSTime(time)
    return time_string

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

    self.boot_uuid_ts_list = self._GetBootUuidTimeSyncList(
        self.header.generation_subchunk.generation_subchunk[0].
        boot_uuid[0])
    logger.error('Tracev3 Header Timestamp: {0:s}'.format(
        self._TimestampFromContTime(self.header.continuous_time)))

  def _ReadCatalog(self, file_object, file_offset):
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

    data_type_map = self._GetDataTypeMap(
      'tracev3_catalog_process_information_entry')
    catalog.process_entries = []

    for _ in range(catalog.number_of_process_information_entries):
      process_entry, new_bytes = self._ReadStructureFromFileObject(
        file_object, file_offset+offset_bytes, data_type_map)
      catalog.process_entries.append(process_entry)
      offset_bytes += new_bytes

    data_type_map = self._GetDataTypeMap(
      'tracev3_catalog_subchunk')
    catalog.subchunks = []

    for _ in range(catalog.number_of_sub_chunks):
      subchunk, new_bytes = self._ReadStructureFromFileObject(
        file_object, file_offset+offset_bytes, data_type_map)
      catalog.subchunks.append(subchunk)
      offset_bytes += new_bytes

    self.catalogs.append(catalog)

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

  def _ReadChunkSet(self, file_object, file_offset, chunk_header):
    """Reads a chunk set.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the chunk set data relative to the start
          of the file.
      chunk_header (tracev3_chunk_header): the chunk header of the chunk set.

    Raises:
      ParseError: if the chunk header cannot be read.
    """
    chunk_data = file_object.read(chunk_header.chunk_data_size)

    data_type_map = self._GetDataTypeMap('tracev3_lz4_block_header')

    lz4_block_header, _ = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map)

    end_of_compressed_data_offset = 12 + lz4_block_header.compressed_data_size

    if lz4_block_header.signature == b'bv41':
      uncompressed_data = lz4.block.decompress(
          chunk_data[12:end_of_compressed_data_offset],
          uncompressed_size=lz4_block_header.uncompressed_data_size)

    elif lz4_block_header.signature == b'bv4-':
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
          uncompressed_data, data_offset, data_type_map)
      data_offset += 16

      data_end_offset = data_offset + chunkset_chunk_header.chunk_data_size
      chunkset_chunk_data = uncompressed_data[data_offset:data_end_offset]

      if chunkset_chunk_header.chunk_tag == self._CHUNK_TAG_FIREHOSE:
        self._ReadFirehoseChunkData(
            chunkset_chunk_data, chunkset_chunk_header.chunk_data_size,
            data_offset)

      data_offset = data_end_offset

      _, alignment = divmod(data_offset, 8)
      if alignment > 0:
        alignment = 8 - alignment

      data_offset += alignment


  def _ReadFirehoseChunkData(self, chunk_data, chunk_data_size, data_offset):
    """Reads firehose chunk data.

    Args:
      chunk_data (bytes): firehose chunk data.
      chunk_data_size (int): size of the firehose chunk data.
      data_offset (int): offset of the firehose chunk relative to the start
          of the chunk set.

    Raises:
      ParseError: if the firehose chunk cannot be read.
    """
    data_type_map = self._GetDataTypeMap('tracev3_firehose_header')

    firehose_header = self._ReadStructureFromByteStream(
        chunk_data, data_offset, data_type_map)

    chunk_data_offset = 32
    while chunk_data_offset < chunk_data_size:
      firehose_tracepoint = self._ReadFirehoseTracepointData(
          chunk_data[chunk_data_offset:], data_offset + chunk_data_offset)

      test_data_offset = chunk_data_offset + 22
      test_data_end_offset = test_data_offset + firehose_tracepoint.data_size

      chunk_data_offset += 22 + firehose_tracepoint.data_size

  def _ReadFirehoseTracepointData(self, tracepoint_data, data_offset):
    """Reads firehose tracepoint data.

    Args:
      tracepoint_data (bytes): firehose tracepoint data.
      data_offset (int): offset of the firehose tracepoint relative to
          the start of the chunk set.

    Returns:
      tracev3_firehose_tracepoint: a firehose tracepoint.

    Raises:
      ParseError: if the firehose tracepoint cannot be read.
    """
    data_type_map = self._GetDataTypeMap('tracev3_firehose_tracepoint')

    firehose_tracepoint = self._ReadStructureFromByteStream(
        tracepoint_data, data_offset, data_type_map)

    return firehose_tracepoint


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

    while file_offset < file_size:
      chunk_header = self._ReadChunkHeader(file_object, file_offset)
      file_offset += 16

      if chunk_header.chunk_tag == self._CHUNK_TAG_HEADER:
        self._ReadHeader(file_object, file_offset)

      if chunk_header.chunk_tag == self._CHUNK_TAG_CATALOG:
        self._ReadCatalog(file_object, file_offset)

      elif chunk_header.chunk_tag == self._CHUNK_TAG_CHUNKSET:
        self._ReadChunkSet(file_object, file_offset, chunk_header)

      file_offset += chunk_header.chunk_data_size

      _, alignment = divmod(file_offset, 8)
      if alignment > 0:
        alignment = 8 - alignment

      file_offset += alignment


class UUIDTextFile(object):
  """Apple Unified Logging and Activity Tracing (uuidtext) file."""

  def __init__(self):
    """Initializes a UUID file.
    """
    super(UUIDTextFile, self).__init__()

class AULEventData(events.EventData):
  """Apple Unified Logging (AUL) event data."""

  DATA_TYPE = 'mac:aul:event'

  def __init__(self):
    """Initializes event data."""
    super(AULEventData, self).__init__(data_type=self.DATA_TYPE)

class AULFileEventData(events.EventData):
  """Apple Unified Logging (AUL) file event data."""
  DATA_TYPE = 'mac:aul:file'


  def __init__(self):
    """Initializes event data."""
    super(AULFileEventData, self).__init__(data_type=self.DATA_TYPE)

class AULParser(interface.FileEntryParser, dtfabric_helper.DtFabricHelper):
  """Parser for Apple Unified Logging (AUL) files."""

  NAME = 'aul_log'
  DATA_FORMAT = 'Apple Unified Log (AUL) file'

  def __init__(self):
    """Initializes an Apple Unified Logging parser."""
    super(AULParser, self).__init__()
    self.timesync_parser = TimesyncParser()
    self.tracev3_parser = TraceV3FileParser(self.timesync_parser)

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
    self.timesync_parser.parseAll(parser_mediator, file_entry, file_system)

    try:
      self.tracev3_parser.ParseFileObject(parser_mediator, file_object)
    except (IOError, errors.ParseError) as exception:
      display_name = parser_mediator.GetDisplayName()
      raise errors.WrongParser(
          '[{0:s}] unable to parse tracev3 file {1:s} with error: {2!s}'.format(
              self.NAME, display_name, exception))

    pass
    # event = time_events.DateTimeValuesEvent(date_time=datetime.now())
    # event_data = AULFileEventData()
    # parser_mediator.ProduceEventWithEventData(event, event_data)

manager.ParsersManager.RegisterParser(AULParser)
