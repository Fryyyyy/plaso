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
    self.records = []
    self.file_entry = file_entry
    self.file_system = file_system
    path_segments = file_system.SplitPath(file_entry.path_spec.location)
    self.uuidtext_location = file_system.JoinPath(path_segments[:-3] + ['uuidtext'])
    if not os.path.exists(self.uuidtext_location):
      raise errors.ParseError(
        "Invalid UUIDText location: {0:s}".format(self.uuidtext_location))

  def FindFile(self, parser_mediator, uuid):
    kwargs = {}
    kwargs['location'] = self.file_system.JoinPath([self.uuidtext_location] + [uuid[0:2]] + [uuid[2:]])
    uuid_file_path_spec = path_spec_factory.Factory.NewPathSpec(
        self.file_entry.path_spec.TYPE_INDICATOR, **kwargs)
    try:
      uuid_file_entry = path_spec_resolver.Resolver.OpenFileEntry(
          uuid_file_path_spec)
    except RuntimeError as exception:
      message = (
          'Unable to open UUID file: {0:s} with error: '
          '{1!s}'.format(kwargs['location'], exception))
      logger.warning(message)
      parser_mediator.ProduceExtractionWarning(message)

    if not uuid_file_entry:
      message = 'Missing UUID file: {0:s}'.format(uuid)
      logger.warning(message)
      parser_mediator.ProduceExtractionWarning(message)
    else:
      uuid_file_object = uuid_file_entry.GetFileObject()
      try:
        self.ParseFileObject(parser_mediator, uuid_file_object, uuid)
      except (IOError, errors.ParseError) as exception:
        message = (
            'Unable to parse UUID file: {0:s} with error: '
            '{1!s}').format(uuid, exception)
        logger.warning(message)
        parser_mediator.ProduceExtractionWarning(message)

  def ParseFileObject(self, parser_mediator, file_object, uuid):
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
    record = UUIDText(
      library_path=uuid_footer.library_path,
      library_name=os.path.basename(uuid_footer.library_path),
      uuid=uuid,
      data=data,
      entries=entries)
    self.records.append(record)


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

  _CATALOG_LZ4_COMPRESSION = 0x100

  _CHUNK_TAG_HEADER = 0x1000
  _CHUNK_TAG_FIREHOSE = 0x6001
  _CHUNK_TAG_OVERSIZE = 0x6002
  _CHUNK_TAG_STATEDUMP = 0x6003
  _CHUNK_TAG_CATALOG = 0x600B
  _CHUNK_TAG_CHUNKSET = 0x600D

  _FIREHOSE_LOG_ACTIVITY_TYPE_ACTIVITY = 0x2
  _FIREHOSE_LOG_ACTIVITY_TYPE_TRACE = 0x3
  _FIREHOSE_LOG_ACTIVITY_TYPE_NONACTIVITY = 0x4
  _FIREHOSE_LOG_ACTIVITY_TYPE_SIGNPOST = 0x6
  _FIREHOSE_LOG_ACTIVITY_TYPE_LOSS = 0x7

  def __init__(self, timesync_parser, uuid_parser):
    """Initializes a tracev3 file parser.
    """
    super(TraceV3FileParser, self).__init__()
    self.timesync_parser = timesync_parser
    self.uuid_parser = uuid_parser
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

    for uuid in catalog.uuids:
      filename = uuid.hex.upper()
      logger.warning("Encountered UUID {0:s} in Catalog.".format(filename))
      self.uuid_parser.FindFile(parser_mediator, filename)
      # TODO(fryy): Check DSC too

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

    # TODO(fryy): Do we need all previous catalogs ?
    self.catalogs.append(catalog)
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

  def _ReadChunkSet(self, file_object, file_offset, chunk_header, catalog,
                        chunkset_index):
    """Reads a chunk set.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the chunk set data relative to the start
          of the file.
      chunk_header (tracev3_chunk_header): the chunk header of the chunk set.
      catalog (tracev3_catalog): Current catalog this chunk belongs to.
      chunkset_index (int): What number chunk this is in the catalog.

    Raises:
      ParseError: if the chunk header cannot be read.
    """
    if catalog.subchunks[
            chunkset_index].compression_algorithm != self._CATALOG_LZ4_COMPRESSION:
      raise errors.ParseError(
        "Unknown compression algorithm : {0:s}".format(catalog.compression_algorithm))

    chunk_data = file_object.read(chunk_header.chunk_data_size)

    data_type_map = self._GetDataTypeMap('tracev3_lz4_block_header')

    lz4_block_header, _ = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map)
    logger.warning("Read LZ4 block")

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
      logger.warning("Reading Decompressed Chunk")
      chunkset_chunk_header = self._ReadStructureFromByteStream(
          uncompressed_data, data_offset, data_type_map)
      data_offset += 16

      data_end_offset = data_offset + chunkset_chunk_header.chunk_data_size
      chunkset_chunk_data = uncompressed_data[data_offset:data_end_offset]

      if chunkset_chunk_header.chunk_tag == self._CHUNK_TAG_FIREHOSE:
        logger.warning("Processing a Firehose Chunk (0x6001)")
        self._ReadFirehoseChunkData(
            chunkset_chunk_data, chunkset_chunk_header.chunk_data_size,
            data_offset, catalog)
      else:
        raise errors.ParseError(
          "Unsupported Chunk Type: {0:s}".format(
            chunkset_chunk_header.chunk_tag))

      data_offset = data_end_offset

      _, alignment = divmod(data_offset, 8)
      if alignment > 0:
        alignment = 8 - alignment

      data_offset += alignment

  def _ParseNonActivity(self, tracepoint, proc_info):
    logger.warning("Parsing non-activity")
    offset = 0
    flags = tracepoint.flags
    data = tracepoint.data

    ret = {}

    if len(self.uuid_parser.records) >= proc_info.main_uuid_index:
      uuid_file = self.uuid_parser.records[proc_info.main_uuid_index]
    else:
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

    if flags & _CURRENT_AID:
      logger.warning("Non-activity has current_aid")
      
      unknown_activity_id = self._ReadStructureFromByteStream(
        data, offset, uint32_data_type_map)
      offset += 4
      sentinel = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
      offset += 4
      if sentinel != _NON_ACTIVITY_SENINTEL:
        raise errors.ParseError("Incorrect sentinel value for Non-Activity")
    
    if flags & _PRIVATE_STRING_RANGE:
      logger.warning("Non-activity has private_string_range")
      
      private_strings_offset = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      private_strings_size = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
      
    # Hopefully 151543
    unknown_message_string_reference  = self._ReadStructureFromByteStream(
        data[offset:], offset, uint32_data_type_map)
    offset += 4
  
    if flags & _HAS_ALTERNATE_UUID:
      raise errors.ParseError("Non-activity with Alternate UUID not supported")

    # Flags ??

    # Yes has subsys (1)
    if flags & _HAS_SUBSYSTEM:
      logger.warning("Non-activity has subsystem")
      subsystem_value = self._ReadStructureFromByteStream(
        data[offset:], offset, uint16_data_type_map)
      offset += 2
    
    # Yes has TTL (30)
    if flags & _HAS_TTL:
      logger.warning("Non-activity has TTL")
      ttl_value = self._ReadStructureFromByteStream(
        data[offset:], offset, uint8_data_type_map)
      offset += 1

    if flags & _HAS_DATA_REF:
      raise errors.ParseError("Non-activity with Alternate UUID not supported")

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
        ret['imageUUID'] = uuid_file.UUID
        ret['senderImagePath'] = uuid_file.library_path

        fmt = uuid_file.ReadFormatString(tracepoint.format_string_location)
        # log_data_len = tracepoint.data_size
        if flags & _HAS_SIGNPOST_NAME:
          raise errors.ParseError("Non-activity signpost not supported")

        # Read log data
        if flags & _PRIVATE_STRING_RANGE:
          raise errors.ParseError("Private strings not supported")

        if tracepoint.log_activity_type == self._FIREHOSE_LOG_ACTIVITY_TYPE_LOSS:
          logger.warning("Loss Type")
        else:
          # tracepoint.data_size - offset
          # log_data = self.ReadLogDataBuffer(buffer[pos + pos3 : pos + pos3 + log_data_len2], log_data_len2, strings_slice, has_context_data)
          # flags & _HAS_CONTEXT_DATA
          # buffer[16 + 71 : 16 + 71 + 49], 49, '', False
          # buffer[87 : 136], 49, '', False
    
    logger.warning("!! Log Line !! : {0:s}".format(ret))

  def _ParseTracepointData(self, tracepoint, proc_info):
    """Parses a log line"""

    # Log Types
    _LOG_TYPES = {
      0x01: "Info",
      0x02: "Debug",
      0x10: "Error",
      0x11: "Fault"
    }

    logger.warning("Parsing log line")
    log_type = _LOG_TYPES.get(tracepoint.log_type, "Default")
    if tracepoint.log_activity_type == self._FIREHOSE_LOG_ACTIVITY_TYPE_NONACTIVITY:
      if log_type == 0x80:
        raise errors.ParseError("Non Activity Signpost ??")
      self._ParseNonActivity(tracepoint, proc_info)
    return

  def _ReadFirehoseChunkData(self, chunk_data, chunk_data_size, data_offset, catalog):
    """Reads firehose chunk data.

    Args:
      chunk_data (bytes): firehose chunk data.
      chunk_data_size (int): size of the firehose chunk data.
      data_offset (int): offset of the firehose chunk relative to the start
          of the chunk set.
      catalog (tracev3_catalog): the current catalog.

    Raises:
      ParseError: if the firehose chunk cannot be read.
    """
    logger.warning("Reading Firehose")
    data_type_map = self._GetDataTypeMap('tracev3_firehose_header')

    firehose_header = self._ReadStructureFromByteStream(
        chunk_data, data_offset, data_type_map)

    proc_id = firehose_header.second_number_proc_id | (firehose_header.first_number_proc_id << 32)
    proc_info = [c for c in catalog.process_entries if c.second_number_proc_id | (c.first_number_proc_id << 32) == proc_id]
    if len(proc_info) == 0:
      logger.warning("Could not find Process Info block for ID: %d", proc_id)
    else:
      proc_info = proc_info[0]

    if firehose_header.private_data_virtual_offset < 4096:
      raise errors.ParseError(
        "Something to do with private strings - tracev3_file.py:794")

    logger.warning("Firehose Header Timestamp: %s", self._TimestampFromContTime(
          firehose_header.base_continuous_time))

    chunk_data_offset = 32
    while chunk_data_offset < chunk_data_size:
      firehose_tracepoint = self._ReadFirehoseTracepointData(
          chunk_data[chunk_data_offset:], data_offset + chunk_data_offset)

      #ct = firehose_header.base_continuous_time + (firehose_tracepoint.continuous_time_lower | (firehose_tracepoint.continuous_time_upper << 32))
      #time = self._FindClosestTimesyncItemInList(self.boot_uuid_ts_list, ct).wall_time + ct - ts.kernel_continuous_timestamp
      self._ParseTracepointData(firehose_tracepoint, proc_info)

      chunk_data_offset += 24 + firehose_tracepoint.data_size
      _, alignment = divmod(chunk_data_offset, 8)
      if alignment > 0:
        alignment = 8 - alignment

      chunk_data_offset += alignment

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

    chunkset_index = 0
    catalog = None

    while file_offset < file_size:
      chunk_header = self._ReadChunkHeader(file_object, file_offset)
      file_offset += 16

      if chunk_header.chunk_tag == self._CHUNK_TAG_HEADER:
        logger.warning("Processing a HEADER (0x1000)")
        self._ReadHeader(file_object, file_offset)

      if chunk_header.chunk_tag == self._CHUNK_TAG_CATALOG:
        logger.warning("Processing a CATALOG (0x600B)")
        catalog = self._ReadCatalog(parser_mediator, file_object, file_offset)
        chunkset_index = 0

      if chunk_header.chunk_tag == self._CHUNK_TAG_CHUNKSET:
        logger.warning("Processing a CHUNKSET (0x600D)")
        self._ReadChunkSet(
          file_object, file_offset, chunk_header, catalog, chunkset_index)
        chunkset_index += 1

      file_offset += chunk_header.chunk_data_size

      _, alignment = divmod(file_offset, 8)
      if alignment > 0:
        alignment = 8 - alignment

      file_offset += alignment


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

    self.tracev3_parser = TraceV3FileParser(self.timesync_parser, self.uuid_parser)

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
