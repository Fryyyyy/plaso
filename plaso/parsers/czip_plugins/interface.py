# -*- coding: utf-8 -*-
"""Interface for compound ZIP file plugins."""

import abc

from plaso.parsers import plugins


class CompoundZIPPlugin(plugins.BasePlugin):
  """Compound ZIP parser plugin."""

  # REQUIRED_PATHS is a list of paths required by a plugin.
  # This is used to understand whether a plugin is suited for a given compound
  # ZIP file.
  # This must be overridden by actual plugins.
  REQUIRED_PATHS = frozenset()

  NAME = 'czip_plugin'
  DATA_FORMAT = 'Compound ZIP file'

  def CheckRequiredPaths(self, zip_file):
    """Check if the ZIP file has the minimal structure required by the plugin.

    Args:
      zip_file (zipfile.ZipFile): the ZIP file. It should not be closed in
          this method, but will be closed by the parser logic in czip.py.

    Returns:
      bool: True if the ZIP file has the minimum paths defined by the plugin,
          or False if it does not or no required paths are defined. The
          ZIP file can have more paths than specified by the plugin and still
          return True.
    """
    if not self.REQUIRED_PATHS:
      return False

    archive_members = zip_file.namelist()
    return set(self.REQUIRED_PATHS).issubset(archive_members)

  @abc.abstractmethod
  def InspectZipFile(self, parser_mediator, zip_file):
    """Inspects a compound ZIP file and produces events.

    This is the main method that a compound ZIP plugin needs to implement.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      zip_file (zipfile.ZipFile): the ZIP file. It should not be closed in
          this method, but will be closed by the parser logic in czip.py.
    """

  # pylint: disable=arguments-differ
  def Process(self, parser_mediator, zip_file=None, **kwargs):
    """Determines if this is the correct plugin; if so proceed with processing.

    This method checks if the ZIP file being contains the paths specified in
    REQUIRED_PATHS. If all paths are present, the plugin logic processing
    continues in InspectZipFile.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      zip_file (Optional[zipfile.ZipFile]): the ZIP file. It should not be
          closed in this method, but will be closed by the parser logic in
          czip.py.

    Raises:
      ValueError: If the ZIP file argument is not valid.
    """
    if zip_file is None:
      raise ValueError('Invalid ZIP file.')

    # This will raise if unhandled keyword arguments are passed.
    super(CompoundZIPPlugin, self).Process(parser_mediator)

    self.InspectZipFile(parser_mediator, zip_file)
