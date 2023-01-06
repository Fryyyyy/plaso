# -*- coding: utf-8 -*-
"""The codepage CLI arguments helper."""

from plaso.cli import tools
from plaso.cli.helpers import interface
from plaso.cli.helpers import manager
from plaso.lib import errors


class CodepageArgumentsHelper(interface.ArgumentsHelper):
  """Codepage CLI arguments helper."""

  NAME = 'codepage'
  DESCRIPTION = 'Codepage command line arguments.'

  @classmethod
  def AddArguments(cls, argument_group):
    """Adds command line arguments to an argument group.

    This function takes an argument parser or an argument group object and adds
    to it all the command line arguments this helper supports.

    Args:
      argument_group (argparse._ArgumentGroup|argparse.ArgumentParser):
          argparse group.
    """
    argument_group.add_argument(
<<<<<<< HEAD:plaso/cli/helpers/text_prepend.py
        '-t', '--text', dest='text_prepend', action='store', type=str,
        default='', metavar='TEXT', help=(
            'Define a free form text string that is prepended to each path '
            'to make it easier to distinguish one record from another in a '
            'timeline (like c:\\, or host_w_c:\\). WARNING: this option is '
            'deprecated use the psort/psteal --custom-fields option instead.'))
=======
        '--codepage', metavar='CODEPAGE', dest='preferred_codepage',
        default=None, type=str, help=(
            'The preferred codepage, which is used for decoding single-byte '
            'or multi-byte character extracted strings.'))
>>>>>>> origin/main:plaso/cli/helpers/codepage.py

  @classmethod
  def ParseOptions(cls, options, configuration_object):
    """Parses and validates options.

    Args:
      options (argparse.Namespace): parser options.
      configuration_object (CLITool): object to be configured by the argument
          helper.

    Raises:
      BadConfigObject: when the configuration object is of the wrong type.
      BadConfigOption: when the codepage tag is not supported.
    """
    if not isinstance(configuration_object, tools.CLITool):
      raise errors.BadConfigObject(
          'Configuration object is not an instance of CLITool')

    codepage_tag = cls._ParseStringOption(options, 'preferred_codepage')

    setattr(configuration_object, '_preferred_codepage', codepage_tag)


manager.ArgumentHelperManager.RegisterHelper(CodepageArgumentsHelper)
