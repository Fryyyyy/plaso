# -*- coding: utf-8 -*-
"""Output module that saves data into a JSON line format.

JSON line format is a single JSON entry or event per line instead
of grouping all the output into a single JSON entity.
"""

import json

from plaso.output import manager
from plaso.output import shared_json


class JSONLineOutputModule(shared_json.SharedJSONOutputModule):
  """Output module for the JSON line format."""

  NAME = 'json_line'
  DESCRIPTION = 'Saves the events into a JSON line format.'

<<<<<<< HEAD
  def __init__(self):
    """Initializes an output module."""
    event_formatting_helper = shared_json.JSONEventFormattingHelper()
    super(JSONLineOutputModule, self).__init__(event_formatting_helper)

  def WriteEventBody(
      self, output_mediator, event, event_data, event_data_stream, event_tag):
    """Writes event values to the output.
=======
  def _WriteFieldValues(self, output_mediator, field_values):
    """Writes field values to the output.
>>>>>>> origin/main

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
<<<<<<< HEAD
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.
      event_tag (EventTag): event tag.
    """
    output_text = self._event_formatting_helper.GetFormattedEvent(
        output_mediator, event, event_data, event_data_stream, event_tag)

    self.WriteLine(output_text)
=======
      field_values (dict[str, str]): output field values per name.
    """
    json_string = json.dumps(field_values, sort_keys=True)
    self.WriteLine(json_string)
>>>>>>> origin/main


manager.OutputManager.RegisterOutput(JSONLineOutputModule)
