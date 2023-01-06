# -*- coding: utf-8 -*-
"""An output module that writes event with geography data to a KML XML file.

The Keyhole Markup Language (KML) is an XML notation for expressing geographic
annotation and visualization within Internet-based, two-dimensional maps and
three-dimensional Earth browsers.
"""

import codecs

from xml.etree import ElementTree

from plaso.output import manager
from plaso.output import rawpy


class KMLOutputModule(rawpy.NativePythonOutputModule):
  """Output module for a Keyhole Markup Language (KML) XML file."""

  NAME = 'kml'
  DESCRIPTION = 'Saves events with geography data into a KML format.'

  def _WriteFieldValues(self, output_mediator, field_values):
    """Writes field values to the output.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
<<<<<<< HEAD
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.
      event_tag (EventTag): event tag.

    Returns:
      str: string representation of the event.
=======
      field_values (dict[str, str]): output field values per name.
>>>>>>> origin/main
    """
    latitude = field_values.get('latitude', None)
    longitude = field_values.get('longitude', None)
    if None in (latitude, longitude):
      return

    # TODO: make description_text KML values.
    description_text = self._GetString(field_values)

    placemark_xml_element = ElementTree.Element('Placemark')

    name_xml_element = ElementTree.SubElement(placemark_xml_element, 'name')
    name_xml_element.text = field_values['_event_identifier']

    description_xml_element = ElementTree.SubElement(
        placemark_xml_element, 'description')
    description_xml_element.text = '{0:s}\n'.format(description_text)

    point_xml_element = ElementTree.SubElement(placemark_xml_element, 'Point')

    coordinates_xml_element = ElementTree.SubElement(
        point_xml_element, 'coordinates')
    coordinates_xml_element.text = '{0!s},{1!s}'.format(longitude, latitude)

    # Note that ElementTree.tostring() will appropriately escape the input data.
    output_text = ElementTree.tostring(placemark_xml_element)

    output_text = codecs.decode(output_text, output_mediator.encoding)

<<<<<<< HEAD

class KMLOutputModule(interface.TextFileOutputModule):
  """Output module for a Keyhole Markup Language (KML) XML file."""

  NAME = 'kml'
  DESCRIPTION = 'Saves events with geography data into a KML format.'

  def __init__(self):
    """Initializes an output module."""
    event_formatting_helper = KMLEventFormattingHelper()
    super(KMLOutputModule, self).__init__(event_formatting_helper)

  def WriteEventBody(
      self, output_mediator, event, event_data, event_data_stream, event_tag):
    """Writes event values to the output.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
      event (EventObject): event.
      event_data (EventData): event data.
      event_data_stream (EventDataStream): event data stream.
      event_tag (EventTag): event tag.
    """
    latitude = getattr(event_data, 'latitude', None)
    longitude = getattr(event_data, 'longitude', None)
    if None not in (latitude, longitude):
      output_text = self._event_formatting_helper.GetFormattedEvent(
          output_mediator, event, event_data, event_data_stream, event_tag)
      self.WriteText(output_text)

  def WriteHeader(self, output_mediator):
    """Writes the header to the output.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
    """
    xml_string = (
        '<?xml version="1.0" encoding="{0:s}"?>'
        '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'.format(
            output_mediator.encoding))
    self.WriteText(xml_string)
=======
    self.WriteText(output_text)
>>>>>>> origin/main

  def WriteFooter(self):
    """Writes the footer to the output."""
    self.WriteText('</Document></kml>')

  def WriteHeader(self, output_mediator):
    """Writes the header to the output.

    Args:
      output_mediator (OutputMediator): mediates interactions between output
          modules and other components, such as storage and dfVFS.
    """
    xml_string = (
        '<?xml version="1.0" encoding="{0:s}"?>'
        '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'.format(
            output_mediator.encoding))
    self.WriteText(xml_string)


manager.OutputManager.RegisterOutput(KMLOutputModule)
