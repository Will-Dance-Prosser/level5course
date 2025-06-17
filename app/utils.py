import xml.etree.ElementTree as ET
import xml.dom.minidom

def xml_parser(xml_string):
    """
    Parses an XML string and returns a dictionary representation of the XML data,
    including nested elements.
    """
    def parse_element(element):
        children = list(element)
        if children:
            result = {}
            for child in children:
                child_result = parse_element(child)
                if child.tag in result:
                    # If already a list, append; else, make it a list
                    if isinstance(result[child.tag], list):
                        result[child.tag].append(child_result)
                    else:
                        result[child.tag] = [result[child.tag], child_result]
                else:
                    result[child.tag] = child_result
            return result
        else:
            return element.text

    try:
        root = ET.fromstring(xml_string)
        return {root.tag: parse_element(root)}
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML format: {e}") from e

def find_field_value(data, field_name, target_value):
    """
    Recursively search for fields named `field_name` in the nested dict and check for a match with `target_value`.
    Returns True if a match is found, otherwise False.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            try:
                # Try float comparison (rounded to 2 decimal places)
                if key == field_name and round(float(value), 2) == round(float(target_value), 2):
                    return True
            except Exception:
                if key == field_name and str(value).strip() == str(target_value).strip():
                    return True
            # Recursively search nested dicts or lists
            if find_field_value(value, field_name, target_value):
                return True
    elif isinstance(data, list):
        for item in data:
            if find_field_value(item, field_name, target_value):
                return True
    return False


#Format the XML string for better readability
def prettify_xml(xml_string):
    import xml.dom.minidom
    try:
        parsed = xml.dom.minidom.parseString(xml_string)
        pretty_xml = parsed.toprettyxml(indent="  ")
        # Remove empty lines
        pretty_xml = "\n".join([line for line in pretty_xml.split('\n') if line.strip()])
        return pretty_xml
    except Exception:
        return xml_string  # fallback if not valid XML


