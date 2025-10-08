import os
import sys
import importlib
import struct

# Dynamically import parser modules
import msr
import hypervisor
import usb
import acpi
import pci
import timers
import ioapic_parser

PARSER_MAP = {
    '.msr': msr,
    '.hv': hypervisor,
    '.usb': usb,
    '.acpi': acpi,
    '.pci': pci,
    '.timers': timers,
    '.ioapic': ioapic_parser,
}

def extract_ioapic_data(data):
    """Extract IOAPIC data from a timers blob.
    
    Args:
        data: Binary data containing timer information
        
    Returns:
        Binary data containing just the IOAPIC information, or None if not found
    """
    offset = 0
    header_format = '<II'  # uint32_t type, uint32_t data_size
    header_size = struct.calcsize(header_format)
    
    while offset + header_size <= len(data):
        # Parse the header
        timer_type, data_size = struct.unpack_from(header_format, data, offset)
        offset += header_size
        
        # Check if this is an IOAPIC entry (type 4)
        if timer_type == 4:  # TIMER_IOAPIC
            # Return the IOAPIC data (header + payload)
            return data[offset:offset + data_size]
            
        # Move to next entry
        offset += data_size
        
    return None

def main():
    input_dir = 'input'
    output_dir = 'csv'

    if not os.path.isdir(input_dir):
        print(f"Error: Input directory '{input_dir}' not found.")
        sys.exit(1)

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory '{output_dir}'")

    # First, process all files except .ioapic
    for filename in os.listdir(input_dir):
        input_file = os.path.join(input_dir, filename)
        if not os.path.isfile(input_file):
            continue

        file_ext = '.' + filename.split('.')[-1]
        
        # Skip .ioapic files for now
        if file_ext == '.ioapic':
            continue
            
        parser_module = PARSER_MAP.get(file_ext)

        if parser_module:
            output_filename = file_ext[1:] + '.csv'
            output_file = os.path.join(output_dir, output_filename)
            
            print(f"Parsing '{input_file}' with '{parser_module.__name__}.py'...")
            try:
                # For timers file, also extract and save IOAPIC data
                if file_ext == '.timers':
                    with open(input_file, 'rb') as f:
                        timers_data = f.read()
                    
                    # Parse the timers file normally
                    parser_module.parse(input_file, output_file)
                    
                    # Extract and save IOAPIC data from timers file
                    ioapic_output = os.path.join(output_dir, 'ioapic.csv')
                    ioapic_data = extract_ioapic_data(timers_data)
                    if ioapic_data:
                        # Parse the IOAPIC data using the timers module
                        from timers import parse_ioapic_data
                        try:
                            ioapic_entries = parse_ioapic_data(ioapic_data, ioapic_output)
                            if ioapic_entries:
                                print(f"Successfully parsed {len(ioapic_entries)} IOAPIC entries into '{ioapic_output}'")
                            else:
                                print("No IOAPIC entries found in the data")
                        except Exception as e:
                            print(f"Error parsing IOAPIC data: {e}")
                            raise
                else:
                    # Normal parsing for other file types
                    parser_module.parse(input_file, output_file)
                    
            except Exception as e:
                print(f"Error parsing '{input_file}': {e}")
        else:
            print(f"Warning: No parser found for file '{filename}' with extension '{file_ext}'")

if __name__ == '__main__':
    # Add the current directory to the path to allow importing sibling modules
    sys.path.insert(0, os.path.dirname(__file__))
    main()
