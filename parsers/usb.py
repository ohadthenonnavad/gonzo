import struct
import csv
import sys

def read_string(data, offset):
    """Reads a length-prefixed string from the data blob."""
    if offset + 2 > len(data):
        return "", offset
    str_len = struct.unpack('<H', data[offset:offset+2])[0]
    offset += 2
    if offset + str_len > len(data):
        return "ERROR_TRUNCATED", offset
    s = data[offset:offset+str_len].decode('utf-8', errors='replace')
    offset += str_len
    return s, offset

def parse_usb_blob(data):
    entries = []
    offset = 0
    header_format = '<HBBHHBBBB'
    header_size = struct.calcsize(header_format)

    while offset < len(data):
        if offset + header_size > len(data):
            break

        header_data = data[offset:offset+header_size]
        entry_len, is_hub, depth, vendor_id, product_id, busnum, devnum, portnum, speed = struct.unpack(header_format, header_data)

        if entry_len == 0: # Should not happen, but as a safeguard
            break

        entry_body_offset = offset + header_size
        
        speed_s, entry_body_offset = read_string(data, entry_body_offset)
        mfg, entry_body_offset = read_string(data, entry_body_offset)
        prod, entry_body_offset = read_string(data, entry_body_offset)
        serial, entry_body_offset = read_string(data, entry_body_offset)

        if entry_body_offset + 2 > len(data):
            break
            
        ncfg, nintf = struct.unpack('<BB', data[entry_body_offset:entry_body_offset+2])

        entries.append((
            entry_len, is_hub, depth, vendor_id, product_id, busnum, devnum, portnum, speed,
            speed_s, mfg, prod, serial, ncfg, nintf
        ))

        offset += entry_len

    return entries

def parse(input_file, output_file):
    """Parses a dekermit.usb file and writes the output to a CSV file."""

    try:
        with open(input_file, 'rb') as f:
            blob_data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    usb_entries = parse_usb_blob(blob_data)

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'I:entry_len', 'I:is_hub', 'I:depth', 'I:vendor_id', 'I:product_id',
            'I:busnum', 'I:devnum', 'I:portnum', 'I:speed', 'S:speed_str',
            'S:manufacturer', 'S:product', 'S:serial', 'I:num_configs', 'I:num_interfaces'
        ])
        writer.writerows(usb_entries)

    print(f"Successfully parsed {len(usb_entries)} USB entries into '{output_file}'")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = input_file + '.csv'
    parse(input_file, output_file)

if __name__ == '__main__':
    main()
