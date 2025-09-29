import struct
import csv
import sys

def parse_pci_blob(data):
    entries = []
    offset = 0
    # struct gonzo_pci_hdr {
    # 	uint8_t bus;
    # 	uint8_t dev;
    # 	uint8_t fun;
    # 	uint8_t reserved;
    # 	__le32 cfg_size;
    # } __packed;
    header_format = '<BBBBI'
    header_size = struct.calcsize(header_format)

    while offset < len(data):
        if offset + header_size > len(data):
            break

        header_data = data[offset:offset+header_size]
        bus, dev, fun, reserved, cfg_size = struct.unpack(header_format, header_data)

        if cfg_size not in [256, 4096]:
            print(f"Warning: Skipping PCI entry for device {bus:02x}:{dev:02x}.{fun} with invalid cfg_size {cfg_size}")
            # Attempt to find the next header by assuming a size, but this is risky.
            # For now, we'll just stop parsing if we hit an invalid size.
            break

        offset += header_size

        if offset + cfg_size > len(data):
            break

        config_space_data = data[offset:offset+cfg_size]
        hex_data = '"' + "".join([f"\\x{byte:02x}" for byte in config_space_data]) + '"'

        entries.append((
            bus, dev, fun, reserved, cfg_size, hex_data
        ))

        offset += cfg_size

    return entries

def parse(input_file, output_file):
    """Parses a dekermit.pci file and writes the output to a CSV file."""

    try:
        with open(input_file, 'rb') as f:
            blob_data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    pci_entries = parse_pci_blob(blob_data)

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'I:bus', 'I:dev', 'I:fun', 'I:reserved', 'I:cfg_size', 'S:config_space'
        ])
        writer.writerows(pci_entries)

    print(f"Successfully parsed {len(pci_entries)} PCI entries into '{output_file}'")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = input_file + '.csv'
    parse(input_file, output_file)

if __name__ == '__main__':
    main()
