import struct
import csv
import sys

def parse_acpi_blob(data):
    entries = []
    offset = 0
    # struct acpi_table_header {
    #   char signature[4];
    #   u32 length;
    #   u8 revision;
    #   u8 checksum;
    #   char oem_id[6];
    #   char oem_table_id[8];
    #   u32 oem_revision;
    #   char compiler_id[4];
    #   u32 compiler_revision;
    # };
    header_format = '<4sLBB6s8sI4sI'
    header_size = struct.calcsize(header_format)

    while offset < len(data):
        if offset + header_size > len(data):
            break

        header_data = data[offset:offset+header_size]
        signature_bytes, length, revision, checksum, oem_id_bytes, oem_table_id_bytes, \
            oem_revision, compiler_id_bytes, compiler_revision = struct.unpack(header_format, header_data)

        if length == 0 or offset + length > len(data):
            break
            
        signature = signature_bytes.split(b'\0', 1)[0].decode('ascii', errors='replace')
        oem_id = oem_id_bytes.split(b'\0', 1)[0].decode('ascii', errors='replace')
        oem_table_id = oem_table_id_bytes.split(b'\0', 1)[0].decode('ascii', errors='replace')
        compiler_id = compiler_id_bytes.split(b'\0', 1)[0].decode('ascii', errors='replace')

        table_data_start = offset + header_size
        table_data_end = offset + length
        table_data = data[table_data_start:table_data_end]
        
        hex_data = '"' + "".join([f"\\x{byte:02x}" for byte in table_data]) + '"'

        entries.append((
            signature, length, revision, checksum, oem_id, oem_table_id,
            oem_revision, compiler_id, compiler_revision, hex_data
        ))

        offset += length

    return entries

def parse(input_file, output_file):
    """Parses a dekermit.acpi file and writes the output to a CSV file."""

    try:
        with open(input_file, 'rb') as f:
            blob_data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    acpi_entries = parse_acpi_blob(blob_data)

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'S:signature', 'I:length', 'I:revision', 'I:checksum', 'S:oem_id',
            'S:oem_table_id', 'I:oem_revision', 'S:compiler_id', 'I:compiler_revision',
            'S:table_data'
        ])
        writer.writerows(acpi_entries)

    print(f"Successfully parsed {len(acpi_entries)} ACPI tables into '{output_file}'")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = input_file + '.csv'
    parse(input_file, output_file)

if __name__ == '__main__':
    main()
