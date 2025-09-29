import struct
import csv
import sys

def parse_msr_blob(data):
    # struct msr_entry {
    #     u32 num;
    #     char name[32];
    #     u64 val;
    #     u8 success;
    # } __packed;
    entry_format = '<I32sQB'
    entry_size = struct.calcsize(entry_format)
    entries = []

    for i in range(0, len(data), entry_size):
        entry_data = data[i:i + entry_size]
        if len(entry_data) < entry_size:
            break
        
        num, name_bytes, val, success = struct.unpack(entry_format, entry_data)
        name = name_bytes.split(b'\0', 1)[0].decode('utf-8')
        entries.append((num, name, val, success))
    
    return entries

def parse(input_file, output_file):
    """Parses a dekermit.msr file and writes the output to a CSV file."""

    try:
        with open(input_file, 'rb') as f:
            blob_data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    msr_entries = parse_msr_blob(blob_data)

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['I:num', 'S:name', 'I:val', 'I:success'])
        writer.writerows(msr_entries)

    print(f"Successfully parsed {len(msr_entries)} MSR entries into '{output_file}'")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = input_file + '.csv'
    parse(input_file, output_file)

if __name__ == '__main__':
    main()
