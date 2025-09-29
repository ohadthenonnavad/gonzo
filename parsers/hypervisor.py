import struct
import csv
import sys

# Instruction enum mapping
INSTR_NAMES = {
    1: "CPUID",
    2: "FYL2XP1",
    3: "RDMSR_TSC"
}

def parse_hv_blob(data):
    """Parse hypervisor profiling data blob into a list of records.
    
    Args:
        data: Binary data containing packed hv_prof_rec structures
        
    Returns:
        List of tuples with (instr_enum, instr_name, alignment, run_count, avg_cycles, max_cycles)
    """
    # struct hv_prof_rec {
    #     uint8_t instr_enum;   /* instruction id (see hv_instr_id) */
    #     uint8_t alignment;    /* reserved/alignment byte (always 0) */
    #     __le16 run_count;     /* number of measurements (<= 65535) */
    #     __le32 avg_cycles;    /* average cycles via RDTSCP */
    #     __le32 max_cycles;    /* maximum cycles observed */
    # } __packed;
    entry_format = '<BBHII'
    entry_size = struct.calcsize(entry_format)
    entries = []

    for i in range(0, len(data), entry_size):
        entry_data = data[i:i + entry_size]
        if len(entry_data) < entry_size:
            break
        
        instr_enum, alignment, run_count, avg_cycles, max_cycles = struct.unpack(entry_format, entry_data)
        instr_name = INSTR_NAMES.get(instr_enum, f"UNKNOWN({instr_enum})")
        entries.append((instr_enum, instr_name, alignment, run_count, avg_cycles, max_cycles))
    
    return entries

def parse(input_file, output_file):
    """Parses a dekermit.hv file and writes the output to a CSV file."""

    try:
        with open(input_file, 'rb') as f:
            blob_data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    hv_entries = parse_hv_blob(blob_data)

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['I:instr_enum', 'S:instr_name', 'I:alignment', 'I:run_count', 'I:avg_cycles', 'I:max_cycles'])
        writer.writerows(hv_entries)

    print(f"Successfully parsed {len(hv_entries)} hypervisor entries into '{output_file}'")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = input_file + '.csv'
    parse(input_file, output_file)

if __name__ == '__main__':
    main()
