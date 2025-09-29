import struct
import csv
import sys
import os

TIMER_TYPE_MAP = {
    1: 'HPET',
    2: 'APIC',
    3: 'ACPI',
    4: 'IOAPIC',
}

def parse_timers_blob(data, output_file=None):
    entries = []
    offset = 0
    header_format = '<B3xI'
    header_size = struct.calcsize(header_format)

    while offset < len(data):
        if offset + header_size > len(data):
            break

        header_data = data[offset:offset+header_size]
        timer_enum, data_size = struct.unpack(header_format, header_data)
        offset += header_size

        if offset + data_size > len(data):
            break

        timer_data = data[offset:offset+data_size]
        timer_type = TIMER_TYPE_MAP.get(timer_enum, 'UNKNOWN')
        
        row = {'S:timer_type': timer_type}

        if timer_type == 'HPET':
            # Main Counter Value is a 64-bit value at offset 0x0F0
            hpet_counter_offset = 0x0F0
            if len(timer_data) >= hpet_counter_offset + 8:
                counter_value = struct.unpack('<Q', timer_data[hpet_counter_offset:hpet_counter_offset+8])[0]
                row['I:counter_value'] = counter_value
            row['S:config_space'] = '"' + "".join([f"\\x{byte:02x}" for byte in timer_data]) + '"'
        elif timer_type == 'APIC':
            # Current Count Register is a 32-bit value at offset 0x390
            apic_counter_offset = 0x390
            if len(timer_data) >= apic_counter_offset + 4:
                counter_value = struct.unpack('<I', timer_data[apic_counter_offset:apic_counter_offset+4])[0]
                row['I:counter_value'] = counter_value
            row['S:config_space'] = '"' + "".join([f"\\x{byte:02x}" for byte in timer_data]) + '"'
        elif timer_type == 'ACPI':
            # struct acpi_timer_data { __le32 counter_value; __le32 reserved; }
            if len(timer_data) >= 4:
                row['I:counter_value'] = struct.unpack('<I', timer_data[:4])[0]
        elif timer_type == 'IOAPIC':
            # Save IOAPIC data to csv/ioapic.csv
            output_dir = os.path.join(os.path.dirname(output_file) if output_file else '.', 'csv')
            os.makedirs(output_dir, exist_ok=True)
            ioapic_output = os.path.join(output_dir, 'ioapic.csv')
            
            # Parse and save IOAPIC data
            ioapic_entries = parse_ioapic_data(timer_data, ioapic_output)
            row['S:ioapic_details'] = f"See {ioapic_output} for detailed IOAPIC redirection table"

        entries.append(row)
        offset += data_size

    return entries

def parse_ioapic_data(data, output_file):
    """Parse IOAPIC data and write to CSV file.
    
    Args:
        data: Binary IOAPIC data
        output_file: Path to output CSV file
        
    Returns:
        List of parsed IOAPIC entries
    """
    if len(data) < 8:
        return []
        
    # Parse IOAPIC header (id and version)
    ioapic_id, ioapic_version = struct.unpack('<II', data[:8])
    table_data = data[8:]
    
    # Each redirection entry is 8 bytes (2x 32-bit registers)
    num_entries = len(table_data) // 8
    if num_entries == 0 or len(table_data) % 8 != 0:
        print(f"Warning: Invalid IOAPIC table size: {len(table_data)} bytes")
        return []
    
    entries = []
    for i in range(min(num_entries, 24)):  # IOAPIC typically has 24 entries
        offset = i * 8
        entry_low, entry_high = struct.unpack('<II', table_data[offset:offset+8])
        
        # Only process valid entries (non-zero)
        if entry_low != 0 or entry_high != 0:
            entry = {
                'I:ioapic_id': ioapic_id,
                'I:ioapic_version': ioapic_version,
                'I:entry_num': i,
                'I:vector': entry_low & 0xFF,
                'S:delivery_mode': {
                    0b000: "Fixed",
                    0b001: "Lowest Priority",
                    0b010: "SMI",
                    0b100: "NMI",
                    0b101: "INIT",
                    0b111: "ExtINT"
                }.get((entry_low >> 8) & 0x7, f"Unknown ({(entry_low >> 8) & 0x7:#04x})"),
                'I:dest_mode': (entry_low >> 11) & 0x1,
                'S:dest_mode_str': "Logical" if (entry_low >> 11) & 0x1 else "Physical",
                'I:delivery_status': (entry_low >> 12) & 0x1,
                'S:polarity': "Active Low" if (entry_low >> 13) & 0x1 else "Active High",
                'I:remote_irr': (entry_low >> 14) & 0x1,
                'S:trigger_mode': "Level" if (entry_low >> 15) & 0x1 else "Edge",
                'I:mask': (entry_low >> 16) & 0x1,
                'I:dest_field': entry_high & 0xFF,
                'S:raw_entry': f"0x{entry_high:08x}{entry_low:08x}"
            }
            entries.append(entry)
    
    # Write to CSV if entries were found
    if entries:
        fieldnames = [
            'I:ioapic_id', 'I:ioapic_version', 'I:entry_num', 'I:vector',
            'S:delivery_mode', 'I:dest_mode', 'S:dest_mode_str', 'I:delivery_status',
            'S:polarity', 'I:remote_irr', 'S:trigger_mode', 'I:mask',
            'I:dest_field', 'S:raw_entry'
        ]
        
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(entries)
    
    return entries

def parse(input_file, output_file):
    """Parses a dekermit.timers file and writes the output to a CSV file."""

    try:
        with open(input_file, 'rb') as f:
            blob_data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    timer_entries = parse_timers_blob(blob_data, output_file)

    if not timer_entries:
        print("No timer entries found.")
        return

    fieldnames = [
        'S:timer_type', 'I:counter_value', 'S:config_space', 'S:ioapic_details'
    ]

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(timer_entries)

    print(f"Successfully parsed {len(timer_entries)} timer entries into '{output_file}'")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = input_file + '.csv'
    parse(input_file, output_file)

if __name__ == '__main__':
    main()
