import struct
import csv
import sys

def parse_ioapic_redir_entry(entry_low, entry_high):
    """Parse a single IOAPIC redirection entry (64-bit) into its components.
    
    Args:
        entry_low: Lower 32 bits of the redirection entry
        entry_high: Upper 32 bits of the redirection entry
        
    Returns:
        Dictionary containing all fields of the redirection entry
    """
    # Parse the lower 32 bits (IOREDTBLn)
    vector = entry_low & 0xFF
    delivery_mode = (entry_low >> 8) & 0x7
    dest_mode = (entry_low >> 11) & 0x1
    delivery_status = (entry_low >> 12) & 0x1
    polarity = (entry_low >> 13) & 0x1
    remote_irr = (entry_low >> 14) & 0x1
    trigger_mode = (entry_low >> 15) & 0x1
    mask = (entry_low >> 16) & 0x1
    
    # Parse the upper 32 bits (IOREDTBLn + 1)
    dest_field = entry_high & 0xFF
    
    # Convert to human-readable values
    delivery_mode_str = {
        0b000: "Fixed",
        0b001: "Lowest Priority",
        0b010: "SMI",
        0b100: "NMI",
        0b101: "INIT",
        0b111: "ExtINT"
    }.get(delivery_mode, f"Unknown ({delivery_mode:#04x})")
    
    return {
        'I:vector': vector,
        'S:delivery_mode': delivery_mode_str,
        'I:dest_mode': dest_mode,
        'S:dest_mode_str': "Logical" if dest_mode else "Physical",
        'I:delivery_status': delivery_status,
        'S:polarity': "Active Low" if polarity else "Active High",
        'I:remote_irr': remote_irr,
        'S:trigger_mode': "Level" if trigger_mode else "Edge",
        'I:mask': mask,
        'I:dest_field': dest_field,
        'S:raw_entry': f"0x{entry_high:08x}{entry_low:08x}"
    }

def parse_ioapic_blob(data):
    """Parse IOAPIC data blob into a list of redirection table entries.
    
    Args:
        data: Binary data containing IOAPIC ID, version, and redirection table
        
    Returns:
        List of dictionaries, each representing a redirection table entry
    """
    if len(data) < 8:
        print("Error: IOAPIC data too short")
        return []
        
    # Parse IOAPIC header (id and version)
    ioapic_id, ioapic_version = struct.unpack('<II', data[:8])
    table_data = data[8:]
    
    # Each redirection entry is 8 bytes (2x 32-bit registers)
    num_entries = len(table_data) // 8
    if num_entries == 0 or len(table_data) % 8 != 0:
        print(f"Warning: Invalid IOAPIC table size: {len(table_data)} bytes")
    
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
                **parse_ioapic_redir_entry(entry_low, entry_high)
            }
            entries.append(entry)
    
    return entries

def parse(input_file, output_file):
    """Parse an IOAPIC dump file and write the output to a CSV file.
    
    Args:
        input_file: Path to the input binary file
        output_file: Path to the output CSV file
    """
    try:
        with open(input_file, 'rb') as f:
            blob_data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    
    ioapic_entries = parse_ioapic_blob(blob_data)
    
    if not ioapic_entries:
        print("No valid IOAPIC entries found.")
        return
    
    # Define fieldnames in a logical order
    fieldnames = [
        'I:ioapic_id',
        'I:ioapic_version',
        'I:entry_num',
        'I:vector',
        'S:delivery_mode',
        'I:dest_mode',
        'S:dest_mode_str',
        'I:delivery_status',
        'S:polarity',
        'I:remote_irr',
        'S:trigger_mode',
        'I:mask',
        'I:dest_field',
        'S:raw_entry'
    ]
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ioapic_entries)
    
    print(f"Successfully parsed {len(ioapic_entries)} IOAPIC entries into '{output_file}'")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = input_file + '.csv'
    parse(input_file, output_file)

if __name__ == '__main__':
    main()
