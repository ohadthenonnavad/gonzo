import struct
import csv
import sys
import os
from typing import List, Dict, Any

# These values must match the enum timer_type in timers.c
TIMER_TYPE_MAP = {
    1: 'HPET',     # TIMER_HPET = 1
    2: 'APIC',     # TIMER_APIC = 2
    3: 'ACPI',     # TIMER_ACPI = 3
    4: 'IOAPIC',   # TIMER_IOAPIC = 4
}

# Timers dump header structure (matches C struct timers_dump_header)
TIMERS_HEADER_FORMAT = '<IIIIIIII'
TIMERS_HEADER_SIZE = struct.calcsize(TIMERS_HEADER_FORMAT)
TIMERS_MAGIC = 0x524D4954  # 'TIMR' in little-endian

# IOAPIC structures - must match the C definitions in timers.c
IOAPIC_MAGIC = 0x4F41504F  # 'OAPO' in little-endian
IOAPIC_VERSION = 1

# IOAPIC header format - matches struct ioapic_timer_config in C
# magic (4), version (4), header_size (4), num_ioapic (4), num_irq_override (4), num_nmi_source (4)
# ioapic_id (4), ioapic_version (4), gsi_base (4), redir_table (64*8)
IOAPIC_HEADER_FORMAT = '<IIIIIIIII'  # Fixed header part
IOAPIC_HEADER_SIZE = 9 * 4  # 9 32-bit integers = 36 bytes

# Redirection table is 64 64-bit entries (8 bytes each)
IOAPIC_REDIR_TABLE_FORMAT = '<64Q'  # 64-bit unsigned integers for redirection table
IOAPIC_REDIR_TABLE_SIZE = 64 * 8  # 64 entries * 8 bytes each

# IOAPIC entry formats
IOAPIC_IRQ_OVERRIDE_FORMAT = '<BBHI'  # bus, source_irq, global_irq, inti_flags
IOAPIC_IRQ_OVERRIDE_SIZE = struct.calcsize(IOAPIC_IRQ_OVERRIDE_FORMAT)

IOAPIC_NMI_SOURCE_FORMAT = '<IH'  # global_irq, inti_flags
IOAPIC_NMI_SOURCE_SIZE = struct.calcsize(IOAPIC_NMI_SOURCE_FORMAT)

def parse_timers_blob(data, output_file=None):
    entries = []
    offset = 0
    
    # Parse timers dump header if present
    if len(data) >= TIMERS_HEADER_SIZE:
        print(data[:(TIMERS_HEADER_SIZE-1)])
        header = struct.unpack(TIMERS_HEADER_FORMAT, data[:((TIMERS_HEADER_SIZE))])
        magic, version, hpet_count, apic_count, acpi_count, ioapic_count, _, _ = header
        
        print(f"Timers dump header: magic={magic:#x}, version={version}, HPET={hpet_count}, APIC={apic_count}, ACPI={acpi_count}, IOAPIC={ioapic_count}")
        if magic == TIMERS_MAGIC and version == 1:
            offset = TIMERS_HEADER_SIZE
    
    # Timer entry header format - matches struct timer_header in C
    # type (4 bytes), data_size (4 bytes)
    entry_header_format = '<II'
    header_size = struct.calcsize(entry_header_format)
    print(f"\n=== Parsing timers blob ===")
    print(f"Total data size: {len(data)} bytes")
    print(f"Timer header format: {entry_header_format}, size: {header_size} bytes")
    print(f"Initial offset: {offset}")
    
    if len(data) > 0:
        print("First 32 bytes of data:", data[:32].hex(' ', 4))

    while offset < len(data):
        if offset + header_size > len(data):
            break

        if offset + header_size > len(data):
            break
            
        header_data = data[offset:offset+header_size]
        print(f"\nParsing timer entry at offset {offset:#x}")
        print(f"Header data: {header_data.hex()}")
        
        try:
            timer_enum, data_size = struct.unpack(entry_header_format, header_data)
            print(f"Timer type: {timer_enum}, Data size: {data_size} bytes")
        except struct.error as e:
            print(f"Error unpacking timer header: {e}")
            print(f"Header data: {header_data.hex()}")
            break
            
        offset += header_size

        if offset + data_size > len(data):
            break

        timer_data = data[offset:offset+data_size]
        timer_type = TIMER_TYPE_MAP.get(timer_enum, 'UNKNOWN')
        
        row = {'S:timer_type': timer_type}

        print(f"timer_type: {timer_type}")
        if timer_type == 'HPET':
            # Main Counter Value is a 64-bit value at offset 0x0F0
            hpet_counter_offset = 0x0F0
            if len(timer_data) >= hpet_counter_offset + 8:
                counter_value = struct.unpack('<Q', timer_data[hpet_counter_offset:hpet_counter_offset+8])[0]
                row['I:counter_value'] = counter_value
            # Use binascii for faster hex conversion
            import binascii
            max_display = 256
            hex_str = binascii.hexlify(timer_data[:max_display]).decode('ascii')
            hex_parts = ['\\x' + hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
            if len(timer_data) > max_display:
                hex_parts.append('...')
            row['S:config_space'] = '"' + ''.join(hex_parts) + '"'
        elif timer_type == 'APIC':
            # Current Count Register is a 32-bit value at offset 0x390
            apic_counter_offset = 0x390
            if len(timer_data) >= apic_counter_offset + 4:
                counter_value = struct.unpack('<I', timer_data[apic_counter_offset:apic_counter_offset+4])[0]
                row['I:counter_value'] = counter_value
            # Use binascii for faster hex conversion
            import binascii
            max_display = 256
            hex_str = binascii.hexlify(timer_data[:max_display]).decode('ascii')
            hex_parts = ['\\x' + hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
            if len(timer_data) > max_display:
                hex_parts.append('...')
            row['S:config_space'] = '"' + ''.join(hex_parts) + '"'
        elif timer_type == 'ACPI':
            # struct acpi_timer_data { __le32 counter_value; __le32 reserved; }
            if len(timer_data) >= 4:
                row['I:counter_value'] = struct.unpack('<I', timer_data[:4])[0]
        elif timer_type == 'IOAPIC':
            # Use the same directory as the output file
            output_dir = os.path.dirname(output_file) if output_file else '.'
            os.makedirs(output_dir, exist_ok=True)
            ioapic_output = os.path.join(output_dir, 'ioapic.csv')
            
            # Parse and save IOAPIC data
            ioapic_entries = parse_ioapic_data(timer_data, ioapic_output)
            
            # Format raw table data as a list of hex values
            # The first 20 bytes are the header (ioapic_id, gsi_base, ioapic_version, num_overrides, num_nmi_sources)
            table_data = timer_data[36:]  # Skip the header
            num_entries = len(table_data) // 4  # Each entry is 4 bytes (1x 32-bit value)
            redir_table = []
            
            for i in range(min(num_entries, 64)):  # Max 64 entries in IOAPIC
                entry_offset = i * 4 
                if entry_offset + 4 > len(table_data):
                    break
                low, = struct.unpack('<I', table_data[entry_offset:entry_offset+4])
                redir_table.append(f"0x{low:08x}")
            
            # Store both the raw table and the path to the detailed CSV
            row['S:ioapic_details'] = f"Table: [{', '.join(redir_table)}], See {ioapic_output} for detailed IOAPIC redirection table"

        entries.append(row)
        offset += data_size

    return entries

def hexdump(data, start=0, length=32):
    """Generate a hex dump of binary data."""
    result = []
    for i in range(0, min(len(data), length), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        result.append(f'{start+i:08x}: {hex_str.ljust(47)}  {ascii_str}')
    return '\n'.join(result)

def parse_ioapic_redir_entry(entry_low: int, entry_high: int) -> Dict[str, Any]:
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

def parse_ioapic_data(data: bytes, output_file: str) -> List[Dict[str, Any]]:
    """Parse IOAPIC data and write to three separate CSV files.
    
    Args:
        data: Binary data containing IOAPIC information
        output_file: Base path for output files (will append _redir.csv, _overrides.csv, _nmi.csv)
        
    Returns:
        List of dictionaries, each representing a redirection table entry
    """
    print("=== IOAPIC Data Parser ===")
    print(f"Input data size: {len(data)} bytes")

    print("first four bytes of the input data are  {} {} {} {}".format(hex(data[0]), hex(data[1]), hex(data[2]), hex(data[3])))

    try:
        # Parse the fixed header part (first 9 32-bit integers)
        header_format = '<9I'
        header_size = struct.calcsize(header_format)
        
        if len(data) < header_size:
            print(f"Error: Data too small for IOAPIC header (needed {header_size} bytes, got {len(data)})")
            return []
            
        # Unpack the header
        magic, version, header_size, num_ioapic, num_irq_override, \
        num_nmi_source, ioapic_id, ioapic_version, gsi_base = \
            struct.unpack_from(header_format, data)
        
        # Validate magic number
        if magic != 0x4F41504F:  # 'OAPO' in little-endian
            print(f"Error: Invalid IOAPIC magic: 0x{magic:08x}, expected 0x4F41504F")
            return []
            
        if version != 1:
            print(f"Warning: Unsupported IOAPIC version: {version}")
            
        print(f"IOAPIC ID: {ioapic_id}, Version: {ioapic_version}, GSI Base: {gsi_base}")
        print(f"IRQ Overrides: {num_irq_override}, NMI Sources: {num_nmi_source}")
        
        # Parse redirection table (64 entries * 4 bytes each)
        redir_entries = []
        redir_offset = len(data) - header_size + 0x14 #account for the additional entries in there
        
        # Make sure we don't read past the end of the data
        max_entries = min(64, (len(data) - redir_offset) // 4)
        print("max_entries is {}, len of data is {}, redir_offset is {}".format(max_entries, len(data), redir_offset)) 
        
        for i in range(max_entries):
            if redir_offset + 4 > len(data):
                print(f"Warning: Truncated redirection table at entry {i}")
                break
                
            entry = struct.unpack_from('<I', data, redir_offset)[0]
            vector = entry & 0xFF
            delivery_mode = (entry >> 8) & 0x7
            dest_mode = (entry >> 11) & 0x1
            polarity = (entry >> 13) & 0x1
            trigger = (entry >> 15) & 0x1
            mask = (entry >> 16) & 0x1
            dest = (entry >> 56) & 0xFF  # Only relevant for physical destination mode
            
            redir_entries.append({
                'entry': i,
                'vector': vector,
                'delivery_mode': delivery_mode,
                'dest_mode': dest_mode,
                'polarity': polarity,
                'trigger': trigger,
                'mask': mask,
                'dest': dest,
                'gsi': gsi_base + i,
                'raw_value': f"0x{entry:08x}"
            })
            redir_offset += 4
            
        # Parse IRQ overrides
        overrides = []
        if num_irq_override > 0:
            print(f"Looking for {num_irq_override} IRQ overrides at offset 0x{redir_offset:x}")
            print(f"Data at offset: {data[redir_offset:redir_offset+16].hex(' ', 1)}")
            
            for i in range(num_irq_override):
                if redir_offset + 8 > len(data):
                    print(f"Warning: Truncated IRQ override entry at offset {redir_offset}")
                    break
                    
                # The override format is: bus (1B), source_irq (1B), global_irq (4B), inti_flags (2B)
                try:
                    # Format: bus (1B), source_irq (1B), global_irq (4B), inti_flags (2B)
                    override_data = struct.unpack_from('<BBIH', data, redir_offset)
                    bus, source_irq, global_irq, inti_flags = override_data
                    print(f"Override {i}: bus={bus}, source_irq={source_irq}, global_irq={global_irq}, inti_flags=0x{inti_flags:08x}")
                    
                    overrides.append({
                        'bus': bus,
                        'source_irq': source_irq,
                        'global_irq': global_irq,
                        'inti_flags': inti_flags,
                        'polarity': 'Active Low' if inti_flags & 0x2 else 'Active High',
                        'trigger': 'Level' if inti_flags & 0x8 else 'Edge'
                    })
                    
                    redir_offset += 8  # 8 bytes per override entry
                except struct.error as e:
                    print(f"Error parsing IRQ override at offset {redir_offset}: {e}")
                    print(f"Data at offset: {data[redir_offset:redir_offset+8].hex(' ', 1)}")
                    break
            
            # This was a duplicate append that was causing the issue
            # The append is already done in the try block above
            pass
            
        # Parse NMI sources
        nmi_sources = []
        if num_nmi_source > 0:
            print(f"\nLooking for {num_nmi_source} NMI sources at offset 0x{redir_offset:x}")
            print(f"Data at offset: {data[redir_offset:redir_offset+8].hex(' ', 1)}")
            
            for i in range(num_nmi_source):
                if redir_offset + 8 > len(data):
                    print(f"Warning: Truncated NMI source entry at offset {redir_offset}")
                    break
                    
                try:
                    # NMI source format: global_irq (4B), inti_flags (4B)
                    global_irq, inti_flags = struct.unpack_from('<II', data, redir_offset)
                    print(f"NMI Source {i}: global_irq={global_irq}, inti_flags=0x{inti_flags:08x}")
                    
                    nmi_sources.append({
                        'global_irq': global_irq,
                        'inti_flags': inti_flags,
                        'polarity': 'Active Low' if inti_flags & 0x2 else 'Active High',
                        'trigger': 'Level' if inti_flags & 0x8 else 'Edge'
                    })
                    
                    redir_offset += 6  # 6 bytes per NMI source entry
                except struct.error as e:
                    print(f"Error parsing NMI source at offset {redir_offset}: {e}")
                    print(f"Data at offset: {data[redir_offset:redir_offset+6].hex(' ', 1)}")
                    break
            
            # This was a duplicate append that was causing the issue
            # The append is already done in the try block above
            pass
        
        # Write output files if output_file is provided
        if output_file:
            # Get the output directory from the output_file path
            output_dir = os.path.dirname(output_file) or '.'
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Create base name for output files (without extension)
            base_name = os.path.splitext(os.path.basename(output_file))[0]
            base_path = os.path.join(output_dir, base_name)
            
            # 1. Write redirection table entries
            redir_file = f"{base_path}_redir.csv"
            with open(redir_file, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow([
                    'entry', 'vector', 'delivery_mode', 'dest_mode', 
                    'polarity', 'trigger', 'mask', 'dest', 'gsi', 'raw_value'
                ])
                
                # Write each entry
                for entry in redir_entries:
                    writer.writerow([
                        entry['entry'],
                        entry['vector'],
                        entry['delivery_mode'],
                        entry['dest_mode'],
                        entry['polarity'],
                        entry['trigger'],
                        entry['mask'],
                        entry['dest'],
                        entry['gsi'],
                        entry['raw_value']
                    ])
            
            print(f"Wrote {len(redir_entries)} redirection entries to '{redir_file}'")
            
            # 2. Write IRQ overrides
            if overrides:
                overrides_file = f"{base_path}_overrides.csv"
                with open(overrides_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['bus', 'source_irq', 'global_irq', 'inti_flags', 'polarity', 'trigger'])
                    for ov in overrides:
                        writer.writerow([
                            ov['bus'],
                            ov['source_irq'],
                            ov['global_irq'],
                            f"0x{ov['inti_flags']:04x}",
                            ov['polarity'],
                            ov['trigger']
                        ])
                print(f"Wrote {len(overrides)} IRQ overrides to '{overrides_file}'")
            
            # 3. Write NMI sources
            if nmi_sources:
                nmi_file = f"{base_path}_nmi.csv"
                with open(nmi_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['global_irq', 'inti_flags', 'polarity', 'trigger'])
                    for nmi in nmi_sources:
                        writer.writerow([
                            nmi['global_irq'],
                            f"0x{nmi['inti_flags']:04x}",
                            nmi['polarity'],
                            nmi['trigger']
                        ])
                print(f"Wrote {len(nmi_sources)} NMI sources to '{nmi_file}'")
        
        # Return a summary of the parsed data
        return [{
            'ioapic_id': ioapic_id,
            'ioapic_version': ioapic_version,
            'gsi_base': gsi_base,
            'num_redir_entries': len(redir_entries),
            'num_overrides': len(overrides),
            'num_nmi_sources': len(nmi_sources),
            'entries': redir_entries
        }]
        
    except struct.error as e:
        print(f"Error parsing IOAPIC data: {e}")
        import traceback
        traceback.print_exc()
        return []

def parse(input_file, output_file):
    """Parses a dekermit.timers file and writes the output to a CSV file."""
    print(f"\n=== Parsing timers file: {input_file} ===")
    
    try:
        with open(input_file, 'rb') as f:
            blob_data = f.read()
        print(f"Successfully read {len(blob_data)} bytes from {input_file}")
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file {input_file}: {e}")
        sys.exit(1)

    print("\n=== Starting timers blob parsing ===")
    try:
        timer_entries = parse_timers_blob(blob_data, output_file)
        print(f"Successfully parsed {len(timer_entries)} timer entries")
    except Exception as e:
        print(f"Error parsing timers blob: {e}", file=sys.stderr)
        raise

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
