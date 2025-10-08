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
    """Parse IOAPIC data blob into a list of redirection table entries with NMI and overrides.
    
    Args:
        data: Binary data containing IOAPIC ID, version, redirection table, overrides and NMI sources
        
    Returns:
        List of dictionaries, each representing a redirection table entry with NMI/override info
    """
    if len(data) < 24:  # Minimum size for ioapic_timer_config header
        print(f"Error: IOAPIC data too short ({len(data)} bytes)")
        return []
    
    # Parse IOAPIC header (24 bytes)
    # struct ioapic_timer_config {
    #   __le32 ioapic_id;       /* IOAPIC ID */
    #   __le32 ioapic_version;  /* IOAPIC version */
    #   __le32 gsi_base;        /* Global System Interrupt base */
    #   __le32 num_irq_overrides; /* Number of IRQ overrides */
    #   __le32 num_nmi_sources;   /* Number of NMI sources */
    #   __le32 redir_table[64];  /* Redirection table entries */
    #   /* Followed by:
    #    * - Array of ioapic_irq_override (num_irq_overrides entries)
    #    * - Array of ioapic_nmi_source (num_nmi_sources entries)
    #    */
    # };
    # 
    # struct ioapic_irq_override {
    #     __u8 bus;               /* Bus number */
    #     __u8 source_irq;        /* Source IRQ */
    #     __u32 global_irq;       /* Global system interrupt */
    #     __u16 inti_flags;       /* MPS INTI flags */
    # };
    # 
    # struct ioapic_nmi_source {
    #     __u32 global_irq;       /* Global system interrupt */
    #     __u16 inti_flags;       /* MPS INTI flags */
    # };
    
    # Parse the fixed header (24 bytes)
    ioapic_id, ioapic_version, gsi_base, num_overrides, num_nmi_sources = \
        struct.unpack('<IIIII', data[:20])
    
    # The redirection table is 64 entries of 4 bytes each (256 bytes)
    redir_table = list(struct.unpack('<64I', data[20:276]))
    
    # Calculate offsets for overrides and NMI sources
    offset = 276  # 20 (header) + 256 (redir_table)
    
    # Read interrupt overrides (8 bytes each)
    overrides = []
    override_size = 8  # 1 + 1 + 4 + 2 = 8 bytes
    for _ in range(num_overrides):
        if offset + override_size > len(data):
            print(f"Warning: Not enough data for all overrides at offset {offset}")
            break
        bus, source_irq, global_irq, inti_flags = \
            struct.unpack('<BBHI', data[offset:offset + override_size])
        overrides.append({
            'bus': bus,
            'source_irq': source_irq,
            'global_irq': global_irq,
            'inti_flags': inti_flags
        })
        offset += override_size
    
    # Read NMI sources (6 bytes each)
    nmi_sources = []
    nmi_size = 6  # 4 + 2 = 6 bytes
    for _ in range(num_nmi_sources):
        if offset + nmi_size > len(data):
            break
        global_irq, inti_flags = \
            struct.unpack('<IH', data[offset:offset + nmi_size])
        nmi_sources.append({
            'global_irq': global_irq,
            'inti_flags': inti_flags,
            'polarity': 'Active Low' if inti_flags & 0x2 else 'Active High',
            'trigger': 'Level' if inti_flags & 0x8 else 'Edge'
        })
        offset += nmi_size
    
    # Generate entries for redirection table with override and NMI info
    entries = []
    for i in range(64):  # Always generate all 64 entries for the redirection table
        if i < len(redir_table):
            entry = redir_table[i]
            entry_low = entry & 0xFFFFFFFF
            entry_high = (entry >> 32) & 0xFFFFFFFF if i * 8 + 4 < len(data) else 0
        else:
            # If we don't have data for this entry, use zeros
            entry = 0
            entry_low = 0
            entry_high = 0
        
        # Find matching overrides for this entry
        entry_overrides = [o for o in overrides if o['global_irq'] == gsi_base + i]
        
        # Create base entry with all fields
        entry_data = {
            'I:ioapic_id': ioapic_id,
            'I:ioapic_version': ioapic_version & 0xFF,  # Lower byte is version
            'I:gsi_base': gsi_base,
            'I:entry_num': i,
            'I:gsi': gsi_base + i,
            'I:num_overrides': len(entry_overrides),
            **parse_ioapic_redir_entry(entry_low, entry_high)
        }
        
        # Add override information
        if entry_overrides:
            entry_data['S:overrides'] = ';'.join([
                f"{o['bus']}:{o['source_irq']}->{o['global_irq']}" 
                for o in entry_overrides
            ])
        
        # Add NMI information if this entry has an NMI source
        for nmi in nmi_sources:
            if nmi['global_irq'] == gsi_base + i:
                entry_data.update({
                    'S:nmi_flags': f"0x{nmi['inti_flags']:04x}",
                    'S:nmi_polarity': nmi['polarity'],
                    'S:nmi_trigger': nmi['trigger']
                })
                break
                
        entries.append(entry_data)
    
    return entries

def parse(input_file, output_file):
    """Parse an IOAPIC dump file and write the output to a CSV file.
    
    Args:
        input_file: Path to the input binary file
        output_file: Path to the output CSV file
    """
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading '{input_file}': {e}")
        sys.exit(1)
    
    ioapic_entries = parse_ioapic_blob(data)
    
    if not ioapic_entries:
        print("No IOAPIC entries found.")
        return
    
    # Get all possible field names from the first entry
    fieldnames = [
        'I:ioapic_id',
        'I:ioapic_version',
        'I:gsi_base',
        'I:entry_num',
        'I:gsi',
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
        'I:num_overrides',
        'S:overrides',
        'S:nmi_flags',
        'S:nmi_polarity',
        'S:nmi_trigger',
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
