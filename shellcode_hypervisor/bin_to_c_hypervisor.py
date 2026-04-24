import sys
import os

def create_shellcode_header(input_file):
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    # Read binary data_text
    with open(input_file, "rb") as f:
        data_text = f.read()

    # Hardcoded output name
    output_name = "shellcode_hypervisor.h"
    array_name = "shellcode_hypervisor"
    
    with open(output_name, "w") as f:
        f.write(f"// Generated from {input_file}\n")
        f.write(f"#ifndef SHELLCODE_HV_H\n")
        f.write(f"#define SHELLCODE_HV_H\n\n")
        f.write(f"#include <unistd.h>\n\n")

        f.write(f"uint8_t {array_name}[] = {{\n    ")
        
        for i, byte in enumerate(data_text):
            f.write(f"0x{byte:02X}")
            
            if i < len(data_text) - 1:
                f.write(", ")
            
            # New line every 12 bytes
            if (i + 1) % 12 == 0:
                f.write("\n    ")
        
        f.write(f"\n}};\n\n")
        f.write(f"uint64_t {array_name}_len = {len(data_text)};\n\n")

        f.write(f"#endif // SHELLCODE_HV_H\n")

    print(f"Done! Created {output_name} ({len(data_text)} bytes)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python bin_to_c_hypervisor.py <shellcode.bin>")
    else:
        create_shellcode_header(sys.argv[1])