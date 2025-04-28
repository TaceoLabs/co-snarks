import re
import sys

def hex_to_dec(match):
    hex_value = match.group(0)  # Get the matched hex value
    decimal_value = str(int(hex_value, 16))  # Convert hex to decimal
    return decimal_value  # Return the decimal string

def replace_hex_in_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        
        # Regex pattern to match hex numbers (e.g., 0x1A, 0XFF)
        hex_pattern = r'0x[0-9A-Fa-f]+'
        
        # Replace hex values with decimal equivalents
        modified_content = re.sub(hex_pattern, hex_to_dec, content)
        
        with open(file_path, 'w') as file:
            file.write(modified_content)
        
        print(f"Successfully replaced hex values in {file_path}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
        replace_hex_in_file("outputthem")
