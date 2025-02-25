import os
import re
import json

# Define a list of weak cryptographic primitives to search for, with refined regex patterns for specific function calls
VULNERABLE_FUNCTION_PATTERNS = {
    # C, Python, and other general cryptographic function patterns
    r"\bAES_set_encrypt_key\b": "AES: Outdated; 56-bit key size is insufficient for modern security.",
    r"\bAES_cbc_encrypt\b": "AES CBC Encrypt: Vulnerable function.",
    r"\bDES\b": "DES: Outdated; 56-bit key size is insufficient for modern security.",
    r"\bAES\b": "AES: Outdated; 56-bit key size is insufficient for modern security.",
    r"\b3DES\b.*\b1\s*key\b": "3DES with 1 key: Operates like DES; insecure.",
    r"\b3DES\b.*\b2\s*keys\b": "3DES with 2 keys: Provides ~80 bits of security; inadequate for modern standards.",
    r"\b3DES\b.*\b3\s*keys\b": "3DES with 3 keys: Deprecated; provides ~112 bits of security, insufficient against quantum attacks.",
    r"\bAES-128\b": "AES-128: Secure against classical attacks but vulnerable to quantum attacks.",
    r"\bAES-192\b": "AES-192: Offers slightly better security than AES-128 but still vulnerable to quantum attacks.",
    r"\bRSA\b.*\b512\b|\bRSA\b.*\b1024\b": "RSA with short keys (512, 1024 bits): Easily breakable with classical attacks; insecure against quantum attacks.",
    r"\bRSA\b.*\b2048\b|\bRSA\b.*\b3072\b": "RSA with 2048, 3072+ bits: Secure against classical attacks but vulnerable to quantum computing.",
    r"RSA\b.*\bwithout proper padding\b": "RSA without proper padding: Vulnerable to padding oracle attacks.",
    r"crypto\.createHash\(['\"]md5['\"]\)": "MD5: Broken due to collision vulnerabilities; insecure under both classical and quantum attacks.",
    r"crypto\.createHash\(['\"]sha1['\"]\)": "SHA-1: Obsolete; vulnerable to collision attacks under classical and quantum contexts.",
    r"crypto\.createHash\(['\"]sha256['\"]\)": "SHA-256: Secure under classical conditions, but Grover's algorithm reduces effective security to ~128 bits.",
    r"\bECB\b.*\bmode\b": "Weak Modes: ECB mode is insecure and leaks patterns in plaintext due to lack of diffusion.",
    # C specific patterns
    r"DES_new\([^\)]*\)\s*,\s*DES_MODE_ECB": "C function: DES with ECB mode is insecure.",
    r"3DES_new\([^\)]*\)\s*,\s*3DES_MODE_ECB": "C function: 3DES with ECB mode is insecure.",
    r"AES_new\([^\)]*\)\s*,\s*AES_MODE_ECB": "C function: AES with ECB mode is insecure.",
    r"MD5_Init\([^\)]*\)": "C function: MD5 initialization detected, which is vulnerable to collisions.",
    r"md5_hash\([^\)]*\)": "C function: MD5 initialization detected, which is vulnerable to collisions.",
    r"SHA1_Init\([^\)]*\)": "C function: SHA-1 initialization detected, which is vulnerable to collisions.",
}

def is_in_comment(line, file_extension):
    """Check if a given line is part of a comment."""
    line = line.strip()
    
    # For Python and JavaScript: Check if the line starts with a comment symbol (# or //)
    if file_extension in ['.py', '.js']:
        return line.startswith("#") or line.startswith("//")
    
    # For C and C++: Check for single-line comments (//)
    if file_extension in ['.c', '.cpp', '.h']:
        return line.startswith("//")
    
    # Default: Assume not in comment if file type is unrecognized
    return False

def scan_file_for_vulnerabilities(filename):
    """Scan a file for vulnerable cryptographic function calls and return a list of findings."""
    findings = []
    
    # Skip the specific file 'risk_assessment_tool.py' (case-insensitive)
    base_filename = os.path.basename(filename).lower().strip()
    if base_filename == "risk_assesement_tool.py":
        print(f"Skipping file: {filename}")  # Debug print statement
        return findings  # Return an empty list if this file is encountered
    
    matched_lines = set()  # Set to track already matched lines (line_no, pattern)
    file_extension = os.path.splitext(filename)[1]  # Get file extension
    
    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line_no, line in enumerate(file, start=1):
                # Check for vulnerabilities and ensure the match is not in a comment
                for pattern, description in VULNERABLE_FUNCTION_PATTERNS.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        # Only process if the match is not already reported
                        if not is_in_comment(line, file_extension) and (line_no, pattern) not in matched_lines:
                            # Dynamically assign risk level based on description
                            risk = "High" if "insecure" in description or "broken" in description else "Medium"
                            
                            findings.append({
                                "line_no": line_no,
                                "line": line.strip(),
                                "risk": risk,
                                "description": description,
                            })
                            matched_lines.add((line_no, pattern))  # Track that we've matched this line and pattern
    except Exception as e:
        print(f"Error reading {filename}: {e}")

    return findings

def generate_full_report(scan_results):
    """Generate a single risk assessment report for all scanned files."""
    with open("scan_results.txt", "w") as report:
        report.write("Risk Assessment Report for All Files\n")
        report.write("=" * 50 + "\n\n")

        if scan_results:
            for file, findings in scan_results.items():
                report.write(f"\n\nFile: {file}\n")
                report.write("-" * 50 + "\n")
                for finding in findings:
                    report.write(f"Line {finding['line_no']}: {finding['line']}\n")
                    report.write(f"Risk Level: {finding['risk']}\n")
                    report.write(f"Description: {finding['description']}\n")
                    report.write("-" * 50 + "\n")
        else:
            report.write("No vulnerabilities were found in any files.\n\n")

    print("Full risk assessment report has been generated in 'scan_results.txt'.")

def scan_folder_for_vulnerabilities(folder_path):
    scan_results = {}

    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith((".py", ".c", ".java", ".js")):
                file_path = os.path.join(root, file)
                findings = scan_file_for_vulnerabilities(file_path)

                if findings:
                    scan_results[file_path] = findings

    generate_full_report(scan_results)
    save_scan_results(scan_results)

    print("\nScan complete.")

def save_scan_results(scan_results, output_file="scan_results.json"):
    """Save scan results to a JSON file."""
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(scan_results, f, indent=4)
        print(f"Scan results saved to {output_file}.")
    except Exception as e:
        print(f"Error saving scan results: {e}")


if __name__ == "__main__":
    folder = input("Enter the folder path to scan: ")
    scan_folder_for_vulnerabilities(folder)
    if os.path.isdir(folder):
        print(f"Scanning folder: {folder}\n")
        scan_folder_for_vulnerabilities(folder)
    else:
        print("Invalid folder path. Please try again.")



