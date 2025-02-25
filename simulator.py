import os
import re
import json

# SHA3 import lines for each language
SHA3_IMPORTS = {
    "python": "import hashlib",
    "javascript": "const crypto = require('crypto');",
    "c": "#include <openssl/evp.h>"
}

# SHA3 hashing function for each language
SHA3_FUNCTIONS = {
    "python": """
def SHA3_hash(password, stored_hash=None):
    import hashlib

    if stored_hash is None:
        # Hash the password directly using SHA3-256
        hashed = hashlib.sha3_256(password.encode('utf-8')).digest()
        return hashed
    else:
        # Compare the provided password's hash with the stored hash
        test_hashed = hashlib.sha3_256(password.encode('utf-8')).digest()
        return test_hashed == stored_hash
""",
    "javascript": """
function SHA3_hash(password, storedHash = null) {
    const crypto = require('crypto');
    if (storedHash === null) {
        const salt = crypto.randomBytes(16); // Generate a random salt
        const hash = crypto.createHash('sha3-256').update(Buffer.concat([salt, Buffer.from(password, 'utf-8')])).digest();
        return Buffer.concat([salt, hash]); // Store the salt with the hash
    } else {
        const salt = storedHash.slice(0, 16); // Extract the salt
        const storedHashed = storedHash.slice(16);
        const testHashed = crypto.createHash('sha3-256').update(Buffer.concat([salt, Buffer.from(password, 'utf-8')])).digest();
        return testHashed.equals(storedHashed);
    }
}
""",
    "c": """
unsigned char* SHA3_hash(const char* password, const unsigned char* stored_hash, size_t salt_len, int* is_match) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char* hash = malloc(EVP_MAX_MD_SIZE);
    unsigned int hash_len;

    if (!stored_hash) {
        unsigned char* salt = malloc(16);
        RAND_bytes(salt, 16); // Generate a random salt

        EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
        EVP_DigestUpdate(ctx, salt, 16);
        EVP_DigestUpdate(ctx, password, strlen(password));
        EVP_DigestFinal_ex(ctx, hash, &hash_len);

        unsigned char* result = malloc(16 + hash_len);
        memcpy(result, salt, 16);
        memcpy(result + 16, hash, hash_len);

        free(salt);
        free(hash);
        EVP_MD_CTX_free(ctx);
        return result; // Store the salt with the hash
    } else {
        unsigned char* salt = malloc(salt_len);
        memcpy(salt, stored_hash, salt_len);

        unsigned char* stored_hashed = (unsigned char*)(stored_hash + salt_len);
        EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
        EVP_DigestUpdate(ctx, salt, salt_len);
        EVP_DigestUpdate(ctx, password, strlen(password));
        EVP_DigestFinal_ex(ctx, hash, &hash_len);

        *is_match = memcmp(hash, stored_hashed, hash_len) == 0;

        free(salt);
        free(hash);
        EVP_MD_CTX_free(ctx);
        return NULL; // No new hash generated, just comparison
    }
}
"""
}

# Detect the language based on file extension
def detect_language(file_path):
    ext = os.path.splitext(file_path)[1]
    if ext in ['.py']:
        return "python"
    elif ext in ['.js']:
        return "javascript"
    elif ext in ['.c', '.h']:
        return "c"
    else:
        return None

# Insert the SHA3 import at the first line
def add_import(file_content, language):
    return SHA3_IMPORTS[language] + "\n" + file_content

# Add the SHA3 function after imports
def add_functions(file_content, language):
    lines = file_content.splitlines()
    for i, line in enumerate(lines):
        if "import" in line or "#include" in line:
            continue
        else:
            lines.insert(i + 1, SHA3_FUNCTIONS[language])
            break
    return "\n".join(lines)

# Replace vulnerable encryption functions with AES256-safe functions
def replace_vulnerable_code(file_content, scan_results, language):
    changes = []
    lines = file_content.splitlines()

    for finding in scan_results:
        line_number = finding["line_no"]-1 # Convert to 0-based index
        original_line = lines[line_number + 14]
        description = finding["description"]
        line_code = finding["line"]

        if language == "python" and "md5_hash" in line_code:
            if line_code.strip().startswith("def"):  # Check if the line starts with "def"
                print(f"[MANUAL REVIEW] Line {line_number}: Definition of unsafe MD5 hash function")
                continue
            new_line = original_line.replace("md5_hash", "SHA3_hash")
            lines[line_number+14] = new_line
            changes.append((line_number + 15, original_line, new_line))
        elif language == "python" and "RSA" in line_code and "2048" in line_code:
            print(f"[MANUAL REVIEW] Line {line_number}: RSA with 2048 bits is unsecure, consider changing your key size")
            continue
        elif language == "python" and "MODE_ECB" in line_code:
            print(f"[MANUAL REVIEW] Line {line_number}: ECB MODE is generally unsecure, consider migrating to another mode")
        elif language == "python" and "import" in line_code:
            print(f"[MANUAL REVIEW] Line {line_number}: You have imported an unsecure crypto primitive: {line_code}, consider removing it")    
        # elif language == "javascript" and "encrypt" in description or "md5" in description:
        #     new_line = original_line.replace("md5", "AES256_safe_encrypt")
        #     lines[line_number] = new_line
        #     changes.append((line_number + 1, original_line, new_line))

        # elif language == "c" and "encrypt" in description or "md5" in description:
        #     new_line = original_line.replace("md5", "AES256_safe_encrypt")
        #     lines[line_number] = new_line
        #     changes.append((line_number + 1, original_line, new_line))
        else:
            changes.append((line_number + 1, original_line, "Manual review needed"))

    return "\n".join(lines), changes

# Main processing function
def process_file(file_path, scan_results):
    with open(file_path, 'r') as file:
        file_content = file.read()

    language = detect_language(file_path)
    if not language:
        print(f"Unsupported language for file: {file_path}")
        return

    # Add import
    file_content = add_import(file_content, language)

    # Add functions
    file_content = add_functions(file_content, language)



    # Replace vulnerable code
    file_content, changes = replace_vulnerable_code(file_content, scan_results, language)

    # Save the updated file
    with open(file_path, 'w') as file:
        file.write(file_content)

    # Output the changes
    for line_no, original, new in changes:
        if original != new:
            print(f"[UPDATED] Line {line_no}: {original} -> {new}")
        else:
            print(f"[MANUAL REVIEW] Line {line_no}: {original}")

def main():
    input_json = "scan_results.json"
    with open(input_json, 'r') as file:
        scan_results = json.load(file)

    for file_path, findings in scan_results.items():
        process_file(file_path, findings)

if __name__ == "__main__":
    main()
