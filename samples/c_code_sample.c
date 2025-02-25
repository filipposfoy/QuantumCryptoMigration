#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>

void aes_cbc_vulnerability() {
    // Hardcoded AES key and IV
    unsigned char key[16] = "hardcodedkey123";
    unsigned char iv[16] = "hardcodediv1234";

    unsigned char plaintext[16] = "SensitiveData";
    unsigned char ciphertext[16];
    unsigned char decryptedtext[16];

    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(key, 128, &enc_key);
    AES_cbc_encrypt(plaintext, ciphertext, 16, &enc_key, iv, AES_ENCRYPT);

    printf("Encrypted Data: ");
    for (int i = 0; i < 16; i++) printf("%02x", ciphertext[i]);
    printf("\n");

    // Reset IV for decryption
    memcpy(iv, "hardcodediv1234", 16);
    AES_set_decrypt_key(key, 128, &dec_key);
    AES_cbc_encrypt(ciphertext, decryptedtext, 16, &dec_key, iv, AES_DECRYPT);

    printf("Decrypted Data: %s\n", decryptedtext);
}

int main() {
    aes_cbc_vulnerability();
    return 0;
}