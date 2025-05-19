#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void init_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

// Replace with actual payload from your C
unsigned char payload[] ="Your shellcode";
size_t payload_len = sizeof(payload);

void print_byte_array(const char *name, const unsigned char *data, size_t len) {
    printf("unsigned char %s[%zu] = {", name, len);
    for (size_t i = 0; i< len; i++) {
        printf("0x%02x", data[i]);
        if (i < len - 1) printf(", ");

        
    }
    printf("};\n\n");
}

int main(int argc, char *argv[]) {
    init_openssl();
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <password>\n", argv[0]); 
        return 1;
    }
    else if (argc > 2) {
        fprintf(stderr, "Error: Too many arguments. Only one password is expected.\n");
        return 1;
    }
    
    const char *password = argv[1];
    printf("Password received: %s\n", password);

    // Hash password with SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)password, strlen(password), hash);

    // generate random salt
    unsigned char salt[16];
    if (!RAND_bytes(salt, sizeof(salt))) {
        fprintf(stderr, "Failed to generate salt.\n");
        return 1;
    }

    // Derive key and IV using PBKDF2
    unsigned char key[32], iv[16];
    unsigned char derived[48]; // 32 for key + 16 for IV
    if (!PKCS5_PBKDF2_HMAC((const char *)hash, SHA256_DIGEST_LENGTH, salt, sizeof(salt), 1000, EVP_sha256(), sizeof(derived), derived)) {
        fprintf(stderr, "PBKDF2 failed.\n");
        return 1;
    }
    memcpy(key, derived, 32);
    memcpy(iv, derived + 32, 16);

    // Encrypt payload with AES-256-CBC
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create cipher context.\n");
        return 1;
    }

    unsigned char ciphertext[1024];
    int len, ciphertext_len;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Failed to initialize encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, payload, payload_len)) {
        fprintf(stderr, "Encryption update failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fprintf(stderr, "Encryption finalization failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Output result--------------------------------------------------
    print_byte_array("encrypted_payload", ciphertext, ciphertext_len);
    print_byte_array("salt", salt, sizeof(salt));
    printf("char *password = \"%s\";\n", password);

    return 0;
}
// this command to generate the exe file
// gcc -o encryptionn encryptionn.c -lssl -lcrypto





