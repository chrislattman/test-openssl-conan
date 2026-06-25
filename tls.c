#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

int main(void)
{
    struct stat statbuf = {0};
    FILE *fp;
    unsigned char *encoded_rsa_public_key, *encoded_rsa_private_key,
        *encoded_server_ecdh_public_key, *ptr, *signature,
        *encoded_client_ecdh_public_key, *client_master_secret,
        *server_master_secret, *aes_key, iv[12], *ciphertext, tag[16], *decrypted;
    int encoded_rsa_public_key_len, encoded_rsa_private_key_len,
        encoded_server_ecdh_public_key_len, verified,
        encoded_client_ecdh_public_key_len, len, ciphertext_len, decrypted_len;
    const unsigned char *const_ptr;
    EVP_PKEY *rsa_private_key = NULL, *server_ecdh_params = NULL,
        *server_ecdh_keypair = NULL, *decoded_rsa_public_key = NULL,
        *decoded_server_ecdh_public_key = NULL, *client_ecdh_params = NULL,
        *client_ecdh_keypair = NULL, *decoded_client_ecdh_public_key = NULL;
    EVP_PKEY_CTX *server_ecdh_param_context, *server_ecdh_key_context,
        *rsa_private_key_ctx = NULL, *encoded_rsa_public_key_ctx = NULL,
        *client_ecdh_param_context, *client_ecdh_key_context,
        *client_master_secret_context, *server_master_secret_context;
    EVP_MD_CTX *sign_context, *verify_context, *sha256_context;
    unsigned int aes_key_len;
    size_t signature_len, client_master_secret_len, server_master_secret_len;
    const char *plaintext = "Hello world!", *aad = "authenticated but unencrypted data";
    EVP_CIPHER_CTX *aes_gcm_encrypt_context, *aes_gcm_decrypt_context;

    stat("public_key.der", &statbuf);
    encoded_rsa_public_key_len = statbuf.st_size;
    encoded_rsa_public_key = malloc(encoded_rsa_public_key_len);
    fp = fopen("public_key.der", "rb");
    fread(encoded_rsa_public_key, sizeof(unsigned char), encoded_rsa_public_key_len, fp);
    fclose(fp);
    memset(&statbuf, 0, sizeof(struct stat));
    stat("private_key.der", &statbuf);
    encoded_rsa_private_key_len = statbuf.st_size;
    encoded_rsa_private_key = malloc(encoded_rsa_private_key_len);
    fp = fopen("private_key.der", "rb");
    fread(encoded_rsa_private_key, sizeof(unsigned char), encoded_rsa_private_key_len, fp);
    fclose(fp);
    const_ptr = encoded_rsa_private_key;
    d2i_AutoPrivateKey(&rsa_private_key, &const_ptr, encoded_rsa_private_key_len);

    server_ecdh_param_context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_paramgen_init(server_ecdh_param_context);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(server_ecdh_param_context, NID_secp384r1);
    EVP_PKEY_paramgen(server_ecdh_param_context, &server_ecdh_params);
    server_ecdh_key_context = EVP_PKEY_CTX_new(server_ecdh_params, NULL);
    EVP_PKEY_keygen_init(server_ecdh_key_context);
    EVP_PKEY_keygen(server_ecdh_key_context, &server_ecdh_keypair);
    encoded_server_ecdh_public_key_len = i2d_PUBKEY(server_ecdh_keypair, NULL);
    encoded_server_ecdh_public_key = malloc(encoded_server_ecdh_public_key_len);
    ptr = encoded_server_ecdh_public_key;
    i2d_PUBKEY(server_ecdh_keypair, &ptr);

    sign_context = EVP_MD_CTX_new();
    EVP_DigestSignInit(sign_context, &rsa_private_key_ctx, EVP_sha384(), NULL, rsa_private_key);
    EVP_PKEY_CTX_set_rsa_padding(rsa_private_key_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(rsa_private_key_ctx, -2);
    EVP_DigestSignUpdate(sign_context, encoded_server_ecdh_public_key,
        encoded_server_ecdh_public_key_len);
    EVP_DigestSignFinal(sign_context, NULL, &signature_len);
    signature = malloc(signature_len);
    EVP_DigestSignFinal(sign_context, signature, &signature_len);

    const_ptr = encoded_rsa_public_key;
    d2i_PUBKEY(&decoded_rsa_public_key, &const_ptr, encoded_rsa_public_key_len);
    verify_context = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(verify_context, &encoded_rsa_public_key_ctx, EVP_sha384(),
        NULL, decoded_rsa_public_key);
    EVP_PKEY_CTX_set_rsa_padding(encoded_rsa_public_key_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(encoded_rsa_public_key_ctx, -2);
    EVP_DigestVerifyUpdate(verify_context, encoded_server_ecdh_public_key,
        encoded_server_ecdh_public_key_len);
    verified = EVP_DigestVerifyFinal(verify_context, (const unsigned char *) signature, signature_len);
    if (!verified) {
        puts("RSA signature wasn't verified.");
        exit(1);
    }

    // client should import "#include <openssl/crypto.h>" and use
    // CRYPTO_memcmp() to compare server's hash with its own hash of the
    // server's encoded ECDH public key to avoid timing attacks
    const_ptr = encoded_server_ecdh_public_key;
    d2i_PUBKEY(&decoded_server_ecdh_public_key, &const_ptr, encoded_server_ecdh_public_key_len);
    client_ecdh_param_context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_paramgen_init(client_ecdh_param_context);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(client_ecdh_param_context, NID_secp384r1);
    EVP_PKEY_paramgen(client_ecdh_param_context, &client_ecdh_params);
    client_ecdh_key_context = EVP_PKEY_CTX_new(client_ecdh_params, NULL);
    EVP_PKEY_keygen_init(client_ecdh_key_context);
    EVP_PKEY_keygen(client_ecdh_key_context, &client_ecdh_keypair);
    encoded_client_ecdh_public_key_len = i2d_PUBKEY(client_ecdh_keypair, NULL);
    encoded_client_ecdh_public_key = malloc(encoded_client_ecdh_public_key_len);
    ptr = encoded_client_ecdh_public_key;
    i2d_PUBKEY(client_ecdh_keypair, &ptr);
    client_master_secret_context = EVP_PKEY_CTX_new(client_ecdh_keypair, NULL);
    EVP_PKEY_derive_init(client_master_secret_context);
    EVP_PKEY_derive_set_peer(client_master_secret_context, decoded_server_ecdh_public_key);
    EVP_PKEY_derive(client_master_secret_context, NULL, &client_master_secret_len);
    client_master_secret = malloc(client_master_secret_len);
    EVP_PKEY_derive(client_master_secret_context, client_master_secret, &client_master_secret_len);
    sha256_context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(sha256_context, EVP_sha256(), NULL);
    EVP_DigestUpdate(sha256_context, client_master_secret, client_master_secret_len);
    aes_key_len = EVP_MD_get_size(EVP_sha256());
    aes_key = malloc(aes_key_len);
    EVP_DigestFinal_ex(sha256_context, aes_key, &aes_key_len);

    const_ptr = encoded_client_ecdh_public_key;
    d2i_PUBKEY(&decoded_client_ecdh_public_key, &const_ptr, encoded_client_ecdh_public_key_len);
    server_master_secret_context = EVP_PKEY_CTX_new(server_ecdh_keypair, NULL);
    EVP_PKEY_derive_init(server_master_secret_context);
    EVP_PKEY_derive_set_peer(server_master_secret_context, decoded_client_ecdh_public_key);
    EVP_PKEY_derive(server_master_secret_context, NULL, &server_master_secret_len);
    server_master_secret = malloc(server_master_secret_len);
    EVP_PKEY_derive(server_master_secret_context, server_master_secret, &server_master_secret_len);
    if (client_master_secret_len != server_master_secret_len ||
            memcmp(client_master_secret, server_master_secret, client_master_secret_len) != 0) {
        puts("Master secrets don't match.");
        exit(1);
    }
    OPENSSL_cleanse(client_master_secret, client_master_secret_len);
    OPENSSL_cleanse(server_master_secret, server_master_secret_len);

    RAND_bytes(iv, 12); // uses RDRAND and /dev/urandom
    aes_gcm_encrypt_context = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(aes_gcm_encrypt_context, EVP_aes_256_gcm(), NULL, aes_key, iv);
    EVP_EncryptUpdate(aes_gcm_encrypt_context, NULL, &len, (const unsigned char *) aad, strlen(aad));
    ciphertext = malloc(strlen(plaintext));
    EVP_EncryptUpdate(aes_gcm_encrypt_context, ciphertext, &len,
        (const unsigned char *) plaintext, strlen(plaintext));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(aes_gcm_encrypt_context, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(aes_gcm_encrypt_context, EVP_CTRL_GCM_GET_TAG, 16, tag);

    aes_gcm_decrypt_context = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(aes_gcm_decrypt_context, EVP_aes_256_gcm(), NULL, aes_key, iv);
    EVP_DecryptUpdate(aes_gcm_decrypt_context, NULL, &len, (const unsigned char *) aad, strlen(aad));
    decrypted = malloc(strlen(plaintext));
    EVP_DecryptUpdate(aes_gcm_decrypt_context, decrypted, &len, ciphertext, ciphertext_len);
    decrypted_len = len;
    EVP_CIPHER_CTX_ctrl(aes_gcm_decrypt_context, EVP_CTRL_GCM_SET_TAG, 16, tag);
    EVP_DecryptFinal_ex(aes_gcm_decrypt_context, decrypted + len, &len);
    decrypted_len += len;
    decrypted[decrypted_len] = '\0';
    if (strcmp(plaintext, (const char *) decrypted) != 0) {
        puts("Plaintexts don't match.");
        exit(1);
    }

    // server_ecdh_keypair and client_ecdh_keypair get destroyed below
    OPENSSL_cleanse(aes_key, aes_key_len);

    free(decrypted);
    EVP_CIPHER_CTX_free(aes_gcm_decrypt_context);
    free(ciphertext);
    EVP_CIPHER_CTX_free(aes_gcm_encrypt_context);
    free(server_master_secret);
    EVP_PKEY_CTX_free(server_master_secret_context);
    EVP_PKEY_free(decoded_client_ecdh_public_key);
    free(aes_key);
    EVP_MD_CTX_free(sha256_context);
    free(client_master_secret);
    EVP_PKEY_CTX_free(client_master_secret_context);
    free(encoded_client_ecdh_public_key);
    EVP_PKEY_free(client_ecdh_keypair);
    EVP_PKEY_CTX_free(client_ecdh_key_context);
    EVP_PKEY_free(client_ecdh_params);
    EVP_PKEY_CTX_free(client_ecdh_param_context);
    EVP_PKEY_free(decoded_server_ecdh_public_key);
    EVP_MD_CTX_free(verify_context);
    EVP_PKEY_free(decoded_rsa_public_key);
    free(signature);
    EVP_MD_CTX_free(sign_context);
    free(encoded_server_ecdh_public_key);
    EVP_PKEY_free(server_ecdh_keypair);
    EVP_PKEY_CTX_free(server_ecdh_key_context);
    EVP_PKEY_free(server_ecdh_params);
    EVP_PKEY_CTX_free(server_ecdh_param_context);
    EVP_PKEY_free(rsa_private_key);
    free(encoded_rsa_private_key);
    free(encoded_rsa_public_key);
    return 0;
}
