#include <stdio.h>
#include <stdint.h>

#include "psa/crypto.h"

#define AES_128_KEY_SIZE    (16)
#define AES_256_KEY_SIZE    (32)

#if TEST_TIME
#include "periph/gpio.h"
gpio_t external_gpio = GPIO_PIN(1, 8);
gpio_t internal_gpio = GPIO_PIN(1, 7);
#endif

static const uint8_t KEY_128[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static uint8_t PLAINTEXT[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
static uint8_t PLAINTEXT_LEN = 32;

static void _test_init(void)
{
#if TEST_TIME
    gpio_init(external_gpio, GPIO_OUT);
    gpio_init(internal_gpio, GPIO_OUT);

    gpio_set(external_gpio);
    gpio_clear(internal_gpio);
#endif
    psa_crypto_init();
}

static void cipher_aes_128(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT;

    size_t encr_output_size = PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_CBC_NO_PADDING, PLAINTEXT_LEN);

    uint8_t cipher_out[encr_output_size];
    size_t output_len = 0;

    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, 128);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

#ifdef SECURE_ELEMENT
    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV0);
    psa_set_key_lifetime(&attr, lifetime);
#endif

#if TEST_TIME
    gpio_clear(external_gpio);
    psa_import_key(&attr, KEY_128, AES_128_KEY_SIZE, &key_id);
    gpio_set(external_gpio);

    gpio_clear(external_gpio);
    psa_cipher_encrypt(key_id, PSA_ALG_CBC_NO_PADDING, PLAINTEXT, PLAINTEXT_LEN, cipher_out, encr_output_size, &output_len);
    gpio_set(external_gpio);
#else
    status = psa_import_key(&attr, KEY_128, AES_128_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        printf("AES 128 Key Import failed: %ld\n", status);
        return;
    }

    status = psa_cipher_encrypt(key_id, PSA_ALG_CBC_NO_PADDING, PLAINTEXT, PLAINTEXT_LEN, cipher_out, encr_output_size, &output_len);
    if (status != PSA_SUCCESS) {
        printf("AES 128 CBC Encrypt failed: %ld\n", status);
        return;
    }
#endif
    status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        printf("Destroy Key failed: %ld\n", status);
        return;
    }
}

#ifdef MULTIPLE_SE
static void cipher_aes_128_sec_se(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT;
    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV1);

    size_t encr_output_size = PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(PSA_KEY_TYPE_AES, PSA_ALG_CBC_NO_PADDING, PLAINTEXT_LEN);
    uint8_t ciphertext[encr_output_size];
    size_t cipher_len = 0;

    psa_set_key_lifetime(&attr, lifetime);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, 128);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

#if TEST_TIME
    gpio_clear(external_gpio);
    psa_import_key(&attr, KEY_128, AES_128_KEY_SIZE, &key_id);
    gpio_set(external_gpio);

    gpio_clear(external_gpio);
    psa_cipher_encrypt(key_id, PSA_ALG_CBC_NO_PADDING, PLAINTEXT, PLAINTEXT_LEN, ciphertext, encr_output_size, &cipher_len);
    gpio_set(external_gpio);
#else
    status = psa_import_key(&attr, KEY_128, AES_128_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        printf("AES 128 Key Import failed: %ld\n", status);
        return;
    }

    status = psa_cipher_encrypt(key_id, PSA_ALG_CBC_NO_PADDING, PLAINTEXT, PLAINTEXT_LEN, ciphertext, encr_output_size, &cipher_len);
    if (status != PSA_SUCCESS) {
        printf("AES 128 CBC Encrypt failed: %ld\n", status);
        return;
    }
#endif
    status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        printf("Secondary Destroy Key failed: %ld\n", status);
        return;
    }
}
#endif


int main(void)
{
    _test_init();
#if TEST_TIME
    for (int i = 0; i < 1000; i++) {
#ifdef MULTIPLE_SE
        if (i % 2) {
            cipher_aes_128_sec_se();
        }
        else {
            cipher_aes_128();
        }
#else
        cipher_aes_128();
#endif
    }
#else
    cipher_aes_128();
#ifdef MULTIPLE_SE
    cipher_aes_128_sec_se();
#endif
#endif

    puts("AES 128 CBC Done");
    return 0;
}