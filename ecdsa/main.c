#include <stdio.h>
#include <stdint.h>

#include "psa/crypto.h"

#if TEST_TIME
#include "periph/gpio.h"
gpio_t external_gpio = GPIO_PIN(1, 8);
gpio_t internal_gpio = GPIO_PIN(1, 7);
#endif

#define ECDSA_MESSAGE_SIZE  (127)
#define ECC_KEY_SIZE    (256)

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

static void ecdsa(void)
{
    psa_key_id_t privkey_id;
    psa_key_attributes_t privkey_attr = psa_key_attributes_init();
    psa_key_id_t pubkey_id;
    psa_key_attributes_t pubkey_attr = psa_key_attributes_init();

    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_bits_t bits = ECC_KEY_SIZE;
    uint8_t bytes = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), bits);

    uint8_t public_key[PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), ECC_KEY_SIZE)] = { 0 };
    size_t pubkey_length;
    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_length;

    psa_set_key_algorithm(&privkey_attr, alg);
    psa_set_key_usage_flags(&privkey_attr, usage);
    psa_set_key_type(&privkey_attr, type);
    psa_set_key_bits(&privkey_attr, bits);

#ifdef SECURE_ELEMENT
    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV0);
    psa_set_key_lifetime(&privkey_attr, lifetime);
#endif

#if TEST_TIME
    gpio_clear(external_gpio);
    psa_generate_key(&privkey_attr, &privkey_id);
    gpio_set(external_gpio);

    gpio_clear(external_gpio);
    psa_export_public_key(privkey_id, public_key, sizeof(public_key), &pubkey_length);
    gpio_set(external_gpio);

    gpio_clear(external_gpio);
    psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    gpio_set(external_gpio);

#ifdef SECURE_ELEMENT
    psa_set_key_lifetime(&privkey_attr, lifetime);
#endif
    psa_set_key_algorithm(&pubkey_attr, alg);
    psa_set_key_usage_flags(&pubkey_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(&pubkey_attr, PSA_BYTES_TO_BITS(bytes));
    psa_set_key_type(&pubkey_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    gpio_clear(external_gpio);
    psa_import_key(&pubkey_attr, public_key, pubkey_length, &pubkey_id);
    gpio_set(external_gpio);

    gpio_clear(external_gpio);
    psa_sign_hash(privkey_id, alg, hash, sizeof(hash), signature, sizeof(signature), &sig_length);
    gpio_set(external_gpio);

    gpio_clear(external_gpio);
    psa_verify_hash(privkey_id, alg, hash, sizeof(hash), signature, sig_length);
    gpio_set(external_gpio);
#else
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    status = psa_generate_key(&privkey_attr, &privkey_id);
    if (status != PSA_SUCCESS) {
        printf("Local Generate Key failed: %ld\n", status);
        return;
    }

    status = psa_export_public_key(privkey_id, public_key, sizeof(public_key), &pubkey_length);
    if (status != PSA_SUCCESS) {
        printf("Export Public Key failed: %ld\n", status);
        return;
    }

    status = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS) {
        printf("Hash Generation failed: %ld\n", status);
        return;
    }

#ifdef SECURE_ELEMENT
    psa_set_key_lifetime(&pubkey_attr, lifetime);
#endif
    psa_set_key_algorithm(&pubkey_attr, alg);
    psa_set_key_usage_flags(&pubkey_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(&pubkey_attr, PSA_BYTES_TO_BITS(bytes));
    psa_set_key_type(&pubkey_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&pubkey_attr, public_key, pubkey_length, &pubkey_id);
    if (status != PSA_SUCCESS) {
        printf("PSA Import Public Key failed: %ld\n", status);
        return;
    }

    status = psa_sign_hash(privkey_id, alg, hash, sizeof(hash), signature, sizeof(signature), &sig_length);
    if (status != PSA_SUCCESS) {
        printf("Sign hash failed: %ld\n", status);
        return;
    }

    status = psa_verify_hash(pubkey_id, alg, hash, sizeof(hash), signature, sig_length);
    if (status != PSA_SUCCESS) {
        printf("Verify hash failed: %ld\n", status);
        return;
    }
#endif
    psa_destroy_key(privkey_id);
    psa_destroy_key(pubkey_id);
}

#ifdef MULTIPLE_SE
static void ecdsa_sec_se(void)
{
    psa_key_id_t privkey_id;
    psa_key_attributes_t privkey_attr = psa_key_attributes_init();
    psa_key_id_t pubkey_id;
    psa_key_attributes_t pubkey_attr = psa_key_attributes_init();

    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV1);
    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_bits_t bits = 256;
    uint8_t bytes = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),bits);

    uint8_t public_key[PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256)] = { 0 };
    size_t pubkey_length;

    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_length;

    psa_set_key_lifetime(&privkey_attr, lifetime);
    psa_set_key_algorithm(&privkey_attr, alg);
    psa_set_key_usage_flags(&privkey_attr, usage);
    psa_set_key_type(&privkey_attr, type);
    psa_set_key_bits(&privkey_attr, bits);

#if TEST_TIME
    gpio_clear(external_gpio);
    psa_generate_key(&privkey_attr, &privkey_id);
    gpio_set(external_gpio);

    gpio_clear(external_gpio);
    psa_export_public_key(privkey_id, public_key, sizeof(public_key), &pubkey_length);
    gpio_set(external_gpio);

    gpio_clear(external_gpio);
    psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    gpio_set(external_gpio);

    psa_set_key_lifetime(&pubkey_attr, lifetime);
    psa_set_key_algorithm(&pubkey_attr, alg);
    psa_set_key_usage_flags(&pubkey_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(&pubkey_attr, PSA_BYTES_TO_BITS(bytes));
    psa_set_key_type(&pubkey_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    gpio_clear(external_gpio);
    psa_import_key(&pubkey_attr, public_key, pubkey_length, &pubkey_id);
    gpio_set(external_gpio);

    gpio_clear(external_gpio);
    psa_sign_hash(privkey_id, alg, hash, sizeof(hash), signature, sizeof(signature), &sig_length);
    gpio_set(external_gpio);

    gpio_clear(external_gpio);
    psa_verify_hash(pubkey_id, alg, hash, sizeof(hash), signature, sig_length);
    gpio_set(external_gpio);
#else
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;
    status = psa_generate_key(&privkey_attr, &privkey_id);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Generate Key failed: %ld\n", status);
        return;
    }

    status = psa_export_public_key(privkey_id, public_key, sizeof(public_key), &pubkey_length);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Export Public Key failed: %ld\n", status);
        return;
    }

    status = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS) {
        printf("Hash Generation failed: %ld\n", status);
        return;
    }

    psa_set_key_lifetime(&pubkey_attr, lifetime);
    psa_set_key_algorithm(&pubkey_attr, alg);
    psa_set_key_usage_flags(&pubkey_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(&pubkey_attr, PSA_BYTES_TO_BITS(bytes));
    psa_set_key_type(&pubkey_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&pubkey_attr, public_key, pubkey_length, &pubkey_id);
    if (status != PSA_SUCCESS) {
        printf("PSA Import Public Key failed: %ld\n", status);
        return;
    }

    status = psa_sign_hash(privkey_id, alg, hash, sizeof(hash), signature, sizeof(signature), &sig_length);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Sign hash failed: %ld\n", status);
        return;
    }

    status = psa_verify_hash(pubkey_id, alg, hash, sizeof(hash), signature, sig_length);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Verify hash failed: %ld\n", status);
        return;
    }

#endif /* TEST_TIME */
    psa_destroy_key(privkey_id);
    psa_destroy_key(pubkey_id);
}
#endif

int main(void)
{
    _test_init();

#if TEST_TIME
    for (int i = 0; i < 1000; i++) {
#ifdef MULTIPLE_SE
        if (i % 2) {
            ecdsa_sec_se();
        }
        else {
            ecdsa();
        }
#else
        ecdsa();
#endif /* MULTIPLE_SE */
    }
#else
    ecdsa();
#if defined(MULTIPLE_SE) && !defined(TEST_TIME)
    ecdsa_sec_se();
#endif /* MULTIPLE_SE */
#endif /* TEST_TIME */

    puts("ECDSA Done");
    return 0;
}
