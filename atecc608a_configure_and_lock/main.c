
/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Is an application to configure and lock CryptoAuth Device zones
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "atca.h"
#include "atca_params.h"

uint8_t pattern_slot_config[] = {
    0x00, 0x00, 0x00, 0x00, /* Read only serial number */
    0x00, 0x00, 0x00, 0x00, /* Read only revision number */
    0x00, 0x00, 0x00, 0x00, /* Read only serial number */
    0x00, 0x00, 0x00, 0x00, /* Read only reserved, I2C enable, reserved */
    0xC0, 0x00, 0x00, 0x00, /* I2C address, reserved, OTP mode, chip mode*/

    0x87, 0x20, 0x87, 0x20, /* Slot 0, Slot 1 */
    0x87, 0x20, 0x87, 0x20, /* Slot 2, Slot 3 */
    0x83, 0x20, 0x83, 0x20, /* Slot 4, Slot 5 */
    0x8F, 0x20, 0x87, 0x20, /* Slot 6, Slot 7 */
    0x00, 0x00, 0x00, 0x00, /* Slot 8, Slot 9 */
    0x00, 0x00, 0x00, 0x00, /* Slot 10, Slot 11 */
    0x00, 0x00, 0x00, 0x00, /* Slot 12, Slot 13 */
    0x00, 0x00, 0xA7, 0x20, /* Slot 14, Slot 15 */

    0xFF, 0xFF, 0xFF, 0xFF, /* Counter 0 */
    0x00, 0x00, 0x00, 0x00, /* Counter 0 */
    0xFF, 0xFF, 0xFF, 0xFF, /* Counter 1 */
    0x00, 0x00, 0x00, 0x00, /* Counter 1 */
    0xFF, 0xFF, 0xFF, 0xFF, /* LastKeyUse */
    0xFF, 0xFF, 0xFF, 0xFF, /* LastKeyUse */
    0xFF, 0xFF, 0xFF, 0xFF, /* LastKeyUse */
    0xFF, 0xFF, 0xFF, 0xFF, /* LastKeyUse */
    0x00, 0x00, 0x55, 0x55, /* UserExtra, Selector, LockValue, LockConfig */
    0xFF, 0xFF, 0x00, 0x00, /* SlotLocked */
    0x00, 0x00, 0x00, 0x00, /* X509format */

    0x33, 0x00, 0x33, 0x00, /* KeyConfig 0, KeyConfig 1 */
    0x33, 0x00, 0x33, 0x00, /* KeyConfig 2, KeyConfig 3 */
    0x1C, 0x00, 0x1C, 0x00, /* KeyConfig 4, KeyConfig 5 */
    0x13, 0x00, 0x1F, 0x00, /* KeyConfig 6, KeyConfig 7 */
    0x1C, 0x00, 0x10, 0x00, /* KeyConfig 8, KeyConfig 9 */
    0x10, 0x00, 0x10, 0x00, /* KeyConfig 10, KeyConfig 11 */
    0x10, 0x00, 0x10, 0x00, /* KeyConfig 12, KeyConfig 13 */
    0x10, 0x00, 0x13, 0x00  /* KeyConfig 14, KeyConfig 15 */
};

static void get_bin(char *result, uint8_t byte)
{
    for (int i = 0; i < 8; i++) {
        result[i] = (((byte << i) & 0x80) ? '1' : '0');
    }
    result[8] = '\0';
}

static int read_config(ATCADevice dev)
{
    uint8_t data[ATCA_ECC_CONFIG_SIZE];
    uint8_t data_count = 0;
    char binary[9];

    memset(data, 0, ATCA_ECC_CONFIG_SIZE);

    int status = calib_read_config_zone(dev, data);
    if (status != ATCA_SUCCESS) {
        printf("Error reading config zone\n");
        return 1;
    }

    printf("Config zone: \n\n");

    printf("%03d:%03d ", data_count, data_count+3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("SN0 SN1 SN2 SN3\n");

    printf("%03d:%03d ", data_count, data_count+3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("RN0 RN1 RN2 RN3\n");

    printf("%03d:%03d ", data_count, data_count+3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("SN4 SN5 SN6 SN7\n");

    printf("%03d:%03d ", data_count, data_count+3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("SN8 RSVD I2CE RSVD\n");

    printf("%03d:%03d ", data_count, data_count+3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("I2CA RSVD OTPM CM\n");

    for (int i = 0; i < 32; i += 4) {
        static int slotcount = 0;
        printf("%03d:%03d ", data_count, data_count+3);
        for (int j = 0; j < 4; j++) {
            get_bin(binary, data[data_count]);
            printf("%s ", binary);
            data_count++;
        }
        printf("SC%d SC%d ", slotcount, slotcount);
        slotcount++;
        printf("SC%d SC%d\n", slotcount, slotcount);
        slotcount++;
    }

    for (int k = 0; k < 2; k++) {
        static int cnt_no = 0;
        for (int i = 0; i < 8; i += 4) {
            printf("%03d:%03d ", data_count, data_count+3);
            for (int j = 0; j < 4; j++) {
                get_bin(binary, data[data_count]);
                printf("%s ", binary);
                data_count++;
            }
            printf("CNT%d CNT%d CNT%d CNT%d\n", cnt_no, cnt_no, cnt_no, cnt_no);
        }
        cnt_no++;
    }

    for (int i = 0; i < 16; i += 4) {
        printf("%03d:%03d ", data_count, data_count+3);
        for (int j = 0; j < 4; j++) {
            get_bin(binary, data[data_count]);
            printf("%s ", binary);
            data_count++;
        }
        printf("LKU%d LKU%d LKU%d LKU%d\n", i, i+1, i+2, i+3);
    }

    printf("%03d:%03d ", data_count, data_count+3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("UE SEL LV LC\n");

    printf("%03d:%03d ", data_count, data_count+3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("SL0 SL1 RFU0 RFU1\n");

    printf("%03d:%03d ", data_count, data_count+3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("X509-0 X509-1 X509-2 X509-3\n");

    for (int i = 0; i < 32; i += 4) {
        static int key_cnt = 0;
        printf("%03d:%03d ", data_count, data_count+3);
        for (int j = 0; j < 4; j++) {
            get_bin(binary, data[data_count]);
            printf("%s ", binary);
            data_count++;
        }
        printf("KC%d KC%d ", key_cnt, key_cnt);
        key_cnt++;
        printf("KC%d KC%d\n", key_cnt, key_cnt);
        key_cnt++;
    }

    return 0;
}

void program_config(void)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 20, &pattern_slot_config[20], ATCA_ECC_CONFIG_SIZE - 20);
    if (status != ATCA_SUCCESS) {
        printf("Write went wrong\n");
    }
}

int main(void)
{
    ATCADevice dev;
    atcab_init_ext(&dev, (ATCAIfaceCfg *)&atca_params[0].cfg);

#ifdef CONFIG_CRYPTO
    program_config();
#endif
#ifdef LOCK_CRYPTO
    ATCA_STATUS status = ATCA_SUCCESS;

    status = calib_lock_config_zone(dev);
    if (status != ATCA_SUCCESS) {
        printf("Lock config zone went wrong\n");
    }
    status = calib_lock_data_zone(dev);
    if (status != ATCA_SUCCESS) {
        printf("Lock data zone went wrong\n");
    }
#endif

    read_config(dev);
    bool is_locked_config = false;
    bool is_locked_data = false;
    calib_is_locked(dev, LOCK_ZONE_CONFIG, &is_locked_config);
    if (!is_locked_config)
    {
        printf("Config zone not locked.\n");
    }
    else {
        printf("Config zone locked.\n");
    }

    calib_is_locked(dev, LOCK_ZONE_DATA, &is_locked_data);
    if (!is_locked_data)
    {
        printf("Data zone not locked.\n");
    }
    else {
        printf("Data zone locked.\n");
    }
    return 0;
}