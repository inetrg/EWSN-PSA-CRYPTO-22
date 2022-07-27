### How to build and execute applications in RIOT

1. Navigate to an application folder. The applications are organized according to the cryptographic algorithms used in the evaluation:
   * [AES-128 CBC](aes-cbc/),
   * [ECDSA](ecdsa/),
   * [HMAC SHA-256](hmac_sha256/),
   * [All Backends Combined](backend-combination/).


2. To compile an application, you will need to use *make*:

    `make`
1. To flash an application to a board:

    `make flash`
1. To access the terminal:

    `make term`
1. For specific experiments you need to set compiler flags. The documentation in the respective application folder lists available modes.
   Set compiler flags before the *make* command (e.g. `TEST_TIME=1 make`).
2. For further information please refer to the [RIOT Getting Started Guide](https://doc.riot-os.org/getting-started.html).

### Target Boards

- Nordic nRF52840dk **NRF52**: `nRF52840dk` .
- Microchip or Adafruit ATECC608A extension board.