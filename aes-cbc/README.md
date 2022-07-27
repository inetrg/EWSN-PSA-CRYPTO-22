### About

This application can be used to measure the processing time and memory usage of the PSA Cipher AES CBC-128 operation.

### Backend Options
- `SOFTWARE=1` builds the RIOT Crypto Module as a backend
- `SECURE_ELEMENT=1` builds the ATECC608A as a backend
- `MULTIPLE_SE=1` builds two ATECC6080A instances as backends
- No Flags: Builds the hardware crypto driver for the nrf52840dk as a backend
- `TEST_TIME=1` builds the specified backend and runs the application for 1000 iterations

##### Firmware Size
- The binary can be analyzed with common tools such as `readelf`.