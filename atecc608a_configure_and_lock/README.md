### About
This application configures the ATECC608A *config zone* and locks both the *config zone* and *data zone*.

The configuration pattern is declared as an array in [main](main.c). Used key slots are configured for use with ECC functions. Not all slots are configured, though, and left untouched for later use of the device for other purposes.

**Note**: This helper applies permanent configurations. For further details about slot configuration please refer to [technical documentation](https://www.microchip.com/wwwproducts/en/ATECC608A) of the device.

### Usage
This application only locks the device connected to the main I2C bus of a device.

To prevent accidental locking, configuration and locking are separate operations and must be enabled with compiler flags. If no flag is set, the application will display the current configuration and log the status in the terminal.
If zones are already locked, the application will display a message that locking went wrong. This is intended.

- Configure: Build the application with CONFIG_CRYPTO=1.
- Lock (locks *config zone* and *data zone*): Build with LOCK_CRYPTO=1.
