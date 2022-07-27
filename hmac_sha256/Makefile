# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../RIOT

APPLICATION = hmac_sha256
BOARD ?= nrf52840dk

ifeq (1, $(TEST_TIME))
	CFLAGS += -DTEST_TIME
endif

ifeq (1, $(SECURE_ELEMENT))
	CFLAGS += -DSECURE_ELEMENT
	CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(3*THREAD_STACKSIZE_DEFAULT\)
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.se
	ifeq (1, $(MULTIPLE_SE))
		CFLAGS += -DMULTIPLE_SE
		KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.se.multiple
	endif
else
	ifeq (1, $(SOFTWARE))
		KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.software
	else
		KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.hardware
	endif
endif

export TEST_KCONFIG ?= 1

include $(RIOTBASE)/Makefile.include