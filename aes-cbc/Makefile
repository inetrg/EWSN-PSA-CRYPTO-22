# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../RIOT

APPLICATION = aes-cbc

BOARD=nrf52840dk

ifeq (1, $(SECURE_ELEMENT))
	CFLAGS += -DSECURE_ELEMENT
	CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(12*THREAD_STACKSIZE_DEFAULT\)
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.se
else
	ifeq (1, $(MULTIPLE_SE))
		CFLAGS += -DMULTIPLE_SE
		CFLAGS += -DSECURE_ELEMENT
		CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(12*THREAD_STACKSIZE_DEFAULT\)
		KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.se
		KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.se.multiple
	endif
else
	ifeq (1, $(SOFTWARE))
		KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.software
	else
		KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.hardware
	endif
endif

ifeq (1, $(TEST_TIME))
	CFLAGS += -DTEST_TIME
endif

export TEST_KCONFIG ?= 1

include $(RIOTBASE)/Makefile.include