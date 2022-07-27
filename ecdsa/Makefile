# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../RIOT

APPLICATION = ecdsa-periph
BOARD ?= nrf52840dk

CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(12*THREAD_STACKSIZE_DEFAULT\)

ifeq (1, $(SECURE_ELEMENT))
	CFLAGS += -DSECURE_ELEMENT
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.se
	ifeq (1, $(MULTIPLE_SE))
		CFLAGS += -DMULTIPLE_SE
		KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.se.multiple
	endif
else
	KCONFIG_ADD_CONFIG += $(APPDIR)/app.config.test.periph
endif

ifeq (1, $(TEST_TIME))
	CFLAGS += -DTEST_TIME
endif

export TEST_KCONFIG ?= 1

include $(RIOTBASE)/Makefile.include