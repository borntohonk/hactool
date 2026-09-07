-include config.mk

# Keep the build usable without a generated config.mk.  This is particularly
# useful on macOS, where the system compiler is clang rather than gcc.
CC ?= cc
AR ?= ar
CFLAGS ?= -O2 -Wall -Wextra -pedantic -std=gnu11 -fPIC
LDFLAGS ?= -lmbedtls -lmbedx509 -lmbedcrypto

UNAME_S := $(shell uname -s 2>/dev/null)
UNAME_M := $(shell uname -m 2>/dev/null)

# The old flags were Linux/MinGW-specific.  They cause feature-test macro
# conflicts with Apple's libc, especially on older Intel macOS releases.
ifeq ($(UNAME_S),Darwin)
PLATFORM_CFLAGS += -D_DARWIN_C_SOURCE
else
PLATFORM_CFLAGS += -D_BSD_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE
endif
PLATFORM_CFLAGS += -D_FILE_OFFSET_BITS=64

# MinGW needs its printf compatibility mode, but defining it on clang/GCC
# builds for Unix is incorrect and can hide portability problems.
MINGW_TRIPLE := $(shell $(CC) -dumpmachine 2>/dev/null)
ifneq ($(findstring mingw,$(MINGW_TRIPLE)),)
PLATFORM_CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

PKG_CONFIG ?= pkg-config
CAPSTONE_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags capstone 2>/dev/null)
CAPSTONE_LIBS ?= $(shell $(PKG_CONFIG) --libs capstone 2>/dev/null)

# Support both Intel Homebrew and MacPorts when pkg-config is not available.
# Users can always override CAPSTONE_CFLAGS/CAPSTONE_LIBS in config.mk.
ifeq ($(strip $(CAPSTONE_LIBS)),)
CAPSTONE_PREFIX := $(shell brew --prefix capstone 2>/dev/null)
ifneq ($(strip $(CAPSTONE_PREFIX)),)
CAPSTONE_CFLAGS += -I$(CAPSTONE_PREFIX)/include
CAPSTONE_LIBS += -L$(CAPSTONE_PREFIX)/lib -lcapstone
else ifneq ($(wildcard /opt/local/include/capstone/capstone.h),)
CAPSTONE_CFLAGS += -I/opt/local/include
CAPSTONE_LIBS += -L/opt/local/lib -lcapstone
else
CAPSTONE_LIBS = -lcapstone
endif
endif

CFLAGS += $(PLATFORM_CFLAGS) $(CAPSTONE_CFLAGS)

.PHONY: clean

INCLUDE = -I ./mbedtls/include
LIBDIR = ./mbedtls/library
all:
	$(MAKE) -C mbedtls lib CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS)"
	$(MAKE) hactool$(EXEEXT)

.c.o:
	$(CC) $(INCLUDE) -c $(CFLAGS) -o $@ $<

hactool$(EXEEXT): save.o sha.o aes.o extkeys.o rsa.o npdm.o nacp.o cnmt.o nsp.o bktr.o kip.o packages.o pki.o pk11_extract_key_sources.o tsec_fw.o pfs0.o hfs0.o nca0_romfs.o romfs.o utils.o nax0.o nso.o lz4.o nca.o xci.o switchfs.o swipc.o find_patterns.o main.o filepath.o ConvertUTF.o cJSON.o
	$(CC) -o $@ $^ -L $(LIBDIR) $(LDFLAGS) $(CAPSTONE_LIBS)

aes.o: aes.h types.h

bktr.o: bktr.h types.h

extkeys.o: extkeys.h types.h settings.h

filepath.o: filepath.c types.h

hfs0.o: hfs0.h types.h

kip.o: kip.h types.h

lz4.o: lz4.h

find_patterns.o: find_patterns.h settings.h types.h cJSON.h sha.h kip.h

main.o: main.c pki.h types.h settings.h find_patterns.h

packages.o: packages.h aes.h kip.h types.h tsec_fw.h key_sources.h

pk11_extract_key_sources.o: pk11_extract_key_sources.h

tsec_fw.o: tsec_fw.h aes.h types.h

pfs0.o: pfs0.h types.h

pki.o: pki.h aes.h types.h

nax0.o: nax0.h aes.h sha.h types.h

nca.o: nca.h aes.h sha.h rsa.h bktr.h filepath.h nso.h types.h

npdm.o: npdm.c cJSON.h types.h

nacp.o: nacp.c nacp.h cJSON.h types.h

cnmt.o: cnmt.c cnmt.h cJSON.h types.h

nsp.o: nsp.c nsp.h pfs0.h extkeys.h nca.h filepath.h types.h

nso.o: nso.h types.h

romfs.o: ivfc.h types.h

nca0_romfs.o: nca0_romfs.h ivfc.h types.h

rsa.o: rsa.h sha.h types.h

save.o: save.h ivfc.h aes.h sha.h filepath.h types.h

sha.o: sha.h types.h

switchfs.o: switchfs.h nca.h types.h filepath.h

swipc.o: swipc.h nca.h packages.h kip.h types.h filepath.h sha.h

utils.o: utils.h types.h

xci.o: xci.h types.h hfs0.h

ConvertUTF.o: ConvertUTF.h

cJSON.o: cJSON.h

clean:
	rm -f *.o hactool hactool.exe

clean_full:
	rm -f *.o hactool hactool.exe
	$(MAKE) -C mbedtls clean

# Build an Intel 64-bit Mach-O binary explicitly.  On an Intel Mac this is
# equivalent to the normal build; on Apple Silicon it cross-compiles and the
# installed Capstone library must also provide an x86_64 slice.
.PHONY: macos-x86 macos-x86_64
macos-x86 macos-x86_64:
	@test "$(UNAME_S)" = "Darwin" || (echo "macos-x86 requires macOS"; exit 1)
	$(MAKE) clean
	$(MAKE) CC=clang CFLAGS="$(CFLAGS) -arch x86_64" LDFLAGS="$(LDFLAGS) -arch x86_64"

dist: clean_full
	$(eval HACTOOLVER = $(shell grep '\bHACTOOL_VERSION\b' version.h \
		| cut -d' ' -f3 \
		| sed -e 's/"//g'))
	mkdir hactool-$(HACTOOLVER)
	cp -R *.c *.h config.mk.template Makefile README.md LICENSE mbedtls hactool-$(HACTOOLVER)
	tar czf hactool-$(HACTOOLVER).tar.gz hactool-$(HACTOOLVER)
	rm -r hactool-$(HACTOOLVER)
