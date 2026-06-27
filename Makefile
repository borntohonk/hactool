include config.mk

.PHONY: clean

INCLUDE = -I ./mbedtls/include
LIBDIR = ./mbedtls/library
CFLAGS += -D_BSD_SOURCE -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE -D__USE_MINGW_ANSI_STDIO=1 -D_FILE_OFFSET_BITS=64

all:
	$(MAKE) -C mbedtls lib
	$(MAKE) hactool$(EXEEXT)

.c.o:
	$(CC) $(INCLUDE) -c $(CFLAGS) -o $@ $<

hactool$(EXEEXT): save.o sha.o aes.o extkeys.o rsa.o npdm.o nacp.o cnmt.o nsp.o bktr.o kip.o packages.o pki.o pk11_extract_key_sources.o tsec_fw.o pfs0.o hfs0.o nca0_romfs.o romfs.o utils.o nax0.o nso.o lz4.o nca.o xci.o switchfs.o swipc.o find_patterns.o main.o filepath.o ConvertUTF.o cJSON.o
	$(CC) -o $@ $^ -L $(LIBDIR) $(LDFLAGS)

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

dist: clean_full
	$(eval HACTOOLVER = $(shell grep '\bHACTOOL_VERSION\b' version.h \
		| cut -d' ' -f3 \
		| sed -e 's/"//g'))
	mkdir hactool-$(HACTOOLVER)
	cp -R *.c *.h config.mk.template Makefile README.md LICENSE mbedtls hactool-$(HACTOOLVER)
	tar czf hactool-$(HACTOOLVER).tar.gz hactool-$(HACTOOLVER)
	rm -r hactool-$(HACTOOLVER)
