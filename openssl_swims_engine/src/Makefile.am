openssl_engine_LTLIBRARIES=libswims.la
#bin_PROGRAMS=create_tpm_key
openssl_enginedir=@libdir@/openssl/engines


libswims_la_LIBADD=-L@OPENSSL_LIB_DIR@ -lcrypto -lc
libswims_la_LDFLAGS=-module -avoid-version -shared
libswims_la_CFLAGS=-I@OPENSSL_INCLUDE_DIR@ -Wall -Werror -c -g -fstack-protector-all -D_FORTIFY_SOURCE=2 -DENGINE_DYNAMIC_SUPPORT
libswims_la_SOURCES= hw_swims.c hw_swims_err.c hw_swims_err.h imsign.h imsign.c certs.c certs.h b64.c b64.h jsmn.c jsmn.h

#create_tpm_key_SOURCES=create_tpm_key.c
#create_tpm_key_LDADD=-ltspi
