noinst_PROGRAMS=engine_key_loading

engine_key_loading_SOURCES=engine_key_loading.c
engine_key_loading_LDADD=-L@OPENSSL_LIB_DIR@ -lcrypto -ldl
engine_key_loading_CFLAGS=-I@OPENSSL_INCLUDE_DIR@

TESTS = test.sh
