/*
 * Copyright 2013 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 */

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

#define __STDC_VERSION__ 199901L
#include <efi.h>

#include <kernel_efivars.h>
#include <guid.h>
#include <sha256.h>
#include <version.h>
#include "efiauthenticated.h"


#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

typedef struct pw_cb_data {
    const void *password;
    const char *prompt_info;
} PW_CB_DATA;


static void usage(const char *progname)
{
    printf
        ("Usage: %s: [-a] [-e] [-s <file>] [-engine <engine>] [-w | -d <list>[-<entry>] -v <variable-file>] [-k <key>] [-g <guid>] [-b <file>|-f <file>|-c file] [-n <var>|<var>] [-o <file>]\n",
         progname);
}

static void help(const char *progname)
{
    usage(progname);
    printf("Manipulate the UEFI key database via the efivarfs filesystem\n\n"
           "Options:\n"
           "\t-a\tappend a value to the variable instead of replacing it\n"
           "\t-engine <engine>\topenssl engine\n"
           "\t-v <file>\tEFI variable file binary dump path.\n"
           "\t-n <var>\tEFI Variable name\n"
           "\t-s <file>\tSigner certificate file\n"
           "\t-w       \tConvert the whole variable file into an AV file\n"
           "\t-o <file>\tOutput AV to this file.\n"
           "\t-e\tuse EFI Signature List instead of signed update (only works in Setup Mode\n"
           "\t-b <binfile>\tAdd hash of <binfile> to the signature list\n"
           "\t-f <file>\tAdd or Replace the key file (.esl or .auth) to the <var>\n"
           "\t-c <file>\tAdd or Replace the x509 certificate to the <var> (with <guid> if provided)\n"
           "\t-g <guid>\tOptional <guid> for the X509 Certificate\n"
           "\t-k <key>\tSecret key file for authorising User Mode updates\n"
           "\t-d <list>[-<entry>]\tDelete the signature list <list> (or just a single <entry> within the list)\n"
           "\t-t <timestamp>   Use <timestamp> as the timestamp of the timed variable update\n"
           "\t                 If not present, then the timestamp will be taken from system\n"
           "\t                 time.  Note you must use this option when doing detached\n"
           "\t                 signing otherwise the signature will be incorrect because\n"
           "\t                 of timestamp mismatches.\n");
}
EFI_GUID GUID_CISCO =
    { 0x7dc87112, 0x2bd5, 0x4154, {0x95, 0x0a, 0xce, 0x31, 0x83, 0x10, 0x76, 0x19} };
int main(int argc, char *argv[])
{
    char *variables[] = { "PK", "KEK", "db", "dbx", "PKCisco", "KEKCisco", "dbCisco", "dbxCisco" };
    char *signedby[] = { "PK", "PK", "KEK", "KEK", "PKCisco", "PKCisco", "KEKCisco", "KEKCisco" };
    EFI_GUID *owners[] =
        { &GV_GUID, &GV_GUID, &SIG_DB, &SIG_DB, &GUID_CISCO, &GUID_CISCO, &GUID_CISCO,
&GUID_CISCO };
    EFI_GUID *owner, guid = MOK_OWNER;
    EVP_PKEY *pkey = NULL;
    static UI_METHOD *ui_method = NULL;
    ENGINE *e = NULL;
    PW_CB_DATA cb_data;
    uint32_t len = 0;
    int i, esl_mode = 0, fd, ret, delsig = -1, delentry = -1, whole_variable = FALSE;
    struct stat st;
    uint32_t attributes = EFI_VARIABLE_NON_VOLATILE
        | EFI_VARIABLE_RUNTIME_ACCESS
        | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    char *hash_mode = NULL, *file = NULL, *var = NULL, *progname = argv[0], *buf,
        *name, *crt_file = NULL, *key_file = NULL, *engine = NULL, *authfile = NULL,
        *certfile = NULL, *var_file = NULL, *timestampstr = NULL;


    while (argc > 1 && argv[1][0] == '-')
    {
        if (strcmp("--version", argv[1]) == 0)
        {
            version(progname);
            exit(0);
        } else if (strcmp("--help", argv[1]) == 0)
        {
            help(progname);
            exit(0);
        } else if (strcmp(argv[1], "-a") == 0)
        {
            attributes |= EFI_VARIABLE_APPEND_WRITE;
            argv += 1;
            argc -= 1;
        } else if (strcmp(argv[1], "-e") == 0)
        {
            esl_mode = 1;
            argv += 1;
            argc -= 1;
        } else if (strcmp(argv[1], "-o") == 0)
        {
            authfile = argv[2];
            argv += 2;
            argc -= 2;
        } else if (strcmp(argv[1], "-engine") == 0)
        {
            engine = argv[2];
            argv += 2;
            argc -= 2;
        } else if (strcmp(argv[1], "-b") == 0)
        {
            hash_mode = argv[2];
            argv += 2;
            argc -= 2;
        } else if (strcmp(argv[1], "-f") == 0)
        {
            file = argv[2];
            argv += 2;
            argc -= 2;
        } else if (strcmp(argv[1], "-g") == 0)
        {
            if (str_to_guid(argv[2], &guid))
            {
                fprintf(stderr, "Invalid GUID %s\n", argv[2]);
                exit(1);
            }
            argv += 2;
            argc -= 2;
        } else if (strcmp(argv[1], "-c") == 0)
        {
            crt_file = argv[2];
            argv += 2;
            argc -= 2;
        } else if (strcmp(argv[1], "-n") == 0)
        {
            var = argv[2];
            argv += 2;
            argc -= 2;
        } else if (strcmp(argv[1], "-s") == 0)
        {
            certfile = argv[2];
            argv += 2;
            argc -= 2;
        } else if (strcmp(argv[1], "-k") == 0)
        {
            key_file = argv[2];
            argv += 2;
            argc -= 2;
        } else if (strcmp(argv[1], "-v") == 0)
        {
            var_file = argv[2];
            argv += 2;
            argc -= 2;
        } else if (strcmp("-t", argv[1]) == 0)
        {
            timestampstr = argv[2];
            argv += 2;
            argc -= 2;
        } else if (strcmp("-w", argv[1]) == 0)
        {
            whole_variable = TRUE;
            argv++;
            argc--;
        } else if (strcmp(argv[1], "-d") == 0)
        {
            sscanf(argv[2], "%d-%d", &delsig, &delentry);
            argv += 2;
            argc -= 2;
        } else
        {
            /* unrecognised option */
            break;
        }
    }

    if (!var)
    {
        usage(progname);
        exit(1);
    }


    for (i = 0; i < ARRAY_SIZE(variables); i++)
    {
        if (strcmp(var, variables[i]) == 0)
        {
            owner = owners[i];
            break;
        }
    }
    if (i == ARRAY_SIZE(variables))
    {
        fprintf(stderr, "Invalid Variable %s\nVariable must be one of: ", var);
        for (i = 0; i < ARRAY_SIZE(variables); i++)
            fprintf(stderr, "%s ", variables[i]);
        fprintf(stderr, "\n");
        exit(1);
    }

    if (delsig == -1 && (! !file + ! !hash_mode + ! !crt_file + ! !whole_variable != 1))
    {
        fprintf(stderr, "must specify exactly one of -w  -f, -b or -c\n");
        exit(1);
    }
    //kernel_variable_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_ciphers();

    if (engine)
    {
        ENGINE_load_builtin_engines();

        e = ENGINE_by_id(engine);
        if (!e)
        {
            fprintf(stderr, "error: Engine %s not found\n", engine);
            return EXIT_FAILURE;
        }
        if (!ENGINE_init(e))
        {
            fprintf(stderr, "error: Engine couldn't initialise\n");
            ENGINE_free(e);
            return EXIT_FAILURE;
        }

        if (!ENGINE_set_default_RSA(e) || !ENGINE_set_default_RAND(e))
        {
            fprintf(stderr, "error: Engine setup failed\n");
            ENGINE_free(e);
            return EXIT_FAILURE;
        }
    }
    name = file ? file : hash_mode;
    if (var_file)
    {
        fd = open(var_file, O_RDONLY);

        if (fd < 0)
        {
            fprintf(stderr, "Failed to read file %s: ", var_file);
            perror("");
            exit(1);
        }
        if (fstat(fd, &st) < 0)
        {
            perror("stat failed");
            exit(1);
        }
        len = st.st_size - sizeof(attributes);
        buf = malloc(st.st_size);
        read(fd, buf, sizeof(attributes));
        read(fd, buf, len);
        st.st_size = len;
        close(fd);

        if (whole_variable)
            esl_mode = TRUE;
    }

    if (delsig != -1)
    {
        if (!var_file)
        {
            int status = get_variable_alloc(variables[i], owners[i], NULL,
                                            &len, (uint8_t **) & buf);
            if (status == ENOENT)
            {
                fprintf(stderr, "Variable %s has no entries\n", variables[i]);
                exit(1);
            }
        }
        EFI_SIGNATURE_LIST *CertList = (EFI_SIGNATURE_LIST *) buf;
        EFI_SIGNATURE_DATA *Cert;
        int size, DataSize = len, count = 0;


        certlist_for_each_certentry(CertList, buf, size, DataSize)
        {
            int Index = 0;

            if (count++ != delsig)
                continue;
            if (delentry == -1)
                goto found;
            certentry_for_each_cert(Cert, CertList)
            {
                if (Index++ == delentry)
                    goto found;
            }
        }
        if (delentry == -1)
            fprintf(stderr, "signature %d does not exist in %s\n", delsig, variables[i]);
        else
            fprintf(stderr, "signature %d-%d does not exist in %s\n", delsig, delentry,
                    variables[i]);
        exit(1);
      found:
        ;
        int certs =
            (CertList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) -
             CertList->SignatureHeaderSize) / CertList->SignatureSize;
        if (certs == 1 || delentry == -1)
        {
            /* delete entire sig list + data */
            DataSize -= CertList->SignatureListSize;
            if (DataSize > 0)
                memcpy(CertList, (void *) CertList + CertList->SignatureListSize,
                       DataSize - ((char *) CertList - buf));
        } else
        {
            int remain = DataSize - ((char *) Cert - buf) - CertList->SignatureSize;
            /* only delete single sig */
            DataSize -= CertList->SignatureSize;
            CertList->SignatureListSize -= CertList->SignatureSize;
            if (remain > 0)
                memcpy(Cert, (void *) Cert + CertList->SignatureSize, remain);
        }
        st.st_size = DataSize;  /* reduce length of buf */
        esl_mode = 1;
    } else if (name)
    {
        fd = open(name, O_RDONLY);
        if (fd < 0)
        {
            fprintf(stderr, "Failed to read file %s: ", name);
            perror("");
            exit(1);
        }
        if (fstat(fd, &st) < 0)
        {
            perror("stat failed");
            exit(1);
        }
        buf = malloc(st.st_size);
        read(fd, buf, st.st_size);
        close(fd);
    } else if (!whole_variable)
    {
        X509 *X = NULL;
        BIO *bio;
        char *crt_file_ext = &crt_file[strlen(crt_file) - 4];

        esl_mode = 1;

        bio = BIO_new_file(crt_file, "r");
        if (!bio)
        {
            fprintf(stderr, "Failed to load certificate from %s\n", crt_file);
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        if (strcasecmp(crt_file_ext, ".der") == 0 || strcasecmp(crt_file_ext, ".cer") == 0)
            /* DER format */
            X = d2i_X509_bio(bio, NULL);
        else
            /* else assume PEM */
            X = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (!X)
        {
            fprintf(stderr, "Failed to load certificate from %s\n", crt_file);
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        BIO_free_all(bio);

        int cert_len = i2d_X509(X, NULL);
        cert_len += sizeof(EFI_SIGNATURE_LIST) + OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData);
        EFI_SIGNATURE_LIST *esl = malloc(cert_len);
        unsigned char *tmp =
            (unsigned char *) esl + sizeof(EFI_SIGNATURE_LIST) + OFFSET_OF(EFI_SIGNATURE_DATA,
                                                                           SignatureData);
        i2d_X509(X, &tmp);
        esl->SignatureListSize = cert_len;
        esl->SignatureSize = (cert_len - sizeof(EFI_SIGNATURE_LIST));
        esl->SignatureHeaderSize = 0;
        esl->SignatureType = EFI_CERT_X509_GUID;

        EFI_SIGNATURE_DATA *sig_data = (void *) esl + sizeof(EFI_SIGNATURE_LIST);

        sig_data->SignatureOwner = guid;

        buf = (char *) esl;
        st.st_size = cert_len;
    }

    if (hash_mode)
    {
        uint8_t hash[SHA256_DIGEST_SIZE];
        EFI_STATUS status;
        int len;

        esl_mode = 1;
        attributes |= EFI_VARIABLE_APPEND_WRITE;
        status = sha256_get_pecoff_digest_mem(buf, st.st_size, hash);
        free(buf);
        if (status != EFI_SUCCESS)
        {
            fprintf(stderr, "Failed to get hash of %s\n", name);
            exit(1);
        }
        buf = (char *) hash_to_esl(&guid, &len, hash);
        st.st_size = len;
    }

    if (esl_mode)
    {
        if (!key_file)
        {
            fprintf(stderr, "Can't update variable%s without a key\n",
                    variable_is_setupmode()? "" : " in User Mode");
            exit(1);
        }
        if (engine)
        {
            pkey = ENGINE_load_private_key(e, key_file, ui_method, &cb_data);
            cb_data.password = NULL;
            cb_data.prompt_info = key_file;
        } else
        {
            BIO *key = BIO_new_file(key_file, "r");
            pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
        }
        if (!pkey)
        {
            fprintf(stderr, "error reading private key %s\n", key_file);
            exit(1);
        }


        BIO *cert_bio = BIO_new_file(certfile, "r");
        X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
        if (!cert)
        {
            fprintf(stderr, "error reading certificate %s\n", certfile);
            exit(1);
        }


        EFI_TIME timestamp;
        time_t t;
        struct tm *tm, tms;
        memset(&timestamp, 0, sizeof(timestamp));
        if (!(attributes & EFI_VARIABLE_APPEND_WRITE))
        {

            if (timestampstr)
            {
                strptime(timestampstr, "%Y-%m-%d %H:%M:%S", &tms);
                tm = &tms;
            } else
            {
                time(&t);
                tm = localtime(&t);
                /* FIXME: currently timestamp is one year into future because of
                 * the way we set up the secure environment  */
            }
            timestamp.Year = tm->tm_year + 1900;
            timestamp.Month = tm->tm_mon + 1;
            timestamp.Day = tm->tm_mday;
            timestamp.Hour = tm->tm_hour;
            timestamp.Minute = tm->tm_min;
            timestamp.Second = tm->tm_sec;
            printf("Timestamp is %d-%d-%d %02d:%02d:%02d\n", timestamp.Year,
                   timestamp.Month, timestamp.Day, timestamp.Hour, timestamp.Minute,
                   timestamp.Second);
        }

        /* signature is over variable name (no null and uc16
         * chars), the vendor GUID, the attributes, the
         * timestamp and the contents */
        int j = 0, varlen = 0;

        wchar_t str[100];
        do
        {
            str[j] = var[j];
        }
        while (var[j++] != '\0');

        varlen = (j - 1) * sizeof(wchar_t);
        int signbuflen = varlen + sizeof(EFI_GUID) + sizeof(UINT32) + sizeof(EFI_TIME) + st.st_size;
        char *signbuf = malloc(signbuflen);
        char *ptr = signbuf;
        memcpy(ptr, str, varlen);
        ptr += varlen;
        memcpy(ptr, owners[i], sizeof(*owners[i]));
        ptr += sizeof(*owners[i]);
        memcpy(ptr, &attributes, sizeof(attributes));
        ptr += sizeof(attributes);
        memcpy(ptr, &timestamp, sizeof(timestamp));
        ptr += sizeof(timestamp);
        memcpy(ptr, buf, st.st_size);

        printf("Authentication Payload size %d\n", signbuflen);
        BIO *bio = BIO_new_mem_buf(signbuf, signbuflen);
        PKCS7 *p7 =
            PKCS7_sign(NULL, NULL, NULL, bio,
                       PKCS7_BINARY | PKCS7_PARTIAL | PKCS7_DETACHED | PKCS7_NOATTR);
        const EVP_MD *md = EVP_get_digestbyname("SHA256");
        PKCS7_sign_add_signer(p7, cert, pkey, md, PKCS7_BINARY | PKCS7_NOATTR);
        PKCS7_final(p7, bio, PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOATTR);



        int sigsize = i2d_PKCS7(p7, NULL);

        EFI_VARIABLE_AUTHENTICATION_2 *var_auth =
            malloc(sizeof(EFI_VARIABLE_AUTHENTICATION_2) + sigsize);
        var_auth->TimeStamp = timestamp;
        var_auth->AuthInfo.CertType = EFI_CERT_TYPE_PKCS7_GUID;
        var_auth->AuthInfo.Hdr.dwLength = sigsize + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData);
        var_auth->AuthInfo.Hdr.wRevision = 0x0200;
        var_auth->AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
        unsigned char *tmp = var_auth->AuthInfo.CertData;
        i2d_PKCS7(p7, &tmp);
        ERR_print_errors_fp(stderr);

        printf("Signature of size %d\n", sigsize);
        /* new update now consists of two parts: the
         * authentication header with the signature and the
         * payload (the original esl) */
        int siglen = OFFSET_OF(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData) + sigsize;
        char *newbuf = malloc(siglen + st.st_size);

        memcpy(newbuf, var_auth, siglen);
        memcpy(newbuf + siglen, buf, st.st_size);

        free(buf);
        free(var_auth);
        buf = newbuf;
        st.st_size = siglen + st.st_size;
        esl_mode = 0;
        if (authfile)
        {
            FILE *f = fopen(authfile, "wb");
            if (!f)
            {
                fprintf(stderr, "failed to open auth file %s: for writing ", authfile);
                perror("");
                exit(1);
            }
            if (fwrite(buf, 1, st.st_size, f) != st.st_size)
            {
                perror("Did not write enough bytes to efi file");
                exit(1);
            }
            fclose(f);
            exit(1);
        }

    }

    if (esl_mode)
    {
        ret = set_variable_esl(var, owner, attributes, st.st_size, buf);
    } else
    {
        ret = set_variable(var, owner, attributes, st.st_size, buf);
    }

    if (ret == EACCES)
    {
        fprintf(stderr, "Cannot write to %s, wrong filesystem permissions\n", var);
        exit(1);
    } else if (ret != 0)
    {
        fprintf(stderr, "Failed to update %s: ", var);
        perror("");
        exit(1);
    }

    return 0;
}
