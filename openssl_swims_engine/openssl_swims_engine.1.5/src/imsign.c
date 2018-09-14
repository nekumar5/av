/* imsign.c*/
/* author Russell Leake (abraxas), Manish Mahajan(SWIMS), Burhan Wani (STO)
 * 
 * version 0.1
 * version 0.2 : 
 * 	Added support for stage server and prod server 
 *      Added support for decryption using asymmetric private key in SWIMS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <curl/curl.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#ifdef WIN32
#pragma warning(disable : 4996)
#include <limits.h>
#include <stdarg.h>
#include <Winsock2.h>
#include <io.h>
#else
#include <unistd.h>
#include <arpa/inet.h>
#endif
#include <fcntl.h>
#include <openssl/sha.h>

// local includes
#include "imsign.h"
#include "certs.h"
#include "b64.h"
#include "jsmn.h"

//#define TESTING

/// Server URL for the security system.  Currently this is the SWIMS server
#define SERV_URL "https://abraxas.cisco.com/SignEngine/sign.jsp"
/// Following URLs for SWIMS server
#ifdef TESTING
#define SWIMS_FETCHPUBKEY_URL "https://swims-stg.cisco.com/abraxas/fetchpublickey"
#define SWIMS_SIGNHASH_URL "https://swims-stg.cisco.com/abraxas/signhash"
#define SWIMS_SIGNPADDEDHASH_URL "https://swims-stg.cisco.com/abraxas/signpaddedhash"
#define SWIMS_SIGNPLAINHASH_URL "https://swims-stg.cisco.com/abraxas/signplainhash"
#define SWIMS_ENCRYPT_URL "https://swims-stg.cisco.com/abraxas/encrypt"
#define SWIMS_DECRYPT_URL "https://swims-stg.cisco.com/abraxas/decrypt"

#else 

#define SWIMS_FETCHPUBKEY_URL "https://swims.cisco.com/abraxas/fetchpublickey"
#define SWIMS_SIGNHASH_URL "https://swims.cisco.com/abraxas/signhash"
#define SWIMS_SIGNPADDEDHASH_URL "https://swims.cisco.com/abraxas/signpaddedhash"
#define SWIMS_SIGNPLAINHASH_URL "https://swims.cisco.com/abraxas/signplainhash"
#define SWIMS_ENCRYPT_URL "https://swims.cisco.com/abraxas/encrypt"
#define SWIMS_DECRYPT_URL "https://swims.cisco.com/abraxas/decrypt"
#endif
///Hash lengths
#define SHA1_OID_LEN            (120/8) //120 bits
#define SHA1_LEN                (160/8) //160 bits
#define OID_PADDED_SHA1_LEN     (SHA1_OID_LEN + SHA1_LEN)

#define SHA2_OID_LEN            (152/8) //152 bits

#define SHA256_LEN              (256/8) //256 bits
#define OID_PADDED_SHA256_LEN   (SHA2_OID_LEN + SHA256_LEN)

#define SHA384_LEN              (384/8) //384 bits
#define OID_PADDED_SHA384_LEN (SHA2_OID_LEN + SHA384_LEN)

#define SHA512_LEN              (512/8) //512 bits
#define OID_PADDED_SHA512_LEN (SHA2_OID_LEN + SHA512_LEN)

tGlobalData gData; ///< Master global data instance
char *gCertFileName = NULL;  ///< Temporary certificate file name

#if 0
////////////////////////////////////////////////////////////////////////////////
/// \fn void hexdump (int cnt, unsigned char *data)
///
/// \brief Dumps a hexdecimal buffer
///
/// \param data - data to dump
/// \param cnt - number of bytes to dump
///
/// \returns void
////////////////////////////////////////////////////////////////////////////////
void hexdump (unsigned char *data, int cnt)
{
	int i;
	int run;
	int offset;

	offset = 0;
	while (cnt) {
		printf ("%04X : ", offset);
		if (cnt >= 16)
			run = 16;
		else
			run = cnt;
		cnt -= run;
		for (i = 0; i < run; i++)
			printf ("%02X ", (unsigned int) data[i]);
		printf (": ");
		for (i = 0; i < run; i++)
			printf ("%c", isprint (data[i]) ? data[i] : '.');
		printf ("\n");
		data = &data[16];
		offset += run;
	}
}
#endif

////////////////////////////////////////////////////////////////////////////////
/// \fn int jsoneq (const char *json, jsmntok_t *tok, const char *s)
///
/// \brief looks for a token string in JSON string
///
/// \param json - JSON string
/// \param tok  - JSON token
/// \param s    - token string to be look for.
///
/// \returns int
////////////////////////////////////////////////////////////////////////////////
static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

////////////////////////////////////////////////////////////////////////////////
/// \fn void remove_newline_ascii(char *buf, char *outBuf, int len)
///
/// \brief Removes consecutive '\' and 'n' ascii characters.
///
/// \param buf - input string
/// \param outBuf - output string is stored in outBuf
/// \param len - len of buf.
///
/// \returns void
////////////////////////////////////////////////////////////////////////////////
static void remove_newline_ascii(char *buf, char *outBuf, int len) {
    int i = 0, idx = 0;
    for(idx = 0;idx < len;idx++) {
        if((buf[idx] == 0x5C) && (idx<len-1)?(buf[idx+1] == 0x6E):0) {
            idx++;
        } else {
            outBuf[i] = buf[idx];
            i++;
        }
    }
    outBuf[i]='\0';
}


////////////////////////////////////////////////////////////////////////////////
/// \fn size_t write_func( void *ptr, size_t size, size_t nmemb, void *stream)
///
/// \brief Callback function from CURL request upon successful reception of 
///  data.
///
/// This function is a callback function prototyped by the CURL library to 
/// handle the reception of data from HTTP requests.
///
/// \param ptr - A memory pointer to the data
///
/// \param size - The size of each data element passed
///
/// \param nmemb - The number of elements passed
///
/// \param stream - Defined by the WRITE_DATA attribute in the request instance.
/// 
/// \return Number of bytes processed
///
/// \static
////////////////////////////////////////////////////////////////////////////////
static size_t
write_func( void *ptr, size_t size, size_t nmemb, void *stream) {
    char *data = (char *)ptr;
    int   idx, r;
    jsmn_parser p;
    jsmntok_t t[128];
    char *token_val = NULL;

    jsmn_init(&p);
    r = jsmn_parse(&p, data, strlen(data), t, sizeof(t)/sizeof(t[0]));

    if(r < 0) {
        printf("Failed to parse JSON: %d\n", r);
        printf("JSON data: %s\n", data);
    } else {
        for(idx = 1; idx < r; idx++) {
            if(!jsoneq(ptr, &t[idx], "signature") ||
               !jsoneq(ptr, &t[idx], "publicKey") || !jsoneq(ptr, &t[idx], "data")) {
                token_val = (char*)malloc(t[idx+1].end-t[idx+1].start +1);
                
                remove_newline_ascii((char*)(ptr+t[idx+1].start), token_val, t[idx+1].end-t[idx+1].start);

                gData.result_len = decode((unsigned char*)token_val, 
                                          strlen(token_val)+1,
                                          (unsigned char *)gData.result,
                                          kRETURN_BUFFER_SIZE);
                
                gData.code = eCode_Success;
                free(token_val);
                // We only want to explicitly break if we have received a
                // signature, as a signature response will also include a
                // publicKey entry.
                if(!jsoneq(ptr, &t[idx], "signature")) {
                    break;
                }
            } else if(!jsoneq(ptr, &t[idx], "errorCode")) {
                printf("%s\n",data);
                fflush(stdout);
                gData.result_len = 0;
                break;
            }
        }
    }

    for(idx=0; idx < gData.result_len; idx++) {
        if(stream) {
            // Write out to file
            if(write((long int)stream, (char *)gData.result, gData.result_len) != gData.result_len) {
                debug(LOG_LOUD, "ERROR: writing to file");
            }
       }
       debug(LOG_LOUD, "%02X",gData.result[idx]&0xFF);
       if((idx-3)%4 == 0)
          debug(LOG_LOUD, " ");
       if((idx-15)%16 == 0)
          debug(LOG_LOUD, "\n");
   }
   
   return size*nmemb;
}

////////////////////////////////////////////////////////////////////////////////
/// \fn void make_request(int o_fd, char *postdata)
///
/// \brief Submit a request to the SWIMS server
///
/// This module submits a preassembled post string to the Abraxis server.  It
/// initializes the CURL instance, sets up necessary attributes, and submits
/// the request.
/// 
/// \param o_fd - This is a file descriptor to write resulting data from the 
///               SWIMS server.  If NULL, then it is assumed that the
///               data will be transferred to the result buffer in the master
///               global data structure.
///
/// \param postdata - A string of POST data to send to the URL.
///
/// \note The URL is globally defined
///
/// \static
////////////////////////////////////////////////////////////////////////////////
static void
make_request(int o_fd, tGlobalData *gData)
   {
   CURL *c;
   CURLcode ccode;
   struct curl_slist *chunk = NULL;

   char *postdata = gData->postdata;
   printf(" postdata in make_request :  %s \n", postdata);
   curl_global_init(CURL_GLOBAL_ALL);

   c = curl_easy_init();

   do {
      if((ccode = curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,
         write_func)) != CURLE_OK)
            {
            printf("Error (line %d): %s\n", __LINE__, curl_easy_strerror(ccode));
            continue;
            }

      if(o_fd > 0)
         {
         if((ccode = curl_easy_setopt(c, CURLOPT_WRITEDATA,
            o_fd)) != CURLE_OK)
            {
            printf("Error (line %d): %s\n", __LINE__, curl_easy_strerror(ccode));
            continue;
            }
         }
      else if((ccode = curl_easy_setopt(c, CURLOPT_WRITEDATA,
            NULL)) != CURLE_OK)
         {
         printf("Error (line %d): %s\n", __LINE__, curl_easy_strerror(ccode));
         continue;
         }

      if((ccode = curl_easy_setopt(c, CURLOPT_URL, gData->url)) != CURLE_OK)
            {
            printf("Error (line %d): %s\n", __LINE__, curl_easy_strerror(ccode));
            continue;
            }

      if((ccode = curl_easy_setopt(c, CURLOPT_POSTFIELDS, postdata)) != CURLE_OK)
            {
            printf("Error (line %d): %s\n", __LINE__, curl_easy_strerror(ccode));
            continue;
            }

      if((ccode = curl_easy_setopt(c, CURLOPT_CAINFO, gCertFileName)) != CURLE_OK)
            {
            printf("Error (line %d): %s\n", __LINE__, curl_easy_strerror(ccode));
            continue;
            }

      if((ccode = curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1)) != CURLE_OK)
            {
            printf("Error (line %d): %s\n", __LINE__, curl_easy_strerror(ccode));
            continue;
            }

      chunk = curl_slist_append(chunk, "User-agent: openssl_swims_engine/1.5");
      chunk = curl_slist_append(chunk, "Content-Type: application/json");
      chunk = curl_slist_append(chunk, "Accept: application/json");
      if((ccode = curl_easy_setopt(c, CURLOPT_HTTPHEADER, chunk)) != CURLE_OK)
            {
            printf("Error (line %d): %s\n", __LINE__, curl_easy_strerror(ccode));
            continue;
            }

      // Set cURL to verbose if logging has been turned up
      if(gData->debug > 8)
         if((ccode = curl_easy_setopt(c, CURLOPT_VERBOSE, TRUE)) != CURLE_OK)
            {
            printf("Error (line %d): %s\n", __LINE__, curl_easy_strerror(ccode));
            continue;
            }

      
      if((ccode = curl_easy_setopt(c, CURLOPT_POST,
            TRUE)) != CURLE_OK)
            {
            printf("Error (line %d): %s\n", __LINE__, curl_easy_strerror(ccode));
            continue;
            }

      if((ccode = curl_easy_perform(c)) != CURLE_OK)
            {
            printf("Error (line %d): %s\n", __LINE__, curl_easy_strerror(ccode));
            continue;
            }
   } while (0);

   curl_easy_cleanup(c);

   curl_global_cleanup();
   }

////////////////////////////////////////////////////////////////////////////////
/// \fn void process_result(tGlobalData *data)
///
/// \brief Process the results of a reqest from the security server.
///
/// After a request has successfully returned fromt the 
///
/// \param  data - Pointer to data structure containing instance information
///
/// \static
////////////////////////////////////////////////////////////////////////////////
static int 
process_result(tGlobalData *data, char *outBuf, int outBufLen)
   {
   int retCode = TRUE;
   int i;
/*
	printf("result from server :");
	for(i=0;i<data->result_len;i++){
		printf("%c", data->result[i]);
	}
*/
	if(data->result_len > outBufLen)
      {
      debug(LOG_ERROR, "outBuf too small (%d) for result (%d)!\n",
            outBufLen, data->result_len);

      retCode = FALSE;
      }
   else if(data->code == eCode_Success)
      {
      debug(LOG_DEBUG, "Operation Successful\n");
      memcpy(outBuf, data->result, data->result_len);
      retCode = data->result_len;
      }
   else
      {
      debug(LOG_ERROR, "Server Request Failed!\n");
      retCode = FALSE;
      }

   return retCode;
   }

////////////////////////////////////////////////////////////////////////////////
/// \fn void initStruct(tGlobalData *data)
///
/// \brief        
///
/// \param   data - global data structure to initialize
/// 
/// \static
////////////////////////////////////////////////////////////////////////////////
void initStruct(tGlobalData *data)
   {
   data->debug = 0;           /// assign default debug level here
   data->code  = 0;
   data->url   = SERV_URL;    /// set up default URL
   strncpy(data->postdata, "", kPOST_BUFFER_SIZE);
   strncpy(data->ticket, "", kTICKET_BUFFER_SIZE);
   memset(data->result, 0, kRETURN_BUFFER_SIZE);
   }

////////////////////////////////////////////////////////////////////////////////
/// \fn void createCerts(void)
///
/// \brief        
///
////////////////////////////////////////////////////////////////////////////////
 int
createCerts(void)
   {
   int   retCode = 0;
   FILE *stream;
   int   bytesWritten = 0;

   if(gCertFileName != NULL)
      {
      return retCode;
      }

   gCertFileName = tmpnam(NULL);

   debug(LOG_DEBUG, "%s: Certificate file set to: %s\n",
         __FUNCTION__,
         gCertFileName);

   if(gCertFileName != NULL)
      {
#ifdef WIN32
      stream = fopen(gCertFileName, "wb");
#else
      stream = fopen(gCertFileName, "w");
#endif

      if(stream != NULL)
         {
         while(retCode != sizeof(swims_root_ca_pem))
            {
            retCode = fwrite(swims_root_ca_pem, 1, sizeof(swims_root_ca_pem), stream);
            bytesWritten += retCode;

            if(retCode <= 0)
               break;
            }

         fclose(stream);
         }
      else
         {
         // Error opening file
         gCertFileName = NULL;
         retCode = -1;
         }
      }

   return retCode;
   }

////////////////////////////////////////////////////////////////////////////////
/// \fn int read_ticket_file
///
/// \brief  Read ticket into buffer
///
/// \public
////////////////////////////////////////////////////////////////////////////////
int
read_ticket_file(char *filename, char *buf)
   {
   FILE *stream;
   int retCode   = 0;
   int bytesRead = 0;
   int len;
   char *temp;

#ifdef WIN32
      stream = fopen(filename, "rb");
#else
      stream = fopen(filename, "r");
#endif

      if(stream != NULL)
         {
         retCode = fread(buf, 1, kTICKET_BUFFER_SIZE, stream);
         while ((temp = strstr(buf, "\n")) != NULL) {
            /* remove \n's in ticket */
            len = strlen(buf);
            memmove(temp, temp + 1, len);
            retCode--;
         }
         bytesRead += retCode;

         fclose(stream);
         }
      else
         debug(LOG_ERROR, "ERROR-%s: Could not open file %s\n",
               __FUNCTION__,
               filename);

   return retCode;
   }

////////////////////////////////////////////////////////////////////////////////
/// \fn int process_post
///
/// \brief  Process the post to the server
///
/// \public
////////////////////////////////////////////////////////////////////////////////
int process_post(char *outBuf, int outBufLen)
   {
   debug((!strcmp(gData.url,SERV_URL) ? LOG_DEBUG : LOG_NORMAL), "%s: Requesting from %s\n", 
         __FUNCTION__,
         gData.url);

   debug(LOG_DEBUG, "%s: Requesting %s\n", 
         __FUNCTION__,
         gData.postdata);

   debug(LOG_DEBUG, "Requesting %s operation from server; please wait a moment . . . \n", 
         gData.cmd);

   make_request(-1, &gData);

   return process_result(&gData, outBuf, outBufLen);
   }

////////////////////////////////////////////////////////////////////////////////
/// \fn int get_hash_index_type
///
/// \brief  Identify hash algorithm using hash lengh. If hash is
///         pre-padded with OID, then skip OID bytes and return
///         starting index of actual hash.
///
/// \public
////////////////////////////////////////////////////////////////////////////////
int
get_hash_index_type(int len, char *hashAlg) {
    int hi = 0; //hash starting index.
    switch(len) {
        case OID_PADDED_SHA1_LEN:
            hi = SHA1_OID_LEN;
        case SHA1_LEN:
            strcpy(hashAlg, "SHA1");
            break;
        case OID_PADDED_SHA256_LEN:
            hi = SHA2_OID_LEN;
        case SHA256_LEN:
            strcpy(hashAlg, "SHA256");
            break;
        case OID_PADDED_SHA384_LEN:
            hi = SHA2_OID_LEN;
        case SHA384_LEN:
            strcpy(hashAlg, "SHA384");
            break;
        case OID_PADDED_SHA512_LEN:
            hi = SHA2_OID_LEN;
        case SHA512_LEN:
            strcpy(hashAlg, "SHA512");
            break;
        default:
            strcpy(hashAlg, "SHA512");
            debug(LOG_ERROR, "\nUnknown hash length %d\n", len);
    }
    return hi;
}

////////////////////////////////////////////////////////////////////////////////
/// \fn int generate_swims_postdata
///
/// \brief  Generate JSON formatted string from input parameters.
///
/// \public
////////////////////////////////////////////////////////////////////////////////
int
generate_swims_postdata(char *type, char **list, int num_toks, char *hash, int len , char* padding) {
    char *tag = NULL;
    char *val = NULL;
    char *tStr = NULL;
	char* temp;
    char hostname[1024];
    char hashAlg[10];
    char intBuf[len*4];
	char tempBuf[len+1];
    struct passwd *pw;
    int  i = 0, hi = 0; 
    int offset = 0, bytes = 0;

    //get client heuristics
    pw = getpwuid(geteuid());
    gethostname(hostname, 1023);

    //JSON start string
    strncpy(gData.postdata, "{", 1);
    offset = 1;

    //Fill in user provided parameters in JSON format
    for(i=0; i<num_toks; i++) {
        tStr = strdup(list[i]);
        tag = strtok( tStr, "=" );
        /* its unlikely to have \n character in parameter */
        val = strtok( NULL, "\n" );
        if(val == NULL) {
            val = "";
        }
        if(!strcmp(tag, "ticket")) {
            if((i = read_ticket_file(val, gData.ticket)) == 0) {
                printf("Error (line %d): reading ticket file\n", __LINE__);
                free(tStr);
                return -1;
            }
            bytes = sprintf(gData.postdata + offset, "\"%s\":\"%s\",", tag, gData.ticket);
        } else {
            bytes = sprintf(gData.postdata + offset, "\"%s\":\"%s\",", tag, val);
        }

        if(bytes < 0) {
            free(tStr);
            return -1;
        }

        offset += bytes;

        free(tStr);
    }

    if(hash) {
        if(!strcmp(type, "sign_hash")) {
            // Identify hash algorithm from its length.
            // If hash is prepended with OID, then return
            //    actual hash starting index.
            hi = get_hash_index_type(len, &hashAlg[0]);

            if(hi == 0) {
                //Encrypt hash. Plain hash is sent for "rsautl" command.
                gData.url = SWIMS_SIGNPLAINHASH_URL;
            } else {
                //Sign hash. OID padded hash is sent for dgst command.
                gData.url = SWIMS_SIGNHASH_URL;
            }

            for (i = 0; i < (len-hi); i++) {
                // for ASCII translation
                // (i+hi): skip OID bytes.
                sprintf((char *)&intBuf[i*2], "%01X", hash[i+hi] >> 4 & 0xf );
                sprintf((char *)&intBuf[i*2+1], "%01X", hash[i+hi] & 0xf);
            }
            bytes = sprintf(gData.postdata + offset, "\"hashAlgorithm\":\"%s\",\"hash\":\"%s\",", hashAlg, intBuf);
            offset += bytes;
        } else if(!strcmp(type, "encrypt_hash")) {    //encrypt_hash
            for (i = 0; i < len; i++) {
                // for ASCII translation
                sprintf((char *)&intBuf[i*2], "%01X", hash[i] >> 4 & 0xf );
                sprintf((char *)&intBuf[i*2+1], "%01X", hash[i] & 0xf);
            }
            //for signPaddedHash, hashAlgorithm is not used. Hardcoding it to SHA256.
            bytes = sprintf(gData.postdata + offset, "\"hashAlgorithm\":\"SHA256\",\"hash\":\"%s\",", intBuf);
            offset += bytes;
        } else if (!strcmp(type, "decrypt_sig")) { // decrypt 
	    gData.url = SWIMS_DECRYPT_URL;
            for (i = 0; i < len; i++) {
                sprintf((char *)&tempBuf[i], "%c", hash[i]);
            }
            while ((temp = strstr(tempBuf, "\n")) != NULL) {
                /* remove \n's  */
                len = strlen(tempBuf);
                memmove(temp, temp + 1, len);
            }
            bytes = sprintf(gData.postdata + offset, "\"data\":\"%s\",\"mechanism\":\"%s\",", tempBuf, padding);
            offset += bytes;
        }
    }
    //Add client heuristics to JSON string
    /*"clientHeuristics": [{"name": "buildServerHostName","value": "KARTHIRA-M-Q6H8"},{"name": "buildServerHostAddress","value": "10.0.0.1"},{"name": "loggedOnUser","value": "KARTHIRA"}*/

    bytes = sprintf(gData.postdata + offset, "\"clientHeuristics\": [{\"name\":\"buildServerHostName\",\"value\":\"%s\"},{\"name\":\"loggedOnUser\",\"value\":\"%s\"}]}", hostname, pw?pw->pw_name:"");
    offset += bytes;

    return offset;
}

////////////////////////////////////////////////////////////////////////////////
/// \fn int get_pubkey
///
/// \brief  Get the public key
///
/// \public
////////////////////////////////////////////////////////////////////////////////
int
get_pubkey(char **tok_list, int num_toks, char *outBuf, int outBufLen)
   {
   gData.code = eCode_Failure;

   gData.url = SWIMS_FETCHPUBKEY_URL;

   gData.type = eType_PubKey;

   generate_swims_postdata("fetch_public_key", tok_list, num_toks, NULL, 0, "");

   return process_post(outBuf, outBufLen);
   }

#if 0 // now as a part of fetch_public_key
////////////////////////////////////////////////////////////////////////////////
/// \fn int get_pubexp
///
/// \brief  Get the public key exponent
///
/// \public
////////////////////////////////////////////////////////////////////////////////
int
get_pubexp(char *url, char* product_name, char *key_type, char *outBuf, 
            int outBufLen)
   {
   if(!product_name || !key_type)
      return 0; 

   gData.code = eCode_Failure;

   if(url)
      {
      gData.url = url;
      }
   else
      {
      gData.url = SERV_URL;
      }

   gData.type = eType_PubExp;

   sprintf(gData.postdata, "REQ_TYPE=fetch_pubexp&PRODUCT_NAME=%s&KEY_TYPE=%s",
         product_name,
         key_type);

   return process_post(outBuf, outBufLen);
   }
#endif


int 
process_decrypt_op(char *type, char **tok_list, int num_toks, 
                   char *hash, int len, char *outBuf, int outBufLen, char* padding)
   {
   gData.code = eCode_Failure;

   if(!strcmp(type, "decrypt_sig")) {
        gData.url = SWIMS_DECRYPT_URL;
   }

   gData.type = eType_SignHash;//TODO no use so far

   generate_swims_postdata(type, tok_list, num_toks, hash, len, padding);

   return process_post(outBuf, outBufLen);
   }


int decrypt(char **tok_list, int num_toks, char *buf, int len, char *outBuf, int outBufLen, char* padding)
{
   return process_decrypt_op("decrypt_sig", tok_list, num_toks, buf, len, outBuf, outBufLen, padding);
}

////////////////////////////////////////////////////////////////////////////////
/// \fn int process_encrypt_op
///
/// \brief  
///
/// \public
////////////////////////////////////////////////////////////////////////////////
int 
process_encrypt_op(char *type, char **tok_list, int num_toks, 
                   char *hash, int len, char *outBuf, int outBufLen)
   {
   gData.code = eCode_Failure;

   if(!strcmp(type, "encrypt_hash")) {
        gData.url = SWIMS_SIGNPADDEDHASH_URL;
   } else {
        gData.url = SWIMS_SIGNHASH_URL;
   }

   gData.type = eType_SignHash;

   generate_swims_postdata(type, tok_list, num_toks, hash, len, "");

   return process_post(outBuf, outBufLen);
   }

////////////////////////////////////////////////////////////////////////////////
/// \fn int sign
///
/// \brief  encrypt PKCS1 padded hash
///
/// \public
////////////////////////////////////////////////////////////////////////////////
int 
sign(char **tok_list, int num_toks, char *buf, int len, char *outBuf, int outBufLen)
   {
   //SWIMS does pkcs#1 padding internally. Hence no need to manually 
   // add padding and call signpaddedhash url.
   return process_encrypt_op("sign_hash", tok_list, num_toks, buf, len, outBuf, outBufLen);
   }

////////////////////////////////////////////////////////////////////////////////
/// \fn int encrypt_hash
///
/// \brief  encrypt hash
///
/// \public
////////////////////////////////////////////////////////////////////////////////
int 
encrypt_hash(char **tok_list, int num_toks, char *buf, int len, char *outBuf, int outBufLen)
   {
   return process_encrypt_op("encrypt_hash", tok_list, num_toks, buf, len, outBuf, outBufLen);
   }
