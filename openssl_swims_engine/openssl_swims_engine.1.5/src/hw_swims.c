/* hw_swims.c */
/* imported from hw_abraxas.c */
/* Originally written by Russell Leake for Cisco Systems, Inc. 2009
 *
 * Version 1.0       Corrected HASH to IMAGE_HASH for non-ticketing items
 * Version 1.1        
 * Version 1.2       Flush stdout after printing error
 *
 * Modified by Manish Mahajan for Cisco Systems, Inc. 2016
 * Version 1.3      Added SWIMS support
 * Version 1.5      Added decrypt support using asymmetric keys in SWIMS

/* (C) COPYRIGHT International Business Machines Corp. 2001 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/dso.h>
#include <openssl/engine.h>

#include <curl/curl.h>
#include <config.h>
#include "imsign.h"

#include "hw_swims_err.h"

#define MAX_NUM_TOKS     64

static int swims_destroy(ENGINE *e);
static int swims_init(ENGINE *e);
static int swims_finish(ENGINE *e);
static int swims_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)());

int rsa_ex_idx = 0;


// global state variable
static char swims_loaded = 0;

#ifndef OPENSSL_NO_RSA  
/* RSA stuff */
static int swims_priv_enc(int len, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
static int swims_priv_dec(int len,const unsigned char *from,unsigned char *to, RSA *rsa,int padding);
#endif

/* The definitions for control commands specific to this engine */
//#define SWIMS_CMD_URL		ENGINE_CMD_BASE
static const ENGINE_CMD_DEFN swims_cmd_defns[] = {
	{0, NULL, NULL, 0}
	};

#ifndef OPENSSL_NO_RSA  
/* Our internal RSA_METHOD that we provide pointers to */
static RSA_METHOD swims_rsa =
        {
        "SWIMS RSA method",
        NULL,                                // rsa_pub_enc
        NULL,                                // rsa_pub_dec
        swims_priv_enc,                    // rsa_priv_enc
        swims_priv_dec,                                // rsa_priv_dec
        NULL,                                // rsa_mod_exp
        NULL,                                // rsa_mod_exp_mongomery
        NULL,                                // init
        NULL,                                // finish
        0,                                   // RSA flag
        NULL,                                // app_data
        NULL,                                // openssl sign
        NULL,                                // openssl verify
        NULL                                 // keygen
        };
#endif

/* Constants used when creating the ENGINE */
static const char *engine_swims_id = "swims";
static const char *engine_swims_name = "SWIMS crypto support";

#if 0
////////////////////////////////////////////////////////////////////////////////
/// \fn void hexdump (int cnt, unsigned char *data)
///
/// \brief Dumps a hexdecimal buffer
///
/// \param cnt - number of bytes to dump
/// \param data - data to dump
///
/// \returns void
////////////////////////////////////////////////////////////////////////////////
static void hex_dump (unsigned char *data, int cnt)
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// \fn int print_tokens(char *list[])
///
/// \brief 
/// 
/// \param list
///
/// \return 
///
/// \note 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
print_tokens(char *list[MAX_NUM_TOKS], int num_toks)
   {
   unsigned char  i = 0; 

   printf(" token_list %p\n", list);
   for(i = 0; i < num_toks; i++)
      {
      if(list[i] != NULL)
         {
         printf(" [%d] = %s\n", i, list[i]);
         }
      }

   return 0;
   }
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// \fn int get_token_value(char *list[], int num_toks, const char *str)
///
/// \brief Tokenize a string with a delimeter and place into an array
/// 
/// \param list
/// \param str
/// \param delims
///
/// \return 
///
/// \note 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
char *
get_token_value(char *list[MAX_NUM_TOKS], int num_toks, const char *str)
   {
   char *result = NULL;
   unsigned char  i = 0; 
   char  *tStr = NULL;

   for(i=0; i<num_toks; i++)
      {
      tStr = strdup(list[i]);
      result = strtok( tStr, "=" );

      if(strcmp(result, str) == 0)
         {
         result = strtok( NULL, "=" );
         break;
         }
      else
         {
         result = NULL;
         }
      free(tStr);
      }

   return result;
   }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// \fn int tokenize(char *list[], char *str, char *delims)
///
/// \brief Tokenize a string with a delimeter and place into an array
/// 
/// \param list
/// \param str
/// \param delims
///
/// \return 
///
/// \note 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
tokenize(char *list[MAX_NUM_TOKS], const char *str, const char *delims)
   {
   char *result = NULL;
   unsigned char  i = 0; 
   char  *tStr;

   tStr = strdup(str);

   if(tStr)
      {
      result = strtok( tStr, delims );

      while( result != NULL ) 
         {
         // Mallocs memory for the new string
         list[i++] = strdup(result);
         //printf("dupped %s\n", list[i-1]);
         result = strtok( NULL, delims);
         }

      free(tStr);
      }

   return i;
   }


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// \fn int free_tokens(char *list[])
///
/// \brief 
/// 
/// \param list
///
/// \return 
///
/// \note 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
free_tokens(char *list[MAX_NUM_TOKS], int num_toks)
   {
   unsigned char  i = 0; 

   for(i = 0; i < num_toks; i++)
      {
      if(list[i] != NULL)
         {
         free(list[i]);
         }

      list[i] = NULL;
      }

   return 0;
   }
#ifdef ENGINE_DYNAMIC_SUPPORT
static
#endif
int swims_priv_dec(int len,const unsigned char *from,unsigned char *to, 
		RSA *rsa,int padding) 
{
    int outlen = 0;
    char *tok_list[MAX_NUM_TOKS];
    int num_toks = 0;
    char *key_id = RSA_get_ex_data(rsa, rsa_ex_idx);
	
    if(!key_id){
        SWIMSerr(SWIMS_F_SWIMS_PRIVATE_ENCRYPT, SWIMS_R_MISSING_KEY_COMPONENTS);
        printf("Internal Error:  Need key_id\n");
        goto err;
    }
    num_toks = tokenize(tok_list, key_id, ",");
    switch(padding){
        case RSA_PKCS1_PADDING:
            printf("pkcs1 padding \n");
            outlen = decrypt(tok_list, num_toks, (char *)from, len, (char *)to, RSA_size(rsa) , "RSA/ECB/PKCS1v1_5");
            break;
        case RSA_PKCS1_OAEP_PADDING: 
            printf("oaep padding \n");
            outlen = decrypt(tok_list, num_toks, (char *)from, len, (char *)to, RSA_size(rsa), "RSA/ECB/OAEPPadding");
            break;
        case RSA_NO_PADDING:
            printf("no padding \n");
            outlen = decrypt(tok_list, num_toks, (char *)from, len, (char *)to, RSA_size(rsa), "RSA/ECB/NoPadding");
            break;
        default:
            SWIMSerr(SWIMS_F_SWIMS_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
            printf("unknown padding type");
            break;
    }
    if(!outlen)
        SWIMSerr(SWIMS_F_SWIMS_PRIVATE_ENCRYPT, SWIMS_R_REQUEST_FAILED);

err:
   // free the tokens
    if(num_toks)
        free_tokens(tok_list, num_toks);
    return(outlen);
}
////////////////////////////////////////////////////////////////////////////////
/// \fn int swims_priv_enc(int len, const unsigned char *from, unsigned char *to, 
///                           RSA *rsa, int padding)
///
/// \brief Encrypts a piece of data with the private modulus
///
/// This is the SWIMS specific implementation for encrypting data.  This 
/// function accepts both PKCS1_PADDING objects as well as NO_PADDING objects.
/// Each require different SWIMS interfaces.
///
/// \param len - length of the data to encrypt
/// \param *from - buffer of the data to encrypt
/// \param *to - buffer to write encrypted data into
/// \param *RSA - pointer to the RSA structure.  Can be used to access key 
///               information
/// \param padding - type of padding used.
///
/// \returns int - number of bytes written into "to"
////////////////////////////////////////////////////////////////////////////////
#ifdef ENGINE_DYNAMIC_SUPPORT
static 
#endif
int swims_priv_enc(int len, const unsigned char *from, unsigned char *to,
	     RSA *rsa, int padding)
{
    int outlen = 0;
    char *tok_list[MAX_NUM_TOKS];
    int num_toks = 0;
    char *key_id = RSA_get_ex_data(rsa, rsa_ex_idx);

   if(!key_id)
      {
      SWIMSerr(SWIMS_F_SWIMS_PRIVATE_ENCRYPT, SWIMS_R_MISSING_KEY_COMPONENTS);
      printf("Internal Error:  Need key_id\n");
      goto err;
      }

    num_toks = tokenize(tok_list, key_id, ",");

   switch(padding)
      {
      case RSA_PKCS1_PADDING:
         outlen = sign(tok_list, num_toks, (char *)from, len, (char *)to, RSA_size(rsa));
         break;

      case RSA_NO_PADDING:
         outlen = encrypt_hash(tok_list, num_toks, (char *)from, len, (char *)to, RSA_size(rsa));
         break;

      default:
         SWIMSerr(SWIMS_F_SWIMS_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
         printf("unknown padding type");
         break;
      }

   if(!outlen)
      SWIMSerr(SWIMS_F_SWIMS_PRIVATE_ENCRYPT, SWIMS_R_REQUEST_FAILED);

err:
   // free the tokens
    if(num_toks)
        free_tokens(tok_list, num_toks);
    return(outlen);
	}

////////////////////////////////////////////////////////////////////////////////
/// \fn  void key_idx_ex_free(void *obj, void *item, CRYPTO_EX_DATA *ad,
///	                        int idx,long argl, void *argp)
///
/// \brief Frees objects created along with an RSA key
///
/// This function frees up the key_id duplicate string created to track user
/// credentials in the engine.
///
/// \param *obj  - 
/// \param *item - item to free 
/// \param *ad   - 
/// \param idx   - 
/// \param argl  - 
/// \param argp  - 
///
/// \returns void
////////////////////////////////////////////////////////////////////////////////
static void key_idx_ex_free(void *obj, void *item, CRYPTO_EX_DATA *ad,
	int idx,long argl, void *argp)
   {
   // free the object
   if(item)
      free(item);
   }

////////////////////////////////////////////////////////////////////////////////
/// \fn  EVP_PKEY *swims_load_private_key(ENGINE *e, const char *key_id,
///                    UI_METHOD *ui_method, void *callback_data)
///
/// \brief Creates link to the private/public key from the SWIMS server
///
/// This is the SWIMS specific implementation for referencing the private/public
/// key.
///
/// This function is invoked with the -inkey option is specified. 
///
/// product_name and key_type are always required.  
/// For operations that require encryption [username1]/[username2]
/// are required.  If the encryption operation requires the "release" key_type then
/// [username2/passwword2] are required.
///
/// \param *e - pointer to the ENGINE structure
/// \param *key_id - ascii string specified on the command line (-inkey string)
/// \param *ui_method - 
/// \param *callback_data
///
/// \returns EVP_PKEY * - pointer to a new EVP_PKEY holding the RSA key
////////////////////////////////////////////////////////////////////////////////
extern void hexdump (unsigned char *data, int cnt);
#ifdef ENGINE_DYNAMIC_SUPPORT
static
#endif
EVP_PKEY *swims_load_public_key(ENGINE *e, const char *key_id,
                    UI_METHOD *ui_method, void *callback_data)
   {
    EVP_PKEY *res = NULL;
    RSA *rsa = NULL;
    BIO *keybio = NULL;
    char *pubkey = NULL;
    int  pubkeylen=0;
    char *tok_list[20];
    int num_toks = 0;

   if(!key_id)
      {
      SWIMSerr(SWIMS_F_SWIMS_PRIVATE_ENCRYPT, SWIMS_R_MISSING_KEY_COMPONENTS);
      printf("Internal Error:  Need key_id\n");
      goto err;
      }

   if((pubkey=(char *)malloc(1024)) == NULL)
      {
      SWIMSerr(SWIMS_F_SWIMS_PRIVATE_ENCRYPT, SWIMS_R_MISSING_KEY_COMPONENTS);
      printf("Internal Error:  Couldn't allocate appropriate buffer\n");
      goto err;
      }

   if((num_toks = tokenize(tok_list, key_id, ",")) == 0)
      {
      SWIMSerr(SWIMS_F_SWIMS_PRIVATE_ENCRYPT, SWIMS_R_MISSING_KEY_COMPONENTS);
      printf("Internal Error:  No tokens\n");
      goto err;
      }

   // Get the PCKS#1 formatted key from the SWIMS server
   pubkeylen = get_pubkey(tok_list, num_toks, pubkey, 1024);
   if( pubkeylen == 0 )
       {
       SWIMSerr(SWIMS_F_SWIMS_PRIVATE_ENCRYPT, SWIMS_R_MISSING_KEY_COMPONENTS);
       printf("Internal Error:  Failed to get key\n");
       goto err;
       }

   // Create a BIO so we can easily convert to EVP_PKEY
   keybio = BIO_new(BIO_s_mem());
   BIO_write(keybio,pubkey,pubkeylen);

   // convert our SWIMS ASN1 key to a EVP_PKEY
   res=d2i_PUBKEY_bio(keybio, NULL);

   rsa_ex_idx = RSA_get_ex_new_index(0,
			"RSA key handle",
			NULL, NULL, key_idx_ex_free);

   rsa = EVP_PKEY_get1_RSA(res);
   // Duplicate the key_id string for other operations later (like encrypt).
   // Freed when the RSA key is freed.
	RSA_set_ex_data(rsa, rsa_ex_idx, strdup(key_id));

err:
   // Free our pub key buffer
   if(pubkey)
      free(pubkey);

   // Free our BIO
   if(keybio)
      BIO_free(keybio);

   // free the tokens
   if(num_toks)
       free_tokens(tok_list, num_toks);
   
   return res;
   }

#ifdef ENGINE_DYNAMIC_SUPPORT
static
#endif
EVP_PKEY *swims_load_private_key(ENGINE *e, const char *key_id,
                    UI_METHOD *ui_method, void *callback_data)
   {
   return swims_load_public_key(e, key_id, ui_method, callback_data);
   }

/* This internal function is used by ENGINE_swims() and possibly by the
 * "dynamic" ENGINE support too */
#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static 
#endif
int bind_helper(ENGINE *e)
	{
#ifndef OPENSSL_NO_RSA
	const RSA_METHOD *meth1;
#endif

   printf("SWIMS Engine Version %s\n", PACKAGE_VERSION);

	if(!ENGINE_set_id(e, engine_swims_id) ||
		!ENGINE_set_name(e, engine_swims_name) ||
#ifndef OPENSSL_NO_RSA
		!ENGINE_set_RSA(e, &swims_rsa) ||
#endif
		!ENGINE_set_load_privkey_function(e, &swims_load_private_key) ||
		!ENGINE_set_load_pubkey_function(e, &swims_load_public_key) ||
		!ENGINE_set_destroy_function(e, swims_destroy) ||
		!ENGINE_set_init_function(e, swims_init) ||
		!ENGINE_set_finish_function(e, swims_finish) ||
		!ENGINE_set_ctrl_function(e, swims_ctrl) ||
		!ENGINE_set_cmd_defns(e, swims_cmd_defns))
		return 0;

#ifndef OPENSSL_NO_RSA
	// RSA_PKCS1_SSLeay() functions hook properly to SWIMS therefore
   // we need only override certain fucntionality.  If the function isn't
   // already defined (from above) we'll use the default.
	meth1 = RSA_PKCS1_SSLeay();
   if(!swims_rsa.rsa_pub_enc)
      swims_rsa.rsa_pub_enc = meth1->rsa_pub_enc;
   if(!swims_rsa.rsa_pub_dec)
      swims_rsa.rsa_pub_dec = meth1->rsa_pub_dec;
   if(!swims_rsa.rsa_priv_enc)
	   swims_rsa.rsa_priv_enc = meth1->rsa_priv_enc;
   if(!swims_rsa.rsa_priv_dec)
      swims_rsa.rsa_priv_dec = meth1->rsa_priv_dec;
   if(!swims_rsa.rsa_mod_exp)
      swims_rsa.rsa_mod_exp = meth1->rsa_mod_exp;
   if(!swims_rsa.bn_mod_exp)
      swims_rsa.bn_mod_exp = meth1->bn_mod_exp;
   if(!swims_rsa.init)
      swims_rsa.init = meth1->init;
   if(!swims_rsa.finish)
      swims_rsa.finish = meth1->finish;
#endif

	/* Ensure the swims error handling is set up */
	ERR_load_SWIMS_strings(); 
	return 1;
	}

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
//*****************************************************************************
// engine_swims
// internal
//*****************************************************************************
static ENGINE *engine_swims(void)
	{
	ENGINE *ret = ENGINE_new();
	if(!ret)
		return NULL;
	if(!bind_helper(ret))
		{
		ENGINE_free(ret);
		return NULL;
		}
	return ret;
	}

//*****************************************************************************
// ENGINE_load_swims
// external
//*****************************************************************************
#ifdef ENGINE_DYNAMIC_SUPPORT
static
#endif
void ENGINE_load_swims(void)
	{
	ENGINE *toadd = engine_swims();
	if(!toadd) return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
	}
#endif

//*****************************************************************************
// swims_destroy
// internal
//*****************************************************************************
/* Destructor (complements the "ENGINE_swims()" constructor) */
static int swims_destroy(ENGINE *e)
	{
	/* Unload the swims error strings so any error state including our
	 * functs or reasons won't lead to a segfault (they simply get displayed
	 * without corresponding string data because none will be found). */
   ERR_unload_SWIMS_strings(); 
	return 1;
	}



/* These are the function pointers that are (un)set when the library has
 * successfully (un)loaded. */

//*****************************************************************************
// swims_init
//*****************************************************************************
static int swims_init(ENGINE *e)
   {
   int retVal = 1;

   if(swims_loaded == 0)
      {
      initStruct(&gData);

      // create server certificates for https with SWIMS
      createCerts();
   
      // initialize cURL library
      curl_global_init(CURL_GLOBAL_ALL);

      swims_loaded = 1;
      }
   else
      {
      SWIMSerr(SWIMS_F_SWIMS_INIT,SWIMS_R_ALREADY_LOADED);
      retVal = 0;
      }

   return retVal;
   }

//*****************************************************************************
// swims_finish
//*****************************************************************************
static int swims_finish(ENGINE *e)
   {
   if(swims_loaded == 0)
      {
      SWIMSerr(SWIMS_F_SWIMS_FINISH,SWIMS_R_NOT_LOADED);
      return 0;
      }

   if(gCertFileName)
      {
      remove(gCertFileName);
      gCertFileName = NULL;
      }

   // clean up cURL library
   curl_global_cleanup();

   swims_loaded = 0;
   return 1;
   }

//*****************************************************************************
// swims_ctrl
//*****************************************************************************
static int swims_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
	{
	//int initialised = ((swims_loaded == 0) ? 0 : 1);
   int retVal = 0;

	switch(cmd)
		{
      default:
         SWIMSerr(SWIMS_F_SWIMS_CTRL,SWIMS_R_CTRL_COMMAND_NOT_IMPLEMENTED);
         break;
      }

   return retVal;
	}


/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */
#ifdef ENGINE_DYNAMIC_SUPPORT
static int bind_fn(ENGINE *e, const char *id)
	{
	if(id && (strcmp(id, engine_swims_id) != 0))
		return 0;
	if(!bind_helper(e))
		return 0;
	return 1;
	}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif /* ENGINE_DYNAMIC_SUPPORT */
