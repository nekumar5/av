/// Define the maximum buffer length of data returned from the SWIMS server
#define kRETURN_BUFFER_SIZE (2*1024)

/// Define the maximum buffer length of data sent to the SWIMS server
#define kPOST_BUFFER_SIZE (16*1024)

/// Define the maximum buffer length of ticket sent to the SWIMS Server
#define kTICKET_BUFFER_SIZE (16*1024)

/// Define the maximum filename for output files
#define kFILENAME_SIZE 200

/// Define the maximum filename for output files
#define kCOMMAND_SIZE  10

/// Define debug conditional
#ifdef WIN32
void __cdecl debug(int dflag, char* format, ...);
#else
#define debug(a, args...) if(a <= gData.debug) {printf(args);}
#endif

enum {
   OPT_HASH       = 0x1,
   OPT_ASCII      = 0x2,
   OPT_SHA1       = 0x4,
   OPT_CALCHASH   = 0x8,
   OPT_DIAG       = 0x10,
   OPT_CVT        = 0x20,
   OPT_NOCONNECT  = 0x40
};

enum {
   LOG_ERROR  = 0,     ///< Normal logging
   LOG_NORMAL = 0,     ///< Normal logging
   LOG_DEBUG  = 1,     ///< Debug logging
   LOG_NOISY  = 2,     ///< Noisy logging 
   LOG_LOUD   = 3      ///< Loud logging 
};

#ifndef WIN32
enum {
   FALSE = 0,     ///< Boolean false
   TRUE = 1       ///< Boolean true
};
#endif

enum {
   eType_None       = 0, ///< No operation in progress
   eType_PubKey     = 1, ///< Requesting Public Key
   eType_SignHash   = 2, ///< Requesting Signing of hash
   eType_SignImage  = 3, ///< Requesting Signing of hash for image
   eType_Encrypt    = 4, ///< Requesting encryption of nonstandard hash
   eType_PubExp     = 4  ///< Requesting public exponent
};

enum {
   eCode_Success = 1,   ///< Operation Successful
   eCode_Failure = 0    ///< Operation Failed
};

///////////////////////////////////////////////////////////////////////////////
/// \struct tGlobalData
///
/// \brief A global structure to store program instance data.
///////////////////////////////////////////////////////////////////////////////
typedef struct tGlobalData
   {
   /// Return code from a server operation
   int   code; 

   /// Type of operation in process
   int   type;
   
   /// Name of the requested command 
   char  cmd[kCOMMAND_SIZE];         

   /// URL of the site to request operations from
   char  *url;         

   /// \brief Data returned from the SWIMS server.  
   ///
   /// The result varies depending on the type of operation requested.  \n
   /// This could be a public key or encrypted hash.
   char  result[kRETURN_BUFFER_SIZE];

   /// \brief Length of the data returned from the SWIMS server.
   int   result_len;

   /// offset digest in image
   unsigned int digOffset;

   /// \brief Current log level being observed
   ///
   /// 0 - Default; Normal logging output \n
   /// 1 - More descriptive               \n
   int   debug;         

   int   options;
   
   /// \brief Input filename
   char  i_file[kFILENAME_SIZE];         

   /// \brief Output filename
   char  o_file[kFILENAME_SIZE];         

   /// \brief Ticket data
   char  ticket[kTICKET_BUFFER_SIZE]; 
   
   /// \brief Post string for the SWIMS server
   char  postdata[kPOST_BUFFER_SIZE];         
   
   } tGlobalData;

extern tGlobalData gData; ///< Master global data instance
extern char *gCertFileName;  ///< Temporary certificate file name

void initStruct(tGlobalData *data);
int createCerts(void);
int sign(char **tok_list, int num_toks, char *buf, int len, char *outBuf, int outBufLen);
int decrypt(char **tok_list, int num_toks, char *buf, int len, char *outBuf, int outBufLen, char* padding);
int get_pubkey(char **tok_list, int num_toks, char *outBuf, int outBufLen);
//int get_pubexp(char *url, char* product_name, char *key_type, char *outBuf, int outBufLen);
int encrypt_hash(char **tok_list, int num_toks, char *buf, int len, char *outBuf, int outBufLen);
