/* ====================================================================
 * Copyright (c) 2009 Cisco Systems, Inc  All rights reserved.
 * ====================================================================
 *
 * This product includes cryptographic software written by Russell Leake 
 * (leaker@cisco.com)
 */

#ifndef HEADER_SWIMS_ERR_H
#define HEADER_SWIMS_ERR_H

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_SWIMS_strings(void);
void ERR_unload_SWIMS_strings(void);
void ERR_SWIMS_error(int function, int reason, char *file, int line);
#define SWIMSerr(f,r) ERR_SWIMS_error((f),(r),__FILE__,__LINE__)

/* Error codes for the SWIMS functions. */

/* Function codes. */
#define SWIMS_F_SWIMS_CTRL				 100
#define SWIMS_F_SWIMS_FINISH			 101
#define SWIMS_F_SWIMS_INIT				 102
#define SWIMS_F_SWIMS_PRIVATE_ENCRYPT		 103

/* Reason codes. */
#define SWIMS_R_ALREADY_LOADED			 100
#define SWIMS_R_BN_CTX_FULL				 101
#define SWIMS_R_BN_EXPAND_FAIL			 102
#define SWIMS_R_CTRL_COMMAND_NOT_IMPLEMENTED		 103
#define SWIMS_R_DSO_FAILURE				 104
#define SWIMS_R_MEXP_LENGTH_TO_LARGE			 105
#define SWIMS_R_MISSING_KEY_COMPONENTS		 106
#define SWIMS_R_NOT_INITIALISED			 107
#define SWIMS_R_NOT_LOADED				 108
#define SWIMS_R_OPERANDS_TO_LARGE			 109
#define SWIMS_R_OUTLEN_TO_LARGE			 110
#define SWIMS_R_REQUEST_FAILED			 111
#define SWIMS_R_UNDERFLOW_CONDITION			 112
#define SWIMS_R_UNDERFLOW_KEYRECORD			 113
#define SWIMS_R_UNIT_FAILURE				 114

#ifdef  __cplusplus
}
#endif
#endif
