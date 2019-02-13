/**
* \copyright
* MIT License
*
* Copyright (c) 2018 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
* \endcopyright
*
* \author Infineon Technologies AG
*
* \file main_raspberry_pi3_sample.c
*
* \brief   This sample demonstrates OPTIGA use cases.
*
* \ingroup grOptigaExamples
* @{
*/
/* Standard includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

/* MbedTLS includes */
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/x509_crt.h"

/* OPTIGA(TM) Trust X includes */
#include "optiga/optiga_crypt.h"
#include "optiga/optiga_util.h"
#include "optiga/pal/pal_os_event.h"
#include "optiga/pal/pal.h"
#include "optiga/ifx_i2c/ifx_i2c_config.h"

/* JSON parser includes */
#include "JSON_parser.h"


extern void pal_gpio_init(void);
extern void pal_gpio_deinit(void);
extern pal_status_t pal_init(void);

#ifdef USE_LIBUSB_PAL
extern ifx_i2c_context_t ifx_i2c_context_1;
#define IFX_I2C_CONTEXT ifx_i2c_context_1
#else
extern ifx_i2c_context_t ifx_i2c_context_0;
#define IFX_I2C_CONTEXT ifx_i2c_context_0
#endif

optiga_comms_t optiga_comms = {(void*)&IFX_I2C_CONTEXT, NULL,NULL, OPTIGA_COMMS_SUCCESS};
uint16_t POID = 0;

char * i2c_if;

int __optiga_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      unsigned char *sig, size_t *sig_len,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
	uint16_t optiga_key_id = POID;
	int32_t status = (int32_t) OPTIGA_LIB_ERROR;
	uint8_t der_signature[3 + 32 + 3 + 32];
	uint16_t ds_len = 3 + 32 + 3 + 32;

	mbedtls_printf("OPTIGA(TM) Trust X Signature generation\n");
	if (optiga_key_id == 0)
		optiga_key_id = OPTIGA_KEY_STORE_ID_E0F1;
	
	status = optiga_crypt_ecdsa_sign((uint8_t*)hash, hash_len, optiga_key_id, der_signature, &ds_len);
	if (OPTIGA_LIB_SUCCESS != status)
	{
        	//Key pair generation failed
        	return 1;
	}
	
	sig[0] = 0x30;
	sig[1] = ds_len;
	memcpy(sig + 2, der_signature, ds_len);
	*sig_len = 2 + ds_len;

	for(int i = 0; i < *sig_len; i++ )
        	mbedtls_printf("%c%c", "0123456789ABCDEF" [sig[i] / 16], "0123456789ABCDEF" [sig[i] % 16] );
	mbedtls_printf( " Size %zu\n", *sig_len);
	
	return 0;
}

const mbedtls_pk_info_t mbedtls_ecdsa_optiga_info = {
	MBEDTLS_PK_ECKEY,
	"ECDSA",
	NULL,
	NULL,
	NULL,
	__optiga_sign_wrap,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

int __write_csr( mbedtls_x509write_csr *req, const char *output_file,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng )
{
	int ret;
	FILE *f;
	unsigned char output_buf[4096];
	size_t len = 0;

	memset( output_buf, 0, 4096 );
	if( ( ret = mbedtls_x509write_csr_pem( req, output_buf, 4096, f_rng, p_rng ) ) < 0 )
		return( ret );

	len = strlen( (char *) output_buf );

	if( ( f = fopen( output_file, "w+" ) ) == NULL )
		return( -1 );

	if( fwrite( output_buf, 1, len, f ) != len )
	{
		fclose( f );
		return( -1 );
	}

	fclose( f );
	return( 0 );
}

static int32_t __optiga_init(void)
{
	int32_t status = (int32_t) OPTIGA_LIB_ERROR;

	do
	{
		pal_gpio_init();
		pal_os_event_init();
		if (pal_init() != PAL_STATUS_SUCCESS)
			break;

		status = optiga_util_open_application(&optiga_comms);
		if(OPTIGA_LIB_SUCCESS != status)
		{
			printf( "Failure: optiga_util_open_application(): 0x%04X\n\r", status);
			break;
		}

		status = OPTIGA_LIB_SUCCESS;
	} while(0);

	return status;
}

static int32_t __optiga_deinit(void)
{
	int32_t status = (int32_t) OPTIGA_LIB_ERROR;

	do
	{
		pal_gpio_deinit();
		status = optiga_comms_close(&optiga_comms);
		if(OPTIGA_LIB_SUCCESS != status)
		{
			printf( "Failure: optiga_comms_close(): 0x%04X\n\r", status);
			break;
		}

		status = OPTIGA_LIB_SUCCESS;
	} while(0);

	return status;
}

static int32_t __optiga_genkeypair(optiga_key_id_t optiga_key_id, uint8_t* public_key, uint16_t* public_key_length)
{
	int32_t status = (int32_t) OPTIGA_LIB_ERROR;

	do{
		if ((public_key == NULL) || (public_key_length == NULL) || (*public_key_length == 0))
			break;
		
		if (optiga_key_id == 0)
			optiga_key_id = OPTIGA_KEY_STORE_ID_E0F1;
		
		/**
         * Generate ECC Key pair  
         *       - Use ECC NIST P 256 Curve
         *       - Specify the Key Usage (Key Agreement or Sign based on requirement)
         *       - Store the Private key in OPTIGA Key store
         *       - Export Public Key
         */
        status = optiga_crypt_ecc_generate_keypair(OPTIGA_ECC_NIST_P_256,
                                                   (uint8_t)OPTIGA_KEY_USAGE_SIGN,
                                                   FALSE,
                                                   &optiga_key_id,
                                                   public_key,
                                                   public_key_length);
        if (OPTIGA_LIB_SUCCESS != status)
        {
            //Key pair generation failed
            break;
        }
	} while(FALSE);
	
	return status;
}

static void __mbedtls_dump_pubkey( const char *title, mbedtls_ecdsa_context *key )
{
    uint8_t buf[300];
    size_t len;
	size_t i;

    if( mbedtls_ecp_point_write_binary( &key->grp, &key->Q,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        mbedtls_printf("internal error\n");
        return;
    }

	mbedtls_printf( "%s", title );
	for( i = 0; i < len; i++ )
		mbedtls_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16], "0123456789ABCDEF" [buf[i] % 16] );
	mbedtls_printf( "\n" );
}


// prints out error message when user tries to run with bad command line args or
// when user runs with the -h command line arg 
void usage(void){
  fprintf(stderr,
      " usage:\n"
      "    ./optiga_generate_csr -o file -i json_file [-f  i2c_path] [-p  cert_oid] [-r perso_string]\n"
      "       -i  json_file:        Path to input-file. It contains information about the certificate requestor.\n"
      "       -o  file:             Path to output-file. If file does not exist, it will be automatically created.\n"
      "       -f  i2c_path          Path to i2c intreface; e.g. -f /dev/i2c-0 \n" 
      "       -p  private_key_oid:  Select an Object ID to store a new private key within OPTIGA(TM) Trust X.\n"
      "                             Can be 0xE0F1, 0xE0F2, 0xE0F3. 0xE0F1 is used by default\n"
      "       -r  perso_string:     Add you personalisation information to randomise a random number generator.\n"
      "                             All strings followed after 16 characters are silently ignored \n"\
      "\n");
}

/**
 * This function is the entry point of sample.
 *
 * \retval
 *  0 on success
 *  1 on failure
 */

int32_t main(int argc, char ** argv)
{
	int ret = 0;
	mbedtls_pk_context key;
	mbedtls_x509write_csr req;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ecdsa_context   ecdsa_context;
	mbedtls_ecp_keypair keypair;
	
	uint8_t public_key[80];
	uint16_t public_key_length = 80;

	/* Read configuration file to set data written in CSR */
	const char *file_str     = NULL;
	char *subject_name       = 0;
	const char* output_file  = NULL;
	      char* pers         = "csr example app";
	int c;

	/* Parse arguments of function call */
	if(argc < 5) {
		usage();
		return EXIT_FAILURE;
	}	
	
	while((c = getopt (argc, argv, "i:f:o:p:r")) != -1) {
		switch(c) {
		case 'f':
			i2c_if = optarg;
			break;
		case 'i':
			file_str = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'p':
			if (strcmp(optarg, "0xE0F1") == 0) {
				POID = 0xE0F1;
			} else if (strcmp(optarg, "0xE0F2") == 0) {
				POID = 0xE0F2;
			} else if (strcmp(optarg, "0xE0F3") == 0) {
				POID = 0xE0F3;
			}
			else {
				printf("Please enter an Object OID you want to use\n"
						"Possible IDs: \n"
						"	0xE0F1 (by default)\n"
						"	0xE0F2 \n"
						"	0xE0F3 \n");
				return EXIT_FAILURE;
			}
			break;
		case 'r':
			strncpy(pers, optarg, 16);
		break;
		case '?':
			if(optopt == 'i') {
				fprintf(stderr, "Option -%i requires an argument. \n", optopt);
			}
			else if(optopt == 'o') {
				fprintf(stderr, "Option -%i requires an argument. \n", optopt);
			}
			else if (isprint(optopt)) {
				fprintf(stderr, "Unknown option -%c. \n", optopt);
			}
			else {
				fprintf(stderr, "Unknown option character '\\x%x'- \n", optopt);
			}
			return EXIT_FAILURE;
		default:
			abort();
			return EXIT_FAILURE;
		}
	}

    setbuf(stdout, NULL);
	
	/* Read config file for CSR input */
	subject_name = c_JSON_read_config(file_str);
	if( subject_name == NULL) {
		printf("Reading JSON config file failed!\n");
		return EXIT_FAILURE;
	}
	printf("%s\n",subject_name);

	/* Initialise OPTIGA(TM) Trust X */
	if (__optiga_init() != OPTIGA_LIB_SUCCESS)
	{
		printf("OPTIGA Open Application failed.\n");
		return -1;
	}
	printf("OPTIGA(TM) Trust X initialized.\n");
	
	do 
	{
		/* Generate ECC P256 keypair and export the public component*/
		if (__optiga_genkeypair(POID, public_key, &public_key_length) != OPTIGA_LIB_SUCCESS)
		{
			printf("OPTIGA Key Generation failed.\n");
			ret = -1;
			break;
		}
		printf("Keypair generated.\n");
		
		mbedtls_ecp_keypair_init(&keypair);

		mbedtls_ecp_group_load(&keypair.grp, MBEDTLS_ECP_DP_SECP256R1);
		
		if (mbedtls_ecp_point_read_binary(&keypair.grp, &keypair.Q, &public_key[3], public_key_length-3))
		{
			mbedtls_printf( " failed\n  !  mbedtls_ecp_point_read_binary returned\n");
			ret = -1;
			break;
		}

		mbedtls_ecdsa_init(&ecdsa_context);

		if (mbedtls_ecdsa_from_keypair(&ecdsa_context, &keypair))
		{
			mbedtls_printf( " failed\n  !  mbedtls_ecdsa_from_keypair returned\n");
			ret = -1;
			break;
		}

		__mbedtls_dump_pubkey("Public key is \n",&ecdsa_context);

		mbedtls_x509write_csr_init(&req);
		mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
		mbedtls_pk_init(&key);
		mbedtls_ctr_drbg_init(&ctr_drbg);

		mbedtls_x509write_csr_set_key_usage(&req, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);

		mbedtls_printf("  . Seeding the random number generator...\n");
		mbedtls_entropy_init(&entropy);
		if(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
								 (const unsigned char *) pers, strlen(pers)))
		{
			mbedtls_printf( " failed\n  !  mbedtls_ctr_drbg_seed returned %d", ret );
			ret =  -1;
			break;
		}

		mbedtls_printf("  . Checking subject name...\n");
		if (mbedtls_x509write_csr_set_subject_name( &req, subject_name))
		{
			mbedtls_printf( " failed\n  !  mbedtls_x509write_csr_set_subject_name returned %d\n", ret );
			ret = -1;
			break;
		}

		mbedtls_printf("  . Loading the private key ...\n");
		key.pk_info = &mbedtls_ecdsa_optiga_info;
		key.pk_ctx = &keypair;
		mbedtls_x509write_csr_set_key( &req, &key);
		mbedtls_printf("  . Writing the certificate request ...\n");
		if (__write_csr(&req, output_file, mbedtls_ctr_drbg_random, &ctr_drbg))
		{
			mbedtls_printf(" failed\n  !  write_certifcate_request %d\n", ret);
			ret = -1;
			break;
		}

		ret = 0;
		mbedtls_printf("ok\n");
	} while(0);
	
	__optiga_deinit();
    return ret;
}


