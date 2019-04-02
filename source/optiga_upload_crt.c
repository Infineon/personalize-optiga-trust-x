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

#include "optiga/optiga_crypt.h"
#include "optiga/optiga_util.h"
#include "optiga/pal/pal_os_event.h"
#include "optiga/pal/pal.h"
#include "optiga/ifx_i2c/ifx_i2c_config.h"

#include "mbedtls/x509_crt.h"
#include "mbedtls/base64.h"

#define MARK_START(n) 		printf("\n********************	"n"	********************\n");
#define MARK_END 			printf("\n********************	END	********************\n");
#define MAX_LEN			    255
#define HEXDUMP_COLS    	16

static int32_t __optiga_init(void);
static int32_t __optiga_deinit(void);
static int __optiga_write_certificate(uint16_t cert_oid, uint8_t* p_cert, uint16_t cert_length);
static int __read_file (char *path, uint8_t **buffer, uint16_t *file_length);
static void __print_hex (uint8_t *t);
static void __print_str (uint8_t *t);
static uint8_t * __append_tags (uint8_t *buffer, uint16_t length);
void __hexdump(const void* p_buf, uint32_t l_len);

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
uint16_t COID = 0xE0E1;

char * i2c_if;

int pem2der(char *pem, uint16_t pem_size,
			unsigned char *der, uint16_t *der_size )
{
	int ret;
	unsigned char *beg_cert_pos;
	unsigned char *end_cert_pos;
	unsigned char *end = (unsigned char *)pem + pem_size;
	size_t len = 0;

    beg_cert_pos = (unsigned char *) strstr( pem, "-----BEGIN CERTIFICATE-----" );
    if( beg_cert_pos == NULL ) return( -1 );

    end_cert_pos = (unsigned char *) strstr( pem, "-----END CERTIFICATE-----" );
    if( end_cert_pos == NULL ) return( -1 );

    beg_cert_pos += sizeof("-----BEGIN CERTIFICATE-----");
    if( *beg_cert_pos == '\r' ) beg_cert_pos++;
    if( *beg_cert_pos == '\n' ) beg_cert_pos++;

    if( end_cert_pos <= beg_cert_pos || end_cert_pos > end )
        return( -1 );

    ret = mbedtls_base64_decode( NULL, 0, &len, 
								(unsigned char *) beg_cert_pos, end_cert_pos - beg_cert_pos );
    if( ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER )
        return( ret );

    if( len > *der_size )
        return( -1 );

    if( ( ret = mbedtls_base64_decode( der, len, &len, 
				( unsigned char *) beg_cert_pos, end_cert_pos - beg_cert_pos ) ) != 0 )
    {
        return( ret );
    }

    *der_size = len;

    return( 0 );
}

/**
 *
 * Printout data in a standard hex view
   0x000000: 2e 2f 68 65 78 64 75 6d ./hexdum
   0x000008: 70 00 53 53 48 5f 41 47 p.SSH_AG
   0x000010: 45 4e 54 5f             ENT_
 */
inline void __hexdump(const void* p_buf, uint32_t l_len) {
	unsigned int i, j;
	char str[MAX_LEN];
	for (i = 0;	i < l_len + ((l_len % HEXDUMP_COLS) ?
					( HEXDUMP_COLS - l_len % HEXDUMP_COLS) : 0);
			i++) {
		/* print offset */
		if (i % HEXDUMP_COLS == 0) {
			sprintf(str, "0x%06x: ", i);
			printf("%s",str);
		}

		/* print hex data */
		if (i < l_len) {
			sprintf(str, "%02x ", 0xFF & ((char*) p_buf)[i]);
			printf("%s",str);
		} else /* end of block, just aligning for ASCII dump */
		{
			sprintf(str, "   ");
			printf("%s",str);
		}

		/* print ASCII dump */
		if (i % HEXDUMP_COLS == ( HEXDUMP_COLS - 1)) {
			for (j = i - ( HEXDUMP_COLS - 1); j <= i; j++) {
				if (j >= l_len) /* end of block, not really printing */
				{
					printf(" ");
				} else if (isprint((int) ((char*) p_buf)[j])) /* printable char */
				{
					printf("%c", ((char*) p_buf)[j]);
				} else /* other char */
				{
					printf(".");
				}
			}
			printf("\r");
			printf("\n");
		}
	}
}


int main(int argc, char * argv[])
{
	int ret = 0;
	char * cert_file = 0;
	uint8_t * pem_cert;
	uint16_t pem_cert_size;
	uint8_t * der_cert;
	uint16_t der_cert_size;

	/* Parsing arguments of Method-call */

	if (argc < 5) {
		printf("Too few arguments!\n"
				"Help:\n"
				"-f  i2c_path   Path to i2c intreface; e.g. -f /dev/i2c-0 \n" 
				"-c  cert_path  Path to certificate-file\n"
				"-o  oid        Select Object ID to store new certificate within OPTIGA(TM) Trust X.\n"
				"               Can be 0xE0E1, 0xE0E2, 0xE0E3. 0xE0E1 is used by default\n");
		return EXIT_FAILURE;
	}
	int c;
	while((c = getopt (argc, argv, "f:c:o:d")) != -1) {
			switch(c) {
			case 'f':
				i2c_if = optarg;
				break;
			case 'c':
				cert_file = optarg;
				break;
			case 'o':
				if (strcmp(optarg, "0xE0E1") == 0) {
					COID = 0xE0E1;
				} else if (strcmp(optarg, "0xE0E2") == 0) {
					COID = 0xE0E2;
				} else if (strcmp(optarg, "0xE0E3") == 0) {
					COID = 0xE0E3;
				}
				else {
					printf("Please enter an Object OID you want to use\n"
							"Possible IDs: \n"
							"	0xE0E1 (by default)\n"
							"	0xE0E2 \n"
							"	0xE0E3 \n");
					return EXIT_FAILURE;
				}
				break;
			case '?':
				if(optopt == 'c') {
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
				printf("Help:\n"
						"-c		Path to certificate-file\n");
				return EXIT_FAILURE;
			default:
				abort();
				return EXIT_FAILURE;
			}
		}

    /* Initialise OPTIGA(TM) Trust X */
    if (__optiga_init() != OPTIGA_LIB_SUCCESS)
	{
		printf("OPTIGA Open Application failed.\n");
		return -1;
	}
	printf("OPTIGA(TM) Trust X initialized.\n");

	do 
	{
		/* Checking if the correct certificate was read
		 * Could be deleted for a more streamlined program
		 *
		 * mbedtls_x509_crt x509_certificate: Buffer for storing parsed string
		 * */
		MARK_START("Parsing certificate");
		mbedtls_x509_crt x509_certificate;
		mbedtls_x509_crt_init(&x509_certificate);
		if (!mbedtls_x509_crt_parse_file(&x509_certificate, cert_file))
		{
			char * buffer = malloc(1500);
			const char * prefix = "";
			if(mbedtls_x509_crt_info(buffer, 1500, prefix, &x509_certificate) > 0) {
				__print_str((uint8_t *)buffer);
				free(buffer);
			}
			else {
				printf("Error, Info not written!\n");
				free(buffer);
			}
		}
		else {
			printf( " failed\n  !  mbedtls_x509_crt_parse returned\n");
			ret = EXIT_FAILURE;
			break;
		}

		/* Write file to TrustX
		 *
		 * Done with IFX Trust X toolbox
		 *
		*/
		/* Null any remains of former certificates in the memory */
		/* Read certificate into memory */
		if(!__read_file(cert_file, &pem_cert, &pem_cert_size)) {
			MARK_START("Certificate read");
			printf("%s\n", pem_cert);
		}
		else {
			printf("Reading certificate failed!\n");
			ret = EXIT_FAILURE;
			break;
		}
		MARK_START("Writing certificate");
		der_cert = malloc(1500);
		der_cert_size = 1500;
		pem2der((char *)pem_cert, pem_cert_size, der_cert, &der_cert_size);
		/* Append tags in front of certificate  */
		der_cert = __append_tags(der_cert, der_cert_size);
		der_cert_size += 9;
		
		__hexdump(der_cert, der_cert_size);

		/* Write certificate to memory */
		if(__optiga_write_certificate(COID, der_cert, der_cert_size)) 
		{
			printf("\nCertificate not written!\n");
		}
		else {
			printf("\nCertificate successfully written \n");
		}
		
		ret = EXIT_SUCCESS;
	}while(0);
	
	__optiga_deinit();

	return ret;
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

static int __optiga_write_certificate(uint16_t cert_oid, uint8_t* p_cert, uint16_t cert_length)
{
	int32_t status = (int32_t) OPTIGA_LIB_ERROR;
	
	do
	{
		if (cert_oid == 0)
			break;
		if ((p_cert == NULL)|| (cert_length == 0))
			break;
		
	    status = optiga_util_write_data(cert_oid,
									    OPTIGA_UTIL_ERASE_AND_WRITE,
									    0,
									    p_cert, 
									    cert_length);

        if (OPTIGA_LIB_SUCCESS != status)
        {
			//writing data to a data object failed.
            break;
        }
	} while(0);

	return status; 
}

static int __read_file (char *path, uint8_t **buffer, uint16_t *file_length)
{
	 FILE *in = fopen(path, "r");
	 if (!in)
	 {
		 printf("Opening file failed!\n"); return(-1);
	 }
	 fseek(in, 0L, SEEK_END);
	 long lSize = ftell(in);
	 rewind(in);
	 /* allocate memory for entire content */
	 *buffer = malloc(lSize+1);
	 if ( !*buffer )
	 {
		 fclose(in);
		 printf("Memory alloc fails\n");
		 exit(1);
	 }
	 
	 /* copy the file into the buffer */
	 if( 1!=fread( *buffer, lSize, 1 , in))
	 {
		 fclose(in);
		 free(*buffer);
		 printf("Entire read fails\n");
		 exit(1);
	 }
	 *file_length = (int) lSize;
	 fclose(in);
	 return 0;

}
/* Recursive function to content of a char-pointer as hex */
static void __print_hex (uint8_t *t)
{
	 if(*(t+1) != '\0')
	 {
		 printf("%02X ", *t);
	 }
	 else
	 {
		 printf("%02X", *t);
		 return;
	 }
	 __print_hex(++t);
}
/* Recursive function to content of a char-pointer as string*/
static void __print_str (uint8_t *t)
{
	if(*t == '\0')
	{
	 return;
	}
	printf("%c", *t);
	__print_str(++t);
}
static uint8_t * __append_tags (uint8_t * buffer, uint16_t length)
{
		char * t1 = calloc(3, 1);
		char * t2 = calloc(3, 1);
		char * t3 = calloc(3, 1);

		int calc = length;
		int calc1 = 0;
		int calc2 = 0;
		if (calc > 0xFF)
		{
			calc1 = calc >> 8;
			calc = calc%0x100;
			if (calc1 > 0xFF)
			{
				calc2 = calc1 >> 8;
				calc1 = calc1%0x100;
			}
		}
		t3[0] = calc2;
		t3[1] = calc1;
		t3[2] = calc;
		calc = length + 3;
		if (calc > 0xFF)
		{
			calc1 = calc >> 8;
			calc = calc%0x100;
			if (calc1 > 0xFF)
			{
				calc2 = calc1 >> 8;
				calc1 = calc1%0x100;
			}
		}
		t2[0] = calc2;
		t2[1] = calc1;
		t2[2] = calc;
		calc = length + 6;
		if (calc > 0xFF)
		{
			calc1 = calc >> 8;
			calc = calc%0x100;
			if (calc1 > 0xFF)
			{
				calc2 = calc1 >> 8;
				calc1 = calc1%0x100;
			}
		}
		t1[0] = 0xC0;
		t1[1] = calc1;
		t1[2] = calc;
		uint8_t * ret_buffer = calloc(length+9, 1);
		for (int i = 0; i < 3; i++) {
			ret_buffer[i] = t1[i];
		}
		for (int i = 0; i < 3; i++)
		{
			ret_buffer[i+3] = t2[i];
		}
		for (int i = 0; i < 3; i++) {
			ret_buffer[i+6] = t3[i];
		}
		for (int i = 0; i < length; i++) {
			ret_buffer[i+9] = buffer[i];
		}
		return ret_buffer;
}
