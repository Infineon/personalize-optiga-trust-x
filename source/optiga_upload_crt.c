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

#define MARK_START(n) printf("\n********************	"n"	********************\n");
#define MARK_END printf("\n********************	END	********************\n");

static int32_t __optiga_init(void);
static int32_t __optiga_deinit(void);
static int __optiga_write_certificate(uint16_t cert_oid, uint8_t* p_cert, uint16_t cert_length);
static int __read_file (char *path, uint8_t **buffer, uint16_t *file_length);
static void __print_hex (uint8_t *t);
static void __print_str (uint8_t *t);
static uint8_t * __append_tags (uint8_t *buffer, uint16_t length);

extern void pal_gpio_init(void);
extern void pal_gpio_deinit(void);
extern pal_status_t pal_init(void);
extern ifx_i2c_context_t ifx_i2c_context_1;

optiga_comms_t optiga_comms = {(void*)&ifx_i2c_context_1, NULL,NULL, OPTIGA_COMMS_SUCCESS};
uint16_t COID = 0xE0E1;

char * i2c_if;

int main(int argc, char * argv[])
{
	int ret = 0;
	char * cert_file = 0;
	uint8_t * cert_string;
	uint16_t cert_size;

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
	while((c = getopt (argc, argv, "f:c:o:")) != -1) {
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
		/* Read certificate into memory */
		if(!__read_file(cert_file, &cert_string, &cert_size)) {
			MARK_START("Certificate read");
			printf("Length: %d\n", cert_size);
			__print_hex(cert_string);
			MARK_END;
		}
		else {
			printf("Reading certificate failed!\n");
			ret = EXIT_FAILURE;
			break;
		}
		/* Checking if the correct certificate was read
		 * Could be deleted for a more streamlined program
		 *
		 * mbedtls_x509_crt x509_certificate: Buffer for storing parsed string
		 * */
		MARK_START("Parsing certificate");
		mbedtls_x509_crt x509_certificate;
		mbedtls_x509_crt_init(&x509_certificate);
		if (!mbedtls_x509_crt_parse_der(&x509_certificate, cert_string, cert_size))
		{
			char * buffer = malloc(1024);
			const char * prefix = "";
			if(mbedtls_x509_crt_info(buffer, 1024, prefix, &x509_certificate) > 0) {
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
		MARK_END;

		/* Write file to TrustX
		 *
		 * Done with IFX Trust E toolbox
		 * Writing works, but only with an minimum length-offset of either +13 or -2 (try and error method)
		 * Negative offset produces errors on reading and parsing written certificate with mbedTls
		 * This is why positive offset is used in this case (13 Bytes more data is written to chip, but it does not harm anything)
		 *
		*/
		/* Null any remains of former certificates in the memory */

		MARK_START("Writing certificate");

		/* Append tags in front of certificate  */
		cert_string = __append_tags(cert_string, cert_size);

		/* Write certificate to memory */
		if(__optiga_write_certificate(COID, cert_string, cert_size + 9)) 
		{
			printf("\nCertificate not written!\n");
		}
		else {
			printf("\nCertificate successfully written \n");
		}
		MARK_END;
		
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
