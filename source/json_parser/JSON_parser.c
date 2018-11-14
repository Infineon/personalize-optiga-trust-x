/*
 * Hello_cJSON.c
 *
 *  Created on: 16.01.2018
 *      Author: pi
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "cJSON.h"
#include "JSON_parser.h"

int c_JSON_read_file (const char *path, char **buffer, int *file_length) {
 FILE *in = fopen(path, "r");
 if (!in) {
	 printf("Opening file failed!\n"); return(-1);
 }
 fseek(in, 0L, SEEK_END);
 long lSize = ftell(in);
 rewind(in);
 /* allocate memory for entire content */
 *buffer = malloc(lSize+1);
 if ( !*buffer ) fclose(in), printf("Memory alloc fails\n"), exit(1);
 /* copy the file into the buffer */
 if( 1!=fread( *buffer, lSize, 1 , in)) {
	 fclose(in), free(*buffer), printf("Entire read fails\n"), exit(1);
 }
 *file_length = (int) lSize;
 fclose(in);
 return 0;

}
void c_JSON_print_string_pointer_as_string (char *t) {
 if(*t == '\0') {
	 return;
 }
 printf("%c", *t);
 c_JSON_print_string_pointer_as_string(++t);
}
char * c_JSON_CSR_print (cJSON * json, char * string)
{
	const cJSON * object = cJSON_GetObjectItemCaseSensitive(json, string);
	if(object) {
			char * buf = calloc((strlen(string)+1), sizeof(char));
			strcat(buf, string);
			strcat(buf, "=");
			char * print = cJSON_Print(object);
			const char * com = ",";
			print = print+1;
			print[strlen(print)-1] = '\0';
			char * str = calloc((strlen(buf)+strlen(com)+strlen(print)), sizeof(char));
			strcat(str, buf);
			strcat(str, print);
			strcat(str, com);
			return str;
		}
		else {
			return NULL;
		}
}
char * c_JSON_read_config (const char * filepath) {

	char * buffer = NULL;
	int file_length = 0;
	int retVal = c_JSON_read_file(filepath, &buffer, &file_length);
	if(retVal) {
		printf("Reading not successful!\n");
		return NULL;

	}
	printf("Data read:\n");
	c_JSON_print_string_pointer_as_string(buffer);
	cJSON *json = cJSON_Parse(buffer);
	
	if (json == NULL){
		printf("Not a JSON file\n");
		return NULL;
	}

	char * CN = c_JSON_CSR_print(json, "CN");
	char * O = c_JSON_CSR_print(json, "O");
	char * C = c_JSON_CSR_print(json, "C");
	char * ST = c_JSON_CSR_print(json, "ST");
	char * OU = c_JSON_CSR_print(json, "OU");
	char * email = c_JSON_CSR_print(json, "emailAddress");

	int length = 0;

	if (CN) {
		length += strlen(CN);
	} else {
		printf("Major Error: CN not existent!");
		return NULL;
	}
	if (O) {
			length += strlen(O);
		}
	if (C) {
			length += strlen(C);
		}
	if (ST) {
			length += strlen(ST);
		}
	if (OU) {
			length += strlen(OU);
		}
	if (email) {
			length += strlen(email);
		}

	char * csr_return = calloc(length, sizeof(char));
	strcat(csr_return, CN);
	if (O) {
		strcat(csr_return, O);
	}
	if (C) {
		strcat(csr_return, C);
	}
	if (ST) {
		strcat(csr_return, ST);
	}
	if (OU) {
		strcat(csr_return, OU);
	}
	if (email) {
		strcat(csr_return, email);
	}
	//remove last ","
	csr_return[strlen(csr_return)-1] = '\0';
	return csr_return;
}
