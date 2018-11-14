/*
 * Hello_cJSON.h
 *
 *  Created on: 16.01.2018
 *      Author: pi
 */

#ifndef CJSON_PARSER_H_
#define CJSON_PARSER_H_

#include "cJSON.h"

int c_JSON_read_file (const char *path, char **buffer, int *file_length);
void c_JSON_print_string_pointer_as_string (char *t);
char * c_JSON_CSR_print (cJSON * json, char * string);
char * c_JSON_read_config (const char * filepath);

#endif /* CJSON_PARSER_H_ */
