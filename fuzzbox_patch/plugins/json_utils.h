#include "cJSON.h"
#include <curl/curl.h>

/*
 * Read the whole JSON file into a string buffer to be parsed.
 * Remember to free the string. 
 */
static char * read_json(const char *filename);

/*
 * Parse a json file and return the root item.
 */
cJSON * parse_json_file(const char *filename);

/*
 * Returns the json item corresponding to the field of the json parent item.
 * In case of an error it exits the program if exit_on_json_error
 * is set, otherwise it returns NULL.
 */
cJSON * get_json_item(cJSON *json_parent, const char *field);

/*
 * Returns the string value of the child of json_parent.
 * In case of an error it exits the program if exit_on_json_error
 * is set, otherwise it returns NULL.
 */
char * get_json_field_string(cJSON *json_parent, const char *field);

/*
 * Returns 1 if the field is to be fuzzed, as specified
 * by the "fuzz" property.
 * Returns 0 if the field is not to be fuzzed.
 * Returns -1 if an error occurs.
 */
int is_fuzzed(cJSON *json_parent, const char *field);

/*
 * Returns 1 if the item has the argument field, 0 otherwise
 */
int has_field(cJSON *json_parent, const char *field);