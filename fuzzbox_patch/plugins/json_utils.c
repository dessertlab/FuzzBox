#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include "json_utils.h"


/*
 * Read the whole JSON file into a string buffer to be parsed.
 * Remember to free the string. 
 */
static char * read_json(const char *filename) {
    char *buffer = NULL;
    long length;
    FILE *fp = fopen(filename, "rb");

    if(!fp) {
        perror("");
        return NULL;
    }

    fseek (fp, 0, SEEK_END);
    length = ftell(fp);
    fseek (fp, 0, SEEK_SET);
    buffer = (char *) malloc(length);

    if(buffer) {
        fread(buffer, 1, length, fp);
    }

    fclose (fp);

    return buffer;
}

/*
 * Parse a json file and return the root item.
 */
cJSON * parse_json_file(const char *filename) {
    char *json_string = read_json(filename);
    if(!json_string) {
		printf("Error reading JSON file\n");
        return NULL;
	}

    cJSON *json_root = cJSON_Parse(json_string);
	free(json_string);
	if(!json_root) {
		printf("JSON parse error: %s\n", cJSON_GetErrorPtr());
        return NULL;
	}

    return json_root;
}

/*
 * Returns the json item corresponding to the field of the json parent item.
 * In case of an error it exits the program if exit_on_json_error
 * is set, otherwise it returns NULL.
 */
cJSON * get_json_item(cJSON *json_parent, const char *field) {
    cJSON *json_item = cJSON_GetObjectItem(json_parent, field);
	if(!json_item) {
		printf("Unable to get field %s\n", field);
        return NULL;
	}

    return json_item;
}

/*
 * Returns the string value of the child of json_parent.
 * In case of an error it exits the program if exit_on_json_error
 * is set, otherwise it returns NULL.
 */
char * get_json_field_string(cJSON *json_parent, const char *field) {
    cJSON *json_item = get_json_item(json_parent, field);
    if(!json_item)
        return NULL;

	cJSON *json_item_value = get_json_item(json_item, "value");
    if(!json_item_value)
        return NULL;

	char *value = cJSON_GetStringValue(json_item_value);
	if(!value) {
		printf("No valid string for field %s\n", field);
        return NULL;
	}

    return value;
}

/*
 * Returns 1 if the field is to be fuzzed, as specified
 * by the "fuzz" property.
 * Returns 0 if the field is not to be fuzzed.
 * Returns -1 if an error occurs.
 */
int is_fuzzed(cJSON *json_parent, const char *field) {
    cJSON *json_item = get_json_item(json_parent, field);
    if(!json_item)
        return 0;

    cJSON *json_item_fuzz = get_json_item(json_item, "fuzz");
    if(!json_item_fuzz)
        return 0;

    if(!cJSON_IsBool(json_item_fuzz)) {
        printf("Fuzz property of field %s is not a boolean value\n", field);
        return 0;
    }

    return cJSON_IsTrue(json_item_fuzz);
}

/*
 * Returns 1 if the item has the argument field, 0 otherwise
 */
int has_field(cJSON *json_parent, const char *field) {
    return cJSON_HasObjectItem(json_parent, field);
}