#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <qemu-plugin.h>
#include <curl/curl.h>
#include "cJSON.h"
#include "json_utils.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define SEM_HTTP_CLIENT "/sem_http_client"
#define MAX_SIZE 10

static void *http_handler(void *filename);

typedef struct Protocol_Handlers_Map {

	char *protocols[10];
	void *handlers[10];

} Protocol_Handlers_Map;

Protocol_Handlers_Map p_h_map = {
	{"http"},
	{http_handler}
};

CURL *curl = NULL;

/*
 * Return a new string as the lowercase duplicate of the source string.
 * Remember to free the string.
 */
static char * string_to_lowercase(const char *source) {
	char *lowercase = strdup(source);

	int i;
	for(i = 0; lowercase[i]; ++i){
  		lowercase[i] = tolower(lowercase[i]);
	}

	return lowercase;
}

/*
 * Return a new string as the uppercase duplicate of the source string.
 * Remember to free the string.
 */
static char * string_to_uppercase(const char *source) {
	char *uppercase = strdup(source);

	int i;
	for(i = 0; uppercase[i]; ++i){
  		uppercase[i] = toupper(uppercase[i]);
	}

	return uppercase;
}

static void * get_protocol_handler(const char *protocol) {
	int size = sizeof(p_h_map.protocols) / sizeof(char *);
	void *handler = NULL;

	char *protocol_low = string_to_lowercase(protocol);

	int i;
	for(i = 0; i < size; ++i) {
		if(strcmp(protocol_low, p_h_map.protocols[i]) == 0) {
			handler = p_h_map.handlers[i];
			break;
		}
	}

	free(protocol_low);

	return handler;
}

size_t curl_write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
   return size * nmemb;
}


static void *http_handler(void *filename) {
	printf("[THREAD] HTTP Client Thread started\n");

	char *method = NULL;
	char *host = NULL;
	char *path = NULL;
	char *body = NULL;
	char url[100] = {0};

	CURLcode res;
	struct curl_slist *curl_headers = NULL;

	curl_global_init(CURL_GLOBAL_ALL);

	curl = curl_easy_init();
	if(!curl) {
		printf("[THREAD] Error initializing curl\n");
		curl_global_cleanup();
		exit(1);
	}

	FILE *dev_null = fopen("/dev/null", "wb");
	if(!dev_null) {
		perror("[THREAD] Error opening /dev/null");
		dev_null = stdout;
	}


	/***********************************
	 *****      Read JSON data     *****
	 ***********************************/
    cJSON *json_root = parse_json_file((char *) filename);
	if(!json_root) {
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		exit(1);
	}

    cJSON *json_http = get_json_item(json_root, "http");
	if(!json_http) {
		cJSON_Delete(json_root);
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		exit(1);
	}

    method = get_json_field_string(json_http, "method");
	printf("[THREAD] Method: %s\n", method);

	host = get_json_field_string(json_http, "host");
	printf("[THREAD] Host: %s\n", host);

	path = get_json_field_string(json_http, "path");
	printf("[THREAD] Path: %s\n", path);

	if(!method || !host || !path) {
		cJSON_Delete(json_root);
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		exit(1);
	}

	sprintf(url, "http://%s%s", host, path);
	printf("[THREAD] URL: %s\n", url);

	cJSON *json_headers = get_json_item(json_http, "headers");
	if(json_headers && cJSON_IsArray(json_headers)) {
		printf("[THREAD] Headers:\n");
		cJSON *json_header = NULL;
		cJSON *json_header_value = NULL;
		char *header = NULL;
    	cJSON_ArrayForEach(json_header, json_headers) {
			json_header_value = cJSON_GetObjectItem(json_header, "value");
			if(!json_header_value)
				continue;

			header = cJSON_GetStringValue(json_header_value);
			if(header && strcmp(header, "")) {
				curl_headers = curl_slist_append(curl_headers, header);
				printf("  %s\n", header);
			}
    	}
	}

    body = get_json_field_string(json_http, "body");
	if(body) {
		printf("[THREAD] Body: %s\n", body);
	}


	/***********************************
	 *****      Configure CURL     *****
	 ***********************************/

	/* First set the URL that is about to receive our request. This URL can
	   just as well be an https:// URL if that is what should receive the
	   data. */
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);

	method = string_to_uppercase(method);
	if(!strcmp(method, "GET")) {

		curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

	} else if(!strcmp(method, "POST") && body) {

		curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, body);

	} else {

		printf("[THREAD] Unsupported HTTP method %s\n", method);
		cJSON_Delete(json_root);

		if(curl_headers)
			curl_slist_free_all(curl_headers);

		curl_easy_cleanup(curl);
		curl_global_cleanup();
		free(method);
		exit(1);

	}

	cJSON_Delete(json_root);
	free(method);


	sem_t *sem_http_client;
	
	/* Semaphore for http client wait */
    sem_http_client = sem_open(SEM_HTTP_CLIENT, O_CREAT, S_IRWXU, 0);
    if (sem_http_client == NULL)
    {
        fprintf(stderr, "[THREAD] Error in sem_open() of sem_http_client\n");
        exit(1);
    }
    
    printf("[THREAD] HTTP Client Thread waiting to connect...\n");
    sem_wait(sem_http_client);
    
    sleep(10);

    
	/***********************************
	 *****        Connecting       *****
	 ***********************************/
	curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);

	printf("[THREAD] HTTP Client Thread testing connection...\n");
		
	while(1) {
		/* Perform the request, res gets the return code */
		res = curl_easy_perform(curl);
		
		/* Check for server availability */
		if(res == CURLE_OK) {
			break;
		}
		
		fprintf(stderr, "[THREAD] Server still not available\n");
		sleep(30);
	}

	curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 0L);
	curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_data);
	//curl_easy_setopt(curl, CURLOPT_WRITEDATA, dev_null);

	sleep(10);

	int packets_count = 0;
	printf("[THREAD] HTTP Client Thread starting to send packets.\n");
	while(1) {
	
		/* Perform the request, res gets the return code */
		printf("[THREAD] Sending request number %d\n", packets_count++);
		res = curl_easy_perform(curl);
		
		/* Check for errors */
		if(res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));

	}
	
	/* always cleanup */
	curl_slist_free_all(curl_headers);
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	return NULL;
}



/**
 * On plugin exit, print last instruction in cache
 */
static void plugin_exit(qemu_plugin_id_t id, void *p) {

}

/**
 * Install the plugin
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
	
	char *prot = "http";
	char *filename = "/home/kali/FuzzBox/usr/requests.json";

	void *handler = get_protocol_handler(prot);
	
	pthread_t thread;
    pthread_attr_t attr;

    // Initialize attributes
    pthread_attr_init(&attr);

    // Set the thread attribute to detached
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    // Create the detached thread
    pthread_create(&thread, &attr, handler, (void *) filename);

    // Destroy the thread attributes object, since it's no longer needed
    pthread_attr_destroy(&attr);
	

    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
