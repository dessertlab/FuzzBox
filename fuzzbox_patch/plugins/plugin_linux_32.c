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
#include <regex.h>
#include "cJSON.h"
#include "json_utils.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

// Name of the shared memory and semaphores object
#define SEM_RD_FUZZER_MODE "/fuzzer_mode_rd_sem_buffer"
#define SEM_WR_FUZZER_MODE "/fuzzer_mode_wr_sem_buffer"
#define SHM_FUZZER_MODE "/fuzzer_mode_shm_buffer"
#define SEM_RD_END_TEST_CASE_MODE "/fuzzer_end_test_case"
#define SEM_RD_END_TCG_PLUGIN_CONTINUE "/fuzzer_tcg_plugin_continue"

#define SEM_RD_FUZZING_INPUT "/fuzzing_input_rd_sem_buffer"
#define SEM_WR_FUZZING_INPUT "/fuzzing_input_wr_sem_buffer"
#define SHM_FUZZING_INPUT "/fuzzing_input_shm_buffer"
#define SHM_FUZZING_REPORT "/fuzzing_input_shm_report_buffer"
#define SEM_GATHERING "/sem_gathering"
#define SEM_GATHERING2 "/sem_gathering2"
#define DEFAULT_MODE 0
#define SNAPSHOT_MODE 1
#define FUZZING_MODE 2

#define REGEX_FUZZING 0
#define JSON_FUZZING 1
#define FUZZ_ALL 2
#define FUZZ_NONE 3

#define BODY_SUFFIX_SIZE 2000
#define REG_ERR_BUFF_SIZE 100

/* Store last executed instruction on each vCPU as a GString */
static GPtrArray *last_exec = NULL;
static GMutex expand_array_lock;

static GArray *crash_track = NULL;
static GArray *msg_track = NULL;
static GArray *ret_track = NULL;
static int fuzzer_mode_opt;
static int fuzzing_input;

static int instr_index = 0;
static int shmfd_fuzzer_mode;                          // file descriptor
static int *shmptr_fuzzer_mode;                        // shm pointer
static sem_t *sem_rd_fuzzer_mode, *sem_wr_fuzzer_mode; // semaphores to read and write fuzzer mode
static off_t length = sizeof(int);

static sem_t *sem_gathering;
static sem_t *sem_gathering2;
static FILE *fd = NULL;
static FILE *fd1 = NULL;
typedef unsigned char u8;
struct QueueItem
{
    u8 *data;
    size_t length;
};
struct SingleFuzzReport
{
    int status; // 0 = ok, -1 = error, -2=snapshot-err (should retry fuzz)
    char *info; // info on error
    struct QueueItem q;
};
static int shmfd_fuzzing_input;                // file descriptor
static struct QueueItem *shmptr_fuzzing_input; // shm pointer
static int fuzzing_length;
static sem_t *sem_rd_fuzzing_input, *sem_wr_fuzzing_input; // semaphores to read and write fuzzer mode
static off_t length_fuzz_input = sizeof(struct QueueItem);

int shmfd_fuzzing_report;
struct SingleFuzzReport *shmptr_fuzzing_report;
static off_t length_fuzz_report = sizeof(struct SingleFuzzReport);
static sem_t *wait_for_end_test_case, *tcg_plugin_continue;


int size_register = 0, address_register = 0;

/* JSON Fuzzing */
typedef struct JSONItem {

    char *key;
    char *value;
    int fuzz;

} JSONItem;

typedef struct JSONArray {

    int count;
    JSONItem *items;

} JSONArray;

static JSONItem method = {NULL, NULL, 0};
static JSONItem host = {NULL, NULL, 0};
static JSONItem path = {NULL, NULL, 0};
static JSONArray body_parameters = {0, NULL};
static JSONArray headers = {0, NULL};

static cJSON *json_root = NULL;
char *json_filename = NULL;

uint64_t buf_address = 0;
int min_size = 0;
char *reg_pattern = NULL;

/* Regex Fuzzing */
char *regex_fuzzing_pattern = NULL;
char *regex_fuzzing_pattern_cleared = NULL;
char *reg_prefix = NULL, *reg_fuzzed = NULL, *reg_suffix = NULL;

/* Fuzz All */
char *fuzz_all_pattern = NULL;


int fuzzing_type = FUZZ_NONE;
regex_t *regex = NULL;
regmatch_t match[1];

int analyze = 0;


#define MAX_LINE_LENGTH 100
#define MAX_ENTRIES 40000
#define HASH_TABLE_SIZE 4096 // Adjust this as needed
typedef unsigned char u8;

struct CodeNamePair
{
    uint64_t code;
    char name[100];
    struct CodeNamePair *next; // Linked list for hash table collisions
};

static struct CodeNamePair *hashTable[HASH_TABLE_SIZE] = {NULL};


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

/*
 * Prints the json data structures.
 */
void print_json_data() {
    printf("\n---------JSON DATA--------\n");

    printf("Method: %s. %s.\n", method.value ? method.value : "No method", method.fuzz ? "Fuzzed" : "Not fuzzed");

    printf("Host: %s. %s.\n", host.value ? host.value : "No host", host.fuzz ? "Fuzzed" : "Not fuzzed");

    printf("Path: %s. %s.\n", path.value ? path.value : "No path", path.fuzz ? "Fuzzed" : "Not fuzzed");

    printf("Headers: %s\n", headers.count == 0 ? "No headers" : "");
    int i;
    for(i = 0; i < headers.count; ++i)
        printf("  %s: %s. %s.\n", headers.items[i].key, headers.items[i].value, headers.items[i].fuzz ? "Fuzzed" : "Not fuzzed");

    printf("Body: \n");
    for(i = 0; i < body_parameters.count; ++i) {
        // If the key is an empty string
        if(!strcmp("", body_parameters.items[i].key)) {
            printf("  %s%s - %s\n", body_parameters.items[i].value,
                                    i == body_parameters.count - 1 ? "" : "&",
                                    body_parameters.items[i].fuzz ? "Fuzzed whole" : "Not fuzzed");
        } else {
            printf("  %s=%s%s - %s\n", body_parameters.items[i].key, body_parameters.items[i].value,
                                        i == body_parameters.count - 1 ? "" : "&",
                                        body_parameters.items[i].fuzz ? "Fuzzed" : "Not fuzzed");
        }
    }

    printf("\n");    

    if(buf_address)
        printf("Buffer address: %x\n", buf_address);

    if(min_size)
        printf("Minimum size: %d\n", min_size);

    if(regex && reg_pattern)
        printf("Regex pattern: %s\n", reg_pattern);

    printf("\n----------------\n");
}

/*
 * Reads the json file and fills the corresponding data structures.
 */
void fill_json_data() {

    if(!(json_root = parse_json_file(json_filename)))
        exit(1);

    if(has_field(json_root, "bufferAddress")) {
        cJSON *json_address = get_json_item(json_root, "bufferAddress");
        char *address_str = cJSON_GetStringValue(json_address);
        buf_address = g_ascii_strtoull(address_str, NULL, 16);
    }

    if(has_field(json_root, "minimumSize")) {
        cJSON *json_size = get_json_item(json_root, "minimumSize");
        min_size = cJSON_GetNumberValue(json_size);
    }

    if(has_field(json_root, "regex")) {
        cJSON *json_pattern = get_json_item(json_root, "regex");
        reg_pattern = cJSON_GetStringValue(json_pattern);
        regex = malloc(sizeof(regex_t));

        int rc;
        if (0 != (rc = regcomp(regex, reg_pattern, REG_EXTENDED))) {
            char reg_err_buff[REG_ERR_BUFF_SIZE];
            regerror(rc, regex, reg_err_buff, REG_ERR_BUFF_SIZE);
            printf("[TCG PLUGIN] regcomp() failed with '%s'\n", reg_err_buff);
            regfree(regex);
            free(regex);
            regex = NULL;
        }
    }

    cJSON *json_http;
    if(!(json_http = get_json_item(json_root, "http"))) {
        cJSON_Delete(json_root);
        exit(1);
    }

    /*
    if(precondition && has_field(json_http, "precondition"))
        json_http = get_json_item(json_http, "precondition");
    */
   
    method.value = get_json_field_string(json_http, "method");
    method.fuzz = is_fuzzed(json_http, "method");

    host.value = get_json_field_string(json_http, "host");
    host.fuzz = is_fuzzed(json_http, "host");

    path.value = get_json_field_string(json_http, "path");
    path.fuzz = is_fuzzed(json_http, "path");

    headers.count = 0;
    cJSON *json_headers = get_json_item(json_http, "headers");
    if(json_headers && cJSON_IsArray(json_headers)) {
        headers.items = (JSONItem *) malloc(cJSON_GetArraySize(json_headers) * sizeof(JSONItem));

        cJSON *json_header = NULL;
        //cJSON *json_header_value = NULL;
        cJSON *json_header_fuzz = NULL;
        
        cJSON_ArrayForEach(json_header, json_headers) {
            /*
            json_header_value = cJSON_GetObjectItem(json_header, "value");
            if(!json_header_value)
                continue;
            
            json_header_fuzz = cJSON_GetObjectItem(json_header, "fuzz");
            if(!json_header_fuzz || !cJSON_IsBool(json_header_fuzz))
                continue;

            headers[headers_count].value = cJSON_GetStringValue(json_header_value);
            headers[headers_count].fuzz = cJSON_IsTrue(json_header_fuzz);
            ++headers_count;
            */


            if(!json_header->child->string) {
                fprintf(stderr, "[TCG Plugin] No valid key for header at index %d\n", headers.count);
                continue;
            }
            headers.items[headers.count].key = json_header->child->string;

            if(!json_header->child->valuestring) {
                fprintf(stderr, "[TCG Plugin] No valid value for header at index %d\n", headers.count);
                continue;
            }
            headers.items[headers.count].value = json_header->child->valuestring;

            json_header_fuzz = cJSON_GetObjectItem(json_header, "fuzz");
            if(!json_header_fuzz || !cJSON_IsBool(json_header_fuzz)) {
                fprintf(stderr, "[TCG Plugin] No valid boolean value for fuzz field of header at index %d\n", headers.count);
                continue;
            }
            headers.items[headers.count].fuzz = cJSON_IsTrue(json_header_fuzz);

            ++headers.count;
        }
    }

    /*
    body.value = get_json_field_string(json_http, "body");
    body.fuzz = is_fuzzed(json_http, "body");
    */

    body_parameters.count = 0;
    cJSON *json_body = get_json_item(json_http, "body");
    if(json_body && cJSON_IsArray(json_body)) {
        body_parameters.items = (JSONItem *) malloc(cJSON_GetArraySize(json_body) * sizeof(JSONItem));

        cJSON *json_body_param = NULL;
        cJSON *json_param_fuzz = NULL;
        
        cJSON_ArrayForEach(json_body_param, json_body) {

            if(!json_body_param->child->string) {
                fprintf(stderr, "[TCG Plugin] No valid key for body parameter at index %d\n", body_parameters.count);
                continue;
            }
            body_parameters.items[body_parameters.count].key = json_body_param->child->string;

            if(!json_body_param->child->valuestring) {
                fprintf(stderr, "[TCG Plugin] No valid value for body parameter at index %d\n", body_parameters.count);
                continue;
            }
            body_parameters.items[body_parameters.count].value = json_body_param->child->valuestring;

            json_param_fuzz = cJSON_GetObjectItem(json_body_param, "fuzz");
            if(!json_param_fuzz || !cJSON_IsBool(json_param_fuzz)) {
                fprintf(stderr, "[TCG Plugin] No valid boolean value for fuzz field of body parameter at index %d\n", body_parameters.count);
                continue;
            }
            body_parameters.items[body_parameters.count].fuzz = cJSON_IsTrue(json_param_fuzz);

            ++body_parameters.count;
        }
    }

    print_json_data();
}

int containsBraces(const char *str) {
    char *firstBrace = strchr(str, '{');
    if (firstBrace != NULL) {
        char *secondBrace = strchr(firstBrace, '}');
        if (secondBrace != NULL) {
            return 1; // Trovato '{' seguito da '}'
        }
    }
    return 0; // Non trovato '{' seguito da '}'
}

void fill_regex_fuzzing_data() {

    regex = malloc(sizeof(regex_t));
    size_t len = strlen(regex_fuzzing_pattern) - 1;
    
    reg_prefix = malloc(len);
    reg_fuzzed = malloc(len);
    reg_suffix = malloc(len);

    memset(reg_prefix, 0, len);
	memset(reg_fuzzed, 0, len);
	memset(reg_suffix, 0, len);
    
    //sscanf(grey_box_pattern, "%[^{}]{%[^{}]}%s", reg_prefix, reg_fuzzed, reg_suffix);
    parse_pattern(regex_fuzzing_pattern, reg_prefix, reg_fuzzed, reg_suffix, len + 2);
    
    regex_fuzzing_pattern_cleared = malloc(len);
    snprintf(regex_fuzzing_pattern_cleared, len, "%s%s%s", reg_prefix, reg_fuzzed, reg_suffix);
    printf("[TCG Plugin] Regex pattern with no braces: %s\n", regex_fuzzing_pattern_cleared);
}

void fill_fuzz_all_data() {
    regex = malloc(sizeof(regex_t));
    int rc;
    if (0 != (rc = regcomp(regex, fuzz_all_pattern, REG_EXTENDED))) {
        char reg_err_buff[REG_ERR_BUFF_SIZE];
        regerror(rc, regex, reg_err_buff, REG_ERR_BUFF_SIZE);
        printf("[TCG PLUGIN] regcomp() failed with '%s'\n", reg_err_buff);
        regfree(regex);
        free(regex);
        regex = NULL;
        exit(1);
    }
}

void createCodeToNameMapping(const char *file_path)
{
    FILE *file = fopen(file_path, "r");
    if (file == NULL)
    {
        fprintf(stderr, "Failed to open the file.\n");
        return;
    }

    char line[MAX_LINE_LENGTH];
    int numEntries = 0;
    while (fgets(line, sizeof(line), file) != NULL)
    {
        if (numEntries >= MAX_ENTRIES)
        {
            fprintf(stderr, "Too many entries in the file. Increase MAX_ENTRIES if necessary.\n");
            break;
        }

        uint64_t code;
        char name[100];
        if (sscanf(line, "%" SCNx64 " %*s %s", &code, name) == 2)
        {
            struct CodeNamePair *pair = (struct CodeNamePair *)malloc(sizeof(struct CodeNamePair));
            pair->code = code;
            strncpy(pair->name, name, sizeof(pair->name));
            pair->next = NULL;

            // Calculate the hash and insert into the hash table
            size_t index = code % HASH_TABLE_SIZE;
            if (hashTable[index] == NULL)
            {
                hashTable[index] = pair;
            }
            else
            {
                // Handle collisions with a linked list
                struct CodeNamePair *current = hashTable[index];
                while (current->next != NULL)
                {
                    current = current->next;
                }
                current->next = pair;
            }

            numEntries++;
        }
    }

    fclose(file);
}
#include <stdio.h>
const char *shouldRegister(const uint64_t code)
{
    size_t index = code % HASH_TABLE_SIZE;
    struct CodeNamePair *current = hashTable[index];

    while (current != NULL)
    {
        if (current->code == code)
        {
            fprintf(stderr, "%x -> %s,\n", code, current->name);
            if (strstr(current->name, "recv") != NULL)
            {

                return current->name;
            }
            else
            {
                return NULL;
            }
        }

        current = current->next;
    }

    return NULL;
}

/*
 * Expand last_exec array.
 *
 * As we could have multiple threads trying to do this we need to
 * serialise the expansion under a lock. Threads accessing already
 * created entries can continue without issue even if the ptr array
 * gets reallocated during resize.
 */
static void expand_last_exec(int cpu_index)
{
    g_mutex_lock(&expand_array_lock);
    while (cpu_index >= last_exec->len)
    {
        GString *s = g_string_new(NULL);
        g_ptr_array_add(last_exec, s);
    }
    g_mutex_unlock(&expand_array_lock);
}

void displayQ(u8 *data, size_t length)
{
    printf("\n[TCG PLUGIN]\n");
    printf("length is %d\n", length);
    // printf("length is %d\n",q->length);
    for (size_t i = 0; i < length; i++)
    {
        printf("%c", *(data + i));
        // Display in hexadecimal format
        //  For character representation: printf("%c ", *(ptr + i));
        //  Note: Uncomment the above line for character representation
    }
    // printf("\n\n");
    for (size_t i = 0; i < length; i++)
    {
        // printf("%02X", *(data + i));
        //   Display in hexadecimal format
        //    For character representation: printf("%c ", *(ptr + i));
        //    Note: Uncomment the above line for character representation
    }
    // printf("pritned valu\n");
}

int find_pattern(regex_t *regex, const char *reg_pattern, regmatch_t *match, const char *source) {
	int rc;
	if (0 != (rc = regcomp(regex, reg_pattern, REG_EXTENDED))) {
        char reg_err_buff[REG_ERR_BUFF_SIZE];
        regerror(rc, regex, reg_err_buff, REG_ERR_BUFF_SIZE);
        printf("[TCG PLUGIN] regcomp() failed with '%s'\n", reg_err_buff);
        return rc;
	}
         
   	if (0 != (rc = regexec(regex, source, 1, match, 0))) {
		//printf("Failed to match '%s' with '%s', returning %d.\n",
             //source, reg_pattern, rc);

    	return rc;
	}
         
    return rc;
}

void parse_pattern(const char *pattern, char *prefix, char *fuzzed, char *suffix, size_t size) {
    char *brace_1 = strchr(pattern, '{');
    char *brace_2 = strchr(brace_1, '}');
    
    memcpy(prefix, pattern, brace_1 - pattern);
    memcpy(fuzzed, brace_1 + 1, brace_2 - brace_1 - 1);
    memcpy(suffix, brace_2 + 1, &pattern[size] - brace_2 - 1);
}

static bool new_call = false;
static uint32_t size;
static uint32_t address;

static int contrcv = 0;
// print sys call
static void vcpu_insn_exec2(unsigned int cpu_index, char *name)
{
	++contrcv;
    //printf("Rcv number #%d\n", contrcv);
    // should fuzz (it's httpd req)
    //33552, 6768

    size = qemu_plugin_get_cpu_register(cpu_index, size_register);
    // if (size != 8191)
    //     return;

    address = qemu_plugin_get_cpu_register(cpu_index, address_register);

    //if (contrcv > 650 && address == 0x8010a9d0) // address == 0x11dcf0) // || contrcv > 650)
    //if(address == 0x4dffc8 || address == 0x4dcc58 || address == 0x7ffe44c0 || address == 0x7f7ffb90)
    //if(address == 0x4dffc8)
    /*
    if(buf_address)
        if(address != buf_address)
            return;

    if(size < min_size)
        return;
    */
    //printf("Size is %lu\n", size);
    //printf("Address of buffer is %x\n", address);

    new_call = true;
}

static bool SHOULD_REGISTER = false;
static int localint = 0;
static struct QueueItem temp_q;
/**
 * Add memory read or write information to current instruction log
 */
static int testing = 0;
static int ccc = 0;

static void json_fuzz(unsigned int cpu_index, u8 *memContent);
static void regex_fuzz(unsigned int cpu_index, u8 *memContent);
static void fuzz_all(unsigned int cpu_index, u8 *memContent);


static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{	
    if (!new_call)
        return; 

    new_call = false;

    u8 *memContent;
    memContent = g_malloc(size);
    qemu_plugin_vcpu_read_phys_mem(cpu_index, (uint64_t)address, memContent, (uint64_t)size);

    if(analyze) {
        printf("\nBEFORE INJECTION: reading at address %llx of size %d\n", address, size);
        displayQ(memContent, size);
        printf("\n-----\n");
    }

    if(fuzzing_type == JSON_FUZZING) {

        if(buf_address)
            if(address != buf_address)
                return;

        if(size < min_size)
            return;
	    
        if(regex) {
            /*if(address == 0x4dffc8) {
                printf("\nBEFORE INJECTION: reading at address %llx of size %d\n", address, size);
                displayQ(memContent, size);
                printf("\n-----\n");
            }*/
            // Se il contenuto non rispetta il pattern ritorna dalla funzione
            if(regexec(regex, (char *) memContent, 0, NULL, 0)) {
                //printf("[TCG Plugin] Pattern not recognized\n");
                g_free(memContent);
                return;
            }
            /*printf("\nBEFORE INJECTION: reading at address %llx of size %d\n", address, size);
            displayQ(memContent, size);
            printf("\n-----\n");*/
        }
        //printf("[TCG Plugin] Pattern recognized\n");

    } else if(fuzzing_type == FUZZ_ALL) {
        if(regex) {
            // Se il contenuto non rispetta il pattern ritorna dalla funzione
            if(regexec(regex, (char *) memContent, 0, NULL, 0)) {
                //printf("[TCG Plugin] Pattern not recognized\n");
                g_free(memContent);
                return;
            }
        } else
            return;

    } else if(fuzzing_type == REGEX_FUZZING) {
        if(regex) {
            if(find_pattern(regex, regex_fuzzing_pattern_cleared, match, (char *) memContent)) {
                g_free(memContent);
                return;
            }
        } else
            return;

    } else {
        g_free(memContent);
        return;
    }
    
    
    testing++;

    if (localint > 0 && testing > 1)
    {
        shmptr_fuzzing_report->info = NULL;
        shmptr_fuzzing_report->status = 0;
        shmptr_fuzzing_report->q = temp_q;
        printf("input %d ha finito l'esecuzione\n", temp_q.length);
        sem_post(wait_for_end_test_case);
        printf("waiting for tcg plugin continue...\n");

        sem_wait(tcg_plugin_continue);
        //  sleep(1);
        printf("waited for tcg plugin continue!...\n");
    }

    printf("name is %s\n", udata);
    // fprintf(stderr, "test\n");
    printf("crash track is %x\n", crash_track);
    u8 *fuzzContent;
    u8 *memContent1;

    //GString *logLine = g_string_new(NULL);
    // fprintf(fd, "[PLUGIN INSN_EXEC_CALL DONE]\n");

    /* POSIX4 style signal handlers */
    struct sigaction sa;
    sa.sa_flags = 0;

    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGBUS, &sa, NULL);
    (void)sigaction(SIGSEGV, &sa, NULL);

    fuzzer_mode_opt = FUZZING_MODE;
    instr_index++;

    // Read the original parameters
    printf("address is %x\n", address);

    if(fuzzing_type == JSON_FUZZING)
        json_fuzz(cpu_index, memContent);
    else if(fuzzing_type == REGEX_FUZZING)
        regex_fuzz(cpu_index, memContent);
    else if(fuzzing_type == FUZZ_ALL)
        fuzz_all(cpu_index, memContent);

    localint++;

    g_free(memContent);
}

void json_fuzz(unsigned int cpu_index, u8 *memContent)
{
    if (testing == 1) // first call. should not start fuzz campaign yet
    {
        printf("first hardcoded interaction\n");

        uint32_t array_size = size + 1;
        char *array = malloc(array_size);
        memset(array, 0, array_size);

        int bytes_written = 0;

        if (method.value && path.value && host.value)
        {
            const char *prefix = "%s %s HTTP/1.1\nHost: %s\n";
            bytes_written = snprintf(array, array_size, prefix, method.value, path.value, host.value);
        }

        int i;
        for (i = 0; i < headers.count; ++i)
        {
            bytes_written += snprintf(array + bytes_written, array_size - bytes_written, "%s: %s\n", headers.items[i].key, headers.items[i].value);
        }

        if (body_parameters.count)
        {
            int body_bytes_written = 0;
            char body_suffix[BODY_SUFFIX_SIZE] = {0};

            int i;
            for (i = 0; i < body_parameters.count; ++i)
            {
                // If the key is an empty string
                if (!strcmp("", body_parameters.items[i].key))
                {
                    body_bytes_written += snprintf(body_suffix + body_bytes_written, sizeof(body_suffix) - body_bytes_written, "%s%s",
                                                   body_parameters.items[i].value,
                                                   i == body_parameters.count - 1 ? "" : "&");
                }
                else
                {
                    body_bytes_written += snprintf(body_suffix + body_bytes_written, sizeof(body_suffix) - body_bytes_written, "%s=%s%s",
                                                   body_parameters.items[i].key, body_parameters.items[i].value,
                                                   i == body_parameters.count - 1 ? "" : "&");
                }
            }

            // Check later
            if (headers.count)
                snprintf(array + bytes_written, array_size - bytes_written, "Content-Length: %d\n\n%s", strlen(body_suffix), body_suffix);
            else
                snprintf(array + bytes_written, array_size - bytes_written, "%s", body_suffix);
        }

        // Using snprintf to format and store the result in the array
        // snprintf(array, sizeof(array), prefix, method.value, path.value, host.value);

        // Read l'area di memoria
        // Muta pacchetto

        qemu_plugin_vcpu_write_phys_mem(cpu_index, address, array, size);
        free(array);

        printf("\nAFTER INJECTION: reading at address %llx of size %d\n", address, size);
        qemu_plugin_vcpu_read_phys_mem(cpu_index, (uint64_t)address, memContent, (uint64_t)size);
        displayQ(memContent, size);
        printf("\n-----\n");

        // fill_json_data();
    }
    else
    {
        sem_wait(sem_rd_fuzzing_input);

        temp_q = *shmptr_fuzzing_input;

        uint32_t array_size = size + 1;
        char *array = malloc(array_size);
        memset(array, 0, array_size);

        int bytes_written = 0;

        if (method.value && path.value && host.value)
        {
            const char *prefix = "%s %s HTTP/1.1\nHost: %s\n";
            bytes_written = snprintf(array, array_size, prefix,
                                     method.fuzz ? shmptr_fuzzing_input->data : method.value,
                                     path.fuzz ? shmptr_fuzzing_input->data : path.value,
                                     host.fuzz ? shmptr_fuzzing_input->data : host.value);
        }

        int i;
        for (i = 0; i < headers.count; ++i)
        {
            bytes_written += snprintf(array + bytes_written, array_size - bytes_written, "%s: %s\n", headers.items[i].key,
                                      headers.items[i].fuzz ? shmptr_fuzzing_input->data : headers.items[i].value);
        }

        if (body_parameters.count)
        {
            int body_bytes_written = 0;
            char body_suffix[BODY_SUFFIX_SIZE] = {0};

            int i;
            for (i = 0; i < body_parameters.count; ++i)
            {
                // If the key is an empty string
                if (!strcmp("", body_parameters.items[i].key))
                {
                    body_bytes_written += snprintf(body_suffix + body_bytes_written, sizeof(body_suffix) - body_bytes_written, "%s%s",
                                                   body_parameters.items[i].fuzz ? shmptr_fuzzing_input->data : body_parameters.items[i].value,
                                                   i == body_parameters.count - 1 ? "" : "&");
                }
                else
                {
                    body_bytes_written += snprintf(body_suffix + body_bytes_written, sizeof(body_suffix) - body_bytes_written, "%s=%s%s",
                                                   body_parameters.items[i].key,
                                                   body_parameters.items[i].fuzz ? shmptr_fuzzing_input->data : body_parameters.items[i].value,
                                                   i == body_parameters.count - 1 ? "" : "&");
                }
            }

            // Check later
            if (headers.count)
                snprintf(array + bytes_written, array_size - bytes_written, "Content-Length: %d\n\n%s", strlen(body_suffix), body_suffix);
            else
                snprintf(array + bytes_written, array_size - bytes_written, "%s", body_suffix);
        }

        qemu_plugin_vcpu_write_phys_mem(cpu_index, address, array, size);
        free(array);

        printf("\nAFTER INJECTION: reading at address %llx of size %d\n", address, size);
        qemu_plugin_vcpu_read_phys_mem(cpu_index, (uint64_t)address, memContent, (uint64_t)size);
        displayQ(memContent, size);
        printf("\n-----\n");

        sem_post(sem_wr_fuzzing_input);
    }
}

void regex_fuzz(unsigned int cpu_index, u8 *memContent)
{
    if (testing > 1)
    {
        sem_wait(sem_rd_fuzzing_input);

        temp_q = *shmptr_fuzzing_input;

        uint32_t array_size = size + 1;
        char *array = malloc(array_size);
        memset(array, 0, array_size);

        int fuzz_so = 0; // Start offset
        int fuzz_eo = 0; // End offset
        
        fuzz_so = match[0].rm_so; // Qui comincia il pattern

        if(find_pattern(regex, reg_prefix, match, (char *) &memContent[fuzz_so]))
            return;

        fuzz_so += match[0].rm_eo; // Qui dovrebbe trovarsi la parte da fuzzare

        
        if(find_pattern(regex, reg_fuzzed, match, (char *) &memContent[fuzz_so]))
            return;

        fuzz_eo = fuzz_so + match[0].rm_eo;

        snprintf(array, array_size, "%.*s%s%s", fuzz_so, (char *) memContent, shmptr_fuzzing_input->data, (char *) &memContent[fuzz_eo]);

        qemu_plugin_vcpu_write_phys_mem(cpu_index, address, array, size);
        free(array);

        printf("\nAFTER INJECTION: reading at address %llx of size %d\n", address, size);
        qemu_plugin_vcpu_read_phys_mem(cpu_index, (uint64_t)address, memContent, (uint64_t)size);
        displayQ(memContent, size);
        printf("\n-----\n");

        sem_post(sem_wr_fuzzing_input);
    }
}

void fuzz_all(unsigned int cpu_index, u8 *memContent)
{
    if (testing > 1)
    {
        sem_wait(sem_rd_fuzzing_input);

        temp_q = *shmptr_fuzzing_input;

        uint32_t array_size = size + 1;
        char *array = malloc(array_size);
        memset(array, 0, array_size);

        snprintf(array, array_size, "%.*s", shmptr_fuzzing_input->length, shmptr_fuzzing_input->data);

        qemu_plugin_vcpu_write_phys_mem(cpu_index, address, array, size);
        free(array);

        printf("\nAFTER INJECTION: reading at address %llx of size %d\n", address, size);
        qemu_plugin_vcpu_read_phys_mem(cpu_index, (uint64_t)address, memContent, (uint64_t)size);
        displayQ(memContent, size);
        printf("\n-----\n");

        sem_post(sem_wr_fuzzing_input);
    }
}


#define MAX_VALUES 100// Adjust this value based on your needs

int sentValues[MAX_VALUES] = {0}; // Initialize all elements to 0

int isValueSentBefore(int value)
{
    for (int i = 0; i < MAX_VALUES; i++)
    {
        if (sentValues[i] == value)
        {
            return 1; // Value has been sent before
        }
    }
    return 0; // Value has not been sent before
}

void sendValue(int value)
{
    if (!isValueSentBefore(value))
    {
        // Send the value
        fprintf(stderr, "Sending value: %d\n", value);

        // Store the value in the sentValues array
        for (int i = 0; i < MAX_VALUES; i++)
        {
            if (sentValues[i] == 0)
            {
                sentValues[i] = value;
                break;
            }
        }
    }
    else
    {
        fprintf(stderr, "Value %d has already been sent before.\n", value);
    }
}

static int insn_count = 0;
/**
 * On translation block new translation
 *
 * QEMU convert code by translation block (TB). By hooking here we can then hook
 * a callback on each instruction and memory access.
 */
int read_detected_value() {
    FILE *file = fopen("/home/osboxes/Desktop/project/FuzzBox/externalclient/detected", "r");
    if (file == NULL) {
        //perror("Failed to open detected.txt");
        return 0;
    }
    
    int detected_value;
    if (fscanf(file, "%d", &detected_value) != 1) {
        fclose(file);
        //perror("Failed to read value from detected.txt");
        return 0;
    }
    
    fclose(file);
    return detected_value;
}
int write_zero_to_file(const char *file_path) {
    FILE *file = fopen(file_path, "w");
    if (file == NULL) {
        return -1;
    }

    if (fprintf(file, "%d", 0) < 0) {
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{	
    struct qemu_plugin_insn *insn;
    bool skip_crash = (crash_track);
    bool skip_msg = (msg_track);
    bool detected = (read_detected_value() == 1);

    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++)
    {
        char *insn_disas;
        char *str;
        uint64_t insn_vaddr;

        /*
         * `insn` is shared between translations in QEMU, copy needed data here.
         * `output` is never freed as it might be used multiple times during
         * the emulation lifetime.
         * We only consider the first 32 bits of the instruction, this may be
         * a limitation for CISC architectures.
         */
        insn = qemu_plugin_tb_get_insn(tb, i);
        insn_disas = qemu_plugin_insn_disas(insn);

        insn_vaddr = qemu_plugin_insn_vaddr(insn);
        // printf("vaddr %x, istr disas is %s\n", insn_vaddr, insn_disas);
        char msg[] = "mov   r1";
        if (strstr(insn_disas, msg) != NULL)
        {
            printf("Contains!\n\n");
            // exit(0);
        }

        int j;
        for (j = 0; j < ret_track->len; j++) {
            uint64_t v = g_array_index(ret_track, uint64_t, j);
            if (v == insn_vaddr) {
                qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                                   QEMU_PLUGIN_CB_NO_REGS, insn_disas);

                j = ret_track->len;
            }
        }

         /*
          * If we are filtering we better check out if we have any
          * hits. The skip "latches" so we can track memory accesses
          * after the instruction we care about.
          */
        if (skip_crash && crash_track)
        {
            int j;
            for (j = 0; j < crash_track->len && skip_crash; j++)
            {
                uint64_t v = g_array_index(crash_track, uint64_t, j);
                // printf("v is %x\n",v);
                if (v == insn_vaddr || detected)
                {
                    printf("[TCG Plugin] CRASH Detected.");
                    const char *file_path = "/home/osboxes/Desktop/project/FuzzBox/externalclient/detected";
                    write_zero_to_file(file_path);
                    skip_crash = false;
                }
            }
        }

        if (skip_msg && msg_track)
        {
            int j;
            for (j = 0; j < msg_track->len && skip_msg; j++)
            {
                uint64_t v = g_array_index(msg_track, uint64_t, j);
                if (insn_vaddr == v)
                {
                    skip_msg = false;
                }
            }
        }

        if (skip_crash && skip_msg)
        {
            g_free(insn_disas);
        }
        else
        {

            if (!skip_crash)
            {   
                qemu_plugin_outs("\n");
                qemu_plugin_outs("[TCG Plugin] CRASH Detected.");
                qemu_plugin_outs("\n");

                /* reset skip */
                skip_crash = (crash_track);
                skip_msg = (msg_track);

                printf("CRASH DETECTED!!!!\n");
                shmptr_fuzzing_report->info = NULL;
				shmptr_fuzzing_report->status = -1;
				shmptr_fuzzing_report->q = temp_q;
                sem_post(wait_for_end_test_case);
            }
            else
            {

                uint32_t insn_opcode;
                insn_opcode = *((uint32_t *)qemu_plugin_insn_data(insn));
                char *output = g_strdup_printf("0x%" PRIx64 ", 0x%" PRIx32 ", \"%s\"",
                                               insn_vaddr, insn_opcode, insn_disas);
	
                /* Register callback on instruction */
                SHOULD_REGISTER = true;
                qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec2,
                                                       QEMU_PLUGIN_CB_NO_REGS, insn_disas);
                // exit(0);
                /* reset skip */
                skip_crash = (crash_track);
                skip_msg = (msg_track);
                if (skip_msg) {
                    fprintf(stderr, "[TCG Plugin] Function tracked\n");
                }
            }
        }
    }
}

/**
 * On plugin exit, clean JSON structures
 */
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    if(json_root)
        cJSON_Delete(json_root);

    if(headers.items)
        free(headers.items);

    if(regex) {
        regfree(regex);
        free(regex);
    }

    if(reg_prefix)
        free(reg_prefix);

    if(reg_fuzzed)
        free(reg_fuzzed);

    if(reg_suffix)
        free(reg_suffix);

    if(reg_pattern)
        free(reg_pattern);

    if(regex_fuzzing_pattern)
        free(regex_fuzzing_pattern);

    if(regex_fuzzing_pattern_cleared)
        free(regex_fuzzing_pattern_cleared);

    if(fuzz_all_pattern)
        free(fuzz_all_pattern);
}

/* Add a match to the array of matches */
static void parse_mode_match(char *match)
{
    if (g_strcmp0(match, "SNAPSHOT_MODE") == 0)
    {
        fuzzer_mode_opt = SNAPSHOT_MODE;
    }

    else if (g_strcmp0(match, "FUZZING_MODE") == 0)
    {
        fuzzer_mode_opt = FUZZING_MODE;
    }

    else if (g_strcmp0(match, "DEFAULT_MODE") == 0)
    {
        fuzzer_mode_opt = DEFAULT_MODE;
    }
}

static void parse_crash_match(char *match)
{
    uint64_t v = g_ascii_strtoull(match, NULL, 16);

    if (!crash_track)
    {
        crash_track = g_array_new(false, true, sizeof(uint64_t));
    }
    g_array_append_val(crash_track, v);
}

static void parse_msg_match(char *match)
{
    unsigned long v = g_ascii_strtoull(match, NULL, 16);

    if (fprintf(stderr, "[PLUGIN MSG_MATCH]:  %llx (%llu) \n", v, v) == -1)
    {
        fprintf(stderr, "[PLUGIN MSG_MATCH]:  %x \n", v);
    }

    if (!msg_track)
    {
        msg_track = g_array_new(false, true, sizeof(uint64_t));
    }
    g_array_append_val(msg_track, v);
}

static void parse_ret_match(char *match)
{
    unsigned long v = g_ascii_strtoull(match, NULL, 16);

    if (fprintf(stderr, "[PLUGIN RET_MATCH]:  %llx (%llu) \n", v, v) == -1)
    {
        fprintf(stderr, "[PLUGIN RET_MATCH]:  %x \n", v);
    }

    if (!ret_track)
    {
        ret_track = g_array_new(false, true, sizeof(uint64_t));
    }
    g_array_append_val(ret_track, v);
}

static void parse_registers(char *size_reg, char *address_reg)
{
    if (sscanf(size_reg, "%d", &size_register) != 1) {
        fprintf(stderr, "[TCG Plugin] Conversion error on size register index\n");
        exit(1);
    }

    if (sscanf(address_reg, "%d", &address_register) != 1) {
        fprintf(stderr, "[TCG Plugin] Conversion error on address register index\n");
        exit(1);
    }
}


/**
 * Install the plugin
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{

    for (int i = 0; i < HASH_TABLE_SIZE; i++)
    {
        hashTable[i] = NULL;
    }
    createCodeToNameMapping("/home/kali/FuzzBox/usr/res.txt");

    fprintf(stderr, "test32\n");
    fd = fopen("/home/kali/FuzzBox/usr/dump_instr_mem.txt", "w+");
    if (fd == NULL)
    {
        printf("Error fopen()\n");
    }
    fd1 = fopen("/home/kali/FuzzBox/usr/dump_reg_mem.txt", "w+");
    if (fd1 == NULL)
    {
        printf("Error fopen()\n");
    }
    /*
Shared memory and semaphores intialization for fuzzer mode signal (PRODUCER)
*/
    fprintf(stderr, "[TCG Plugin] Semaphores and SHM initialization for fuzzer mode signal\n");
    wait_for_end_test_case = sem_open(SEM_RD_END_TEST_CASE_MODE, O_CREAT, S_IRWXU, 0);
    if (wait_for_end_test_case == NULL)
    {
        fprintf(stderr, "[TCG Plugin] Error in sem_open()\n");
        exit(1);
    }

    tcg_plugin_continue = sem_open(SEM_RD_END_TCG_PLUGIN_CONTINUE, O_CREAT, S_IRWXU, 0);
    if (tcg_plugin_continue == NULL)
    {
        fprintf(stderr, "[TCG Plugin] Error in sem_open()\n");
        exit(1);
    }

    sem_gathering = sem_open(SEM_GATHERING, O_CREAT, S_IRWXU, 0);
    if (sem_gathering == NULL)
    {
        fprintf(stderr, "[fuzzer] Error in sem_open()\n");
        exit(1);
    }

    sem_gathering2 = sem_open(SEM_GATHERING2, O_CREAT, S_IRWXU, 0);
    if (sem_gathering2 == NULL)
    {
        fprintf(stderr, "[fuzzer] Error in sem_open()\n");
        exit(1);
    }

    sem_rd_fuzzer_mode = sem_open(SEM_RD_FUZZER_MODE, O_CREAT, S_IRWXU, 0);
    if (sem_rd_fuzzer_mode == NULL)
    {
        fprintf(stderr, "[TCG Plugin] Error in sem_open()\n");
        exit(1);
    }
    sem_wr_fuzzer_mode = sem_open(SEM_WR_FUZZER_MODE, O_CREAT, S_IRWXU, 1);
    if (sem_wr_fuzzer_mode == NULL)
    {
        fprintf(stderr, "[TCG Plugin] Error in sem_open()\n");
        exit(1);
    }
    shmfd_fuzzer_mode = shm_open(SHM_FUZZER_MODE, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU | S_IRWXG);
    if (shmfd_fuzzer_mode < 0)
    {
        fprintf(stderr, "[TCG Plugin] Error in shm_open()\n");
        exit(1);
    }
    ftruncate(shmfd_fuzzer_mode, length);
    shmptr_fuzzer_mode = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, shmfd_fuzzer_mode, 0);
    if (shmptr_fuzzer_mode == MAP_FAILED)
    {
        fprintf(stderr, "[TCG Plugin] Error in mmap()\n");
        exit(1);
    }

    /*
    Shared memory and semaphores initialization for fuzzing input (CONSUMER)
    */
    sem_rd_fuzzing_input = sem_open(SEM_RD_FUZZING_INPUT, O_CREAT, S_IRWXU, 0);
    if (sem_rd_fuzzing_input == NULL)
    {
        fprintf(stderr, "[tcg] Error in sem_open() of sem_rd_fuzzing_input\n");
        exit(1);
    }
    sem_wr_fuzzing_input = sem_open(SEM_WR_FUZZING_INPUT, O_CREAT, S_IRWXU, 1);
    if (sem_wr_fuzzing_input == NULL)
    {
        fprintf(stderr, "[tcg] Error in sem_open() of sem_rw_fuzzing_input\n");
        exit(1);
    }

    shmfd_fuzzing_input = shm_open(SHM_FUZZING_INPUT, O_CREAT | O_RDONLY, S_IRWXU | S_IRWXG);
    if (shmfd_fuzzing_input == -1)
    {
        fprintf(stderr, "[tcg] Error in shm_open() of shmfd_fuzzing_input\n");
        exit(1);
    }
    ftruncate(shmfd_fuzzing_input, length_fuzz_input);
    shmptr_fuzzing_input = (struct QueueItem *)mmap(0, length_fuzz_input, PROT_READ, MAP_SHARED, shmfd_fuzzing_input, 0);
    if (shmptr_fuzzing_input == MAP_FAILED)
    {
        fprintf(stderr, "[tcg] Error in mmap() of shmptr_fuzzing_input\n");
        exit(1);
    }

    shmfd_fuzzing_report = shm_open(SHM_FUZZING_REPORT, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU | S_IRWXG);
    if (shmfd_fuzzing_report == -1)
    {
        fprintf(stderr, "[tcg] Error in shm_open() of shmfd_fuzzing_report\n");
        exit(1);
    }
    ftruncate(shmfd_fuzzing_report, length_fuzz_report);
    shmptr_fuzzing_report = (struct SingleFuzzReport *)mmap(0, length_fuzz_report, PROT_READ | PROT_WRITE, MAP_SHARED, shmfd_fuzzing_report, 0);
    if (shmptr_fuzzing_report == MAP_FAILED)
    {
        fprintf(stderr, "[tcg] Error in mmap() of shmptr_fuzzing_report\n");
        exit(1);
    }

    /*
     * Initialize dynamic array to cache vCPU instruction. In user mode
     * we don't know the size before emulation.
     */
    if (info->system_emulation)
    {
        last_exec = g_ptr_array_sized_new(info->system.max_vcpus);
    }
    else
    {
        last_exec = g_ptr_array_new();
    }

    if (argc < 10)
    {
        fprintf(stderr, "[TCG Plugin] Plugin options parsing failed. Syntax: 'regex_pattern=REGEX,json_filename=FILENAME,fuzz_all=REGEX,analyze=(true|false),fuzzer_mode=MODE,crash_track=xxxxxxxx,msg_track=yyyyyyyy,ret_track=zzzzzzzz,size_register=i,address_register=j': \n");
        return -1;
    }
    else
    {
        char *opt0 = argv[0];
        char *opt1 = argv[1];
        char *opt2 = argv[2];
		char *opt3 = argv[3];
		char *opt4 = argv[4];
        char *opt5 = argv[5];
        char *opt6 = argv[6];
        char *opt7 = argv[7];
        char *opt8 = argv[8];
        char *opt9 = argv[9];

        g_autofree char **tokens0 = g_strsplit(opt0, "=", 2);
        g_autofree char **tokens1 = g_strsplit(opt1, "=", 2);
        g_autofree char **tokens2 = g_strsplit(opt2, "=", 2);
        g_autofree char **tokens3 = g_strsplit(opt3, "=", 2);
		g_autofree char **tokens4 = g_strsplit(opt4, "=", 2);
        g_autofree char **tokens5 = g_strsplit(opt5, "=", 2);
        g_autofree char **tokens6 = g_strsplit(opt6, "=", 2);
        g_autofree char **tokens7 = g_strsplit(opt7, "=", 2);
        g_autofree char **tokens8 = g_strsplit(opt8, "=", 2);
        g_autofree char **tokens9 = g_strsplit(opt9, "=", 2);

        if (g_strcmp0(tokens0[0], "regex_pattern") == 0 &&
            g_strcmp0(tokens1[0], "json_filename") == 0 &&
            g_strcmp0(tokens2[0], "fuzz_all") == 0 &&
            g_strcmp0(tokens3[0], "analyze") == 0 && 
            g_strcmp0(tokens4[0], "fuzzer_mode") == 0 && 
            g_strcmp0(tokens5[0], "crash_track") == 0 && 
            g_strcmp0(tokens6[0], "msg_track") == 0 && 
            g_strcmp0(tokens7[0], "ret_track") == 0 &&
            g_strcmp0(tokens8[0], "size_register") == 0 &&
            g_strcmp0(tokens9[0], "address_register") == 0 )
        {
            regex_fuzzing_pattern = tokens0[1];
            json_filename = tokens1[1];
            fuzz_all_pattern = tokens2[1];
            analyze = !strcmp("true", tokens3[1]) ? 1 : 0;
            parse_mode_match(tokens4[1]);
            parse_crash_match(tokens5[1]);
            parse_msg_match(tokens6[1]);
            parse_ret_match(tokens7[1]);
            parse_registers(tokens8[1], tokens9[1]);
            printf("[TCG Plugin] parsed arguments\n");
        }
        else
        {
            fprintf(stderr, "[TCG Plugin] Plugin options parsing failed. Syntax: 'regex_pattern=REGEX,json_filename=FILENAME,fuzz_all=REGEX,analyze=(true|false),fuzzer_mode=MODE,crash_track=xxxxxxxx,msg_track=yyyyyyyy,ret_track=zzzzzzzz,size_register=i,address_register=j': \n");
            return -1;
        }
    }

    if(strlen(regex_fuzzing_pattern)) {
        if(!containsBraces(regex_fuzzing_pattern)) {
            fprintf(stderr, "[TCG Plugin] For regex-based fuzzing you need to enclose what to fuzz in curly braces\n");
            return -1;
        }

        printf("[TCG Plugin] Fuzzing type: Regex-Based\n");
        printf("[TCG Plugin] Regex submitted: %s\n", regex_fuzzing_pattern);
        fuzzing_type = REGEX_FUZZING;

        fill_regex_fuzzing_data();
    }
    else if(strlen(json_filename)) {
        printf("[TCG Plugin] Fuzzing type: JSON-Based\n");
        printf("[TCG Plugin] File submitted: %s\n", json_filename);
        fuzzing_type = JSON_FUZZING;

        fill_json_data();
    } 
    else if(strlen(fuzz_all_pattern)) {
        printf("[TCG Plugin] Fuzzing type: Fuzz-All\n");
        printf("[TCG Plugin] Regex submitted: %s\n", fuzz_all_pattern);
        fuzzing_type = FUZZ_ALL;

        fill_fuzz_all_data();
    }
    else {
        printf("[TCG Plugin] No fuzzing enabled\n");
        fuzzing_type = FUZZ_NONE;
    }
    
    if(analyze)
        printf("[TCG Plugin] Analyze mode activated!\n");

    /* Register translation block and exit callbacks */
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
