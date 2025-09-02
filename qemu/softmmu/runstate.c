/*
 * QEMU main system emulation loop
 *
 * Copyright (c) 2003-2020 QEMU contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "audio/audio.h"
#include "block/block.h"
#include "block/export.h"
#include "chardev/char.h"
#include "crypto/cipher.h"
#include "crypto/init.h"
#include "exec/cpu-common.h"
#include "exec/gdbstub.h"
#include "hw/boards.h"
#include "migration/misc.h"
#include "migration/postcopy-ram.h"
#include "migration/snapshot.h"
#include "monitor/monitor.h"
#include "net/net.h"
#include "net/vhost_net.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-run-state.h"
#include "qapi/qapi-events-run-state.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu/job.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/plugin.h"
#include "qemu/sockets.h"
#include "qemu/thread.h"
#include "qom/object.h"
#include "qom/object_interfaces.h"
#include "sysemu/cpus.h"
#include "sysemu/qtest.h"
#include "sysemu/replay.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "sysemu/runstate-action.h"
#include "sysemu/sysemu.h"
#include "sysemu/tpm.h"
#include "trace.h"

#include "libAFL/queue.h"

#include "monitor/monitor-internal.h"

#include <stdio.h>

#define LOOP_DELAY_SBC 50000

/******************************************************************************
 *
 * INCLUDES PER IL FUZZER
 */

#include "libAFL/config.h"
#include "libAFL/types.h"
#include "libAFL/debug.h"
#include "libAFL/xxh3.h"
#include "libAFL/alloc-inl.h"
#include "libAFL/aflpp.h"
#include "libAFL/afl-returns.h"

#define SUPER_INTERESTING (0.5)
#define VERY_INTERESTING (0.4)
#define INTERESTING (0.3)

#define AFL_FEEDBACK_TAG_OUTCOME (0xFEEDC10C)

#define SHM_FUZZING_REPORT "/fuzzing_input_shm_report_buffer"
#define SEM_RD_END_TCG_PLUGIN_CONTINUE "/fuzzer_tcg_plugin_continue"
#define SEM_GATHERING "/sem_gathering"
#define SEM_GATHERING2 "/sem_gathering2"

/******************************************************************************
 *
 * SIPC
 */

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
/******************************************************************************
 *
 * FUZZER
 */

struct QueueItem
{
    u8 *data;
    size_t length;
};

struct SingleFuzzReport
{
    int status; // 0 = ok, -1 = error
    char *info; // info on error
    struct QueueItem q;
};

static afl_queue_feedback_t *coverage_feedback_queue;
static afl_feedback_cov_t *coverage_feedback;
static afl_observer_covmap_t *observer_covmap;

static afl_queue_global_t *global_queue;
static int debug = 0;
static ssize_t calibration_idx = -1;

#include <stdio.h>

#define MAX_SIZE 100

typedef unsigned char u8; // Assuming u8 is an unsigned char

int shm_fd;
int shm_fd2;
static u8 *afl_area_ptr;
static u8 *block_afl_area_ptr;
static u8 *virgin_bits;

sem_t *wait_for_end_test_case;
sem_t *tcg_plugin_continue;
sem_t *fuzzed_input_rdy;
sem_t *sem_gathering;
sem_t *sem_gathering2;

int shmfd_fuzzing_input;                // file descriptor
struct QueueItem *shmptr_fuzzing_input; // shm pointer

int shmfd_fuzzing_report;
struct SingleFuzzReport *shmptr_fuzzing_report;

// Added variables for the fuzzing component
MonitorHMP *mon_hmp;
int fuzzer_mode = DEFAULT_MODE;
void displayQueueItem(struct QueueItem *q)
{
    if (VERBOSE_LOG > 0)
    {
        printf("\n[INJECTOR THREAD]\n");
        printf("length is %d\n", q->length);

        if (VERBOSE_LOG == 2)
            for (size_t i = 0; i < q->length; i++)
            {
                printf("%c", q->data[i]); // Display in hexadecimal format
                // For character representation: printf("%c ", *(ptr + i));
                // Note: Uncomment the above line for character representation
            }
        printf("\n");
    }
}
/* TODO: Make this a method of queue instead */

static void afl_print_queue()
{
    // possibile problema di lettura su entry. problema di concorrenza?
    printf("\nQUEUE. NUMBER OF ENTRIES: %ld\n", ((afl_queue_t *)global_queue)->entries_count);
    size_t i;
    for (i = 0; i < (u32)((afl_queue_t *)global_queue)->entries_count; i++)
    {
        afl_entry_t *queue_entry = global_queue->base.funcs.get_queue_entry((afl_queue_t *)global_queue, i);

        printf("\nENTRY: [%d]", queue_entry->input->len);
        // bug bypass weird item
        if (queue_entry->input->len < 10000)
            printf("%s \n", queue_entry->input->bytes);
        // for(size_t j = 0; j < queue_entry->input->len; j++){
        //     printf("%02X ", *(queue_entry->input->bytes + j));
        // }
        printf("\n");
    }
}

/* Initializer: run initial seeds */
static afl_ret_t mils_fuzzer_initialize(afl_executor_t *executor)
{
    mils_executor_t *mils_executor = (mils_executor_t *)executor;

    global_queue = mils_executor->global_queue;

    if (calibration_idx > 0)
    {
        if (debug)
            printf("\nCalibrations to check: %ld\n", calibration_idx);
        while (calibration_idx > 0)
        {
            --calibration_idx;
            if (debug)
                printf("\nSeed %ld\n", calibration_idx);
            afl_entry_t *queue_entry = mils_executor->global_queue->base.funcs.get_queue_entry((afl_queue_t *)mils_executor->global_queue, calibration_idx);
            if (queue_entry && !queue_entry->info->skip_entry)
            {
                if (debug)
                    printf("Seed %ld testing ...\n", calibration_idx);
                queue_entry->info->skip_entry = 1;
                if (afl_stage_run(mils_executor->stage, queue_entry->input, false) == AFL_RET_SUCCESS)
                {
                    afl_stage_is_interesting(mils_executor->stage);
                    queue_entry->info->skip_entry = 0;
                }
                else
                {
                    WARNF("\nQueue entry %ld misbehaved, disabling...", calibration_idx);
                }
            }
        }
    }

    if (calibration_idx == 0)
    {
        if (debug)
        {
            printf("\nCalibration checks done.\n");
            u32 i;
            printf("%u seeds:\n", (u32)((afl_queue_t *)mils_executor->global_queue)->entries_count);
            for (i = 0; i < (u32)((afl_queue_t *)mils_executor->global_queue)->entries_count; i++)
            {
                afl_entry_t *queue_entry = mils_executor->global_queue->base.funcs.get_queue_entry((afl_queue_t *)mils_executor->global_queue, i);
                if (queue_entry && queue_entry->info->skip_entry)
                    printf("Seed #%u is disabled\n", i);
            }
        }

        calibration_idx = -1; /* we are done */
    }

    return AFL_RET_SUCCESS;
}

/*
void write_cur_state()
{
  state->current_input_len = current_input->len;
  state->calibration_idx = calibration_idx;
}
*/

void writeToLogFile(afl_input_t *input, double timeElapsed, int interactionsCount, afl_input_t *seed)
{

    char filename[50]; // Adjust the size as needed
    time_t currentTime = time(NULL);
    struct tm *localTime = localtime(&currentTime);

    // Format the timestamp as YYYYMMDD_HHMMSS
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", localTime);

    sprintf(filename, "./crash/crash_%s_%d.txt", timestamp, interactionsCount);

    FILE *file;
    file = fopen(filename, "w+"); // Open the file in write mode

    if (file == NULL)
    {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    // Write input string, time elapsed, and interactions count to the file
    fprintf(file, "Seed String: %.*s\n", (int)seed->len, seed->bytes);
    fprintf(file, "Input String: %.*s\n", (int)input->len, input->bytes);
    fprintf(file, "Time Elapsed: %lf seconds\n", timeElapsed);
    fprintf(file, "Interactions Count: %d\n", interactionsCount);

    // Close the file
    fclose(file);
}

static int ixx = 0;
static time_t start_time = 0;

struct timespec start_timeC, end_timeC;

void handleCrash(afl_executor_t *executor)
{
    clock_gettime(CLOCK_MONOTONIC, &end_timeC);
    long elapsed_ = 0;

    elapsed_ = (end_timeC.tv_sec - start_timeC.tv_sec) * 1000;       // seconds to milliseconds
    elapsed_ += (end_timeC.tv_nsec - start_timeC.tv_nsec) / 1000000; // nanoseconds to milliseconds
    printf("seed was %s\n", global_queue->base.entries[0]->input->bytes);
    double timeElapsed = (double)elapsed_ / 1000;
    writeToLogFile(executor->current_input, timeElapsed, ixx, global_queue->base.entries[0]->input);
    // afl_input_dump_to_crashfile(executor->current_input, global_queue->base.funcs.get_dirpath(&global_queue->base));

    printf("CRASH!!!\n\n");
    printf("crash causato da input:\n");

    displayQueueItem(shmptr_fuzzing_input);
    // teoricamente non è giusto stampare shmptr_fuzzing_input, ma bisognerebbe gestirla con una struttura
    // in executor
    // però l'utilizzo del semaforo tcg_plugin_continue ci assicura che quando leggiamo questo ci sia ancora il vecchio valore
    // (se il semaforo l'ho gestito bene lol)

    afl_print_queue();
    FATAL("Crash Detected, execution arrested");
}

static const char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *data, size_t input_length)
{
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(output_length + 1);
    if (encoded_data == NULL)
        return NULL;

    for (size_t i = 0, j = 0; i < input_length;)
    {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 0 * 6) & 0x3F];
    }

    for (size_t i = 0; i < (3 - input_length % 3) % 3; i++)
    {
        encoded_data[output_length - 1 - i] = '=';
    }

    encoded_data[output_length] = '\0';
    return encoded_data;
}

size_t base64_encoded_length(size_t input_length)
{
    return 4 * ((input_length + 2) / 3);
}
int hexCharToInt(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    else if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    else if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    return -1; // Invalid character
}
char *hexToAscii(const char *hexString)
{
    if (hexString == NULL || strlen(hexString) % 2 != 0)
    {
        return NULL; // Invalid input or odd-length string
    }

    size_t hexLen = strlen(hexString);
    size_t asciiLen = hexLen / 2;
    char *asciiString = (char *)malloc(asciiLen + 1); // +1 for null terminator

    if (asciiString == NULL)
    {
        return NULL; // Memory allocation failed
    }

    for (size_t i = 0, j = 0; i < hexLen; i += 2, j++)
    {
        int highNibble = hexCharToInt(hexString[i]);
        int lowNibble = hexCharToInt(hexString[i + 1]);

        if (highNibble == -1 || lowNibble == -1)
        {
            free(asciiString);
            return NULL; // Invalid hexadecimal characters
        }

        asciiString[j] = (char)((highNibble << 4) | lowNibble);
    }

    asciiString[asciiLen] = '\0'; // Null-terminate the ASCII string
    return asciiString;
}
static int shmfd_fuzzer_mode;                   // file descriptor
static int *shmptr_fuzzer_mode;                 // shm pointer
sem_t *sem_rd_fuzzer_mode, *sem_wr_fuzzer_mode; // semaphores to read and write fuzzer mode
off_t length = sizeof(struct QueueItem);

sem_t *sem_rd_fuzzing_input, *sem_wr_fuzzing_input; // semaphores to read and write fuzzing input
off_t length_fuzz_input = sizeof(struct QueueItem);

struct timespec start_timeT, end_timeT;
long elapsed_time;

static int gogo = 0;
// PRODUTTORE
static int retries = 0;
static int max_retries = 0;
static int ixx2 = 0; // for snapshot workaround

afl_exit_t debug_harness_func(afl_executor_t *executor, u8 *input, size_t len)
{
    int status = -2;
    while (status == -2)
    {
        if (++retries > 0)
        {
            printf("tentativo numero %d\n", retries);
            if (retries > max_retries)
            {
                max_retries = retries;
                printf("NEW MAX RETRIES!!! is %d\n", max_retries);
            }
        }
        if (VERBOSE_LOG > 0)
            printf("\n------\n");
        (void)executor;
        /*if (ixx > 0) // else
        {
            printf("Loading snapshot!\n");
            fuzzer_mode = RECOVER_MODE;
            //  sleep(5);
            sleep(1);
            //  sem_wait(sem_rd_fuzzer_mode);
            printf("Loaded snapshot\n");
        }*/
        if (ixx < INIT_TIMES && !SNAPSHOT_ENABLED)
        {
            printf("Waiting %d seconds...\n", INIT_WAIT_TIME);
            sleep(INIT_WAIT_TIME); // this way shm ok is garanteed
        }
        // sleep(1);
        if (ixx > 0)
            sem_post(tcg_plugin_continue); // utile perchè durante il calcolo della bitmap non devbono inficiiare gli input dopo!
                                           // printf("\ntest\n");
                                           //  shmptr_fuzzing_input->data = (u8 *)malloc((len+1) * sizeof(u8)); // len +1 ?

        /*size_t input_length = sizeof(jpeg_data) / sizeof(jpeg_data[0]);
         char *encoded_string = base64_encode(input, input_length);
         if (encoded_string != NULL)
         {
             printf("Encoded string: %s\n", encoded_string);

             size_t encoded_length = base64_encoded_length(input_length);
             printf("Length of the encoded string: %zu\n", encoded_length);
             shmptr_fuzzing_input->data = (u8 *)encoded_string;
             shmptr_fuzzing_input->length = encoded_length;
             //free(encoded_string);
         }
         else
         {
             printf("Failed to encode the string.\n");
         }*/
        // MINIMIZE to obtain a simpler seed

        // sem_wait(sem_rd_fuzzer_mode);

        sem_wait(sem_wr_fuzzing_input);

        if (ixx > -1)
        {
            if (PC_GATHERING_MODE)
            {
                shmptr_fuzzing_input->data = "TEST";
                shmptr_fuzzing_input->length = 4;
            }
            else
            {
                if (BASE64_MODE) // sendMessageSIPC and receivemsg may truncate on \0. A future approach could be base64 encoding the intercepted sys call and decode in MILS (target application)
                {
                    char *input64 = base64_encode(input, len);
                    size_t len64 = strlen(input64);

                    FILE *file = fopen("/tmp/fuzzing_input.txt", "w+");
                    if (file)
                    {
                        fwrite(input64, 1, len64, file);
                        fclose(file);
                        printf("input 64 is %s\n", input64);
                        printf("len 64 is %zu\n", len64);
                    }

                    shmptr_fuzzing_input->data = (u8 *)realloc(shmptr_fuzzing_input->data, (len64 + 1) * sizeof(u8));
                    memcpy(shmptr_fuzzing_input->data, input64, len64 + 1);
                    shmptr_fuzzing_input->length = len64;
                    printf("input 64 is %s\n", input64);
                    printf("len 64 is %d\n", len64);

                    // shmptr_fuzzing_input->data[len64] = '\0';
                }
                else
                {
                    FILE *file = fopen("/tmp/fuzzing_input.txt", "w+");
                    if (file)
                    {
                        fwrite(input, 1, len, file);
                        fclose(file);
                    }
                    shmptr_fuzzing_input->data = (u8 *)realloc(shmptr_fuzzing_input->data, (len + 1) * sizeof(u8));
                    // memcpy(shmptr_fuzzing_input->data, input, len + 1);

                    for (size_t i = 0; i < len; i++)
                    {
                        shmptr_fuzzing_input->data[i] = input[i];
                    }
                    shmptr_fuzzing_input->data[len] = '\0';
                    shmptr_fuzzing_input->length = len;
                }
            }

            // questo peszzo di codice qua sotto serve per verificare che tutte le sys call send del mils
            // vengano effettivamente ricevute (quindi si passa un intero crescente e si vede se arrivano nel log
            // della seriale del mils)

            /*int num = ixx; // You can change this value to any integer
            char str[20];  // Define a character array to hold the resulting string

            // Convert integer to string
            snprintf(str, sizeof(str), "%d", num);

            size_t len = strlen(str);
            shmptr_fuzzing_input->length = len;

            // Allocate memory for shmptr_fuzzing_input->data
            shmptr_fuzzing_input->data = (u8 *)realloc(shmptr_fuzzing_input->data, (len + 1) * sizeof(u8));

            // Copy the string content to shmptr_fuzzing_input->data
            memcpy(shmptr_fuzzing_input->data, str, len + 1); // +1 for null-terminator

            // Update the length if necessary
            shmptr_fuzzing_input->length = len;*/
        }
        else
        {
            char *tar = "XX";
            len = ixx + 1;
            shmptr_fuzzing_input->data = (u8 *)realloc(shmptr_fuzzing_input->data, (len + 1) * sizeof(u8));
            for (size_t i = 0; i < len; i++)
            {
                shmptr_fuzzing_input->data[i] = tar[i];
            }
            shmptr_fuzzing_input->length = len;

            /*char *inputJson = "{ \
                \"nome\": \"Mario\", \
                \"cognome\": \"Rossi\", \
                \"eta\": 30, \
                \"email\": \"mario.rossi@email.com\", \
                \"indirizzo\": { \
                    \"via\": \"Via Roma\", \
                    \"citta\": \"Roma\", \
                    \"CAP\": \"00100\" \
                }, \
                \"interessi\": [ \
                    \"musica\", \
                    \"viaggi\", \
                    \"tecnologia\" \
                ] \
            }";
            inputJson="1+2+3";
            shmptr_fuzzing_input->data = inputJson;

            //memcpy(shmptr_fuzzing_input->data, inputJson, sizeof(inputJson));

            shmptr_fuzzing_input->length = strlen(inputJson) / 2;*/

            // shmptr_fuzzing_input->data = inputJson;
            //  tinyExpr
            //  char *malevolo = "706f7728312c3231353872e8b02b34352b322b332b3433d4342b746f7728313432313538322b332b34352b322b332b34332b342bcaca4bb7442b37";

            /*
            shmptr_fuzzing_input->data = hexToAscii(malevolo);
            shmptr_fuzzing_input->length = strlen(malevolo) / 2;
            */
        }

        /*if (ixx == 100000)
        {
            afl_print_queue();
            exit(0);
            return;
        }*/

        ixx++;

        // printf("\nfirst value:\n");
        displayQueueItem(shmptr_fuzzing_input);

        // SEMAFORO PER DIRE CHE INPUT È PRONTO AL INJECTOR THREAD E A SUA VOLTA GIRA A TCG PLUGIN
        // sem_post(fuzzed_input_rdy);
        printf("input %d è pronto\n", shmptr_fuzzing_input->length);
        // SI ASPETTA CHE FINISCE L'ESECUZIONE DELLA FUNZIONE (ASPETTIAMO SEGNALE DA TCG PLUGIN)

        sem_post(sem_rd_fuzzing_input);

        sem_wait(wait_for_end_test_case);
        printf("input %d ha finito esecuzione, si preleva status\n", shmptr_fuzzing_input->length);

        // sleep(1);
        //  SI PRELEVA IL REPORT DAL TCG PLUGIN
        status = shmptr_fuzzing_report->status;
        executor->info = shmptr_fuzzing_report->info;

        // dopo che finisce il report, calcoliamo il throughput

        if (THROUGHPUT_METRIC)
        {
            if (status != -2)
            {
                ixx2++;
            }
            if (ixx2 == THROUGHPUT_LBOUND)
            {                                                 /* THROUGHPUT GATHERING*/
                clock_gettime(CLOCK_MONOTONIC, &start_timeT); // Get the current time
            }
            if (ixx2 == THROUGHPUT_HBOUND)
            {
                clock_gettime(CLOCK_MONOTONIC, &end_timeT); // Get the current time after the task

                // Calculate elapsed time in milliseconds
                elapsed_time = (end_timeT.tv_sec - start_timeT.tv_sec) * 1000;       // seconds to milliseconds
                elapsed_time += (end_timeT.tv_nsec - start_timeT.tv_nsec) / 1000000; // nanoseconds to milliseconds

                double throughput = (double)ixx2 / elapsed_time * 1000;
                printf("iterations is %d\n", THROUGHPUT_HBOUND - THROUGHPUT_LBOUND);
                printf("elapsed time is %ld\n", elapsed_time);
                printf("throughput is %f\n", throughput);
                exit(0);
            }
        }

        if (PC_GATHERING_MODE)
        {
            return AFL_EXIT_OK;
        }

        if (status == 0)
        {
            // ok
            retries = 0;
            if (VERBOSE_LOG > 0)
                afl_print_queue();
            return AFL_EXIT_OK;
        }
        else if (status == -1)
        {
            // crashed
            handleCrash(executor);
            return AFL_EXIT_ERROR_DETECTED;
        }
        else if (status == -2)
        {
            // status=-4;
            //  snapshot error. should retry writing shared mem on next syscall intercettata
            printf("Trying to fuzz the input %s but failed. trying again..\n", shmptr_fuzzing_report->q.data);
        }
    }
    // should never reach here but just in case
    return AFL_EXIT_OK;
}

afl_engine_t *initialize_engine_istance()
{
    clock_gettime(CLOCK_MONOTONIC, &start_timeC); // initialize start_time

    mils_executor_t *mils_executor = calloc(1, sizeof(mils_executor_t));
    if (!mils_executor)
    {
        PFATAL("Unable to allocate mem.");
    }
    mils_executor_init(mils_executor, debug_harness_func);

    /* Observation channel, map based, we initialize this ourselves since we don't
     * actually create a shared map */
    observer_covmap = afl_observer_covmap_new(MAP_SIZE);
    if (!observer_covmap)
    {
        PFATAL("Trace bits channel error");
    }
    // afl_observer_covmap_init(observer_covmap,MAP_SIZE); test?
    afl_shmem_deinit(&observer_covmap->shared_map);

    if (BLOCKCOV_MODE)
    {
        observer_covmap->shared_map.map = block_afl_area_ptr; // Coverage "Map" we have
        observer_covmap->shared_map.map_size = MAP_SIZE;
        observer_covmap->shared_map.shm_id = -1;
        observer_covmap->shared_map_block_coverage.map = afl_area_ptr;
        observer_covmap->shared_map_block_coverage.map_size = MAP_SIZE;
        observer_covmap->shared_map_block_coverage.shm_id = -2;
    }
    else
    {
        observer_covmap->shared_map.map = afl_area_ptr; // Coverage "Map" we have
        observer_covmap->shared_map.map_size = MAP_SIZE;
        observer_covmap->shared_map.shm_id = -1;
        observer_covmap->shared_map_block_coverage.map = block_afl_area_ptr;
        observer_covmap->shared_map_block_coverage.map_size = MAP_SIZE;
        observer_covmap->shared_map_block_coverage.shm_id = -2;
    }

    mils_executor->base.funcs.observer_add(&mils_executor->base, &observer_covmap->base);

    coverage_feedback_queue = afl_queue_feedback_new(NULL, (char *)"Coverage feedback queue");
    if (!coverage_feedback_queue)
    {
        FATAL("Error initializing feedback queue");
    }

    afl_queue_global_t *new_global_queue = afl_queue_global_new();
    if (!new_global_queue)
    {
        FATAL("Error initializing global queue");
    }

    afl_queue_global_init(new_global_queue);
    new_global_queue->base.funcs.set_dirpath(&new_global_queue->base, "./crash");
    new_global_queue->funcs.add_feedback_queue(new_global_queue, coverage_feedback_queue);

    coverage_feedback = afl_feedback_cov_new(coverage_feedback_queue, observer_covmap);
    coverage_feedback_queue->feedback = &coverage_feedback->base;
    afl_feedback_cov_init(coverage_feedback, coverage_feedback_queue, observer_covmap);

    // printf("dir path is %s\n",global_queue->base.funcs.get_dirpath(&global_queue->base));
    afl_queue_feedback_init(coverage_feedback_queue, coverage_feedback, "queue_name1");
    coverage_feedback_queue->base.funcs.set_dirpath(&coverage_feedback_queue->base, "./coverage");
    // al momento si aggiunge alla global queue

    if (!coverage_feedback)
    {
        FATAL("Error initializing feedback");
    }

    afl_engine_t *engine = afl_engine_new(&mils_executor->base, NULL, new_global_queue);
    if (!engine)
    {
        FATAL("Error initializing Engine");
    }
    engine->verbose = 1;
    engine->funcs.add_feedback(engine, &coverage_feedback->base);
    engine->in_dir = "./seeds";
    engine->funcs.set_global_queue(engine, new_global_queue);

    afl_fuzz_one_t *fuzz_one = afl_fuzz_one_new(engine);
    if (!fuzz_one)
    {
        FATAL("Error initializing fuzz_one");
    }

    /* We also add the fuzzone to the engine here. */
    engine->funcs.set_fuzz_one(engine, fuzz_one);

    /* Deterministic stage */
    
    afl_stage_t *det_stage = calloc(1, sizeof(afl_stage_t));
    if (!det_stage)
    {
        FATAL("Error allocating memory for fuzzing stage");
    }

    if (afl_det_stage_init(det_stage, engine) != AFL_RET_SUCCESS)
    {
        FATAL("Error initializing fuzzing stage");
        free(det_stage); // Free allocated memory before exiting
    }

    AFL_TRY(det_stage->funcs.add_mutator_to_stage(det_stage, (afl_mutator_t *)afl_mutator_deterministic_new(afl_mutate_bitflip_det, afl_get_iters_bitflip_det)),
            { FATAL("Error adding mutator: %s", afl_ret_stringify(err)); });
    AFL_TRY(det_stage->funcs.add_mutator_to_stage(det_stage, (afl_mutator_t *)afl_mutator_deterministic_new(afl_mutate_det_flip_two, afl_get_iters_flip_two_det)),
            { FATAL("Error adding mutator: %s", afl_ret_stringify(err)); });
    AFL_TRY(det_stage->funcs.add_mutator_to_stage(det_stage, (afl_mutator_t *)afl_mutator_deterministic_new(afl_mutate_det_flip_four, afl_get_iters_flip_four_det)),
            { FATAL("Error adding mutator: %s", afl_ret_stringify(err)); });
    AFL_TRY(det_stage->funcs.add_mutator_to_stage(det_stage, (afl_mutator_t *)afl_mutator_deterministic_new(afl_mutate_det_flip_byte, afl_get_iters_flip_byte_det)),
            { FATAL("Error adding mutator: %s", afl_ret_stringify(err)); });
    AFL_TRY(det_stage->funcs.add_mutator_to_stage(det_stage, (afl_mutator_t *)afl_mutator_deterministic_new(afl_mutate_det_flip_two_byte, afl_get_iters_flip_two_byte_det)),
            { FATAL("Error adding mutator: %s", afl_ret_stringify(err)); });

    /* Havoc stage */
    afl_mutator_scheduled_t *mutators_havoc = afl_mutator_scheduled_new(engine, 8);
    if (!mutators_havoc)
    {
        FATAL("Error initializing Mutators");
    }

    AFL_TRY(afl_mutator_scheduled_add_havoc_funcs(mutators_havoc),
            { FATAL("Error adding mutators: %s", afl_ret_stringify(err)); });

    afl_stage_t *stage = afl_stage_new(engine);
    if (!stage)
    {
        FATAL("Error creating fuzzing stage");
    }
    AFL_TRY(stage->funcs.add_mutator_to_stage(stage, &mutators_havoc->base),
            { FATAL("Error adding mutator: %s", afl_ret_stringify(err)); });
    mils_executor->stage = stage;

    mils_executor->global_queue = new_global_queue;

    /* Check for engine to be configured properly */
    if (afl_engine_check_configuration(engine) != AFL_RET_SUCCESS)
    {
        printf("Engine configured incompletely");
    };

    /*AFL_TRY(engine->funcs.load_testcases_from_dir(engine),
                { WARNF("Error loading testcase dir: %s", afl_ret_stringify(err)); });
    */

    AFL_TRY(engine->funcs.load_testcases_from_dir(engine, engine->in_dir),
            { WARNF("Error loading testcase dir: %s", afl_ret_stringify(err)); });

    /* no seeds? add a dummy one  */
    if (((afl_queue_t *)engine->global_queue)->entries_count == 0)
    {
        afl_input_t *input = afl_input_new();
        if (!input)
        {
            FATAL("Could not create input");
        }
        u32 cnt;
        u32 input_len = 15;
        input->len = input_len;
        input->bytes = calloc(input_len + 1, 1);
        if (!input->bytes)
        {
            PFATAL("Could not allocate input bytes");
        }

        for (cnt = 0; cnt < input_len; cnt++)
        {
            input->bytes[cnt] = ' ' + cnt; /*  values: 0x20 ... 0x60 */

            input->bytes[input_len] = 0;

            afl_entry_t *new_entry = afl_entry_new(input, NULL);
            if (!new_entry)
            {
                FATAL("Could not create new entry");
            }
            engine->global_queue->base.funcs.insert(&engine->global_queue->base, new_entry);
        }
    }

    calibration_idx = (ssize_t)((afl_queue_t *)engine->global_queue)->entries_count;
    OKF("\nStarting seed count: %lu", calibration_idx);

    return engine;
}

void fuzzer_process_main(void *data)
{
    afl_engine_t *engine = (afl_engine_t *)data;

    afl_observer_covmap_t *observer_covmap = NULL;
    size_t i;
    for (i = 0; i < engine->executor->observors_count; i++)
    {

        if (engine->executor->observors[i]->tag == AFL_OBSERVER_TAG_COVMAP)
        {

            observer_covmap = (afl_observer_covmap_t *)engine->executor->observors[0];
        }
    }

    if (!observer_covmap)
    {
        FATAL("Got no covmap observer");
    }

    // set the global virgin_bits for error handlers, so we can restore them after a crash
    virgin_bits = observer_covmap->shared_map.map;

    afl_feedback_cov_t *coverage_feedback = NULL;
    for (i = 0; i < engine->feedbacks_count; i++)
    {

        if (engine->feedbacks[i]->tag == AFL_FEEDBACK_TAG_COV)
        {

            coverage_feedback = (afl_feedback_cov_t *)(engine->feedbacks[i]);
            break;
        }
    }

    if (!coverage_feedback)
    {
        FATAL("No coverage feedback added to engine");
    }

    afl_stage_t *stage = engine->fuzz_one->stages[0];
    afl_mutator_scheduled_t *mutators_havoc = (afl_mutator_scheduled_t *)stage->mutators[0];

    mils_fuzzer_initialize(engine->executor);

    /* The actual fuzzing */
    AFL_TRY(engine->funcs.loop(engine), { PFATAL("Error fuzzing the target: %s", afl_ret_stringify(err)); });

    SAYF("Fuzzing ends with all the queue entries fuzzed. No of executions %llu\n", engine->executions);
    printf("segm?\n\n");

    /* Let's free everything now. Note that if you've extended any structure,
     * which now contains pointers to any dynamically allocated region, you have
     * to free them yourselves, but the extended structure itself can be de
     * initialized using the deleted functions provided */

    afl_executor_delete(engine->executor);
    afl_mutator_scheduled_delete(mutators_havoc);
    afl_stage_delete(stage);
    afl_fuzz_one_delete(engine->fuzz_one);

    for (i = 0; i < engine->feedbacks_count; ++i)
    {

        afl_feedback_delete((afl_feedback_t *)engine->feedbacks[i]);
    }

    for (i = 0; i < engine->global_queue->feedback_queues_count; ++i)
    {

        afl_queue_feedback_delete(engine->global_queue->feedback_queues[i]);
    }

    afl_queue_global_delete(engine->global_queue);
    afl_engine_delete(engine);

    // taskSuspend (0);
}

static NotifierList exit_notifiers =
    NOTIFIER_LIST_INITIALIZER(exit_notifiers);

static RunState current_run_state = RUN_STATE_PRELAUNCH;

/* We use RUN_STATE__MAX but any invalid value will do */
static RunState vmstop_requested = RUN_STATE__MAX;
static QemuMutex vmstop_lock;

typedef struct
{
    RunState from;
    RunState to;
} RunStateTransition;

static const RunStateTransition runstate_transitions_def[] = {
    {RUN_STATE_PRELAUNCH, RUN_STATE_INMIGRATE},

    {RUN_STATE_DEBUG, RUN_STATE_RUNNING},
    {RUN_STATE_DEBUG, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_DEBUG, RUN_STATE_PRELAUNCH},

    {RUN_STATE_INMIGRATE, RUN_STATE_INTERNAL_ERROR},
    {RUN_STATE_INMIGRATE, RUN_STATE_IO_ERROR},
    {RUN_STATE_INMIGRATE, RUN_STATE_PAUSED},
    {RUN_STATE_INMIGRATE, RUN_STATE_RUNNING},
    {RUN_STATE_INMIGRATE, RUN_STATE_SHUTDOWN},
    {RUN_STATE_INMIGRATE, RUN_STATE_SUSPENDED},
    {RUN_STATE_INMIGRATE, RUN_STATE_WATCHDOG},
    {RUN_STATE_INMIGRATE, RUN_STATE_GUEST_PANICKED},
    {RUN_STATE_INMIGRATE, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_INMIGRATE, RUN_STATE_PRELAUNCH},
    {RUN_STATE_INMIGRATE, RUN_STATE_POSTMIGRATE},
    {RUN_STATE_INMIGRATE, RUN_STATE_COLO},

    {RUN_STATE_INTERNAL_ERROR, RUN_STATE_PAUSED},
    {RUN_STATE_INTERNAL_ERROR, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_INTERNAL_ERROR, RUN_STATE_PRELAUNCH},

    {RUN_STATE_IO_ERROR, RUN_STATE_RUNNING},
    {RUN_STATE_IO_ERROR, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_IO_ERROR, RUN_STATE_PRELAUNCH},

    {RUN_STATE_PAUSED, RUN_STATE_RUNNING},
    {RUN_STATE_PAUSED, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_PAUSED, RUN_STATE_POSTMIGRATE},
    {RUN_STATE_PAUSED, RUN_STATE_PRELAUNCH},
    {RUN_STATE_PAUSED, RUN_STATE_COLO},

    {RUN_STATE_POSTMIGRATE, RUN_STATE_RUNNING},
    {RUN_STATE_POSTMIGRATE, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_POSTMIGRATE, RUN_STATE_PRELAUNCH},

    {RUN_STATE_PRELAUNCH, RUN_STATE_RUNNING},
    {RUN_STATE_PRELAUNCH, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_PRELAUNCH, RUN_STATE_INMIGRATE},

    {RUN_STATE_FINISH_MIGRATE, RUN_STATE_RUNNING},
    {RUN_STATE_FINISH_MIGRATE, RUN_STATE_PAUSED},
    {RUN_STATE_FINISH_MIGRATE, RUN_STATE_POSTMIGRATE},
    {RUN_STATE_FINISH_MIGRATE, RUN_STATE_PRELAUNCH},
    {RUN_STATE_FINISH_MIGRATE, RUN_STATE_COLO},

    {RUN_STATE_RESTORE_VM, RUN_STATE_RUNNING},
    {RUN_STATE_RESTORE_VM, RUN_STATE_PRELAUNCH},

    {RUN_STATE_COLO, RUN_STATE_RUNNING},
    {RUN_STATE_COLO, RUN_STATE_SHUTDOWN},

    {RUN_STATE_RUNNING, RUN_STATE_DEBUG},
    {RUN_STATE_RUNNING, RUN_STATE_INTERNAL_ERROR},
    {RUN_STATE_RUNNING, RUN_STATE_IO_ERROR},
    {RUN_STATE_RUNNING, RUN_STATE_PAUSED},
    {RUN_STATE_RUNNING, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_RUNNING, RUN_STATE_RESTORE_VM},
    {RUN_STATE_RUNNING, RUN_STATE_SAVE_VM},
    {RUN_STATE_RUNNING, RUN_STATE_SHUTDOWN},
    {RUN_STATE_RUNNING, RUN_STATE_WATCHDOG},
    {RUN_STATE_RUNNING, RUN_STATE_GUEST_PANICKED},
    {RUN_STATE_RUNNING, RUN_STATE_COLO},

    {RUN_STATE_SAVE_VM, RUN_STATE_RUNNING},

    {RUN_STATE_SHUTDOWN, RUN_STATE_PAUSED},
    {RUN_STATE_SHUTDOWN, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_SHUTDOWN, RUN_STATE_PRELAUNCH},
    {RUN_STATE_SHUTDOWN, RUN_STATE_COLO},

    {RUN_STATE_DEBUG, RUN_STATE_SUSPENDED},
    {RUN_STATE_RUNNING, RUN_STATE_SUSPENDED},
    {RUN_STATE_SUSPENDED, RUN_STATE_RUNNING},
    {RUN_STATE_SUSPENDED, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_SUSPENDED, RUN_STATE_PRELAUNCH},
    {RUN_STATE_SUSPENDED, RUN_STATE_COLO},

    {RUN_STATE_WATCHDOG, RUN_STATE_RUNNING},
    {RUN_STATE_WATCHDOG, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_WATCHDOG, RUN_STATE_PRELAUNCH},
    {RUN_STATE_WATCHDOG, RUN_STATE_COLO},

    {RUN_STATE_GUEST_PANICKED, RUN_STATE_RUNNING},
    {RUN_STATE_GUEST_PANICKED, RUN_STATE_FINISH_MIGRATE},
    {RUN_STATE_GUEST_PANICKED, RUN_STATE_PRELAUNCH},

    {RUN_STATE__MAX, RUN_STATE__MAX},
};

static bool runstate_valid_transitions[RUN_STATE__MAX][RUN_STATE__MAX];

bool runstate_check(RunState state)
{
    return current_run_state == state;
}

bool runstate_store(char *str, size_t size)
{
    const char *state = RunState_str(current_run_state);
    size_t len = strlen(state) + 1;

    if (len > size)
    {
        return false;
    }
    memcpy(str, state, len);
    return true;
}

static void runstate_init(void)
{
    const RunStateTransition *p;

    memset(&runstate_valid_transitions, 0, sizeof(runstate_valid_transitions));
    for (p = &runstate_transitions_def[0]; p->from != RUN_STATE__MAX; p++)
    {
        runstate_valid_transitions[p->from][p->to] = true;
    }

    qemu_mutex_init(&vmstop_lock);
}

/* This function will abort() on invalid state transitions */
void runstate_set(RunState new_state)
{
    assert(new_state < RUN_STATE__MAX);

    trace_runstate_set(current_run_state, RunState_str(current_run_state),
                       new_state, RunState_str(new_state));

    if (current_run_state == new_state)
    {
        return;
    }

    if (!runstate_valid_transitions[current_run_state][new_state])
    {
        error_report("invalid runstate transition: '%s' -> '%s'",
                     RunState_str(current_run_state),
                     RunState_str(new_state));
        abort();
    }

    current_run_state = new_state;
}

bool runstate_is_running(void)
{
    return runstate_check(RUN_STATE_RUNNING);
}

bool runstate_needs_reset(void)
{
    return runstate_check(RUN_STATE_INTERNAL_ERROR) ||
           runstate_check(RUN_STATE_SHUTDOWN);
}

StatusInfo *qmp_query_status(Error **errp)
{
    StatusInfo *info = g_malloc0(sizeof(*info));

    info->running = runstate_is_running();
    info->singlestep = singlestep;
    info->status = current_run_state;

    return info;
}

bool qemu_vmstop_requested(RunState *r)
{
    qemu_mutex_lock(&vmstop_lock);
    *r = vmstop_requested;
    vmstop_requested = RUN_STATE__MAX;
    qemu_mutex_unlock(&vmstop_lock);
    return *r < RUN_STATE__MAX;
}

void qemu_system_vmstop_request_prepare(void)
{
    qemu_mutex_lock(&vmstop_lock);
}

void qemu_system_vmstop_request(RunState state)
{
    vmstop_requested = state;
    qemu_mutex_unlock(&vmstop_lock);
    qemu_notify_event();
}
struct VMChangeStateEntry
{
    VMChangeStateHandler *cb;
    void *opaque;
    QTAILQ_ENTRY(VMChangeStateEntry)
    entries;
    int priority;
};

static QTAILQ_HEAD(, VMChangeStateEntry) vm_change_state_head =
    QTAILQ_HEAD_INITIALIZER(vm_change_state_head);

/**
 * qemu_add_vm_change_state_handler_prio:
 * @cb: the callback to invoke
 * @opaque: user data passed to the callback
 * @priority: low priorities execute first when the vm runs and the reverse is
 *            true when the vm stops
 *
 * Register a callback function that is invoked when the vm starts or stops
 * running.
 *
 * Returns: an entry to be freed using qemu_del_vm_change_state_handler()
 */
VMChangeStateEntry *qemu_add_vm_change_state_handler_prio(
    VMChangeStateHandler *cb, void *opaque, int priority)
{
    VMChangeStateEntry *e;
    VMChangeStateEntry *other;

    e = g_malloc0(sizeof(*e));
    e->cb = cb;
    e->opaque = opaque;
    e->priority = priority;

    /* Keep list sorted in ascending priority order */
    QTAILQ_FOREACH(other, &vm_change_state_head, entries)
    {
        if (priority < other->priority)
        {
            QTAILQ_INSERT_BEFORE(other, e, entries);
            return e;
        }
    }

    QTAILQ_INSERT_TAIL(&vm_change_state_head, e, entries);
    return e;
}

VMChangeStateEntry *qemu_add_vm_change_state_handler(VMChangeStateHandler *cb,
                                                     void *opaque)
{
    return qemu_add_vm_change_state_handler_prio(cb, opaque, 0);
}

void qemu_del_vm_change_state_handler(VMChangeStateEntry *e)
{
    QTAILQ_REMOVE(&vm_change_state_head, e, entries);
    g_free(e);
}

void vm_state_notify(bool running, RunState state)
{
    VMChangeStateEntry *e, *next;

    trace_vm_state_notify(running, state, RunState_str(state));

    if (running)
    {
        QTAILQ_FOREACH_SAFE(e, &vm_change_state_head, entries, next)
        {
            e->cb(e->opaque, running, state);
        }
    }
    else
    {
        QTAILQ_FOREACH_REVERSE_SAFE(e, &vm_change_state_head, entries, next)
        {
            e->cb(e->opaque, running, state);
        }
    }
}

static ShutdownCause reset_requested;
static ShutdownCause shutdown_requested;
static int shutdown_signal;
static pid_t shutdown_pid;
static int powerdown_requested;
static int debug_requested;
static int suspend_requested;
static WakeupReason wakeup_reason;
static NotifierList powerdown_notifiers =
    NOTIFIER_LIST_INITIALIZER(powerdown_notifiers);
static NotifierList suspend_notifiers =
    NOTIFIER_LIST_INITIALIZER(suspend_notifiers);
static NotifierList wakeup_notifiers =
    NOTIFIER_LIST_INITIALIZER(wakeup_notifiers);
static NotifierList shutdown_notifiers =
    NOTIFIER_LIST_INITIALIZER(shutdown_notifiers);
static uint32_t wakeup_reason_mask = ~(1 << QEMU_WAKEUP_REASON_NONE);

ShutdownCause qemu_shutdown_requested_get(void)
{
    return shutdown_requested;
}

ShutdownCause qemu_reset_requested_get(void)
{
    return reset_requested;
}

static int qemu_shutdown_requested(void)
{
    return qatomic_xchg(&shutdown_requested, SHUTDOWN_CAUSE_NONE);
}

static void qemu_kill_report(void)
{
    if (!qtest_driver() && shutdown_signal)
    {
        if (shutdown_pid == 0)
        {
            /* This happens for eg ^C at the terminal, so it's worth
             * avoiding printing an odd message in that case.
             */
            error_report("terminating on signal %d", shutdown_signal);
        }
        else
        {
            char *shutdown_cmd = qemu_get_pid_name(shutdown_pid);

            error_report("terminating on signal %d from pid " FMT_pid " (%s)",
                         shutdown_signal, shutdown_pid,
                         shutdown_cmd ? shutdown_cmd : "<unknown process>");
            g_free(shutdown_cmd);
        }
        shutdown_signal = 0;
    }
}

static ShutdownCause qemu_reset_requested(void)
{
    ShutdownCause r = reset_requested;

    if (r && replay_checkpoint(CHECKPOINT_RESET_REQUESTED))
    {
        reset_requested = SHUTDOWN_CAUSE_NONE;
        return r;
    }
    return SHUTDOWN_CAUSE_NONE;
}

static int qemu_suspend_requested(void)
{
    int r = suspend_requested;
    if (r && replay_checkpoint(CHECKPOINT_SUSPEND_REQUESTED))
    {
        suspend_requested = 0;
        return r;
    }
    return false;
}

static WakeupReason qemu_wakeup_requested(void)
{
    return wakeup_reason;
}

static int qemu_powerdown_requested(void)
{
    int r = powerdown_requested;
    powerdown_requested = 0;
    return r;
}

static int qemu_debug_requested(void)
{
    int r = debug_requested;
    debug_requested = 0;
    return r;
}

/*
 * Reset the VM. Issue an event unless @reason is SHUTDOWN_CAUSE_NONE.
 */
void qemu_system_reset(ShutdownCause reason)
{
    MachineClass *mc;

    mc = current_machine ? MACHINE_GET_CLASS(current_machine) : NULL;

    cpu_synchronize_all_states();

    if (mc && mc->reset)
    {
        mc->reset(current_machine);
    }
    else
    {
        qemu_devices_reset();
    }
    if (reason && reason != SHUTDOWN_CAUSE_SUBSYSTEM_RESET)
    {
        qapi_event_send_reset(shutdown_caused_by_guest(reason), reason);
    }
    cpu_synchronize_all_post_reset();
}

/*
 * Wake the VM after suspend.
 */
static void qemu_system_wakeup(void)
{
    MachineClass *mc;

    mc = current_machine ? MACHINE_GET_CLASS(current_machine) : NULL;

    if (mc && mc->wakeup)
    {
        mc->wakeup(current_machine);
    }
}

void qemu_system_guest_panicked(GuestPanicInformation *info)
{
    qemu_log_mask(LOG_GUEST_ERROR, "Guest crashed");

    if (current_cpu)
    {
        current_cpu->crash_occurred = true;
    }
    /*
     * TODO:  Currently the available panic actions are: none, pause, and
     * shutdown, but in principle debug and reset could be supported as well.
     * Investigate any potential use cases for the unimplemented actions.
     */
    if (panic_action == PANIC_ACTION_PAUSE || (panic_action == PANIC_ACTION_SHUTDOWN && shutdown_action == SHUTDOWN_ACTION_PAUSE))
    {
        qapi_event_send_guest_panicked(GUEST_PANIC_ACTION_PAUSE,
                                       !!info, info);
        vm_stop(RUN_STATE_GUEST_PANICKED);
    }
    else if (panic_action == PANIC_ACTION_SHUTDOWN)
    {
        qapi_event_send_guest_panicked(GUEST_PANIC_ACTION_POWEROFF,
                                       !!info, info);
        vm_stop(RUN_STATE_GUEST_PANICKED);
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_PANIC);
    }
    else
    {
        qapi_event_send_guest_panicked(GUEST_PANIC_ACTION_RUN,
                                       !!info, info);
    }

    if (info)
    {
        if (info->type == GUEST_PANIC_INFORMATION_TYPE_HYPER_V)
        {
            qemu_log_mask(LOG_GUEST_ERROR, "\nHV crash parameters: (%#" PRIx64 " %#" PRIx64 " %#" PRIx64 " %#" PRIx64 " %#" PRIx64 ")\n",
                          info->u.hyper_v.arg1,
                          info->u.hyper_v.arg2,
                          info->u.hyper_v.arg3,
                          info->u.hyper_v.arg4,
                          info->u.hyper_v.arg5);
        }
        else if (info->type == GUEST_PANIC_INFORMATION_TYPE_S390)
        {
            qemu_log_mask(LOG_GUEST_ERROR, " on cpu %d: %s\n"
                                           "PSW: 0x%016" PRIx64 " 0x%016" PRIx64 "\n",
                          info->u.s390.core,
                          S390CrashReason_str(info->u.s390.reason),
                          info->u.s390.psw_mask,
                          info->u.s390.psw_addr);
        }
        qapi_free_GuestPanicInformation(info);
    }
}

void qemu_system_guest_crashloaded(GuestPanicInformation *info)
{
    qemu_log_mask(LOG_GUEST_ERROR, "Guest crash loaded");

    qapi_event_send_guest_crashloaded(GUEST_PANIC_ACTION_RUN,
                                      !!info, info);

    if (info)
    {
        qapi_free_GuestPanicInformation(info);
    }
}

void qemu_system_reset_request(ShutdownCause reason)
{
    if (reboot_action == REBOOT_ACTION_SHUTDOWN &&
        reason != SHUTDOWN_CAUSE_SUBSYSTEM_RESET)
    {
        shutdown_requested = reason;
    }
    else if (!cpus_are_resettable())
    {
        error_report("cpus are not resettable, terminating");
        shutdown_requested = reason;
    }
    else
    {
        reset_requested = reason;
    }
    cpu_stop_current();
    qemu_notify_event();
}

static void qemu_system_suspend(void)
{
    pause_all_vcpus();
    notifier_list_notify(&suspend_notifiers, NULL);
    runstate_set(RUN_STATE_SUSPENDED);
    qapi_event_send_suspend();
}

void qemu_system_suspend_request(void)
{
    if (runstate_check(RUN_STATE_SUSPENDED))
    {
        return;
    }
    suspend_requested = 1;
    cpu_stop_current();
    qemu_notify_event();
}

void qemu_register_suspend_notifier(Notifier *notifier)
{
    notifier_list_add(&suspend_notifiers, notifier);
}

void qemu_system_wakeup_request(WakeupReason reason, Error **errp)
{
    trace_system_wakeup_request(reason);

    if (!runstate_check(RUN_STATE_SUSPENDED))
    {
        error_setg(errp,
                   "Unable to wake up: guest is not in suspended state");
        return;
    }
    if (!(wakeup_reason_mask & (1 << reason)))
    {
        return;
    }
    runstate_set(RUN_STATE_RUNNING);
    wakeup_reason = reason;
    qemu_notify_event();
}

void qemu_system_wakeup_enable(WakeupReason reason, bool enabled)
{
    if (enabled)
    {
        wakeup_reason_mask |= (1 << reason);
    }
    else
    {
        wakeup_reason_mask &= ~(1 << reason);
    }
}

void qemu_register_wakeup_notifier(Notifier *notifier)
{
    notifier_list_add(&wakeup_notifiers, notifier);
}

static bool wakeup_suspend_enabled;

void qemu_register_wakeup_support(void)
{
    wakeup_suspend_enabled = true;
}

bool qemu_wakeup_suspend_enabled(void)
{
    return wakeup_suspend_enabled;
}

void qemu_system_killed(int signal, pid_t pid)
{
    shutdown_signal = signal;
    shutdown_pid = pid;
    shutdown_action = SHUTDOWN_ACTION_POWEROFF;

    /* Cannot call qemu_system_shutdown_request directly because
     * we are in a signal handler.
     */
    shutdown_requested = SHUTDOWN_CAUSE_HOST_SIGNAL;
    qemu_notify_event();
}

void qemu_system_shutdown_request(ShutdownCause reason)
{
    trace_qemu_system_shutdown_request(reason);
    replay_shutdown_request(reason);
    shutdown_requested = reason;
    qemu_notify_event();
}

static void qemu_system_powerdown(void)
{
    qapi_event_send_powerdown();
    notifier_list_notify(&powerdown_notifiers, NULL);
}

static void qemu_system_shutdown(ShutdownCause cause)
{
    qapi_event_send_shutdown(shutdown_caused_by_guest(cause), cause);
    notifier_list_notify(&shutdown_notifiers, &cause);
}

void qemu_system_powerdown_request(void)
{
    trace_qemu_system_powerdown_request();
    powerdown_requested = 1;
    qemu_notify_event();
}

void qemu_register_powerdown_notifier(Notifier *notifier)
{
    notifier_list_add(&powerdown_notifiers, notifier);
}

void qemu_register_shutdown_notifier(Notifier *notifier)
{
    notifier_list_add(&shutdown_notifiers, notifier);
}

void qemu_system_debug_request(void)
{
    debug_requested = 1;
    qemu_notify_event();
}

static bool main_loop_should_exit(void)
{
    RunState r;
    ShutdownCause request;

    if (qemu_debug_requested())
    {
        vm_stop(RUN_STATE_DEBUG);
    }
    if (qemu_suspend_requested())
    {
        qemu_system_suspend();
    }
    request = qemu_shutdown_requested();
    if (request)
    {
        qemu_kill_report();
        qemu_system_shutdown(request);
        if (shutdown_action == SHUTDOWN_ACTION_PAUSE)
        {
            vm_stop(RUN_STATE_SHUTDOWN);
        }
        else
        {
            return true;
        }
    }
    request = qemu_reset_requested();
    if (request)
    {
        pause_all_vcpus();
        qemu_system_reset(request);
        resume_all_vcpus();
        /*
         * runstate can change in pause_all_vcpus()
         * as iothread mutex is unlocked
         */
        if (!runstate_check(RUN_STATE_RUNNING) &&
            !runstate_check(RUN_STATE_INMIGRATE) &&
            !runstate_check(RUN_STATE_FINISH_MIGRATE))
        {
            runstate_set(RUN_STATE_PRELAUNCH);
        }
    }
    if (qemu_wakeup_requested())
    {
        pause_all_vcpus();
        qemu_system_wakeup();
        notifier_list_notify(&wakeup_notifiers, &wakeup_reason);
        wakeup_reason = QEMU_WAKEUP_REASON_NONE;
        resume_all_vcpus();
        qapi_event_send_wakeup();
    }
    if (qemu_powerdown_requested())
    {
        qemu_system_powerdown();
    }
    if (qemu_vmstop_requested(&r))
    {
        vm_stop(r);
    }
    return false;
}

static int once = 0;
void qemu_main_loop(void)
{
    int interaction = 0;

    static char *job_id = "qemu_job_123-test";
    static char *job_id2 = "qemu_job_123-test2";
    static char *tag = "thetagishere";

#ifdef CONFIG_PROFILER
    int64_t ti;
#endif
    while (!main_loop_should_exit())
    {
#ifdef CONFIG_PROFILER
        ti = profile_getclock();
#endif
        // printf("value of shmptr fuzzer mode is %d\n", *shmptr_fuzzer_mode);
        if (SNAPSHOT_ENABLED)
        {
            if (*shmptr_fuzzer_mode == SNAPSHOT_MODE) // && once == 0) // salva stato
            {
                /*                mon_hmp = g_new0(MonitorHMP, 1);
                                monitor_data_init(&mon_hmp->common, false, false, false);
                                monitor_list_append(&mon_hmp->common);
                */
                once = 1;
                mon_hmp = g_new0(MonitorHMP, 1);
                monitor_data_init(&mon_hmp->common, false, false, false);
                monitor_list_append(&mon_hmp->common);

                fprintf(stderr, "[QEMU debug] run snapshot command\n");
                // monitor_suspend(&mon_hmp->common);
                char command[100];
                sprintf(command, "savevm %s", SNAPSHOT_LABEL);
                // handle_hmp_command(mon_hmp, command);
                printf("test\n");
                Error *err = NULL;
                // hmp_
                // qmp_snapshot_save(job_id, tag, NULL, &err);

                // printf("error is %s\n",erro);
                bool res = save_snapshot(SNAPSHOT_LABEL, true, NULL, false, NULL, &err);
                printf("save res is %d\n", res);
                if (res == 1)
                {
                    printf("\n[MAIN LOOP] SNAPSHOT DID SUCCESfully!!\n");
                }
                // monitor_resume(&mon_hmp->common);
                // printf("b4 sem_rd_fuzzer_mode\n");
                // sem_post(sem_rd_fuzzer_mode);
                // printf("after sem_rd_fuzzer_mode\n");
                // printf("test1\n");
                *shmptr_fuzzer_mode = FUZZING_MODE; // DEFAULT_MODE;
                // printf("test2\n");
                // fuzzer_mode = RECOVER_MODE;
            }
            else if (*shmptr_fuzzer_mode == RECOVER_MODE)
            {
                struct timeval start_time, end_time;
                double execution_time;

                gettimeofday(&start_time, NULL); // Record the starting time

                printf("\nRecover #%d start\n", interaction);

                clock_t t;
                t = clock();
                printf("\nrecovering sys!\n");
                char command[100];
                sprintf(command, "loadvm %s", SNAPSHOT_LABEL);
                monitor_suspend(&mon_hmp->common);
                handle_hmp_command(mon_hmp, "stop");
                handle_hmp_command(mon_hmp, command);
                handle_hmp_command(mon_hmp, "cont");
                monitor_resume(&mon_hmp->common);

                /*int saved_vm_running = runstate_is_running();
                Error *err = NULL;
                printf("before snapshot!\n");
                // qmp_snapshot_load(job_id2, tag, NULL, &err);
                // const char* msg = error_get_pretty(err);
                // printf("error msg is %s\n",msg);
                vm_stop(RUN_STATE_RESTORE_VM);
                if (load_snapshot(SNAPSHOT_LABEL, NULL, false, NULL, &err) && saved_vm_running)
                {
                    vm_start();
                }*/

                // sleep(5);
                printf("after snapshot!\n");
                t = clock() - t;
                // sleep(5);
                double time_taken = ((double)t) / CLOCKS_PER_SEC;
                printf("time taken is %f\n", time_taken);
                // hmp_handle_error(mon, err);
                //  Error *err = NULL;
                // bool res = load_snapshot(SNAPSHOT_LABEL,NULL,false,NULL,&err);
                // vm_start();
                //  printf("load res is %d\n",res);
                //  printf("error msg is %s\n",&err.);

                gettimeofday(&end_time, NULL); // Record the ending time

                // Calculate execution time in seconds
                execution_time = (double)(end_time.tv_sec - start_time.tv_sec) +
                                 (double)(end_time.tv_usec - start_time.tv_usec) / 1e6;

                printf("\n\nExecution time: %f seconds\n", execution_time);

                printf("\nrecovered. \n");
                // sleep(1);
                // sem_post(sem_rd_fuzzer_mode);

                // sem_post(sem_gathering);
                // printf("sem posted!\n");
                //  fuzzer_mode = FUZZING_MODE;
                *shmptr_fuzzer_mode = FUZZING_MODE;
                //  gogo = 1;
                // sem_post(sem_rd_fuzzer_mode);
                printf("\nRecover #%d end\n", interaction++);
            }
        }
        main_loop_wait(false);
#ifdef CONFIG_PROFILER
        dev_time += profile_getclock() - ti;
#endif
    }
}

void qemu_add_exit_notifier(Notifier *notify)
{
    notifier_list_add(&exit_notifiers, notify);
}

void qemu_remove_exit_notifier(Notifier *notify)
{
    notifier_remove(notify);
}

static void qemu_run_exit_notifiers(void)
{
    notifier_list_notify(&exit_notifiers, NULL);
}

void qemu_init_subsystems(void)
{
    Error *err = NULL;

    os_set_line_buffering();

    module_call_init(MODULE_INIT_TRACE);

    qemu_init_cpu_list();
    qemu_init_cpu_loop();
    qemu_mutex_lock_iothread();

    atexit(qemu_run_exit_notifiers);

    module_call_init(MODULE_INIT_QOM);
    module_call_init(MODULE_INIT_MIGRATION);

    runstate_init();
    precopy_infrastructure_init();
    postcopy_infrastructure_init();
    monitor_init_globals();

    if (qcrypto_init(&err) < 0)
    {
        error_reportf_err(err, "cannot initialize crypto: ");
        exit(1);
    }

    os_setup_early_signal_handling();

    bdrv_init_with_whitelist();
    socket_init();
}

void qemu_cleanup(void)
{
    gdb_exit(0);

    /*
     * cleaning up the migration object cancels any existing migration
     * try to do this early so that it also stops using devices.
     */
    migration_shutdown();

    /*
     * Close the exports before draining the block layer. The export
     * drivers may have coroutines yielding on it, so we need to clean
     * them up before the drain, as otherwise they may be get stuck in
     * blk_wait_while_drained().
     */
    blk_exp_close_all();

    /*
     * We must cancel all block jobs while the block layer is drained,
     * or cancelling will be affected by throttling and thus may block
     * for an extended period of time.
     * vm_shutdown() will bdrv_drain_all(), so we may as well include
     * it in the drained section.
     * We do not need to end this section, because we do not want any
     * requests happening from here on anyway.
     */
    bdrv_drain_all_begin();

    /* No more vcpu or device emulation activity beyond this point */
    vm_shutdown();
    replay_finish();

    job_cancel_sync_all();
    bdrv_close_all();

    /* vhost-user must be cleaned up before chardevs.  */
    tpm_cleanup();
    net_cleanup();
    audio_cleanup();
    monitor_cleanup();
    qemu_chr_cleanup();
    user_creatable_cleanup();
    /* TODO: unref root container, check all devices are ok */
}

void *qemu_afl_thread(void *arg)
{
    shmfd_fuzzing_report = shm_open(SHM_FUZZING_REPORT, O_CREAT | O_RDONLY, S_IRWXU | S_IRWXG);
    if (shmfd_fuzzing_report == -1)
    {
        fprintf(stderr, "[QEMU Fuzzer thread] Error in shm_open() of shmfd_fuzzing_report\n");
        exit(1);
    }

    shmptr_fuzzing_report = (struct SingleFuzzReport *)mmap(0, sizeof(struct SingleFuzzReport), PROT_READ, MAP_SHARED, shmfd_fuzzing_report, 0);
    if (shmptr_fuzzing_report == MAP_FAILED)
    {
        fprintf(stderr, "[QEMU Fuzzer thread] Error in mmap() of shmptr_fuzzing_report\n");
        exit(1);
    }

    shm_fd = shm_open(SHM_FILE, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO); // 0666);
    if (shm_fd == -1)
    {
        printf("Error in shm_open()\n");
        exit(1);
    }

    if (ftruncate(shm_fd, sizeof(u8) * MAP_SIZE) == -1)
    {
        printf("Error in ftruncate()\n");
        exit(1);
    }

    afl_area_ptr = mmap(NULL, sizeof(u8) * MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (afl_area_ptr == MAP_FAILED)
    {
        printf("Error in mmap()\n");
        exit(1);
    }

    // block coverage bitmap (per grafici)
    shm_fd2 = shm_open(SHM_FILE_BLOCK_COV, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO); // 0666);
    if (shm_fd2 == -1)
    {
        printf("Error in shm_open()\n");
        exit(1);
    }

    if (ftruncate(shm_fd2, sizeof(u8) * MAP_SIZE) == -1)
    {
        printf("Error in ftruncate()\n");
        exit(1);
    }

    block_afl_area_ptr = mmap(NULL, sizeof(u8) * MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd2, 0);
    if (afl_area_ptr == MAP_FAILED)
    {
        printf("Error in mmap()\n");
        exit(1);
    }

    // utile questo sleep anche per far passare il transitortio per non avere rumore sulla coverage
    afl_engine_t *engine = initialize_engine_istance();
    printf("\n------------------- NUMBER OF STAGES: %ld -------------------------\n", engine->fuzz_one->stages_count);

    fuzzer_process_main(engine);
}

void qemu_fuzzing_loop(void)
{
    // start merge

    struct sigaction sa;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGBUS, &sa, NULL);
    (void)sigaction(SIGSEGV, &sa, NULL);

    // Shared memory and semaphoreS initialization for fuzzer mode signal (CONSUMER)
    sem_rd_fuzzer_mode = sem_open(SEM_RD_FUZZER_MODE, O_CREAT, S_IRWXU, 0);
    if (sem_rd_fuzzer_mode == NULL)
    {
        fprintf(stderr, "[QEMU Fuzzer thread] Error in sem_open() of sem_rd_fuzzer_mode\n");
        exit(1);
    }
    sem_wr_fuzzer_mode = sem_open(SEM_WR_FUZZER_MODE, O_CREAT, S_IRWXU, 1);
    if (sem_wr_fuzzer_mode == NULL)
    {
        fprintf(stderr, "[QEMU Fuzzer thread] Error in sem_open() of sem_rw_fuzzer_mode\n");
        exit(1);
    }
    shmfd_fuzzer_mode = shm_open(SHM_FUZZER_MODE, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU | S_IRWXG);
    if (shmfd_fuzzer_mode < 0)
    {
        fprintf(stderr, "[QEMU Fuzzer thread] Error in shm_open()\n");
        exit(1);
    }
    ftruncate(shmfd_fuzzer_mode, length);
    shmptr_fuzzer_mode = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, shmfd_fuzzer_mode, 0);
    if (shmptr_fuzzer_mode == MAP_FAILED)
    {
        fprintf(stderr, "[QEMU Fuzzer thread] Error in mmap()\n");
        exit(1);
    }

    // Shared memory and semaphores inizialization for fuzzing input (PRODUCER)
    fprintf(stderr, "[QEMU Fuzzer thread]  Semaphores and SHM initialization for fuzzing input\n");
    sem_rd_fuzzing_input = sem_open(SEM_RD_FUZZING_INPUT, O_CREAT, S_IRWXU, 0);
    if (sem_rd_fuzzing_input == NULL)
    {
        fprintf(stderr, "[QEMU Fuzzer thread]  Error in sem_open()\n");
        exit(1);
    }
    sem_wr_fuzzing_input = sem_open(SEM_WR_FUZZING_INPUT, O_CREAT, S_IRWXU, 1);
    if (sem_wr_fuzzing_input == NULL)
    {
        fprintf(stderr, "[QEMU Fuzzer thread]  Error in sem_open()\n");
        exit(1);
    }
    shmfd_fuzzing_input = shm_open(SHM_FUZZING_INPUT, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
    if (shmfd_fuzzing_input < 0)
    {
        fprintf(stderr, "[QEMU Fuzzer thread]  Error in shm_open()\n");
        exit(1);
    }
    ftruncate(shmfd_fuzzing_input, length_fuzz_input);
    shmptr_fuzzing_input = (struct QueueItem *)mmap(NULL, length_fuzz_input, PROT_READ | PROT_WRITE, MAP_SHARED, shmfd_fuzzing_input, 0);
    if (shmptr_fuzzing_input == MAP_FAILED)
    {
        fprintf(stderr, "[QEMU Fuzzer thread]  Error in mmap()\n");
        exit(1);
    }

    // end merge
    if (SAVE_METRICS)
    {
        printf("\n[METRICS] enabled\n");
    }
    else
    {
        printf("\n[METRICS] disabled\n");
    }
    wait_for_end_test_case = sem_open(SEM_RD_END_TEST_CASE_MODE, O_CREAT, S_IRWXU, 0);
    if (wait_for_end_test_case == NULL)
    {
        fprintf(stderr, "[fuzzer] Error in sem_open()\n");
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
    tcg_plugin_continue = sem_open(SEM_RD_END_TCG_PLUGIN_CONTINUE, O_CREAT, S_IRWXU, 0);
    if (tcg_plugin_continue == NULL)
    {
        fprintf(stderr, "[fuzzer] Error in sem_open()\n");
        exit(1);
    }
    // sem_init(wait_for_end_test_case, 0, 0);
    fprintf(stderr, "Semafori: inizializzati\n");

    fprintf(stderr, "Strutture monitor inizializzate\n");

    pthread_t tid;
    pthread_t tid2;
    int ret;
    int ret2;

    ret2 = pthread_create(&tid2, NULL, qemu_afl_thread, NULL);
    if (ret2 != 0)
    {
        fprintf(stderr, "[QEMU debug] AFL thread creation error.\n");
        exit(EXIT_FAILURE);
    }

    /*            clock_t start, end;
                double cpu_time_used;
    start = clock();
    printf("\nrecovering sys!\n");
    char command[100];
    // sprintf(command, "loadvm %s", SNAPSHOT_LABEL);
    //  monitor_suspend(&mon_hmp->common);
    //  handle_hmp_command(mon_hmp, command);
    int saved_vm_running = runstate_is_running();
    Error *err = NULL;

    vm_stop(RUN_STATE_RESTORE_VM);

    if (load_snapshot(SNAPSHOT_LABEL, NULL, false, NULL, &err) && saved_vm_running)
    {
        vm_start();
    }
    printf("waiting..\n");
    sleep(10);
    printf("finished waiting..\n");
    // hmp_handle_error(mon, err);
    //  Error *err = NULL;
    //  bool res = load_snapshot(SNAPSHOT_LABEL,NULL,false,NULL,&err);
    //  vm_start();
    //  printf("load res is %d\n",res);
    //  printf("error msg is %s\n",&err.);
    //  monitor_resume(&mon_hmp->common);
    end = clock();

    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC; // Calculate the CPU time used

    printf("Execution time: %f seconds\n", cpu_time_used);*/

    /*ret = pthread_create(&tid, NULL, qemu_injector_thread, NULL);
    if (ret != 0)
    {
        fprintf(stderr, "[QEMU debug] INjector thread creation error.\n");
        exit(EXIT_FAILURE);
    }*/
}
