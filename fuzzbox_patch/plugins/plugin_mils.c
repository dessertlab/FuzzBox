#include <glib.h>
#include <inttypes.h>
#include <stdio.h>

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
#include <stdio.h>
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
#define RECOVER_MODE 3

#define SNAPSHOT_ENABLED 0 // if changed, should be update it in config.h qemu too
#define SEED_GATHERING 0   // if changed, should be update it in config.h qemu too
#define NUM_INPUT 5        // it should be >0 (for example 5) if seed gathering is 1

#define MAX_LINE_LENGTH 100
#define MAX_ENTRIES 40000
#define HASH_TABLE_SIZE 9000 // Adjust this as needed

#define VERBOSE 2

struct CodeNamePair
{
	uint64_t code;
	char name[100];
	struct CodeNamePair *next; // Linked list for hash table collisions
};

static struct CodeNamePair *hashTable[HASH_TABLE_SIZE] = {NULL};

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
const char *shouldRegister(const uint64_t code)
{
	size_t index = code % HASH_TABLE_SIZE;
	struct CodeNamePair *current = hashTable[index];
	// printf("code is %d\n",code);

	while (current != NULL)
	{
		if (current->code == code)
		{
			printf("%x -> %s,\n", code, current->name);
		}

		current = current->next;
	}

	return NULL;
}

/* Store last executed instruction on each vCPU as a GString */
static GPtrArray *last_exec;
static GMutex expand_array_lock;

static GArray *crash_track;
static GArray *msg_track;
static GArray *save_snap_track;
static GArray *load_snap_track;

static unsigned int offset1;
static unsigned int offset2;

static int fuzzing_input;

static int fuzzer_mode_opt;

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

static int instr_index = 0;
static int shmfd_fuzzer_mode;						   // file descriptor
static uint8_t *shmptr_fuzzer_mode;					   // shm pointer
static sem_t *sem_rd_fuzzer_mode, *sem_wr_fuzzer_mode; // semaphores to read and write fuzzer mode
static off_t length = sizeof(struct QueueItem);

static sem_t *sem_gathering;
static sem_t *sem_gathering2;

static int shmfd_fuzzing_input;				   // file descriptor
static struct QueueItem *shmptr_fuzzing_input; // shm pointer
static int fuzzing_length;
static sem_t *sem_rd_fuzzing_input, *sem_wr_fuzzing_input; // semaphores to read and write fuzzer mode
static off_t length_fuzz_input = sizeof(struct QueueItem);

int shmfd_fuzzing_report;
struct SingleFuzzReport *shmptr_fuzzing_report;
static off_t length_fuzz_report = sizeof(struct SingleFuzzReport);
static sem_t *wait_for_end_test_case, *tcg_plugin_continue;

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

void printBinary(const char *data, size_t size)
{
	if (VERBOSE == 0)
		return;
	printf("printBINary:\n");
	for (int i = 0; i < size; i++)
	{
		printf("%02X", data[i]);
	}
}

void displayQueueItem(struct QueueItem *q)
{
	if (VERBOSE == 0)
		return;
	printf("\n[TCG PLUGIN]\n");
	// printf("length is %d\n",q->length);

	for (size_t i = 0; i < q->length; i++)
	{
		printf("%02X ", *(q->data + i)); // Display in hexadecimal format
										 // For character representation: printf("%c ", *(ptr + i));
										 // Note: Uncomment the above line for character representation
	}
}

void displayQ(u8 *data, size_t length)
{
	printf("\n[TCG PLUGIN]\n");
	printf("length is %d\n", length);
	// printf("length is %d\n",q->length);
	for (size_t i = 0; i < length; i++)
	{
		printf("%c", *(data + i)); // Display in hexadecimal format
								   // For character representation: printf("%c ", *(ptr + i));
								   // Note: Uncomment the above line for character representation
	}
	// printf("pritned valu\n");
}

/**
 * Add memory read or write information to current instruction log
 */
static int interactions = 0;
static int localint = 0;
static bool shouldJumpReport = false; // useful only when using the snapshot feature

static int asd = 0;
static int should_revert_snapshot = 0;
static int reverting = 0;

static void vcpu_insn_exec_snapshot_save(void *udata)
{
	if (asd++ < 3)
	{
		printf("\n\nroutiune di gestione di SAVE function!\n");
		*shmptr_fuzzer_mode = SNAPSHOT_MODE;
	}
}

static void vcpu_insn_exec_snapshot_load(void *udata)
{
	reverting = 0;
	if (should_revert_snapshot == 1 && SNAPSHOT_ENABLED)
	{
		printf("\n\nevent load!\n\n");
		printf("\n\nRoutine di gestione di LOAD function!\n");
		*shmptr_fuzzer_mode = RECOVER_MODE;
		should_revert_snapshot = 0;
	}
}

static int should_retry_fuzz = 0;

static struct QueueItem temp_q;
static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
	u8 *memContent;
	uint32_t address;
	uint32_t size;

	// printf("\n\nNEW CALL OF THIS FUNCTION!!!!\n\n");
	if (SNAPSHOT_ENABLED && reverting == 1) // apparently the func is called more than one time. workaround.
	{
		return;
	}
	// printf("\n\nnew interaction!\n\n");
	//  if(interactions==102) exit(0);
	//   printf("\n---------------------\n");
	if (VERBOSE > 0)
		printf("\nInteraction: %d\n", ++interactions);

	if (localint > 0)
	{
		shmptr_fuzzing_report->info = NULL;
		if (SNAPSHOT_ENABLED && should_retry_fuzz == 1)
		{
			shmptr_fuzzing_report->status = -2;
			should_retry_fuzz = 0;
		}
		else
		{
			shmptr_fuzzing_report->status = 0;
		}
		shmptr_fuzzing_report->q = temp_q;
		printf("input %d ha finito l'esecuzione\n", temp_q.length);
		sem_post(wait_for_end_test_case);
		printf("waiting for tcg plugin continue...\n");

		sem_wait(tcg_plugin_continue);
		shouldJumpReport = true;
		// sleep(1);
		printf("waited for tcg plugin continue!...\n");
	}
	// localint++;

	// printf("\nvpu insn exec START\n");

	u8 *fuzzContent;

	u8 *testOutput;
	GString *logLine = g_string_new(NULL);

	/* POSIX4 style signal handlers */
	struct sigaction sa;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGINT, &sa, NULL);
	(void)sigaction(SIGBUS, &sa, NULL);
	(void)sigaction(SIGSEGV, &sa, NULL);

	// Send the fuzzer_mode_signal to the fuzzer thread
	// printf("\nvpu insn exec b4 sem_wr_fuzzer_mode\n");
	// sem_wait(sem_wr_fuzzer_mode);
	// printf("\nvpu insn exec after sem_wr_fuzzer_mode\n");

	//        	if (instr_index == 0) fuzzer_mode_opt = SNAPSHOT_MODE;    // Take a snapshot at the first monitored instr.
	//        	else fuzzer_mode_opt = FUZZING_MODE;     // Fuzzing mode to the next instr.
	fuzzer_mode_opt = FUZZING_MODE;
	//*shmptr_fuzzer_mode = fuzzer_mode_opt;
	// g_string_append_printf(logLine, "[TCG Plugin] Snapshot mode. Instr: %d\n", instr_index);
	instr_index++;
	// printf("\nvpu insn exec b4 sem_rd_fuzzer_mode\n");
	// sem_post(sem_rd_fuzzer_mode);
	// printf("\nvpu insn exec after sem_rd_fuzzer_mode\n");

	// Read and fuzz the tracked input
	address = qemu_plugin_get_cpu_register(cpu_index, offset1, offset2, 3);
	// printf("\n\naddress is %x\n\n", address);
	size = qemu_plugin_get_cpu_register(cpu_index, offset1, offset2, 4);

	//  sleep(5);
	//  fprintf(stderr,"sem wait out");
	//  printf("\nvpu insn exec b4 sem_rd_fuzzing_input\n");
	sem_wait(sem_rd_fuzzing_input);
	// printf("\nvpu insn exec after sem_rd_fuzzing_input\n");

	// Read the original message
	// qemu_plugin_vcpu_read_phys_mem(cpu_index, address, memContent, size);
	// printf("\nvalue is %x\n",size);
	// g_string_append_printf(logLine, "[TCG Plugin] Tracked input: %s\n", memContent);

	// printf("[TCG Plugin] Tracked input: %s\n", memContent);
	//   Send the original message to the fuzzer as seed to mutate

	// DEBUG OLD VALUE
	// printf("\n\nB4 FUZZ:\n\n");
	// memContent = g_malloc(size);
	// qemu_plugin_vcpu_read_phys_mem(cpu_index, address, memContent, size);

	if (SEED_GATHERING)
	{
		if (localint > NUM_INPUT)
		{
			exit(1);
		}
		printf("address is %x\n", address);
		printf("size is %d\n", size);
		printf("\nseed gathering!\n");
		memContent = g_malloc(size);
		// printf("test\n");
		// temp_q.data = g_malloc(size);
		qemu_plugin_vcpu_read_phys_mem(cpu_index, address, memContent, size);
		// printf("test2\n");
		displayQ(memContent, size);
		// temp_q.data="abc";
		// memcpy(temp_q.data, memContent, size);
		// temp_q.length = size;
		// memcpy(temp_q.data,memContent,size);
		// shmptr_fuzzing_report->status = -3; // means it contains seed
		// shmptr_fuzzing_report->q = temp_q;
		// sem_post(sem_gathering);

		// printf("waiting for his read...\n");
		// sem_wait(sem_gathering2); // aspettiamo che legga
		// printf("he read!\n");
		// printf("\n\ntest\n\n");

		
		char filename[30];						// Adjust the size as needed
		sprintf(filename, "./seeds/seed_%d", localint); // Constructing file name: output_ID.bin

		// Open the file in binary write mode
		FILE *file = fopen(filename, "w+");

		if (file != NULL)
		{
			// Write the data to the file
			fwrite(memContent, sizeof(u8), size, file);

			// Close the file
			fclose(file);
			printf("Data has been written to the file.\n");
		}
		else
		{
			printf("Error opening the file.\n");
		}

		g_free(memContent);
	}
	else
	{
		fuzzContent = g_malloc(shmptr_fuzzing_input->length);
		// memset(fuzzContent, 0, size);  // azzera l'area di memoria
		temp_q = *shmptr_fuzzing_input;
		// printf("\nshmptr fuzzing input:");
		// displayQueueItem(shmptr_fuzzing_input);

		//  Perform the memcpy
		// memcpy(fuzzContent, shmptr_fuzzing_input->data, shmptr_fuzzing_input->length);
		memcpy(fuzzContent, shmptr_fuzzing_input->data, shmptr_fuzzing_input->length);
		// displayQ(fuzzContent,shmptr_fuzzing_input->length);

		// substitute size
		qemu_plugin_set_cpu_register(cpu_index, offset1, offset2, 4, (uint32_t)shmptr_fuzzing_input->length);
		// qemu_plugin_set_cpu_register(cpu_index, offset1, offset2, 4, (uint32_t)1);

		// substitute content
		qemu_plugin_vcpu_write_phys_mem(cpu_index, address, fuzzContent, (uint32_t)shmptr_fuzzing_input->length);

		printf("NEW SIZE IS %d\n", (uint32_t)shmptr_fuzzing_input->length);
	}

	// displayQ(memContent, size);
	//  fprintf(stderr,"Size is %ld\n",size);
	//  fprintf(stderr, "B4 FUZZ. Memcontent of address in x%d: %s (%d) (0x%llx) \n", 4, memContent, memContent, memContent);

	/*for (int i = 0; i < 16; i++)
	{
		char *memContent1;
		memContent1 = g_malloc(1000);
		uint64_t reg_cont = qemu_plugin_get_cpu_register(cpu_index, offset1, offset2, i);
		fprintf(stderr, "Register x%d  %lx \n", i, reg_cont);
		qemu_plugin_vcpu_read_phys_mem(cpu_index, reg_cont, memContent1, 1000);
		fprintf(stderr, "Memcontent of address in x%d: %s (%d) (0x%llx) \n", i, memContent1, memContent1, memContent1);
	}*/

	// Check if the memory was copied correctly
	/*if (memcmp(fuzzContent, &shmptr_fuzzing_input->data, shmptr_fuzzing_input->length) == 0) {
		printf("Memory was copied successfully.\n");
	} else {
		printf("Memory copy failed or data differs.\n");
	}*/

	// printf("\nOld size is %d\nNew size is %d\n",size,qemu_plugin_get_cpu_register(cpu_index, offset1, offset2, 4));

	// printf("\n\nAFTERFUZZ:\n\n");

	if (SNAPSHOT_ENABLED)
	{
		int result = -1;
		testOutput = g_malloc(shmptr_fuzzing_input->length);
		qemu_plugin_vcpu_read_phys_mem(cpu_index, address, testOutput, shmptr_fuzzing_input->length);
		// displayQ(testOutput, shmptr_fuzzing_input->length);
		result = memcmp(testOutput, fuzzContent, sizeof(testOutput)); // Comparing the memory blocks

		int ind = 0;
		should_retry_fuzz = 0;
		for (ind = 0; ind < shmptr_fuzzing_input->length; ind++)
		{
			if (testOutput[ind] != fuzzContent[ind])
			{
				should_retry_fuzz = 1;
				printf("The two u8* are different.\n");
				printf("Reverting fuzzer..\n");
				displayQ(testOutput, shmptr_fuzzing_input->length);
				displayQ(fuzzContent, shmptr_fuzzing_input->length);
				break;
			}
		}
		/*result = strcmp(testOutput, fuzzContent);
		if (result == 0)
		{
			printf("The two u8* are identical.\n");
			should_retry_fuzz = 0;
		}
		else
		{
			printf("The two u8* are different.\n");
			printf("Reverting fuzzer..\n");
			should_retry_fuzz = 1;
		}*/
		g_free(testOutput);
	}
	/*int result = -1;
	while (result != 0)
	{

		testOutput = g_malloc(shmptr_fuzzing_input->length);
		qemu_plugin_vcpu_read_phys_mem(cpu_index, address, testOutput, shmptr_fuzzing_input->length);
		displayQ(testOutput, shmptr_fuzzing_input->length);
		result = memcmp(testOutput, fuzzContent, sizeof(testOutput)); // Comparing the memory blocks

		if (result == 0)
		{
			printf("The two u8* are identical.\n");
		}
		else
		{
			printf("The two u8* are different.\n");
			sleep(1);
			qemu_plugin_vcpu_write_phys_mem(cpu_index, address, fuzzContent, (uint32_t)shmptr_fuzzing_input->length);

			// exit(1);
		}
	}*/

	should_revert_snapshot = 1;
	sem_post(sem_wr_fuzzing_input);
	qemu_plugin_outs(logLine->str);
	// g_string_free(logLine, TRUE);
	if (!SEED_GATHERING)
		g_free(fuzzContent);

	fflush(stderr);

	// Remove resources
	/*if (munmap(shmptr_fuzzer_mode, length) == -1)
	{
		fprintf(stderr,"err\n");
		//g_string_append_printf(logLine, "[TCG Plugin] error in munmap()\n");
		exit(1);
	}
	if (close(shmfd_fuzzer_mode) == -1)
	{
		fprintf(stderr,"err\n");
		//g_string_append_printf(logLine, "[TCG Plugin] error in close()\n");
		exit(1);
	}*/

	localint++;
	if (SNAPSHOT_ENABLED)
		reverting = 1;
}

/**
 * On translation block new translation
 *
 * QEMU convert code by translation block (TB). By hooking here we can then hook
 * a callback on each instruction and memory access.
 */

static int onetime = 0;
static int onetimeregister = 0;
static int onetimeregister2 = 0;
static int onetimeregister3 = 0;

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{

	struct qemu_plugin_insn *insn;
	bool skip_crash = (crash_track);
	bool skip_msg = (msg_track);

	size_t n = qemu_plugin_tb_n_insns(tb);
	for (size_t i = 0; i < n; i++)
	{
		char *insn_disas;
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

		// fprintf(stderr,"uint64 %x\n",insn_vaddr);
		// fprintf(stderr,"uint64 %x\n",insn_vaddr);
		// const char* name = shouldRegister(insn_vaddr);
		/*
		 * If we are filtering we better check out if we have any
		 * hits. The skip "latches" so we can track memory accesses
		 * after the instruction we care about.
		 */

		if (SNAPSHOT_ENABLED)
		{
			int j;
			for (j = 0; j < save_snap_track->len && skip_crash; j++)
			{
				uint64_t v = g_array_index(save_snap_track, uint64_t, j);
				if (v == insn_vaddr)
				{
					printf("\n\nREGISTERED EVENT SAVE!\n\n");
					qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec_snapshot_save, QEMU_PLUGIN_CB_NO_REGS, (void *)0);
				}
			}

			for (j = 0; j < load_snap_track->len && skip_crash; j++)
			{
				uint64_t v = g_array_index(load_snap_track, uint64_t, j);
				if (v == insn_vaddr)
				{
					printf("\n\nREGISTERED EVENT LOAD!\n\n");
					qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec_snapshot_load, QEMU_PLUGIN_CB_NO_REGS, (void *)0);
				}
			}
		}
		if (skip_crash && crash_track)
		{
			int j;
			for (j = 0; j < crash_track->len && skip_crash; j++)
			{
				uint64_t v = g_array_index(crash_track, uint64_t, j);
				if (v == insn_vaddr)
				{
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
				if (v == insn_vaddr)
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

				// Crash system call detected

				qemu_plugin_outs("\n");
				qemu_plugin_outs("[TCG Plugin] CRASH Detected.");
				qemu_plugin_outs("\n");
				printf("\n\nCRASH DETECTED\n\n\n");
				// if we reach here, we should not proc sem_post in tcg plugin. TBD. importante.
				shmptr_fuzzing_report->info = NULL;
				shmptr_fuzzing_report->status = -1;
				shmptr_fuzzing_report->q = temp_q;
				shouldJumpReport = false;
				sem_post(wait_for_end_test_case); // warning! double sem post critical!

				/* reset skip */
				skip_crash = (crash_track);
				skip_msg = (msg_track);
			}
			else
			{
				fprintf(stderr, "skip_msg %d\n", skip_msg);
				// fprintf(stderr, "uint64 %x\n", insn_vaddr);
				//  Send SIPC system call detected

				uint32_t insn_opcode;
				insn_opcode = *((uint32_t *)qemu_plugin_insn_data(insn));
				char *output = g_strdup_printf("0x%" PRIx64 ", 0x%" PRIx32 ", \"%s\"",
											   insn_vaddr, insn_opcode, insn_disas);

				fprintf(stderr, "opcode %x\n", insn_opcode);

				/* Register callback on instruction */
				qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
													   QEMU_PLUGIN_CB_NO_REGS, output);

				/* reset skip */
				skip_crash = (crash_track);
				skip_msg = (msg_track);
			}
		}
	}
}

/**
 * On plugin exit, print last instruction in cache
 */
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
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
	uint64_t v = g_ascii_strtoull(match, NULL, 16);

	if (!msg_track)
	{
		msg_track = g_array_new(false, true, sizeof(uint64_t));
	}
	g_array_append_val(msg_track, v);
}

static void parse_snap_match(char *match)
{
	uint64_t v = g_ascii_strtoull(match, NULL, 16);

	if (!save_snap_track)
	{
		save_snap_track = g_array_new(false, true, sizeof(uint64_t));
	}
	g_array_append_val(save_snap_track, v);
}
static void parse_snap_load_match(char *match)
{
	uint64_t v = g_ascii_strtoull(match, NULL, 16);

	if (!load_snap_track)
	{
		load_snap_track = g_array_new(false, true, sizeof(uint64_t));
	}
	g_array_append_val(load_snap_track, v);
}
static void parse_offsets(char *match1, char *match2)
{
	offset1 = g_ascii_strtoull(match1, NULL, 10); // base 10
	offset2 = g_ascii_strtoull(match2, NULL, 10); // base 10
}

/**
 * Install the plugin
 */

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
										   const qemu_info_t *info, int argc,
										   char **argv)
{
	/*
Shared memory and semaphores intialization for fuzzer mode signal (PRODUCER)
*/
	for (int i = 0; i < HASH_TABLE_SIZE; i++)
	{
		hashTable[i] = NULL;
	}
	createCodeToNameMapping("/home/valer/Scrivania/fuzzing/plugins/res_SMTP_hypervisor.txt");
	// res 2 is hypervisor. res 3 is sample_vb (server)

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

	if (argc < 5)
	{
		fprintf(stderr, "[TCG Plugin ] Plugin options parsing failed. Syntax: 'fuzzer_mode=MODE,crash_track=xxxxxx,msg_track=yyyyyy': \n");
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

		g_autofree char **tokens0 = g_strsplit(opt0, "=", 2);
		g_autofree char **tokens1 = g_strsplit(opt1, "=", 2);
		g_autofree char **tokens2 = g_strsplit(opt2, "=", 2);
		g_autofree char **tokens3 = g_strsplit(opt3, "=", 2);
		g_autofree char **tokens4 = g_strsplit(opt4, "=", 2);
		g_autofree char **tokens5 = g_strsplit(opt5, "=", 2);
		g_autofree char **tokens6 = g_strsplit(opt6, "=", 2);

		if (g_strcmp0(tokens0[0], "fuzzer_mode") == 0 && g_strcmp0(tokens1[0], "crash_track") == 0 && g_strcmp0(tokens2[0], "msg_track") == 0 && g_strcmp0(tokens3[0], "offset1") == 0 && g_strcmp0(tokens4[0], "offset2") == 0 && g_strcmp0(tokens5[0], "save_snap_track") == 0 && g_strcmp0(tokens6[0], "load_snap_track") == 0)
		{
			parse_mode_match(tokens0[1]);
			parse_crash_match(tokens1[1]);
			parse_msg_match(tokens2[1]);
			parse_offsets(tokens3[1], tokens4[1]);
			parse_snap_match(tokens5[1]);
			parse_snap_load_match(tokens6[1]);
		}
		else
		{
			fprintf(stderr, "[TCG Plugin] Plugin options parsing failed. Syntax: 'fuzzer_mode=MODE,crash_track=xxxxxx,msg_track=yyyyyy,offset1=K,offset2=Z' \n");
			return -1;
		}
	}

	/* Register translation block and exit callbacks */
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

	return 0;
}
