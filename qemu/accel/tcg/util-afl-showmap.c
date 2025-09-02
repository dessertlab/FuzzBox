#include <sys/shm.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#define MAP_SIZE_POW2       21
#define MAP_SIZE            (1 << MAP_SIZE_POW2)


bool isInteresting(bool curr_bitmap[], bool prev_bitmap[]) {

	for (int i=0; i<MAP_SIZE; i++) {
		if (curr_bitmap[i] != prev_bitmap[i]) return true;
	}

	return false;
}

int main() {

	key_t shm_key;
	int shm_id;
	bool *afl_area_ptr;
	bool curr_bitmap[MAP_SIZE];
	bool prev_bitmap[MAP_SIZE];

        /* Setup SHM */
	shm_key = ftok("./afl_shm_bitmap", 'x');
        shm_id = shmget(shm_key, MAP_SIZE, IPC_CREAT|IPC_EXCL|0777);
	if (shm_id == -1) {
                shm_id = shmget(shm_key, MAP_SIZE, 0);
		if(shm_id == -1) {
                        perror("Error in shmget()");
                        return EXIT_FAILURE;
                }
        }

	afl_area_ptr = shmat(shm_id, 0, 0);
        if (afl_area_ptr == (void *) -1) {
                perror("Error in shmat()");
                return EXIT_FAILURE;
        }

	// Clean shared memory
//	for (int i=0; i<MAP_SIZE; i++) {
//		afl_area_ptr[i] = false;
//	}

	// Check bitmap
	while(true) {

		// Copy the current bitmap
		memcpy(curr_bitmap, afl_area_ptr, MAP_SIZE);

		// Compare with the previous bitmap
		if (isInteresting(curr_bitmap, prev_bitmap)) {
			printf("Changed bitmap locations: \n");
			for (int i=0; i<MAP_SIZE; i++) {
				if (curr_bitmap[i] != prev_bitmap[i]) 
					printf("Location %d: %d\n", i, curr_bitmap[i]);
			}
		}

		// Update the previous bitmap for the next iteration
		memcpy(prev_bitmap, curr_bitmap, MAP_SIZE);

	}

        return 0;
}

