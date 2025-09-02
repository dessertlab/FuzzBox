/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
					 Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
					 Andrea Fioraldi <andreafioraldi@gmail.com>,
					 Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

	 http://www.apache.org/licenses/LICENSE-2.0

 */

#include "libAFL/stage.h"
#include "libAFL/engine.h"
#include "libAFL/fuzzone.h"
#include "libAFL/mutator.h"

afl_ret_t afl_stage_init(afl_stage_t *stage, afl_engine_t *engine)
{

	stage->engine = engine;

	// We also add this stage to the engine's fuzzone
	if (engine)
	{
		engine->fuzz_one->funcs.add_stage(engine->fuzz_one, stage);
	}

	stage->funcs.get_iters = afl_stage_get_iters;
	stage->funcs.perform = afl_stage_perform;
	stage->funcs.add_mutator_to_stage = afl_stage_add_mutator;

	return AFL_RET_SUCCESS;
}

void afl_stage_deinit(afl_stage_t *stage)
{

	stage->engine = NULL;

	for (size_t i = 0; i < stage->mutators_count; ++i)
	{

		afl_mutator_deinit(stage->mutators[i]);
	}

	afl_free(stage->mutators);
	stage->mutators = NULL;
}

afl_ret_t afl_stage_add_mutator(afl_stage_t *stage, afl_mutator_t *mutator)
{

	if (!stage || !mutator)
	{
		return AFL_RET_NULL_PTR;
	}

	stage->mutators_count++;
	stage->mutators = afl_realloc(stage->mutators, stage->mutators_count * sizeof(afl_mutator_t *));
	if (!stage->mutators)
	{
		return AFL_RET_ALLOC;
	}

	stage->mutators[stage->mutators_count - 1] = mutator;

	return AFL_RET_SUCCESS;
}

size_t afl_stage_get_iters(afl_stage_t *stage)
{

	return (1 + afl_rand_below(&stage->engine->rand, 128));
}

afl_ret_t afl_stage_run(afl_stage_t *stage, afl_input_t *input, bool overwrite)
{

	afl_input_t *copy;
	if (!overwrite)
		copy = input->funcs.copy(input);
	else
		copy = input;

	/* Let's post process the mutated data now. */
	size_t j;
	for (j = 0; j < stage->mutators_count; ++j)
	{

		afl_mutator_t *mutator = stage->mutators[j];

		if (mutator->funcs.post_process)
		{
			mutator->funcs.post_process(mutator, copy);
		}
	}

	afl_ret_t ret = stage->engine->funcs.execute(stage->engine, copy);

	if (!overwrite)
		afl_input_delete(copy);

	return ret;
}

float afl_stage_is_interesting(afl_stage_t *stage)
{

	float interestingness = 0.0f;

	afl_feedback_t **feedbacks = stage->engine->feedbacks;
	size_t j;
	for (j = 0; j < stage->engine->feedbacks_count; ++j)
	{

		interestingness += feedbacks[j]->funcs.is_interesting(feedbacks[j], stage->engine->executor);
	}

	return interestingness;
}

int cont = 0;
uint64_t cont_tot = 0;
/* Perform default for fuzzing stage */
afl_ret_t afl_stage_perform(afl_stage_t *stage, afl_entry_t *queue_entry)
{
	/*  This is to stop from compiler complaining about the incompatible pointer
	// type for the function ptrs. We need a better solution for this to pass the
	// scheduled_mutator rather than the mutator as an argument. */
	/* printf("\nafl_stage_perform\n"); */

	afl_input_t *input = queue_entry->input;
	/* printf("\nafl_stage_perform ---------------  INPUT: %s\n", input->bytes); */
   printf("\nworkaround111111 input len is %d\n", input->len);
	size_t num = stage->funcs.get_iters(stage);
	/* printf("\nafl_stage_perform ---------------  NUM. OF INPUT TO GENERATE: %d\n", num); */

	// printf("\nNUMBER OF MUTATORS IN STAGE: %d\n", stage->mutators_count);

	size_t i;

		for (i = 0; i < num; ++i)
	{
		afl_input_t *copy = input->funcs.copy(input);

		if (!copy)
		{
			return AFL_RET_ERROR_INPUT_COPY;
		}

		size_t j;
		for (j = 0; j < stage->mutators_count; ++j)
		{

			afl_mutator_t *mutator = stage->mutators[j];
			/* If the mutator decides not to fuzz this input, don't fuzz it. This is to support the custom mutator API of AFL++ */
			if (mutator->funcs.custom_queue_get)
			{
				mutator->funcs.custom_queue_get(mutator, copy);
				continue;
			}

			if (mutator->funcs.trim)
			{
				size_t orig_len = copy->len;
				size_t trim_len = mutator->funcs.trim(mutator, copy);

				if (trim_len > orig_len)
				{
					return AFL_RET_TRIM_FAIL;
				}
			}
			// printf("\n cont: %ld",cont_tot++);
			// printf("\nPRE MUTATE  -  copy: %s  -  len: %d\n", copy->bytes, copy->len);
			mutator->funcs.mutate(mutator, copy);
			// printf("\n[LEN=%d]  %s\n", copy->len, copy->bytes);
		}		//firmware tests. works! :)
		
		// printf("\ntest\n");
		/*if (cont_tot > 15)
		{
			copy->bytes = "ALWAYSTHESAME";
			copy->len = 13;
		}
		
		else if (cont_tot == 20)
		{
			copy->bytes = "YYXX";
			copy->len = 4;
		}
		else if (cont_tot == 400)
		{
			copy->bytes = "ZYXX";
			copy->len = 4;
		}
		else if (cont_tot == 410)
		{
			copy->bytes = "ZZXX";
			copy->len = 4;
		}
		else if (cont_tot == 30)
		{
			copy->bytes = "GYXX";
			copy->len = 4;
		}
		else
		{
			//copy->bytes = "VALORE";
			//copy->len = 6;
		}*/
		cont_tot++;
		afl_ret_t ret = afl_stage_run(stage, copy, true);
		/* printf("\nPOST STAGE_RUN\n"); */

		/* Let's collect some feedback on the input now */
		float interestingness = afl_stage_is_interesting(stage);

		/*interestingness = 0.0;*/

		/*
		if (interestingness >= 0.5)
		{
		*/
		/* TODO: Use queue abstraction instead */
		/* TODO: Modificare in modo tale da inviare le informazioni sull'interestingness all'engine senza shared memory */
		/*
		llmp_message_t *msg = llmp_client_alloc_next(stage->engine->llmp_client, copy->len + sizeof(afl_entry_info_t));
	  if (!msg) {

		DBG("Error allocating llmp message");
		return AFL_RET_ALLOC;
	  }

	  memcpy(msg->buf, copy->bytes, copy->len);
		 */
		/* TODO FIXME - here we fill in the entry info structure on the queue */
		/* afl_entry_info_t *info_ptr = (afl_entry_info_t*)((u8*)(msg->buf + copy->len));
		// e.g. fill map hash */
		/*
	  msg->tag = LLMP_TAG_NEW_QUEUE_ENTRY_V1;
	  if (!llmp_client_send(stage->engine->llmp_client, msg)) {

		DBG("An error occurred sending our previously allocated msg");
		return AFL_RET_UNKNOWN_ERROR;

	  }
		 */
		/* we don't add it to the queue but wait for it to come back from the broker for now.
		TODO: Tidy this up. */
		/*      interestingness = 0.0f;

		}
		*/

		/* If the input is interesting and there is a global queue add the input to
		 * the queue */
		/* TODO: 0.5 is a random value. How do we want to chose interesting input? */
		/* This block of code is never reached in the above case where we wait for it to return from the broker*/

		/* TODO: FIXME */
		/* interestingness = 0.6; */
		cont++;
		printf("cont is %d\n", cont);

		if (interestingness >= 0.5 && stage->engine->global_queue && copy->len < 50000 && copy->len > 0) // || cont == 130) // interestingness >0.5?
		{
			// printf("input is interesting1!!!!\n");
			afl_input_t *input_copy = copy->funcs.copy(copy);

			if (!input_copy)
			{
				return AFL_RET_ERROR_INPUT_COPY;
			}

			afl_entry_t *entry = afl_entry_new(input_copy, NULL);

			if (!entry)
			{
				return AFL_RET_ALLOC;
			}

			afl_queue_global_t *queue = stage->engine->global_queue;

			/*if(cont==130){
				entry->input->bytes="AAAA";
				entry->input->len=4;
			queue->base.funcs.insert((afl_queue_t *)queue, entry);

			}else
			*/
			queue->base.funcs.insert((afl_queue_t *)queue, entry);
			
			// printf("input is interesting2!!!!\n");

			if (VERBOSE_LOG)
			{

				printf("INTERESTING AND ADDED: \n");
				for (size_t i = 0; i < entry->input->len; i++)
				{
					printf("%02X ", *(entry->input->bytes + i));
				}
				// printf("interestingness is %f\n",interestingness);
				printf("\n");

				// exit(0);
				printf("copy length is %d\n", copy->len);
			}
			// afl_input_delete(copy);  //this makes free():invalidsize crash. commented for the moment
		}
		else // non c'era else. afl_input_delete era fuori da solo
		{
			afl_input_delete(copy);
		}
		afl_queue_global_t *queue = stage->engine->global_queue;
		if (VERBOSE_LOG > 0)
			printf("queue length is %d\n", queue->base.funcs.get_size(queue));
		// printf("input is interesting3!!!!\n");

		switch (ret)
		{
		case AFL_RET_SUCCESS:
			continue;
		/* We'll add more cases here based on the type of exit_ret value given by
		// the executor.Those will be handled in the engine itself. */
		default:
			return ret;
		}
	}
	// printf("input is interesting4!!!!\n");
	return AFL_RET_SUCCESS;
}

/* Functions related to det stage */

afl_ret_t afl_det_stage_perform(afl_stage_t *det_stage, afl_entry_t *entry)
{
	// printf("\nafl_det_stage_perform\n");

	if (entry->info->det_done)
	{
		return AFL_RET_SUCCESS;
	} /* Deterministic stage done for this entry */
	//
	bool bugged=false;
	afl_input_t *input = entry->input;
	// printf("entry input is %d\n", input->len);
	afl_input_t *copy=afl_input_new() ;
	if (input->len < 0 || input->len > 10000) // MKO
	{										  // bug workaround
		bugged=true;
		printf("\nDETworkaround111111 input len is %d\n", input->len);
		// probably some instruction doesnt handle writing properly
		// we could fix bug or take advantage of this to randomize even more. ipotesi abbastanza forte ma dovrebbe andare bene

		/*afl_queue_global_t *global_queue = det_stage->engine->global_queue;
		afl_entry_t *queue_entry = global_queue->base.funcs.get_queue_entry((afl_queue_t *)global_queue, 0);
		afl_input_t *seed = queue_entry->input;

		printf("queue input is %s\n", seed->bytes);
		for(int i =0; i< seed->len; i++){
			input->bytes[i]=seed->bytes[i];
		}
		input->len=seed->len;
		*/
		// queue->feedback_queues->// sizeof(input->bytes);
		//printf("1\n");
		//afl_queue_global_t *global_queue = det_stage->engine->global_queue;
		//printf("2\n");
		//afl_entry_t *seed_entry = global_queue->base.funcs.get_queue_entry((afl_queue_t *)global_queue, 0);
		//printf("3\n");
		//afl_input_t *seed = seed_entry->input;
		//printf("seed lenght:%d\n",seed->len);
		/*for (int i = 0; i < seed->len; i++)
		{
			printf("seed num:%d\n",i);
			input->bytes[i] = 'a';
		}
		*/
		//printf("4\n");
		//input->len = seed->len;
		//printf("5\n");
		//copy = afl_input_new();
  		if (!copy)
  		{
    		return AFL_RET_ERROR_INITIALIZE;
  		}
  		copy->bytes = calloc(16, 1 );

  		if (!copy->bytes)
  		{

    		afl_input_delete(copy);
    		return AFL_RET_ERROR_INITIALIZE;
  		}

  		memcpy(copy->bytes, "aaaaaaaaaaaaaaa\0", 16);
  		copy->len = 16;
  		input->len=copy->len;
		printf("\nDETworkaround222222 input len is %d\n", input->len);
		// input->len = 1 + afl_rand_below(&det_stage->engine->rand, 128); // randomize on bug. NOT A BUG, NOW A FEATURE!
		// printf("entry input is %d\n", input->len);
		/*for(int i =0; i< input->len; i++){
		   printf("%02x ",input->bytes[i]);
		   printf("afngaianigna\n\n");
	   }*/
		// exit(0);
		/*
		for (int i = 0; i < input->len; i++)
		{
			printf("%02x ", input->bytes[i]);
		}
		*/
	}
	else
	{
		printf("\nDETno workaround33333 input len is %d\n", input->len);
		for (int i = 0; i < det_stage->mutators_count; ++i)
	{
		// printf("\ntest1 %d\n",det_stage->mutators_count);
		afl_mutator_deterministic_t *mutator_det = (afl_mutator_deterministic_t *)(det_stage->mutators[i]);
		mutator_det->stage_max = mutator_det->funcs.get_iters(mutator_det, input);
		printf("\nDETno workaround44444 stage max is %d\n", mutator_det->stage_max );
		// printf("\ntest2 %d\n", mutator_det->stage_max);
		/*if (mutator_det->stage_max > 5000 || mutator_det->stage_max < 0)
		 { // bug workaround
		  // bisognerebbe investigare sulla causa.
		  // copy->bytes="aaaaaaaaaaaaaaaa";
		  // copy->len=16;
		  // printf("fixing..\n");
		  // afl_ret_t ret = afl_stage_run(det_stage, copy, true);
		  // return AFL_RET_SUCCESS;
		  // printf("fixed\n");
		  // return ret;
		} */

		for (mutator_det->stage_cur = 0; mutator_det->stage_cur < mutator_det->stage_max; ++mutator_det->stage_cur)
		{
			// printf("\ntest3\n");
			/* Much better to have a post-exec function here to restore the original input? So that we don't always have to copy?  */
			printf("\nDETno workaround55555 len is %d\n", input->len);
			copy = input->funcs.copy(input);
			if (copy)
			{
				// printf("\ntest4\n");
				mutator_det->base.funcs.mutate((afl_mutator_t *)mutator_det, copy);
			}
			// printf("\ntest5\n");
		}
	}
	}
	/* Let's make a copy of the input now */
	size_t i = 0;
	
	// printf("\nafl_det_stage_perform2\n");

	

	cont += 1;
	printf("\nafl_det_stage_perform3\n");
	afl_ret_t ret = afl_stage_run(det_stage, copy, true);
	/* printf("\nPOST STAGE_RUN\n"); */
	printf("\nafl_det_stage_perform4\n");
	/* Let's collect some feedback on the input now */
	float interestingness = afl_stage_is_interesting(det_stage);
	printf("\nafl_det_stage_perform5\n");
	/* TODO: FIXME */
	/* interestingness = 0.6; */
	/* interestingness = 0.0;*/

	// printf("it's interesting %f\n\n",interestingness);
	// printf("\nafl_det_stage_perform6\n");

	if (!bugged && interestingness >= 0.5 && det_stage->engine->global_queue && copy->len < 50000 && copy->len > 0)
	{
		printf("it's interesting %f\n\n",interestingness);
		afl_entry_t *entry = afl_entry_new(copy, NULL);

		if (!entry)
		{
			return AFL_RET_ALLOC;
		}

		afl_queue_global_t *queue = det_stage->engine->global_queue;
		printf("\nDETno workaround55555 len is %d\n", entry->input->len);
		queue->base.funcs.insert((afl_queue_t *)queue, entry);
	}

	//afl_input_delete(copy);
	/* Deterministic stage done for this entry. */
	printf("Det stage done for: %s", entry->input->bytes);
	entry->info->det_done = 1;

	return ret;
	/* return AFL_RET_SUCCESS; */
}

afl_ret_t afl_det_stage_init(afl_stage_t *det_stage, afl_engine_t *engine)
{

	if (afl_stage_init(det_stage, engine) != AFL_RET_SUCCESS)
	{
		return AFL_RET_ERROR_INITIALIZE;
	}

	det_stage->funcs.perform = afl_det_stage_perform;
	return AFL_RET_SUCCESS;
}
