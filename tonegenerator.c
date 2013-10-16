/* coydog - Reusable monophonic tone generation module meant to approximate
 * BSD /dev/speaker functionality. */
/* TODO: Make this the basis of a polyphonic generator/synth with multiple
 * passes for Fourier transforms; should be interesting */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h> /* might can lose?*/
#include <string.h>
#include <portaudio.h>
#include <math.h> /* sin() etc for waveform tone generation */

#include "tonegenerator.h"
#define DEBUG 0
#define SAMPLE_RATE 192000

#define FRAMES_PER_BUF (8 ) /* play with this */

/* Internal API. See header for client API. */
int InitPortAudio(TG_State *);
int BuildBuffer(TG_State *tg, tone_t tone, int *cur_frame);
int tableIndexFromFreq(int nd, int freq);

int TG_Init(TG_State *tg) {
	tg->pa = NULL;
	return InitPortAudio(tg);
}
void TG_DeInit(TG_State *tg) {
	Pa_Terminate();
}
	
int InitPortAudio (TG_State *tg) {
	int i = 0;
	int r = 0;

	r = Pa_Initialize(); /* must come first */
	if (r != paNoError) {
		printf("Error: Pa_Initialize() error: %s\n", Pa_GetErrorText(r));
		return 0;
	}
	r = Pa_OpenDefaultStream(&(tg->pa),
	  		0, /* input chans */
			2, /* output chans */
			paFloat32,
			SAMPLE_RATE,
			0, /* *** was 128. Shouldn't it be FRAMES_PER_BUF? *** */
			NULL,
			NULL);
	if (r != paNoError) {
		printf("Error: Pa_OpenStream() error!: %s\n", Pa_GetErrorText(r));
		return 0;
	}
	r = Pa_StartStream(tg->pa);
	if (r != paNoError) {
		printf("Error, Pa_StartStream() error: %s\n", Pa_GetErrorText(r));
		return 0;
	}
	/* build a wave table for tone generation. Copied from portaudio examples */
	if (DEBUG) printf("Building wavetable...\n");
	for (i = 0; i < WAVETABLE_SIZE; i++) {
		tg->table[i] = (float)sin( (double)i / (double)WAVETABLE_SIZE * M_PI * 2.);
		if (DEBUG) printf("%d, %f\n", i, tg->table[i]);
	}
	return 1;
}

int BuildBuffer(TG_State *tg, tone_t tone, int *cur_frame) {
	/* transform wavetable into buffer */
	/* argument is current frame count of entire write, not just this buffer. */
	int i = 0;
	float smpl = 0;
	int table_ind = 0;
	/*static int offset = 0;*/ /* to allow small buffer, period overlaps boundary */

	/* clear buffer in case we don't fill it all */
	for (i = 0; i < TG_FRAMES_PER_BUF; i++) tg->buf[i][0] = tg->buf[i][1] = 0; 


	for (i = 0; i < TG_FRAMES_PER_BUF; i++) {
		table_ind = tableIndexFromFreq((*cur_frame)++, tone.frequency);
		/*table_ind += offset;*/ /* compensate for overlapping buffer boundaries. */
		smpl = tg->table[table_ind]; /* potentially unsafe - no real bounds check ? */
		/*smpl += fade = ampAdd(*cur_frame, smpl, 1.0);*/
		/*printf("Outputting: %f", smpl + fade);*/
		tg->buf[i][0] = smpl;
		tg->buf[i][1] = smpl;
	}
	/*offset = table_ind;*/ /* need to +1? or % WAVETABLE_SIZE? */
	return 1;
}

int TG_WriteBuffered(TG_State * tg, tone_t tone) {
	int r = 0;
	int i = 0;
	int total_frames = 0;
	int current_frame = 0;
	int buffer_writes = 0;
	/* TODO: get this algorithm right.*/
	total_frames = tone.duration * SAMPLE_RATE / 1000;
	buffer_writes = total_frames / TG_FRAMES_PER_BUF; /* TODO: what to do with remainder? truncate? */
	printf("total frames: %d\n", total_frames);
	printf("buffer writes to perform: %d\n", buffer_writes);	

	for (i = 0; i <= buffer_writes; i++) {
		/* TODO: build the buffer here. */
		BuildBuffer(tg, tone, &current_frame);

		r = Pa_WriteStream(tg->pa, tg->buf, TG_FRAMES_PER_BUF);
		if (r != paNoError)
			printf("Pa_WriteStream() error: %s\n", Pa_GetErrorText(r));
	}
	return 1;
}

int TG_WriteBufferedSequence(TG_State *tg, tone_t *tones) {
	/* TODO: Write some blank tones between writes to 
	 * mimic stacatto effect of BSD speaker. */
	int i = 0;
	tone_t rest = {0, 10};
	if (tones != NULL)
		while (tones[i].duration != 0){
			TG_WriteBuffered(tg, tones[i++]); 
			TG_WriteBuffered(tg, rest);
		}
	return i;
}


float ampAdd(int i, float smpl, float peak) {
	float r = 0;
	/*if (i < (FRAMES_PER_BUF / 2)) {*/
		/*printf("FPB-1:%f  ", FRAMES_PER_BUF - i*/
		/*r = (peak - (peak / (float)(FRAMES_PER_BUF - i)));*/
		/*r = smpl - ( ( ((float)i) /FRAMES_PER_BUF) * smpl);*/
		/*r = -1. * (peak - ((float)i / (float)FRAMES_PER_BUF * peak)); / * TODO: reimplement. Will need to base something off total_frames or like. */
		/*if (smpl >= 0)
			r = r * -1.;*/
	/*} else {
		r = 0;
	}*/
	/*printf("ampAdd() returning %f\t", r);*/
	return r;
}

int tableIndexFromFreq(int bufind, int frequency) {
	int ret = 0;
	/*ret = (float)bufind / (( ((float)FRAMES_PER_BUF/(float)frequency) / (float)WAVETABLE_SIZE));*/
	/* had FRAMES_PER_BUF but probably want SAMPLE_RATE here. */
	ret = (float)bufind / (( ((float)SAMPLE_RATE/(float)frequency) / (float)WAVETABLE_SIZE));
	ret %= WAVETABLE_SIZE;
	/*printf("mapping bufind %d to table index %d\n", bufind, ret);*/
	return ret;
}
