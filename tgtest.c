/* coydog - sandbox program for testing portaudio functionality. Yes, it has globals. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <portaudio.h>
#include "tonegenerator.h"

#define DEBUG 0

int main (int argc, char **argv) {
	TG_State tg;
	tone_t tone = {440, 100};
	int i = 0;
#define NUM_TONES 500
	tone_t tones[NUM_TONES+1];
	memset (tones, '\0', sizeof(tones));
	while (i < NUM_TONES) {
		tones[i].frequency = 440 + i * 10;
		tones[i].duration = (i+1) * 25;
		i++;
	}


	if (argc > 1 ) 
		tone.frequency = atoi(argv[1]);

	if (argc > 2)
		tone.duration = atoi(argv[2]);
	printf("Using frequency %d\n", tone.frequency);

	TG_Init(&tg);
	TG_WriteBuffered(&tg, tone);
	TG_WriteBufferedSequence(&tg, tones);
	TG_DeInit(&tg);
	return 0;
}
