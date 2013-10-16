/* coydog - sandbox program for testing portaudio functionality. Yes, it has globals. */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <portaudio.h>
#include <math.h> /* sin() etc for waveform tone generation */

#define DEBUG 0

#define SAMPLE_RATE 192000

#define WAVETABLE_SIZE 16384
//#define WAVETABLE_SIZE 15

#define FRAMES_PER_BUF SAMPLE_RATE /* play with this */
#define FRAMES_PER_BUF (SAMPLE_RATE ) /* play with this */
PaStream *pa;

float sine[WAVETABLE_SIZE];
float buf[FRAMES_PER_BUF][2];
int sine_lphase;
int sine_rphase;
FILE *err = NULL;
FILE *fplot = NULL;
int freq;
int peakcount = 0;

int InitAudio();
int BuildBuffer();
int WriteBuffer();
int WritePlot(); /* output dsp samples for plotting externally (debugging waveforms) */
int detectPeak(float buf[][2], int cur ); /* return true if we just PASSED the peak. (cur-1) */
int tableIndexFromFreq(int nd, int freq);

void printDiag();

/* experimental functions */
float ampAdd(int i, float smpl, float peak); /* based on location in buffer, ramp up and down amplitude for fade */

int main (int argc, char **argv) {
	int fdplot = 0;
	err = stderr;
	freq = 440;

	if (argc > 1 ) 
		freq = atoi(argv[1]);

	printf("Using frequency %d\n", freq);

	InitAudio();
	fdplot = open("plot.txt", O_WRONLY | O_CREAT | O_TRUNC);
	fplot = fdopen(fdplot, "w");
	if (BuildBuffer())
		WriteBuffer();
	printDiag();
	Pa_Terminate();
	fclose(fplot);
	return 0;
}

int InitAudio () {
#define NUM_CHANS 1 
#define PA_SAMPLE_TYPE 0 /* ??? */
	int i = 0;
	int r = 0;
	PaStreamParameters inParams, outParams;
	const PaDeviceInfo *pdevinfo = NULL;
	memset(&inParams, sizeof(inParams), '0');
	memset(&outParams, sizeof(outParams), '0');

	r = Pa_Initialize(); /* must come first */
	if (r != paNoError) {
		printf("Error: Pa_Initialize() error: %s\n", Pa_GetErrorText(r));
		return 0;
	}
	inParams.device = r = Pa_GetDefaultInputDevice();
	if (inParams.device < 0) {
		printf("error! from Pa_GetDefaultInputDevice(): %s\n", Pa_GetErrorText(r));
	}
	inParams.channelCount = NUM_CHANS;
	pdevinfo = Pa_GetDeviceInfo(inParams.device);
	if (pdevinfo == NULL) {
		printf("error! from Pa_GetDeviceInfo()\n");
		return 0;
	}
	inParams.sampleFormat = pdevinfo->defaultSampleRate; /* ??? */
	inParams.suggestedLatency = pdevinfo->defaultHighInputLatency;
	inParams.hostApiSpecificStreamInfo = NULL;

	outParams.device = r = Pa_GetDefaultOutputDevice();
	if (outParams.device < 0) {
		printf("error! from Pa_GetDefaultOutputDevice(): %s\n", Pa_GetErrorText(r));
	}
	outParams.channelCount = NUM_CHANS;
	pdevinfo = Pa_GetDeviceInfo(outParams.device);
	if (pdevinfo == NULL) {
		printf("error! from Pa_GetDeviceInfo()\n");
		return 0;
	}
	outParams.sampleFormat = pdevinfo->defaultSampleRate; /* ??? */
	printf("Getting portaudio latency...\n");
	outParams.suggestedLatency = pdevinfo->defaultHighOutputLatency;
	outParams.hostApiSpecificStreamInfo = NULL;

	r = Pa_OpenDefaultStream(&(pa),
	  		0, /* input chans */
			2, /* output chans */
			//paInt24, /* or specify eg paInt24 */
			paFloat32, /* or specify eg paInt24 */
			SAMPLE_RATE,
			0, /* *** was 128. Shouldn't it be FRAMES_PER_BUF? *** */
			NULL,
			NULL);
	if (r != paNoError) {
		printf("Error: Pa_OpenStream() error!: %s\n", Pa_GetErrorText(r));
		return 0;
	}
	r = Pa_StartStream(pa);
	if (r != paNoError) {
		printf("Error, Pa_StartStream() error: %s\n", Pa_GetErrorText(r));
		return 0;
	}
	/* build a wave table for tone generation. Copied from portaudio examples */
	if (DEBUG) fprintf(err, "Building wavetable...\n");
	for (i = 0; i < WAVETABLE_SIZE; i++) {
		sine[i] = (float)sin( (double)i / (double)WAVETABLE_SIZE * M_PI * 2.);
		if (DEBUG) fprintf(err, "%d, %f\n", i, sine[i]);
	}
	return 1;
}

int BuildBuffer() {
	/* transform wavetable into buffer */
	int i;
	float smpl = 0;
	float fade = 0;
	int table_ind = 0;
	/*static int offset = 0;*/ /* to allow small buffer, period overlaps boundary */

	for (i = 0; i < FRAMES_PER_BUF; i++) {
		table_ind = tableIndexFromFreq(i, freq);
		/*table_ind += offset;*/ /* compensate for overlapping buffer boundaries. */
		smpl = sine[table_ind]; /* potentially unsafe - no real bounds check ? */
		/*smpl = sine[i % WAVETABLE_SIZE];*/

		/*printf ("smpl: %f ", smpl);*/
		/*smpl += fade = ampAdd(i, smpl, 1.0);*/
		/*printf("Outputting: %f", smpl + fade);*/
		buf[i][0] = smpl;
		buf[i][1] = smpl;
		/*printf("\n");*/
		if (detectPeak(buf, i))
			peakcount++;
	}
	/*offset = table_ind;*/ /* need to +1? or % WAVETABLE_SIZE? */
	return 1;
}

int WriteBuffer() {
	int r = 0;
	int i = 0;
	int repeats = 100;

	WritePlot(); /* write samples in plottable format to file */
	for (i = 0; i < repeats; i++) {
		r = Pa_WriteStream(pa, buf, FRAMES_PER_BUF);
		if (r != paNoError)
			fprintf(err, "Pa_WriteStream() error: %s\n", Pa_GetErrorText(r));
	}
	return 1;
}

float ampAdd(int i, float smpl, float peak) {
	float r = 0;

	/*if (i < (FRAMES_PER_BUF / 2)) {*/
		/*printf("FPB-1:%f  ", FRAMES_PER_BUF - i*/
		/*r = (peak - (peak / (float)(FRAMES_PER_BUF - i)));*/
		/*r = smpl - ( ( ((float)i) /FRAMES_PER_BUF) * smpl);*/
		r = -1. * (peak - ((float)i / (float)FRAMES_PER_BUF * peak));
		/*if (smpl >= 0)
			r = r * -1.;*/
	/*} else {
		r = 0;
	}*/
	printf("ampAdd() returning %f\t", r);
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

int WritePlot() {
	int i = 0;
	for (i = 0; i < FRAMES_PER_BUF; i++) 
		fprintf(fplot, "%d, %f\n", i, buf[i][0]);
	fflush(fplot);
	return 1;
}

int detectPeak(float buf[][2], int cur) {
	int ret = 0;
	static int descending = 0;
	float now, justnow;
	now 	= buf[cur]	[0];
	justnow = buf[cur-1][0];
	/*printf("now: %f\tjustnow: %f\tthen:%f\n", now, justnow, then);*/
	if (descending) {
		if (now > justnow)
			descending = 0;
	}
	else if (now < justnow) {
		ret = 1;
		descending = 1;
	}

	return ret;
}

void printDiag() {
	printf("\nPeaks: %d\n", peakcount);
}
