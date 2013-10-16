typedef struct {int frequency; int duration;} tone_t;

#define WAVETABLE_SIZE 		1024
#define TG_FRAMES_PER_BUF 	32
typedef struct {
	float table[WAVETABLE_SIZE];
	float buf[TG_FRAMES_PER_BUF][2]; /* 2-channel dsp frame buffer */
	PaStream *pa;
} TG_State;

int TG_Init(TG_State *);
void TG_DeInit(TG_State *);

int TG_WriteBuffered(TG_State *, tone_t);
int TG_WriteBufferedSequence(TG_State *, tone_t *); /* terminated with zero-duration */
