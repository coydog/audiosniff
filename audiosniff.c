/* Thanks to networksorcery.com. This valuable resource saved me much time. Without them
   I would have had to wade through a LOT of RFC's. Their hypertext breakdowns of every 
   protocol imaginable, along with diagrams, made this much easier. The info is out there
   in other places, but I've never seen a better centralized comprehensive reference.   */

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DEBUG 1
/*#include <netinet/in_systm.h>*/ /* required by ip_icmp.h */
/* #include <netinet/ip_icmp.h> */

/* The BSD's have diverged in where they keep headers for esr's
   speaker driver (or perhaps it was backported; not sure if it was
   in 386BSD. */
#ifdef __NETBSD__
#define __BSD_SPEAKER__
#include <machine/spkr.h>
#endif

#ifdef __OPENBSD__
#define __BSD_SPEAKER__
#include <sys/ioctl.h>
#include <dev/isa/spkrio.h>
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif 

#ifdef __FREEBSD__
#define __BSD_SPEAKER__
#include <dev/speaker/speaker.h>
#endif

#ifdef __LINUX__
#include <portaudio.h>
#include "tonegenerator.h"
#endif


#include "audiosniff.h"


#define MAX_FUNC_LEN 		1024 /* max length of function name strings */
#define PCAPTOY_BUFFSIZE	8192 /* buffer for queued packets. Additional 
									packets will be dropped. Keep it low for
									this toy program. */
#define PCAPTOY_INF			-1	/* capture indefinitely */
#define PCAPTOY_CAPCOUNT	50
#define PCAPTOY_VERBOSE		1
#define PCAPTOY_TIMEOUT		500 	/* ms? */

/* older native pcap on OpenBSD doesn't have this constant. 
   TODO: test filtering on OpenBSD */
#ifdef __OPENBSD__
	#define PCAPTOY_NETMASK_UNKNOWN 0
#else
	#define PCAPTOY_NETMASK_UNKNOWN PCAP_NETMASK_UNKNOWN
#endif

#define PCAPTOY_BUFFERING	_IONBF /*TODO replace with cmd line opt */

/* values to play with for speaker note duration */
/* might should put the speaker stuff in a separate module, 
   to maximize code reuse. We can build other toys for other
   platforms based on this module, maybe... */

/* timings are quirky with BSD speaker vs. portaudio (pa seems higher
 * resolution, more accurate; BSD has natural stacatto) */
#ifdef __LINUX__
/* TODO: These aren't being used!!@!@1 */
#define PCAPTOY_NOTEDURATION_HEADER		500
#define PCAPTOY_NOTEDURATION_PAYLOAD	500
#else
#define PCAPTOY_NOTEDURATION_HEADER		50
#define PCAPTOY_NOTEDURATION_PAYLOAD	50
#endif

/* arrrgh not working, forget it for now */
#if 0
/* use -DCHATTY=1 */
#ifdef CHATTY
#define VERBOSE( v_msg ) {(\
if (CHATTY) 			\
	printf( (v_msg) )			\
)}
#else
#define VERBOSE ( v_msg ) {()}
#endif

/* code in here for errno? */
#define ERR (e_str)	{(	 \
	fprintf(stderr, (e_str) ) \
)}
#endif /* end if 0 */

/* userdata struct for pcap callback */
typedef struct {
	char invok[PATH_MAX+1]; /* TODO: replace w/ runtime pathconf() and dynamic alloc */
	FILE *out; 		/* normally stdout 	*/
	FILE *err; 		/* stderr 			*/
	int fd_spkr; 	/* descriptor for speaker device */

#ifdef __LINUX__ /* getting messy quick */
	TG_State tonegen;
#endif

	long count;
} handler_state;

int InitAudio(handler_state *phs); /* stub in everything but Linux */
void DeInitAudio();

#ifdef __LINUX__
int InitAudioLinux(handler_state *phs);
void DeInitAudioLinux();
#endif
			   

/* print diagnostic messages from pcap return codes */
int print_diag_pcap_options(int pcap_ret, const char *func, const handler_state *hs);

/* print diagnostics for pcap_activate() errors */
int print_diag_pcap_activate(pcap_t *p, int pcap_ret, const handler_state *invok);

/* forward declaration of pcap_handler for callback*/
void handle_packet(u_char *user, const struct pcap_pkthdr *h,
					const u_char *raw);

/* callback will call these functions conditionally. Args TBD */
void handle_packet_print(handler_state *phs,
							const struct pcap_pkthdr *h,
							const u_char *raw);
void handle_packet_spkr(handler_state *phs,
							const struct pcap_pkthdr *h,
							const u_char *raw);
void handle_packet_spkr_array(handler_state *phs,
							const struct pcap_pkthdr *h,
							const u_char *raw);

/* loop functions which pass through args to pcap handle errors appropriately */
int do_pcap_loop	(pcap_t *p, int cnt, pcap_handler h, handler_state *phs);
int do_pcap_dispatch(pcap_t *p, int cnt, pcap_handler h, handler_state *phs);

/* TESTING ONLY! REMOVE! */
unsigned short testfreq = 20;

int main(int argc, char** argv) {
	int verbose = PCAPTOY_VERBOSE; /* TODO: arg */
	/*int fd_log  = STDOUT_FILENO;
	int fd_err  = STDOUT_FILENO;*/
	/*FILE *fp_log = stdout;
	FILE *fp_err = stderr;*/

  	int ret = 0; 	/* main() return code */
	int pc_ret = 0; /* return codes from libpcap */
 	pcap_t *p;	 	/* pcap handle */
	handler_state hs;

	/* bytes to capture. Could make this a command-line arg. Do we want
	   payload or just headers? */
	int framelen = 1024; 
	int promisc  = 0;   /* TODO: command-line arg */
	int read_timeout  	= PCAPTOY_TIMEOUT; /* read timeout in ms */
	int pc_bufsize 		= PCAPTOY_BUFFSIZE;

	/* TODO: be more sophisticated, copy arg */
	const char * szdev = argv[1];
	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE]; /* for pcap to give us info */ 
	char funcbuf[MAX_FUNC_LEN];
	memset(&filter, '\0', sizeof(filter));
	memset(errbuf, '\0', PCAP_ERRBUF_SIZE);
	memset(funcbuf, '\0', MAX_FUNC_LEN);
	hs.count = 0;
	strncpy(hs.invok, argv[0], PATH_MAX);
	hs.invok[PATH_MAX] = '\0';
	hs.out = stdout;
	hs.err = stderr;
	hs.fd_spkr = open("/dev/speaker", O_WRONLY);

	/* do some input validation; ensure we can continue */
	if (!(argc-1)) {
		fprintf(hs.err, "%s: No interface specified!\n", hs.invok);
		fprintf(hs.err, "usage: %s <interface>\n", hs.invok);
		ret = 1;
		exit(ret);
	}

 	printf("audiosniff - coydog's silly libpcap/NetBSD tricks.\n\n");
	if (verbose) {
		fprintf(hs.out, "Initializing, getting pcap handle for >%s<\n",
						szdev);
	}
	/* if we wanted to read from a previous capture, we could call
	   pcap_open_offline() here instead.							*/

	/* audio initialization - (portaudio on linux) */
	if (!InitAudio(&hs))
		exit(1);
			
	if ( !(p = pcap_create(szdev, errbuf))) {
		fprintf(hs.err, "pcap_create() failed!: \n");
		fprintf(hs.err, errbuf);
		if (verbose) 
			fprintf(hs.out, "pcap_create() error, bailing\n");
		
		ret = 1;
		exit(ret);	
	}
	else if (verbose) 
		fprintf(hs.out, "pcap_create() success, continuing.\n");

	/* set capture handle options */
	pc_ret = pcap_set_snaplen(p, framelen); /* capture length */
	snprintf(funcbuf, MAX_FUNC_LEN, "pcap_set_snaplen(%d, %d)", 
					(int)p, 
					framelen);
	print_diag_pcap_options(pc_ret, funcbuf, &hs);
	if (pc_ret != 0) {						/* 0 is success */
		/*print_diag_pcapreturn(pc_ret, funcbuf, argv[0]);*/
		fprintf(hs.err, "%s: can't set snapshot length, bailing!\n", hs.invok);
		ret = 1;
		exit(ret);
	} else if (verbose) {
		fprintf(hs.out, "Successfully set snapshot len to %d, continuing...\n",
					framelen);
	}
	pc_ret = pcap_set_promisc(p, promisc); 	/* promiscuous mode */
	snprintf(funcbuf, MAX_FUNC_LEN, "pcap_set_promisc(%d, %d)",
					(int)p,
					promisc);
	print_diag_pcap_options(pc_ret, funcbuf, &hs);
	if (pc_ret != 0) {
		fprintf(hs.err, "%s: can't set promisc flag, bailing!\n", hs.invok);
		ret = 1;
		exit (ret);
	} else if (verbose) {
		fprintf(hs.out, "Successfully set promiscuous flag to %d, "
						"continuing...\n",
						promisc);
	}
	/* TODO: handle 802.11-specific stuff with pcap_set_rfmon() and
	   	pcap_can_set_rfmon(). accept default for now.	*/

	/* set read timeout. If OS and pcap are queueing up packets for us, 
	   but network traffic is slow and we want to work with the packets
	   we already have, set this timeout so that we don't wait indefinitely
	   for enough packets to arrive. Timeout will not start until a packet
 	   arrives.	 */
	pc_ret = pcap_set_timeout(p, read_timeout);
	snprintf(funcbuf, MAX_FUNC_LEN, "pcap_set_timeout(%d, %d)",
			(int)p,
			read_timeout);
	print_diag_pcap_options(pc_ret, funcbuf, &hs);
	if (pc_ret != 0) {
		fprintf(hs.out, "%s: can't set read timeout, bailing!\n", hs.invok);
		ret = 1;
		exit(ret);
	} else if (verbose) {
		fprintf(hs.out, "Successfully set read timeout to %d, continuing...\n",
					read_timeout);
	}

	/* set capture buffer size */
	pc_ret = pcap_set_buffer_size(p, pc_bufsize);
	snprintf(funcbuf, MAX_FUNC_LEN, "pcap_set_buffer_size(%d, %d)",
					(int)p,
					pc_bufsize);
	print_diag_pcap_options(pc_ret, funcbuf, &hs);
	if (pc_ret != 0) {
		fprintf(hs.err, "%s: can't set pcap buffer size, bailing!\n", hs.invok);
		ret = 1;
		exit(ret);
	} else if (verbose) {
		fprintf(hs.out, "Successfully set pcap buffer size to %d, "
						"continuing...\n",
						pc_bufsize);
	}

	/* activate handle */
	/* for now, we should probably treat warnings as errors. */
	pc_ret = pcap_activate(p);
	if (pc_ret != 0) {
		print_diag_pcap_activate(p, pc_ret, &hs);
		ret = 1;
		exit(ret);
	} else if (verbose) {
		fprintf(hs.out, "Success with no warnings from pcap_activate().\n");
	}

	/* apply bpf filter; TODO: fix quick and dirty arg parsing */
	if (argc > 2) {
		if (pcap_compile(p, &filter, argv[argc-1], 1, PCAPTOY_NETMASK_UNKNOWN) == -1) 
			 pcap_perror(p, hs.invok);
		else
			fprintf(hs.out, "Successfully compiled filter: %s\n", argv[argc-1]);

		if (pcap_setfilter(p, &filter) == -1) 
			pcap_perror(p, hs.invok);
		else
			fprintf(hs.out, "Successfuly set filter.\n");

	}
		


	/* outer loop, to force early returns from pcap_loop()*/
	/*while (1) {
		/ * TODO: last arg is ptr to arg for callback handler * /
		/ *pc_ret = pcap_loop(p, PCAPTOY_INF, handle_packet, (u_char*)&hs);* /
		/ * TODO: want _loop or _dispatch? RETURNS ARE DIFFERENT!*/
		/*pc_ret = pcap_loop(p, PCAPTOY_CAPCOUNT, handle_packet, (u_char*)&hs);* /
		pc_ret = pcap_dispatch(p, PCAPTOY_CAPCOUNT, handle_packet, (u_char*)&hs);
		if (pc_ret == -2 && verbose) {
			fprintf(fp_err, "%s: pcap_loop() broken by pcap_breakloop() before "
							"capture\n", hs.invok);
		} else if (pc_ret == -1) {
			fprintf(fp_err, "%s: pcap_loop() encountered error!\n", hs.invok);
			pcap_perror(p, hs.invok);
		} else if (pc_ret == 0 && verbose) {
			fprintf(fp_err, "%s: pcap_loop() returned all requested packets.\n", hs.invok);
		} else {
			fprintf(fp_err, "%s: pcap_loop() unknown return code! wtf?\n", hs.invok);
		}
	}A*/
	do_pcap_dispatch(p, PCAPTOY_CAPCOUNT, handle_packet, &hs);


  	return ret;
}

int do_pcap_loop	(pcap_t *p, int cnt, pcap_handler h, handler_state *phs) {
	int pc_ret = 0;
	int verbose = 1; /* TODO: replace with flag/args */
	int fatal = 0;
	/* TODO if we wanna be paranoid, we could validate FILE*'s. Let's not. */

	while (!fatal) {
		pc_ret = pcap_loop(p, cnt, h, (u_char*)phs);
		if (pc_ret == -2 && verbose) {
			fprintf(phs->err, "%s: pcap_loop() broken by pcap_breakloop() before "
							"capture\n", phs->invok);
		} else if (pc_ret == -1) {
			fprintf(phs->err, "%s: pcap_loop() encountered error!\n", phs->invok);
			pcap_perror(p, phs->invok);
			fatal = 1;
		} else if (pc_ret == 0 && verbose) {
			fprintf(phs->out, "%s: pcap_loop() returned all requested packets.\n", phs->invok);
		} else {
			fprintf(phs->err, "%s: pcap_loop() unknown return code! wtf?\n", phs->invok);
			fatal = 1;
		}
	}
	if (fatal)
		return -1;
	else
		return 1; /* should never be hit */
}

int do_pcap_dispatch(pcap_t *p, int cnt, pcap_handler h, handler_state *phs) {
	int pc_ret = 0;
	int fatal = 0;
	int verbose = 1;
	
	while (!fatal) {
		pc_ret = pcap_dispatch(p, cnt, h, (u_char*)phs);

		if (pc_ret == 0 && verbose) {
			/* TODO: Cleanly remove test code? */
			/*fprintf(phs->out, "_");*/
			fflush(phs->out); /* TODO: error handling for fflush()? */
		} else if (pc_ret == -1) { 		/* TODO: get_err? */
			fprintf(phs->err, "%s: pcap_dispatch() returned error!\n", phs->invok);
			fatal = 1;
		} else if (pc_ret == -2) {
			fprintf(phs->err, "%s: pcap_dispatch() broken by pcap_breakloop()!", phs->invok);
			fatal = 1;
		}
	}
	if (fatal)
		return -1;
	else
		return 1; /* should never be hit */
}

/* print diagnostic messages based on pcap return values. */
int print_diag_pcap_options(int pcap_ret, 
					const char* func, 
					const handler_state *phs) {
	/*int verbose = PCAPTOY_VERBOSE;*/

	if (pcap_ret != 0) {
		if (pcap_ret == PCAP_ERROR_ACTIVATED) {
			fprintf(phs->err, "%s: error: %s called on already-activated "
							"handle!\n", phs->invok, func);
		} else {
			fprintf(phs->err, "%s: error: unknown error from %s!\n", 
						phs->invok, func);
		}
	}
	return pcap_ret;
}

int print_diag_pcap_activate(pcap_t *p, 
						int pcap_ret, 
						const handler_state *phs) {
	/*char *perr = NULL;*/
	int verbose = PCAPTOY_VERBOSE;

	/* some cases will allow additional diagnostics from pcap_geterr() */
	switch (pcap_ret) {
		case 0:
			if (verbose) 
				fprintf(phs->out, "%s: success! pcap_activate().\n", phs->invok);
			break;

		case PCAP_WARNING_PROMISC_NOTSUP:
			fprintf(phs->err, "%s: pcap_activate() warns promiscuous not "
							"supported!\n", phs->invok);
			fprintf(phs->err, "%s:\tDetails: >%s<\n", phs->invok, pcap_geterr(p));
			break;
		case PCAP_WARNING:
			fprintf(phs->err, "%s: error! pcap_activate claims success, "
							"but returned a warning!\n", phs->invok);
			fprintf(phs->err, "%s:\tDetails: >%s<\n", phs->invok, pcap_geterr(p));
			break;
		case PCAP_ERROR_ACTIVATED:
			fprintf(phs->err, "%s: pcap_activate() returned error! Handle "
							"is already activated!\n", phs->invok);	
			break;
		case PCAP_ERROR_NO_SUCH_DEVICE:
			fprintf(phs->err, "%s: pcap_activate() returned error! No such "
							"device!\n", phs->invok);	
			fprintf(phs->err, "%s:\tDetails: >%s<\n", phs->invok, pcap_geterr(p));
			break;
		case PCAP_ERROR_PERM_DENIED:
			fprintf(phs->err, "%s: pcap_activate() returned error! You "
							"don't seem to have permissions for cap "
							"device!\n", phs->invok);
			fprintf(phs->err, "%s:\tDetails: >%s<\n", phs->invok, pcap_geterr(p));
			break;
		case PCAP_ERROR_RFMON_NOTSUP:
			fprintf(phs->err, "%s: pcap_activate() returned error! 802.11 "
							"RF monitor mode not supported!\n", phs->invok);
			break;
		case PCAP_ERROR_IFACE_NOT_UP:
			fprintf(phs->err, "%s: pcap_activate() returned error! "
							"Interface seems to exist, but is down!\n", phs->invok);
			break;
		case PCAP_ERROR:
		default:	
			fprintf(phs->err, "%s: pcap_activate() returned unknown error!\n",
						phs->invok);
			break;
	}


		
	return pcap_ret;
}


void handle_packet(u_char *user, const struct pcap_pkthdr *h,
					const u_char *bytes) {
	/* dummy handler TODO: flesh out; decide how layered we want 
	   out speaker/print interface */
	handler_state *phs = (handler_state*)user;
	phs->count++;

	handle_packet_print(phs, h, bytes);
	/*handle_packet_spkr(phs, h, bytes);*/
	handle_packet_spkr_array(phs, h, bytes);
}

void handle_packet_print(handler_state *phs,
							const struct pcap_pkthdr *h,
							const u_char *raw) {

	/* TODO: Need bounds checking for access to raw. A packet crafter
	   could crash this with terrible consequences since run as root. */
	/* This code might crap its pants if invoked in a non-IP 
	   ethernet environment (ie, DECNet, Appletalk. Like that's 
	   gonna happen ;).											  */
	/* pointers to the parts we're interested in, for convenience */
	/* also grab things like header length we'll need later. 	  */
	const sniff_ethernet *hdr_eth = (sniff_ethernet*)raw;
	const u_char  *eth_src = hdr_eth->ether_shost;
	const u_char  *eth_dst = hdr_eth->ether_dhost;
	const sniff_ip *hdr_ip = (sniff_ip*)(raw+ETHER_HDR_LEN);

	/* TODO: Whoops, can't really assume IP at this point. Need to look at 
	   EtherType first? */
	u_char ip_vr  = hdr_ip->ip_vhl >> 4; /* could use macros in audiosniff.h */
	u_char ip_hl  = hdr_ip->ip_vhl & 0x0f; /* header length */
	u_short ip_len = ntohs(hdr_ip->ip_len);	/* IP packet total len */
	u_short ip_flagoff = ntohs(hdr_ip->ip_off);
	u_short ip_df = (ip_flagoff & IP_DF) >> 14; /* don't frag */
	u_short ip_fragoffset = 0;
	const struct in_addr *ip_src = &(hdr_ip->ip_src);
	const struct in_addr *ip_dst = &(hdr_ip->ip_dst);
#define MAX_PADDR 32 /* TODO: Find real value. Handle IPv6 */
	char bufsrc[MAX_PADDR+1], bufdst[MAX_PADDR+1];

	/* TODO: endianness issues here? getting x806 types, when ARP is x608,
	   and x0008, when expecting x0800 for IP.	*/
	/* probably want ntohs().	*/
	const u_short *eth_typ = &hdr_eth->ether_type;
	u_short h_typ = ntohs(*eth_typ);
	memset(bufsrc, '\0', sizeof(bufsrc));
	memset(bufdst, '\0', sizeof(bufdst));
	/* TODO: This is IPv4-specific. Also, error handling */
	/* inet_net_ntop() isn't documented on linux, doesn't seem to conform to 
	   any POSIX that I'm aware of. Use inet_ntop() instead.
	   And the were damned to an eternity in IPv4					*/
	if (inet_ntop(AF_INET, (void*)ip_src, bufsrc, MAX_PADDR) == NULL) 
		perror(phs->invok);

	if (inet_ntop(AF_INET, (void*)ip_dst, bufdst, MAX_PADDR) == NULL) 
		perror(phs->invok);

	fprintf(phs->out, "%5ld: ", phs->count);
	fflush(phs->out); /* no error check XD */

	/* TODO: unspaghettify. Replace below condition with this. */
	if (h->caplen < (ETHER_HDR_LEN + ip_hl) )
		return;

	if (h->caplen > 0) {
		/* do stuff */
		fprintf(phs->out, "cap: %3d total: %5d  "
				/* 0 - "left-pad with zero" flag. 2 - minimuym field width */
				"EthTyp: %4x  "
				"EthSrc: %02X:%02X:%02X:%02X:%02X:%02X  "
				"EthDst: %02X:%02X:%02X:%02X:%02X:%02X  "
				"\n",
				h->caplen, h->len,
				h_typ,
				eth_src[0], eth_src[1], eth_src[2], eth_src[3], eth_src[4], eth_src[5],
				eth_dst[0], eth_dst[1], eth_dst[2], eth_dst[3], eth_dst[4], eth_dst[5]
		);
		if (h_typ >= 0x0800) {
			switch (h_typ) {
			  case ETYPE_ARP:
				printf("\t ARP!\n"); /* TODO: details? */
				break;
			  case ETYPE_IPV4:
				ip_flagoff = ntohs(hdr_ip->ip_off);
				ip_fragoffset = ip_flagoff & IP_OFFMASK; /* grab frag offset */
				printf("\tIPv%d  len: %4d DontFrag:%d FragOff: %d Src: %s Dst: %s\n", ip_vr, ip_len, 
															ip_df, ip_fragoffset, bufsrc, bufdst);
				break;
			  case ETYPE_IPV6:	
			  case ETYPE_RARP:	
			  default:
				printf("Unknown EtherType! Weird, check it out!\n");
				/*exit(1);*/	/* TODO:remove bailout on unknown EtherType? */
			} 
		}else {
				printf("no EtherType; payload size %d\n", h_typ);
		}
	}
	else {
		perror("pcap_pkthdr caplen of <= 0!");
	}
}

void handle_packet_spkr(handler_state *phs, 
							const struct pcap_pkthdr *h,
							const u_char *raw) {
#ifdef __BSD_SPEAKER__
/* TODO: Very rough proof of concept. Refine. */
	tone_t t;

	/* TODO: Probably makes more sense to keep descriptor in 
	   handler_state rather than open at every callback */
   	/*fd = open("/dev/speaker", O_WRONLY);*/
	if (phs->fd_spkr == -1) {
		perror("open() of /dev/speaker failed! ");
		exit(1); /* TODO: unspaghettify */
	}
	else {
		/* see man spkr */
		/* TODO: check length! Might need to pass an arg, maybe pcap_pkthdr */
		   
		t.duration = 1;
		t.frequency = testfreq; /* test with A */

		if (ioctl(phs->fd_spkr, SPKRTONE, &t) == -1) {
			perror("ioctl() failed! ");
		}
		else {
			/*testfreq += 10;*/
			testfreq += rand() % 16000;
		}
	}
	/*close(fd);*/ /* TODO: remove when fd in handler_state */
#endif  /* __BSD_SPEAKER__ */
}
void handle_packet_spkr_array(handler_state *phs, 
							const struct pcap_pkthdr *h,
							const u_char *raw) {
	/* tone for AF, encode src and dst addy's/ports, tone for 
	   proto (TCP/UDP; start with TCP), encode payload */
	/* TODO: How big to make tone_t array? Dynamically allocate? Figure out
	   a good maximum for static alloc? Start with 2048 I guess */
	/* decl */
	const sniff_ethernet *hdr_eth = NULL;
	const u_char *eth_src = NULL;
	const u_char *eth_dst = NULL;
	const u_short *eth_typ = NULL; /* ptr to type field */
	u_short h_typ = 0; /* host-order type */
	const sniff_ip *hdr_ip = NULL;
	bpf_u_int32 ip_hl = 0;
	u_short ip_flagoff = 0;	/* flags, frag offset field */
	u_short ip_fragoffset = 0;
	u_char ip_proto = 0;
	const sniff_icmp *hdr_icmp = NULL;
	u_char icmp_type = 0;

/* TODO: #defines for EtherType tones here */
#define MAX_TONES 		2048
#ifdef __LINUX__
#define DUR_ETYPE		10		/* duration for EtherType field freq */
#define DUR_IPPROTO		10 		/* TCP, UDP, ICMP, etc */
#define DUR_FRAGMENTS   15 		/* fragment offset */
#define DUR_ICMP		20 

#else
#define DUR_ETYPE		2		/* duration for EtherType field freq */
#define DUR_IPPROTO		2 		/* TCP, UDP, ICMP, etc */
#define DUR_FRAGMENTS   3 		/* fragment offset */
#define DUR_ICMP		4 
#endif 

#define FREQ_ARP 		660   	/* E5 (above A) */
#define FREQ_RARP		1319  	/* E6 */
#define FREQ_IPV4		440
#define FREQ_IPV6		880   	/* A5 */
#define FREQ_ICMP_REQ	2217 	/* D7	*/
#define FREQ_ICMP_RES	1661 	/* C#7	*/
#define FREQ_TCP		494  	/* C5 	*/
/*#define FREQ_UDP		392*/ 	/* G 	*/
#define FREQ_UDP		554  	/* C# 	*/
#define FREQ_UNKNOWN	262 	/* C4 	*/
	int tncnt = 0;
	tone_t tones[MAX_TONES+1];

	/* init */
	memset(tones, '\0', sizeof(tones));
	tones[MAX_TONES].duration = 0; /* terminates array for ioctl */

	/* silently abort at any step if caplen is too short to complete. */
	/* specifically, we need to at least read the IP header length to 
	   get anything worth generating a tone. It's in first octet of IP */
	if (h->caplen < ETHER_HDR_LEN+1)
		return;
	hdr_eth = (sniff_ethernet*) raw;
	eth_src = hdr_eth->ether_shost;
	eth_dst = hdr_eth->ether_dhost;
	eth_typ = &(hdr_eth->ether_type);

	/* let's not bother with a tone for ethernet. */

	/* Here, let's grab Ether Type. Check for ARP? How to handle tone generation and 
	   quick return if we get ARP or something other than IPv4? Maybe have a separate
	   block here to build array then exit? Switch statement? */
	h_typ = ntohs(*eth_typ);
	tones[tncnt].duration = DUR_ETYPE;
	switch (h_typ) {
		case ETYPE_ARP:
			tones[tncnt++].frequency = FREQ_ARP;
			/*tones[tncnt].duration = 0;*/ /* terminate array */
			break;
	 	case ETYPE_RARP:
			tones[tncnt++].frequency = FREQ_RARP;
			/*tones[tncnt].duration = 0;*/
			break;
		case ETYPE_IPV4: { /* This isn't going to be pretty */
			/* make sure the rest of IP header is contained in capture (paranoia) */
			printf("IPv4!\n"); /* DEBUG */

			hdr_ip = (sniff_ip*)(raw+ETHER_HDR_LEN);
			ip_hl = (bpf_u_int32)hdr_ip->ip_vhl & 0x0f; /* grab second nibble */
			ip_hl *= 4; /* convert from 32-bit words to octets for easier use */

			if (h->caplen < (ETHER_HDR_LEN + ip_hl) )
				break;
			tones[tncnt++].frequency = FREQ_IPV4;

			tones[tncnt].duration = DUR_IPPROTO;
			/* chirp for fragmented IP packets */
			ip_flagoff = ntohs(hdr_ip->ip_off);
			ip_fragoffset = ip_flagoff & IP_OFFMASK; /* grab frag offset */
			if (ip_fragoffset) {
				printf("Frag!\n"); /* DEBUG */
				/* override DUR_IPPROTO, special case */
				tones[tncnt].duration = DUR_FRAGMENTS; /* TODO: increment looks questionable */
				tones[tncnt++].frequency = FREQ_IPV4 << ip_fragoffset; /* octaves of A440 */
			}

			/* grab IP proto. We'll use it for logic in a nested switch below. */
			ip_proto = hdr_ip->ip_p;
			/* TODO: also grab src/dst in_addr's? Not sure how to encode them. */
			
			switch (ip_proto) { /* these are defined in <netinet/in.h> */
				case IPPROTO_ICMP: {
				printf("ICMP! \n"); /* DEBUG */
					if (h->caplen >= (ETHER_HDR_LEN + ip_hl + ICMP_HDR_LEN)) {
						/* want something ping-y. break up ICMP types, req/resp, etc? */
						/* grab ICMP type. */
						hdr_icmp = (sniff_icmp*)(raw + ETHER_HDR_LEN + ip_hl); /* likely problem here */
						icmp_type = hdr_icmp->type; /* TODO consider removing variable */
						tones[tncnt].duration = DUR_ICMP;
						switch (icmp_type) {
							case PCT_ICMP_ECHO:
								printf("Echo!\n"); /* DEBUG */
								tones[tncnt++].frequency = FREQ_ICMP_REQ;
								break;
							case PCT_ICMP_ECHOREPLY:
								printf("Reply!\n"); /* DEBUG */
								tones[tncnt++].frequency = FREQ_ICMP_RES;
								break;
							default: /* TODO: handle any others? */	
								printf("Unknown ICMP! %d\n", icmp_type); /* DEBUG */
								break; /* TODO: iffy. */
						} /* end switch icmp type */
					}
					break;
			   } /* end case IPPROTO_ICMP */
				case IPPROTO_TCP:
					printf("TCP!\n"); /* DEBUG */
					tones[tncnt++].frequency = FREQ_TCP;
					break;
				case IPPROTO_UDP:
					printf("UDP!\n"); /* DEBUG */
					tones[tncnt++].frequency = FREQ_UDP;
					break;
				default:
					/* TODO: make it noticeable if we get unknown protocol. */
					printf("Uknown IP Protocol!\n"); /* DEBUG */
					break;
			} /* end switch ip_proto */

			/*tones[tncnt].duration = 0;*/ /* terminate array */
			break;
		 } /* end case ETYPE_IPV4 */
		case ETYPE_IPV6:
			printf("IPV6!\n"); /* DEBUG */
			tones[tncnt++].frequency = FREQ_IPV6;
			/*tones[tncnt].duration = 0;*/
			break;
		default:
			printf("Unknown EtherType!\n");
			tones[tncnt++].frequency = FREQ_UNKNOWN;
			break;
	} /* end switch h_typ (EtherType */

	/* TODO: Maybe should terminate array here instead of within switch statements. 
	 * Less likelihood of error, less code. Can assume any code that added to the 
	 * array incremented the index. */
	/* That way we can break when we run out of header, and still play the tones. */
	tones[tncnt].duration = 0; /* terminate array */
	/* array should be prepared, now send to ioctl. */

#ifdef __BSD_SPEAKER__
	if (ioctl(phs->fd_spkr, SPKRTUNE, tones) == -1)
		perror("ioctl() failed!");
#endif  /* __BSD_SPEAKER__ */
#ifdef __LINUX__
	TG_WriteBufferedSequence(&(phs->tonegen), tones);
#endif /* __LINUX__ */


	/* make sure the rest of IP header is contained in capture (paranoia) */
	/*if (h->caplen < (ETHER_HDR_LEN + ip_hl) )
		return; moved this into switch above  */
}

int InitAudio(handler_state *phs) {

#ifdef __LINUX__
	return InitAudioLinux(phs);
#else
	return 1;
#endif
}

void DeInitAudio(handler_state *phs) {
#ifdef __LINUX__
	DeInitAudioLinux(phs);
#endif
}

#ifdef __LINUX__
int InitAudioLinux(handler_state *phs) {
	return TG_Init(&(phs->tonegen));
}

void DeInitAudioLinux(handler_state *phs) {
	TG_DeInit(&(phs->tonegen));
}
#endif
