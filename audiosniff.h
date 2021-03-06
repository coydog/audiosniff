#ifndef __PCAPTOY_H__
#define __PCAPTOY_H__
/* struct definitions for accessing frames and packets */

/* shamelessly copied from Tim Carsten's "sniffex" example from tcpdumporg.
   Alternatively, we could use the system "net/" headers. Changes include
   some typedefs to save typing on client code.  Since it's so derivative,
   here is his permissive license to be on the safe side: 					*/

/* This document is Copyright 2002 Tim Carstens. All rights reserved. 
   Redistribution and use, with or without modification, are permitted 
   provided that the following conditions are met:
       Redistribution must retain the above copyright notice and this
	   list of conditions.
	   The name of Tim Carstens may not be used to endorse or promote
	   products derived from this document without specific prior
	   written permission. */
/*
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 */

#include <sys/types.h> 		/* for u_char, u_short and the like */
#include <netinet/in.h> 	/* for in_addr 	*/
#include <netinet/tcp.h>	/* for tcp_seq	*/

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define ETHER_HDR_LEN	14	/* wbk - adding to avoid sizeof(sniff_ethernet) */

	/* Ethernet preamble doesn't make it to pcap. It's raw; not THAT raw. */
	/* Ethernet header */
	typedef struct {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */

		/* extending with some EtherTypes - wbk*/
	#define ETYPE_IPV4 	0x0800
	#define ETYPE_IPV6	0x86dd
	#define ETYPE_ARP 	0x0806
	#define ETYPE_RARP	0x8035
	} sniff_ethernet;

	/* IP header */
	typedef struct {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service [obsolete, now 
							   Differentiated Services - wbk] */

		/* wbk - be sure to use ntohs() on short members. */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_FLAGMASK 0xe000	/* flags are first 3 bits of ip_off - wbk */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	} sniff_ip;
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef struct {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */

		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
#ifndef TH_FLAGS /* wbk - FreeBSD has equivalent in netinet/tcp.h */
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#endif 
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
	} sniff_tcp;

/* wbk - have to write one for ICMP from scratch I guess...	*/
/* beware of type width, endianness, the usual suspects.   	*/
/* Make sure types have guaranteed widths.					*/
/* This can be as basic or as involved as I want it, but if */
/* we look at ICMP payloads, we'll need all the fields.     */
#define ICMP_HDR_LEN 64
	typedef struct {
		u_char type;
		u_char code;
		u_short chksum;
		/*u_short id; / * this part is different for different ICMP services * /
		u_short seq; */

		/* We could get these from system headers, but we end up with 
		   hairy include dependencies and probably hurt portability.
		   Since it's all standard and we're using a small subset, let's
		   just define our own values with our own macro names. */
	#define PCT_ICMP_ECHO 			8
	#define PCT_ICMP_ECHOREPLY		0
	} sniff_icmp;
#endif /* def __PCAPTOY_C__ */
