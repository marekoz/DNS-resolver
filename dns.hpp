//author: Marek Kozumplik, xkozum08
#pragma once

#include <iostream> //cout
#include <cstring>
#include <netdb.h> //gethostbyname()
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bitset>
#include <regex>
#include <iomanip>

#define DNS_PORT 53
#define TYPE_IP4 0
#define TYPE_IP6 1
#define TYPE_DOMAIN 2

struct parsed_arguments
{
	int recursion = 0;
	int reverse = 0;
	int ip6 = 0;
	int port = DNS_PORT;
	int address_type;
	char server[256];
	char hostname[256];
};

struct dns_header
{
	/*

		DNS Header in RFC 1035

										1  1  1  1  1  1
		0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|                      ID                       |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|                    QDCOUNT                    |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|                    ANCOUNT                    |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|                    NSCOUNT                    |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|                    ARCOUNT                    |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	*/
	unsigned short id; // identification number 16 bits

	// Flags in single byte
	unsigned char rd : 1;	  // recursion desired
	unsigned char tc : 1;	  // truncated message
	unsigned char aa : 1;	  // authoritive answer
	unsigned char opcode : 4; // 0 - standard query / 1 - reverse q / 2 - server status request ...
	unsigned char qr : 1;	  // 0 - query / 1 - response

	// Response flags in single byte
	unsigned char rcode : 4; // response code
	/*
		0 - no error
		1 - format error
		2 - server failure
		3 - name error - domain name referenced does not exist
		5 - refused
	*/
	unsigned char cd : 1; // checking disabled
	unsigned char ad : 1; // authenticated data
	unsigned char z : 1;  // its z! reserved
	unsigned char ra : 1; // recursion available

	unsigned short q_count;	   // number of question entries, 2 bytes
	unsigned short ans_count;  // number of answer entries, 2 bytes
	unsigned short auth_count; // number of authority entries, 2 bytes
	unsigned short add_count;  // number of resource entries, 2 bytes
};

struct dns_question
{
	// unsigned char *qname; qname has dynamic length
	unsigned short qtype;
	unsigned short qclass;
};

// Define a structure for the DNS answer resource record (RR).
struct dns_answer
{
	// name
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
	// data
};

/// @brief returns address type: TYPE_IP4, TYPE_IP6, TYPE_DOMAIN using regex patterns
/// @param addr
/// @return
int get_address_type(char *addr);

/// @brief fills the dns header with data
/// @param dns
/// @param args
void fill_dns_header(struct dns_header *dns, struct parsed_arguments *args);

/// @brief rewrites the domain name to ipv4 address using gethostbyname. Only when -s argument is domain name
/// @param args
void domain_to_address(struct parsed_arguments *args);

/// @brief sends and receives datagram using sendto and recvfrom, UDP only
/// @param buf
/// @param sock
/// @param dest
/// @param qname
/// @param dest_size
/// @param args
void send_and_receive(unsigned char *buf, int sock, struct sockaddr *dest, unsigned char *qname, int dest_size, struct parsed_arguments *args);

/// @brief Main function for communication with the server
/// @param args
void send_dns_query(struct parsed_arguments *args);
