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


std::string intToBinaryString(int value)
{
	return std::bitset<sizeof(int) * 8>(value).to_string();
}


bool is_name_compressed(unsigned char *name)
{
	return (name[0] == 0b11000000);
}	 

int get_compressed_offset(unsigned char *name)
{
	return ((name[0] & 0x3F) << 8) + name[1]; 
}

int get_address_type(char *addr)
{
	// std::cout << std::endl <<args->server << std::endl;
	std::regex ipv4Pattern(R"((\d{1,3}\.){3}\d{1,3})");
	std::regex ipv6Pattern(R"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}(:[0-9a-fA-F]{1,4}){1,7}|([0-9a-fA-F]{1,4}:){1,7}:|::)");
	std::regex domainPattern(R"(([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})");
	std::string server_str(reinterpret_cast<const char *>(addr));

	if (std::regex_match(server_str, ipv4Pattern))
	{
		// std::cout << "ip4" << std::endl;
		return TYPE_IP4;
	}
	else if (std::regex_match(server_str, ipv6Pattern))
	{
		// std::cout << "ip6" << std::endl;
		return TYPE_IP6;
	}
	else if (std::regex_match(server_str, domainPattern))
	{
		// std::cout << "domain" << std::endl;
		return TYPE_DOMAIN;
	}
	return -1;
}

void parse_arguments(int argc, char *argv[], struct parsed_arguments *args)
{
	int opt;
	int non_opt_argc = 0;
	while (optind < argc)
	{
		if ((opt = getopt(argc, argv, "rx6s:p:h")) != -1)
		{
			switch (opt)
			{
			case 'r':
				args->recursion = 1;
				break;
			case 'x':
				args->reverse = 1;
				break;
			case '6':
				args->ip6 = 1;
				break;
			case 's':
				strncpy(args->server, optarg, sizeof(args->server));
				// args->server = (unsigned char*)optarg;
				break;
			case 'p':
				args->port = std::stoi(optarg);
				break;
			case '?':
				free(args);
				exit(1);
				break;
			case 'h':
				// TODO print help
				std::cout << "Usage: dns [-r] [-x] [-6] -s server [-p port] address" << std::endl;
				free(args);
				exit(0);
				break;
			default:
				break;
			}
		}
		else
		{
			// optind - index of next argument to be parsed
			// we have only 1 non option argument - address
			non_opt_argc += 1;
			strncpy(args->hostname, argv[optind], sizeof(args->hostname) - 1);
			// args->hostname = argv[optind];
			if (non_opt_argc > 1)
			{
				std::cerr << "Too many arguments" << std::endl;
				free(args);
				exit(1);
			}
			optind++;
		}
	}

	if (non_opt_argc != 1)
	{
		std::cerr << "Missing address argument" << std::endl;
		free(args);
		exit(1);
	}
	// optind - index of next argument to be parsed
	// we have only 1 non option argument - address
}

void fill_dns_header(struct dns_header *dns, struct parsed_arguments *args)
{
	dns->id = (unsigned short)htons(getpid());
	dns->qr = 0;			   // query
	dns->opcode = 0;		   // normal query
	dns->aa = 0;			   // not authoritive
	dns->tc = 0;			   // not truncated
	dns->rd = args->recursion; // Recursion Desired
	dns->ra = 0;
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); // 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;
}

void convert_hostname_to_dns(char *hostname, unsigned char *result)
{
	int last_dot_pos = 0;
	int char_cnt = 0;
	int i = 0;
	for (i = 0; hostname[i] != '\0'; i++)
	{
		if (hostname[i] == '.')
		{
			result[last_dot_pos] = char_cnt;
			char_cnt = 0;
			last_dot_pos = i + 1;
		}
		else
		{
			char_cnt += 1;
			result[i + 1] = hostname[i];
		}
	}
	result[last_dot_pos] = char_cnt;
	result[i + 1] = '\0';
}

void convert_ip4_to_dns(char *ip4, unsigned char *result)
{
	char *all_parts = (char *)malloc(16);
	char *part = std::strtok(ip4, ".");
	int i = 0;
	while (part)
	{
		// std::cout << part << std::endl;
		strcpy(&all_parts[i], part);
		part = std::strtok(NULL, ".");
		i += 4;
	}

	int index = 0;
	for (i = 0; i < 4; i++)
	{
		result[index] = strlen(&all_parts[(3 - i) * 4]);
		index++;
		strcpy((char *)&result[index], &all_parts[(3 - i) * 4]);
		index += strlen(&all_parts[(3 - i) * 4]);
	}

	result[index] = 7;
	index++;
	strcpy((char *)&result[index], "in-addr");
	index += strlen("in-addr");
	result[index] = char(4);
	index++;
	strcpy((char *)&result[index], "arpa");
	free(all_parts);
}

void convert_ip6_to_dns(char *ip6, unsigned char *result)
{
	return;
}

void send_and_receive(unsigned char *buf, int sock, struct sockaddr* dest, unsigned char *qname, int dest_size)
{
	// TIMEOUT SET WOW
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
	if (sendto(sock, (char *)buf, sizeof(struct dns_header) + (strlen((const char *)qname) + 1) + 4, 0, dest, dest_size) < 0)
	{
		perror("Error sending datagram");
	}
	if (recvfrom(sock, (char *)buf, 65536, 0, dest, (socklen_t *)&dest_size) < 0)
	{
		perror("Error receiving datagram");
	}
}

void print_domain(unsigned char* buf_pointer)
{
	// reverse
	int i = 1;
	int letters = buf_pointer[0];
	while (buf_pointer[i] != '\0')
	{
		if (letters == 0)
		{
			std::cout << '.';
			letters = buf_pointer[i];
		}
		else
		{
			std::cout << buf_pointer[i];
			letters--;
		}
		i++;			
	}
	std::cout << '.';
}

void print_ip6(unsigned char* buf_pointer)
{
	// ipv6 TODO
    for (int i = 0; i < 16; i += 2) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buf_pointer[i]);
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buf_pointer[i + 1]);

        if (i < 14) {
            std::cout << ":";
        }
    }
}

void print_ip4(unsigned char* buf_pointer)
{
	std::cout << std::dec << (int)buf_pointer[0] << ".";
	std::cout << std::dec << (int)buf_pointer[1] << "."; 
	std::cout << std::dec << (int)buf_pointer[2] << ".";
	std::cout << std::dec << (int)buf_pointer[3];
}


void print_question_section(unsigned char buf[65536], int* offset, struct parsed_arguments* args)
{
	std::cout << std::endl << "  ";
	unsigned char *name_pointer = &buf[sizeof(struct dns_header)]; //Only 1 question is allowed
	*offset = (strlen((const char *)name_pointer)) + 1; // \0 -> +1 

	struct dns_question* question = (struct dns_question*)&buf[sizeof(struct dns_header) + *offset];

	switch (ntohs(question->qtype))
	{
		case 1:
			print_domain(name_pointer);
			std::cout << ", A";
			break;
		case 28:
			print_domain(name_pointer);
			std::cout << ", AAAA";
			break;
		case 12:
			print_domain(name_pointer);
			std::cout << ", PTR";
			break;
		default:
			break;
	}

	//std:: cout << (ntohs(question->qtype) ? "A" : "AAAA");
	std::cout << ", ";
	std::cout << (ntohs(question->qclass) ? "IN" : "");
}


void print_answer_section(unsigned char buf[65536], int*offset, struct parsed_arguments* args, int i)
{
	std::cout << std::endl << "  ";
	unsigned char *buf_pointer = &buf[sizeof(struct dns_header) + sizeof(struct dns_answer)*i + sizeof(struct dns_question) + *offset];

	struct dns_answer *answer = NULL;
	
	if (is_name_compressed(buf_pointer))
	{
		answer = (struct dns_answer *)(buf_pointer + 2);
		//*offset += 2;
		buf_pointer = &buf[get_compressed_offset(buf_pointer)];
	}
	else
	{
		int name_len = strlen((const char*)buf_pointer) + 1;
		answer = (struct dns_answer *)buf_pointer + name_len;
		*offset += name_len;
	}

	switch (ntohs(answer->type))
	{
		case 1:
			print_domain(buf_pointer);
			std::cout << ", A";
			break;
		case 28:
			print_domain(buf_pointer);
			std::cout << ", AAAA";
			break;
		case 5:
			print_domain(buf_pointer);
			std::cout << ", CNAME";
			break;
		case 2:
			print_domain(buf_pointer);
			std::cout << ", NS";
			break;
		case 12:
			print_domain(buf_pointer);
			std::cout << ", PTR";
			break;
		default:
			break;
	}
	
	std::cout << ", ";
	switch (ntohs(answer->_class))
	{
		case 1:
			std::cout << "IN";
			break;
		default:
			std::cerr << "Class not supported";
			free(args);
			exit(1);
			break;
	}
	
	
	std::cout << ", " << std::dec << ntohl(answer->ttl) << ", " << ntohs(answer->data_len);
	
	// move ahead of the dns header and the query field
	buf_pointer = &buf[sizeof(struct dns_header) + *offset
	+ sizeof(struct dns_question) + sizeof(struct dns_answer)*(i+1)];
	*offset += ntohs(answer->data_len);
	switch (ntohs(answer->type))
	{
		case 1:
			std::cout << ", ";
			print_ip4(buf_pointer);
			break;
		case 28:
			std::cout << ", ";
			print_ip6(buf_pointer);
			break;
		case 5:
			std::cout << ", ";

			if(is_name_compressed(buf_pointer))
			{	
				buf_pointer = &buf[get_compressed_offset(buf_pointer)];
			}
			print_domain(buf_pointer);
			break;
		case 12:
			std::cout << ", ";
			if(is_name_compressed(buf_pointer))
			{
				buf_pointer = &buf[get_compressed_offset(buf_pointer)];
			}
			print_domain(buf_pointer);
			break;
		default:
			break;
	}
}


void send_dns_query(struct parsed_arguments *args)
{
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // UDP packet for DNS queries

	struct dns_header *dns = NULL;
	struct dns_question *question = NULL;
	unsigned char buf[65536];
	dns = (struct dns_header *)&buf;

	fill_dns_header(dns, args);

	unsigned char *qname;
	qname = (unsigned char *)&buf[sizeof(struct dns_header)];
	if (args->reverse == 0)
	{
		// if hostname == hostname
		// otherwise done
		if (get_address_type(args->hostname) == TYPE_DOMAIN)
		{
			convert_hostname_to_dns(args->hostname, qname);
		}
		else
		{
			std::cerr << "Address is not domain type\n";
			exit(1);
		}
	}
	else
	{
		int addr_type = get_address_type(args->hostname);
		if (addr_type == TYPE_IP4)
		{
			convert_ip4_to_dns(args->hostname, qname);
		}
		else if(addr_type == TYPE_IP6)
		{
			//convert_ip6_to_dns()
		}
		else
		{
			std::cerr << "Address is not IP type\n";
			exit(1);
		}
		//-6 cant because its  AAAA and -x is PTR hmmmmm
	}

	question = (struct dns_question *)&buf[sizeof(dns_header) + strlen((const char *)qname) + 1]; // +1 because of 0 at the end of string

	if (args->reverse == 0)
	{
		question->qtype = (args->ip6) ? htons(28) : htons(1); // type of the query, 1-A, 28-AAAA, 12 - PTR
	}
	else
	{
		question->qtype = htons(12); // PTR
	}

	question->qclass = htons(1); // type IN


	if (args->address_type == 0)
	{
		struct sockaddr_in dest;
		dest.sin_family = AF_INET;
		dest.sin_port = htons(args->port);
		dest.sin_addr.s_addr = inet_addr(args->server);
		send_and_receive(buf, sock, (struct sockaddr*)&dest, qname, sizeof(dest));
	}
	else
	{
		struct sockaddr_in6 dest;
		std::memset(&dest, 0, sizeof(dest));
		dest.sin6_port = htons(args->port);
		dest.sin6_family = AF_INET6;
		std::cout << args->server << std::endl;
		inet_pton(AF_INET6, args->server, &dest.sin6_addr);
		send_and_receive(buf, sock, (struct sockaddr*)&dest, qname, sizeof(dest));
	}

	// Check error codes
	dns = (struct dns_header *)buf;
	switch (ntohl(dns->rcode))
	{
	case 1:
		std::cerr << "Error: Format error" << std::endl;
		free(args);
		exit(1);
		break;
	case 2:
		std::cerr << "Error: Server failure" << std::endl;
		free(args);
		exit(1);
		break;
	case 3:
		std::cerr << "Error: Name error" << std::endl;
		free(args);
		exit(1);
		break;
	case 5:
		free(args);
		exit(1);
		std::cerr << "Error: Refused" << std::endl;
	default:
		break;
	}

	std::cout << "Authoritative: " << ((dns->aa) ? "Yes" : "No") << ", Recursive: " << ((dns->rd) ? "Yes" : "No") << ", Truncated: " << ((dns->tc) ? "Yes" : "No")<< std::endl; 


	int add_cnt = ntohs(dns->add_count);
	int q_cnt = ntohs(dns->q_count);
	int ans_cnt = ntohs(dns->ans_count);
	int aut_cnt = ntohs(dns->auth_count);
	int i = 0;
	int offset = 0;
	std::cout << "Question section (" << q_cnt << ")"; 
	print_question_section(buf, &offset, args);
	std::cout << std::endl << "Answer section (" << ans_cnt << ")"; 
	while(i < ans_cnt)
	{
		print_answer_section(buf, &offset, args, i);
		i++;
	}
	std::cout << std::endl << "Authority section (" << aut_cnt << ")"; 
	while(i < ans_cnt + aut_cnt)
	{
		print_answer_section(buf, &offset, args, i);
		i++;
	}
	std::cout << std::endl << "Additional section (" << add_cnt << ")"; 
	while(i < ans_cnt + aut_cnt + add_cnt)
	{
		print_answer_section(buf, &offset, args, i);
		i++;
	}
}


void handle_domain(struct parsed_arguments *args)
{

	struct hostent *host_info;
	struct in_addr **addr_list;
	host_info = gethostbyname(args->server);
	if (host_info == nullptr)
	{
		std::cerr << "Failed to get server address" << std::endl;
		exit(1);
	}

	addr_list = reinterpret_cast<struct in_addr **>(host_info->h_addr_list);

	strcpy(args->server, inet_ntoa(*addr_list[0]));
}

int main(int argc, char *argv[])
{

	struct parsed_arguments *args = (struct parsed_arguments *)malloc(sizeof(struct parsed_arguments));
	args->port = DNS_PORT;
	parse_arguments(argc, argv, args);

	if (false)
	{
		std::cout << "recursion: " << args->recursion << "\n";
		std::cout << "reverse: " << args->reverse << "\n";
		std::cout << "ipv6: " << args->ip6 << "\n";
		std::cout << args->server << "\n";
		std::cout << "port: " << args->port << "\n";
		std::cout << args->hostname << "\n";
	}

	

	if (args->server[0] == '\0')
	{
		std::cerr << "-s argument is missing" << std::endl;
		return 1;
	}

	int server_type = get_address_type(args->server);
	switch (server_type)
	{
	case TYPE_DOMAIN:
		handle_domain(args);
		send_dns_query(args);
		args->address_type = 0;
		break;
	case TYPE_IP4:
		send_dns_query(args);
		args->address_type = 0;
		break;
	case TYPE_IP6:
		args->address_type = 1;
		send_dns_query(args);
		break;
	}

	free(args);
	return 0;
}

// reverse answer ip6 OR ip4
// print ipv6 address in format from ipk AAAA query

// print nameserver