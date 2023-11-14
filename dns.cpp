#include <iostream> //cout
#include <cstring>
#include <netdb.h> //gethostbyname()
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bitset>
#include <regex>




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
	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // 0 - standard query / 1 - inverse q / 2 - server status request ...
	unsigned char qr :1; // 0 - query / 1 - response

	// Response flags in single byte
	unsigned char rcode :4; // response code 
	/*
		0 - no error
		1 - format error
		2 - server failure
		3 - name error - domain name referenced does not exist
		5 - refused
	*/
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available


	unsigned short q_count; // number of question entries, 2 bytes
	unsigned short ans_count; // number of answer entries, 2 bytes
	unsigned short auth_count; // number of authority entries, 2 bytes
	unsigned short add_count; // number of resource entries, 2 bytes
};

struct dns_question
{
	//unsigned char *qname; qname has dynamic length 
	unsigned short qtype;
	unsigned short qclass;
};

// Define a structure for the DNS answer resource record (RR).
struct dns_answer {
	//name
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
    // data
};


void convert_hostname_to_dns(char* hostname, unsigned char* result)
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
			last_dot_pos = i+1;
		}
		else
		{
			char_cnt += 1;
			result[i+1] = hostname[i];
		}
	}
	result[last_dot_pos] = char_cnt;
	result[i+1] = '\0';
}

void convert_ip4_to_dns(char* ip4, unsigned char* result)
{
	char *all_parts = (char*)malloc(16);
	char *part = std::strtok(ip4, ".");
	int i = 0;
	while(part)
	{
		//std::cout << part << std::endl;
		strcpy(&all_parts[i], part);
		part = std::strtok(NULL, ".");
		i += 4;
	}


	
	int index = 0;
	for(i = 0; i < 4; i++)
	{
		result[index] = strlen(&all_parts[(3-i)*4]);
		index++;
		strcpy((char *)&result[index], &all_parts[(3-i)*4]);
		index += strlen(&all_parts[(3-i)*4]);
	}

	result[index] = 7;
	index++;
	strcpy((char *)&result[index], "in-addr");
	index += strlen("in-addr");
	result[index] = char(4);
	index++;
	strcpy((char *)&result[index], "arpa");
	free(all_parts);
	std::cout << result << std::endl;
}

std::string intToBinaryString(int value) {
    return std::bitset<sizeof(int) * 8>(value).to_string();
}

bool is_qname_compressed(unsigned char* name)
{
	return name[0] == 0b11000000;
}



int get_address_type(char *addr)
{
	//std::cout << std::endl <<args->server << std::endl;
	std::regex ipv4Pattern(R"((\d{1,3}\.){3}\d{1,3})");
	std::regex ipv6Pattern(R"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}(:[0-9a-fA-F]{1,4}){1,7}|([0-9a-fA-F]{1,4}:){1,7}:|::)");


	std::regex domainPattern(R"(([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})");
	std::string server_str(reinterpret_cast<const char*>(addr));
	std::cout << addr << std::endl;

	if (std::regex_match(server_str, ipv4Pattern))
	{
		std::cout << "ip4" << std::endl;
		return TYPE_IP4;
	}
	else if (std::regex_match(server_str, ipv6Pattern))
	{
		std::cout << "ip6" << std::endl;
		return TYPE_IP6;
	}
	else if (std::regex_match(server_str, domainPattern))
	{
		std::cout << "domain" << std::endl;
		return TYPE_DOMAIN;
	}
	return -1;
}

void parse_arguments(int argc, char* argv[], struct parsed_arguments *args)
{
	int opt;
	int non_opt_argc = 0;
	while (optind < argc)
	{
		if ((opt = getopt(argc, argv, "rx6s:p:h")) != -1)
		{
			switch(opt)
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
				//args->server = (unsigned char*)optarg;
				break;
			case 'p':
				args->port = std::stoi(optarg);
				break;
			case '?':
				free(args);
				exit(1);
				break;
			case 'h':
				//TODO print help
				free(args);
				exit(0);
				break;
			default:
				break;
		}
		}else
		{
			// optind - index of next argument to be parsed
			// we have only 1 non option argument - address
			non_opt_argc += 1;
			strncpy(args->hostname, argv[optind], sizeof(args->hostname) - 1);
			//args->hostname = argv[optind];
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
	//get_address_type(args);

	// optind - index of next argument to be parsed
	// we have only 1 non option argument - address
}


void fill_dns_header(struct dns_header *dns, struct parsed_arguments *args)
{
	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; // query
	dns->opcode = 0; // normal query
	dns->aa = 0; // not authoritive
	dns->tc = 0; // not truncated
	dns->rd = args->recursion; //Recursion Desired
	dns->ra = 0; 
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;
}

void send_dns_query(struct parsed_arguments* args)
{
	//get s_addr -s type - ip4, ip6, hostname

	//if ip4
	struct sockaddr_in dest;
	std::cout << "\n" << args->port << "\n"; 
	int sock = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
	dest.sin_family = AF_INET;

	dest.sin_port = htons(args->port);
	dest.sin_addr.s_addr = inet_addr(args->server);


	struct dns_header *dns = NULL;
	struct dns_question *question = NULL;
	unsigned char buf[65536];
	unsigned char *buf_pointer;
	dns = (struct dns_header *)&buf;

	fill_dns_header(dns, args);
	
	unsigned char *qname;
	qname =(unsigned char*)&buf[sizeof(struct dns_header)];

	if (args->reverse == 0)
	{
		//if hostname == hostname
		convert_hostname_to_dns(args->hostname, qname);
	}
	else
	{
		//if hostname == ip4
		convert_ip4_to_dns(args->hostname, qname);
		//else convert_ip6_to_dns
	}

	question =(struct dns_question*)&buf[sizeof(dns_header)+ strlen((const char *)qname) + 1]; // +1 because of 0 at the end of string

	if (args->reverse == 0)
	{
		question->qtype = (args->ip6) ? htons(28) : htons(1);// type of the query, 1-A, 28-AAAA, 12 - PTR
	}
	else
	{
		question->qtype = htons(12); // PTR
	}

	question->qclass = htons(1); // type IN

	printf("\nSending Packet...");
	if( sendto(sock,(char*)buf,sizeof(struct dns_header) + (strlen((const char*)qname)+1) + 4,0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
	{
		perror("sendto failed");
	}
	printf("Done");

	int i = sizeof(dest);
	printf("\nReceiving answer...");
	if(recvfrom (sock,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
	{
		perror("recvfrom failed");
	}
	printf("Done\n");

	dns = (struct dns_header*) buf;
	//int answer_count = ntohs(dns->ans_count); // Number of answers in the response
	//std::cout << "answer count: " << answer_count << "\n";
	buf_pointer = &buf[sizeof(struct dns_header) + sizeof(struct dns_question)  + (strlen((const char*)qname)+1)];

	struct dns_answer *answer = NULL;
	if (is_qname_compressed(buf_pointer))
	{
		unsigned int name_pointer;
		name_pointer = buf[sizeof(struct dns_header) + sizeof(struct dns_question)  + (strlen((const char*)qname)+1) + 1];
		buf_pointer = &buf[name_pointer];
		answer = (struct dns_answer*)&buf[sizeof(struct dns_header) + (strlen((const char*)qname)+1) + sizeof(struct dns_question) + 2];
	}
	else
	{
		answer = (struct dns_answer*)&buf[sizeof(struct dns_header) + (strlen((const char*)qname)+1)*2 + sizeof(struct dns_question)];
		std::cout << "name is not compressed" << "\n";
	}

	if (false)
	{
		std::cout <<  sizeof(struct dns_answer) << "\n";
		std::cout << "answer info" << "\n";
		std::cout << "type: " << ntohs(answer->type) << std::endl;
		std::cout << "class: " << ntohs(answer->_class) << std::endl;
		std::cout << "ttl: " << ntohl(answer->ttl) << std::endl;
		std::cout << "data_len: " << ntohs(answer->data_len) << std::endl;
	}

	//move ahead of the dns header and the query field
	buf_pointer = &buf[sizeof(struct dns_header) + (strlen((const char*)qname)+1) + sizeof(struct dns_question) +  sizeof(struct dns_answer)];


	if (args->reverse == 0)
	{
		if (args->ip6)
		{
			//ipv6
			for(int i = 0; i < 8; i += 2)
			{
				std::cout << std::hex << ((int)buf_pointer[i]);
				std::cout << std::hex << ((int)buf_pointer[i+1]);
				std::cout << ":";
			}
			std::cout << std::hex << ((int)buf_pointer[i]);
			std::cout << std::hex << ((int)buf_pointer[i+1]);
			std::cout << std::endl;
		}
		else
		{
			//ipv4
			std::cout << (int)buf_pointer[0] << "." << (int)buf_pointer[1] << "."<< (int)buf_pointer[2] << "." <<  (int)buf_pointer[3] << "\n";
		}
	}
	else
	{
		//reverse

	}
}


int main(int argc, char* argv[]) {

	struct parsed_arguments *args = (struct parsed_arguments*)malloc(sizeof(struct parsed_arguments));
	args->port = DNS_PORT;
	strcpy(args->server, "8.8.8.8");
	parse_arguments(argc, argv, args);
	if (1 == 12)
	{
		std::cout << "recursion: " << args->recursion << "\n";
		std::cout << "reverse: " << args->reverse << "\n";
		std::cout << "ipv6: " <<args->ip6 << "\n";
		//std::cout << args->server << "\n";
		std::cout << "port: " << args->port << "\n";
		//std::cout << args->hostname << "\n";
	}
	int server_type = get_address_type(args->server);
	switch(server_type)
	{
		case TYPE_DOMAIN:
			struct hostent *host_info;
			host_info = gethostbyname(args->server);
			strcpy(args->server, host_info->h_name);
			send_dns_query(args);
			break;
		case TYPE_IP4:
			send_dns_query(args);
			break;
		case TYPE_IP6:
			break;
	}

	free(args);
    return 0;
}
