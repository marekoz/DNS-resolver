#include <iostream> //cout
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bitset>
#include <regex>




#define DNS_PORT 53

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


std::string intToBinaryString(int value) {
    return std::bitset<sizeof(int) * 8>(value).to_string();
}

bool is_qname_compressed(unsigned char* name)
{
	return name[0] == 0b11000000;
}



int get_address_type(struct parsed_arguments *args)
{
	//std::cout << std::endl <<args->server << std::endl;
	std::regex ipv4Pattern(R"((\d{1,3}\.){3}\d{1,3})");
	std::regex ipv6Pattern(R"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}(:[0-9a-fA-F]{1,4}){1,7}|([0-9a-fA-F]{1,4}:){1,7}:|::)");
	std::regex domainPattern(R"(([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})");
	std::string server_str(reinterpret_cast<const char*>(args->hostname));
	std::cout << args->hostname << std::endl;
    std::cout << std::regex_match(server_str, ipv4Pattern) << std::endl;
	std::cout << std::regex_match(server_str, ipv6Pattern) << std::endl;
	std::cout << std::regex_match(server_str, domainPattern) << std::endl;
	return 1;
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
				exit(1);
				break;
			case 'h':
				//TODO print help
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
				exit(1);
			}
			optind++;
		}
	}


	if (non_opt_argc != 1)
	{
		std::cerr << "Missing address argument" << std::endl;
		exit(1);
	}
	//get_address_type(args);

	// optind - index of next argument to be parsed
	// we have only 1 non option argument - address
}

void get_hostname(struct parsed_arguments* args, const char* s_addr)
{
	unsigned char buf[65536];
	unsigned char *buf_pointer;

	struct sockaddr_in dest;
	
	struct dns_header *dns = NULL;
	struct dns_question *question = NULL;

	std::cout << "\n" << args->port << "\n"; 
	int sock = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
	dest.sin_family = AF_INET;
	dest.sin_port = htons(args->port);
	dest.sin_addr.s_addr = inet_addr(s_addr);

	dns = (struct dns_header *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = args->recursion;//Recursion Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;


	unsigned char *qname;
	qname =(unsigned char*)&buf[sizeof(struct dns_header)];

	std::cout <<  "-----------------" << "\n";
	
	convert_hostname_to_dns(args->hostname, qname);

	std::cout << "qname length: "<< (strlen((char*)qname)) << "\n";
	std::cout << "qname:  " 	<< (char*)qname << "\n";
	std::cout <<  "-----------------" << "\n";
	
	question =(struct dns_question*)&buf[sizeof(dns_header)+ strlen((const char *)qname) + 1]; // +1 because of 0 at the end of string

	question->qtype = (args->ip6) ? htons(28) : htons(1);//type of the query , A , MX , CNAME , NS etc
	question->qclass = htons(1); // type IN



	buf_pointer = &buf[sizeof(struct dns_header)];
	std::cout << buf_pointer << "\n";
	for (size_t i = 0; i < strlen((const char *)qname) +1; i++) {
        std::bitset<8> binaryByte(buf_pointer[i]);
        std::cout << binaryByte << " "; // Print each byte in binary
    }


	printf("\nSending Packet...");
	if( sendto(sock,(char*)buf,sizeof(struct dns_header) + (strlen((const char*)qname)+1) + 4,0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
	{
		perror("sendto failed");
	}
	printf("Done");



	//Receive the answer
	int i = sizeof dest;
	printf("\nReceiving answer...");
	if(recvfrom (sock,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
	{
		perror("recvfrom failed");
	}
	printf("Done\n");

	dns = (struct dns_header*) buf;

	printf("\nThe response contains : ");
	printf("\n %d Questions.",ntohs(dns->q_count));
	printf("\n %d Answers.",ntohs(dns->ans_count));
	printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
	printf("\n %d response code.\n\n",ntohs(dns->rcode));
	
	int answer_count = ntohs(dns->ans_count); // Number of answers in the response
	std::cout << "answer count: " << answer_count << "\n";



	buf_pointer = &buf[sizeof(struct dns_header) + sizeof(struct dns_question)  + (strlen((const char*)qname)+1)];
	// std::cout << "qname" << "\n";
	// 	for (size_t i = 0; i < 12; i++) {
    //     std::bitset<8> binaryByte(buf_pointer[i]);
    //     std::cout << binaryByte << " "; // Print each byte in binary
    // }

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

	std::cout <<  sizeof(struct dns_answer) << "\n";
	std::cout << "answer info" << "\n";
	std::cout << "type: " << ntohs(answer->type) << std::endl;
	std::cout << "class: " << ntohs(answer->_class) << std::endl;
	std::cout << "ttl: " << ntohl(answer->ttl) << std::endl;
	std::cout << "data_len: " << ntohs(answer->data_len) << std::endl;

	// for (size_t i = 0; i < 12; i++) {
    //     std::bitset<8> binaryByte(buf_pointer[i]);
    //     std::cout << binaryByte << " "; // Print each byte in binary
    // }

	//move ahead of the dns header and the query field
	buf_pointer = &buf[sizeof(struct dns_header) + (strlen((const char*)qname)+1) + sizeof(struct dns_question) +  sizeof(struct dns_answer)];


	// for (size_t i = 0; i < 32; i++) {
    // 	std::bitset<8> binaryByte(buf_pointer[i]);
    // 	std::cout << binaryByte << " "; // Print each byte in binary
    // }
	std::cout << "address:   " << "\n";
	if (args->ip6)
	{
		int i = 0;
		for(i; i < 8; i += 2)
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
		std::cout << (int)buf_pointer[0] << "." << (int)buf_pointer[1] << "."<< (int)buf_pointer[2] << "." <<  (int)buf_pointer[3] << "\n";
	}
	
// 	for (size_t i = 0; i < 4; i++) {
//         std::bitset<8> binaryByte(buf_pointe[i]);
//         std::cout << binaryByte << " "; // Print each byte in binary
//     }
}


void get_hostname_reverse(struct parsed_arguments* args, const char* s_addr)
{
	unsigned char buf[65536];
	unsigned char *buf_pointer;

	struct sockaddr_in dest;
	
	struct dns_header *dns = NULL;
	struct dns_question *question = NULL;

	std::cout << "\n" << args->port << "\n"; 
	int sock = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
	dest.sin_family = AF_INET;
	dest.sin_port = htons(args->port);
	dest.sin_addr.s_addr = inet_addr(s_addr);

	dns = (struct dns_header *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //This is a query
	dns->opcode = 1; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = args->recursion;//Recursion Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;


	unsigned char *qname;
	qname =(unsigned char*)&buf[sizeof(struct dns_header)];

	std::cout <<  "-----------------" << "\n";
	
	convert_hostname_to_dns(args->hostname, qname);

	std::cout << "qname length: "<< (strlen((char*)qname)) << "\n";
	std::cout << "qname:  " 	<< (char*)qname << "\n";
	std::cout <<  "-----------------" << "\n";
	
	question =(struct dns_question*)&buf[sizeof(dns_header)+ strlen((const char *)qname) + 1]; // +1 because of 0 at the end of string

	question->qtype =  htons(12);//type of the query , A , MX , CNAME , NS etc
	question->qclass = htons(1); // type IN



	buf_pointer = &buf[sizeof(struct dns_header)];
	std::cout << buf_pointer << "\n";
	for (size_t i = 0; i < strlen((const char *)qname) +1; i++) {
        std::bitset<8> binaryByte(buf_pointer[i]);
        std::cout << binaryByte << " "; // Print each byte in binary
    }


	printf("\nSending Packet...");
	if( sendto(sock,(char*)buf,sizeof(struct dns_header) + (strlen((const char*)qname)+1) + 4,0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
	{
		perror("sendto failed");
	}
	printf("Done");



	//Receive the answer
	int i = sizeof dest;
	printf("\nReceiving answer...");
	if(recvfrom (sock,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
	{
		perror("recvfrom failed");
	}
	printf("Done\n");

	dns = (struct dns_header*) buf;

	printf("\nThe response contains : ");
	printf("\n %d Questions.",ntohs(dns->q_count));
	printf("\n %d Answers.",ntohs(dns->ans_count));
	printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
	printf("\n %d response code.\n\n",ntohs(dns->rcode));
	
	int answer_count = ntohs(dns->ans_count); // Number of answers in the response
	std::cout << "answer count: " << answer_count << "\n";



	buf_pointer = &buf[sizeof(struct dns_header) + sizeof(struct dns_question)  + (strlen((const char*)qname)+1)];
	// std::cout << "qname" << "\n";
	// 	for (size_t i = 0; i < 12; i++) {
    //     std::bitset<8> binaryByte(buf_pointer[i]);
    //     std::cout << binaryByte << " "; // Print each byte in binary
    // }

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

	std::cout <<  sizeof(struct dns_answer) << "\n";
	std::cout << "answer info" << "\n";
	std::cout << "type: " << ntohs(answer->type) << std::endl;
	std::cout << "class: " << ntohs(answer->_class) << std::endl;
	std::cout << "ttl: " << ntohl(answer->ttl) << std::endl;
	std::cout << "data_len: " << ntohs(answer->data_len) << std::endl;

	// for (size_t i = 0; i < 12; i++) {
    //     std::bitset<8> binaryByte(buf_pointer[i]);
    //     std::cout << binaryByte << " "; // Print each byte in binary
    // }

	//move ahead of the dns header and the query field
	buf_pointer = &buf[sizeof(struct dns_header) + (strlen((const char*)qname)+1) + sizeof(struct dns_question) +  sizeof(struct dns_answer)];


	// for (size_t i = 0; i < 32; i++) {
    // 	std::bitset<8> binaryByte(buf_pointer[i]);
    // 	std::cout << binaryByte << " "; // Print each byte in binary
    // }
	std::cout << "address:   " << "\n";
	if (args->ip6)
	{
		int i = 0;
		for(i; i < 8; i += 2)
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
		std::cout << (int)buf_pointer[0] << "." << (int)buf_pointer[1] << "."<< (int)buf_pointer[2] << "." <<  (int)buf_pointer[3] << "\n";
	}
	
// 	for (size_t i = 0; i < 4; i++) {
//         std::bitset<8> binaryByte(buf_pointe[i]);
//         std::cout << binaryByte << " "; // Print each byte in binary
//     }
}

int main(int argc, char* argv[]) {

	struct parsed_arguments *args = (struct parsed_arguments*)malloc(sizeof(struct parsed_arguments) + 256);
	args->port = DNS_PORT;

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


    const char* dns_server = "76.76.2.0";//;
	//get_address_type(args);
	if (args->reverse)
	{
		std::cout << "reverse" << std::endl;
		get_hostname_reverse(args, dns_server);
	}
	else
	{
		std::cout << "normal" << std::endl;
		get_hostname(args, dns_server);
	}
	

    return 0;
}
