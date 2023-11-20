// author: Marek Kozumplik, xkozum08
#include "dns.hpp"
#include "arg_parser.cpp"
#include "encoder.cpp"
#include "printer.cpp"

/// @brief returns address type: TYPE_IP4, TYPE_IP6, TYPE_DOMAIN using regex patterns
/// @param addr
/// @return
int get_address_type(char *addr)
{
	std::regex ipv4Pattern(R"((\d{1,3}\.){3}\d{1,3})");
	std::regex ipv6Pattern(R"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}(:[0-9a-fA-F]{1,4}){1,7}|([0-9a-fA-F]{1,4}:){1,7}:|::)");
	std::regex domainPattern(R"(([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})");
	std::string server_str(reinterpret_cast<const char *>(addr));

	if (std::regex_match(server_str, ipv4Pattern))
	{
		return TYPE_IP4;
	}
	else if (std::regex_match(server_str, ipv6Pattern))
	{
		return TYPE_IP6;
	}
	else if (std::regex_match(server_str, domainPattern))
	{
		return TYPE_DOMAIN;
	}
	return -1;
}

// fills the dns header with data
void fill_dns_header(struct dns_header *dns, struct parsed_arguments *args)
{
	dns->id = (unsigned short)htons(getpid());
	dns->qr = 0;			   // query
	dns->opcode = 0;		   // normal query
	dns->aa = 0;			   // not authoritive
	dns->tc = 0;			   // not truncated
	dns->rd = args->recursion; // Recursion Desired
	dns->ra = 0;			   // Recursion Available
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;			 // No error
	dns->q_count = htons(1); // 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;
}

/// @brief rewrites the domain name to ipv4 address using gethostbyname. Only when -s argument is domain name
/// @param args
void domain_to_address(struct parsed_arguments *args)
{
	struct hostent *host_info;
	struct in_addr **addr_list;
	host_info = gethostbyname(args->server);
	if (host_info == nullptr)
	{
		std::cerr << "Error: Failed to get server address" << std::endl;
		free(args);
		exit(1);
	}

	addr_list = reinterpret_cast<struct in_addr **>(host_info->h_addr_list);
	strcpy(args->server, inet_ntoa(*addr_list[0]));
}

/// @brief sends and receives datagram using sendto and recvfrom, UDP only
/// @param buf
/// @param sock
/// @param dest
/// @param qname
/// @param dest_size
void send_and_receive(unsigned char *buf, int sock, struct sockaddr *dest, unsigned char *qname, int dest_size, struct parsed_arguments *args)
{
	// set timeout at 5 seconds
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
		free(args);
		exit(1);
	}
}

/// @brief Main function for communication with the server
/// @param args parsed arguments
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
		if (get_address_type(args->hostname) == TYPE_DOMAIN)
		{
			convert_domain_to_dns(args->hostname, qname);
		}
		else
		{
			std::cerr << "Address is not domain type\n";
			free(args);
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
		else if (addr_type == TYPE_IP6)
		{
			convert_ip6_to_dns(args->hostname, qname);
		}
		else
		{
			std::cerr << "Address is not IP type\n";
			free(args);
			exit(1);
		}
	}

	question = (struct dns_question *)&buf[sizeof(dns_header) + strlen((const char *)qname) + 1]; // +1 because of 0 at the end of string

	if (args->reverse == 0)
	{
		question->q_type = (args->ip6) ? htons(28) : htons(1); // type of the query, 1-A, 28-AAAA, 12 - PTR
	}
	else
	{
		question->q_type = htons(12); // PTR
	}

	question->q_class = htons(1); // type IN

	if (args->address_type == 0)
	{
		// Send to IPv4
		struct sockaddr_in dest;
		dest.sin_family = AF_INET;
		dest.sin_port = htons(args->port);
		dest.sin_addr.s_addr = inet_addr(args->server);
		send_and_receive(buf, sock, (struct sockaddr *)&dest, qname, sizeof(dest), args);
	}
	else
	{
		// Send to IPv6
		struct sockaddr_in6 dest;
		std::memset(&dest, 0, sizeof(dest));
		dest.sin6_port = htons(args->port);
		dest.sin6_family = AF_INET6;
		std::cout << args->server << std::endl;
		inet_pton(AF_INET6, args->server, &dest.sin6_addr);
		send_and_receive(buf, sock, (struct sockaddr *)&dest, qname, sizeof(dest), args);
	}

	// Check error codes
	uint32_t rcode = (dns->rcode);
	if (rcode != 0)
	{
		print_rcode(rcode);
		free(args);
		exit(1);
	}

	// print every section of answer and information
	print_all_sections(buf, args);
}

/// @brief Main function of application
/// @param argc
/// @param argv
/// @return
int main(int argc, char *argv[])
{
	struct parsed_arguments *args = (struct parsed_arguments *)malloc(sizeof(struct parsed_arguments));
	args->port = DNS_PORT;
	args->recursion = 0;
	args->address_type = 0;
	args->reverse = 0;
	args->ip6 = 0;

	parse_arguments(argc, argv, args);

	if (args->server[0] == '\0')
	{
		std::cerr << "-s argument is missing" << std::endl;
		free(args);
		return 1;
	}

	int server_type = get_address_type(args->server);
	switch (server_type)
	{
	case TYPE_DOMAIN:
		// if -s is domain name, we need the find the ip4 address
		domain_to_address(args); // this converts domain to ip4
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
	default:
		std::cerr << "Error: Invalid server address\n";
		free(args);
		return 1;
		break;
	}

	free(args);
	return 0;
}

