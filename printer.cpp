#include "printer.hpp"

/// @brief Prints domain at the pointer
/// @param buf_pointer
void print_domain(unsigned char buf[65536], unsigned char *buf_pointer)
{
	if (is_name_compressed(&buf_pointer[0]))
	{
		buf_pointer = &buf[get_compressed_offset(&buf_pointer[0])];
		print_domain(buf, &buf_pointer[0]);
		return;
	}
	int i = 1;
	int letters = buf_pointer[0];
	while (buf_pointer[i] != '\0')
	{
		if (is_name_compressed(&buf_pointer[i]))
		{
			buf_pointer = &buf[get_compressed_offset(&buf_pointer[i])];
			print_domain(buf, &buf_pointer[i]);
			return;
		}
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

/// @brief prints the ip6 address at the pointer
/// @param buf_pointer
void print_ip6(unsigned char *buf_pointer)
{
	// ipv6 TODO
	for (int i = 0; i < 16; i += 2)
	{
		std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buf_pointer[i]);
		std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buf_pointer[i + 1]);

		if (i < 14)
		{
			std::cout << ":";
		}
	}
}

/// @brief prints the ip4 address at the pointer
/// @param buf_pointer
void print_ip4(unsigned char *buf_pointer)
{
	std::cout << std::dec << (int)buf_pointer[0] << ".";
	std::cout << std::dec << (int)buf_pointer[1] << ".";
	std::cout << std::dec << (int)buf_pointer[2] << ".";
	std::cout << std::dec << (int)buf_pointer[3];
}

/// @brief prints answer error codes before exiting
/// @param rcode
void print_rcode(int rcode)
{
	switch (rcode)
	{
	case 1:
		std::cerr << "Error: Format error (1)" << std::endl;
		break;
	case 2:
		std::cerr << "Error: Server failure (2)" << std::endl;
		break;
	case 3:
		std::cerr << "Error: Name error (3)" << std::endl;
		break;
	case 5:
		std::cerr << "Error: Refused (5)" << std::endl;
		break;
	default:
		std::cerr << "Error          : " << rcode << std::endl;
		break;
	}
}

/// @brief prints type of answer/question
/// @param type
void print_type(int type)
{
	switch (type)
	{
	case 1:
		// print_domain(buf,buf_pointer);
		std::cout << ", A";
		break;
	case 28:
		// print_domain(buf,buf_pointer);
		std::cout << ", AAAA";
		break;
	case 5:
		// print_domain(buf,buf_pointer);
		std::cout << ", CNAME";
		break;
	case 2:
		// print_domain(buf,buf_pointer);
		std::cout << ", NS";
		break;
	case 12:
		// print_domain(buf,buf_pointer);
		std::cout << ", PTR";
		break;
	default:
		break;
	}
}

/// @brief prints the question section. Always only once because we can only ask 1 question
/// @param buf
/// @param offset
/// @param args
void print_question_section(unsigned char buf[65536], int *offset, struct parsed_arguments *args)
{
	std::cout << std::endl
			  << "  ";
	unsigned char *name_pointer = &buf[sizeof(struct dns_header)]; // Only 1 question is allowed
	*offset = (strlen((const char *)name_pointer)) + 1;			   // \0 -> +1

	struct dns_question *question = (struct dns_question *)&buf[sizeof(struct dns_header) + *offset];

	print_domain(buf, name_pointer);
	print_type(ntohs(question->qtype));

	std::cout << ", ";
	std::cout << (ntohs(question->qclass) ? "IN" : "Error");
}

/// @brief Prints the i-th answer/authority/additional section
/// @param buf buffer with answer
/// @param offset current offset (sum of data_len of previous sectoins)
/// @param args
/// @param i i-th section
void print_answer_section(unsigned char buf[65536], int *offset, struct parsed_arguments *args, int i)
{
	std::cout << std::endl
			  << "  ";
	unsigned char *buf_pointer = &buf[sizeof(struct dns_header) + sizeof(struct dns_answer) * i + sizeof(struct dns_question) + *offset];

	struct dns_answer *answer = NULL;

	if (is_name_compressed(buf_pointer))
	{
		answer = (struct dns_answer *)(buf_pointer + 2);
		//*offset += 2;
		buf_pointer = &buf[get_compressed_offset(buf_pointer)];
	}
	else
	{
		int name_len = strlen((const char *)buf_pointer) + 1;
		answer = (struct dns_answer *)buf_pointer + name_len;
		*offset += name_len;
	}

	print_domain(buf, buf_pointer);
	print_type(ntohs(answer->type));

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
	buf_pointer = &buf[sizeof(struct dns_header) + *offset + sizeof(struct dns_question) + sizeof(struct dns_answer) * (i + 1)];
	*offset += ntohs(answer->data_len);

	std::cout << ", ";
	switch (ntohs(answer->type))
	{
	case 1:
		print_ip4(buf_pointer);
		break;
	case 28:
		print_ip6(buf_pointer);
		break;
	default:
		print_domain(buf, buf_pointer);
		break;
	}
}

/// @brief Prints all sections from Answer to Additional
/// @param buf
/// @param args
void print_all_sections(unsigned char buf[65536], struct parsed_arguments *args)
{
	struct dns_header *dns = (struct dns_header *)buf;
	std::cout << "Authoritative: " << ((dns->aa) ? "Yes" : "No");
	std::cout << ", Recursive: " << ((dns->rd) ? "Yes" : "No");
	std::cout << ", Truncated: " << ((dns->tc) ? "Yes" : "No") << std::endl;

	int add_cnt = ntohs(dns->add_count);
	int q_cnt = ntohs(dns->q_count);
	int ans_cnt = ntohs(dns->ans_count);
	int aut_cnt = ntohs(dns->auth_count);
	int i = 0;
	int offset = 0;

	std::cout << "Question section (" << q_cnt << ")";
	print_question_section(buf, &offset, args);

	std::cout << std::endl
			  << "Answer section (" << ans_cnt << ")";
	while (i < ans_cnt)
	{
		print_answer_section(buf, &offset, args, i);
		i++;
	}

	std::cout << std::endl
			  << "Authority section (" << aut_cnt << ")";
	while (i < ans_cnt + aut_cnt)
	{
		print_answer_section(buf, &offset, args, i);
		i++;
	}

	std::cout << std::endl
			  << "Additional section (" << add_cnt << ")";
	while (i < ans_cnt + aut_cnt + add_cnt)
	{
		print_answer_section(buf, &offset, args, i);
		i++;
	}
}