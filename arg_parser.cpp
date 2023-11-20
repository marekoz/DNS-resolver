//author: Marek Kozumplik, xkozum08
#include "arg_parser.hpp"

/// @brief parses arguments and stores them into the allocated struct
/// @param argc
/// @param argv
/// @param args
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

