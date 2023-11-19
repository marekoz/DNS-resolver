#pragma once
#include "dns.hpp"

/// @brief parses arguments and stores them into the allocated struct
/// @param argc 
/// @param argv 
/// @param args 
void parse_arguments(int argc, char *argv[], struct parsed_arguments *args);


