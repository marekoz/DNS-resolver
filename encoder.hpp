#pragma once
#include "dns.hpp"

/// @brief Converts domain name to dns format. Example: www.example.com to 3www7example3com0
/// @param hostname 
/// @param result 
void convert_domain_to_dns(char *hostname, unsigned char *result);

/// @brief converts ip4 address to dns format. For -x
/// @param ip4 
/// @param result 
void convert_ip4_to_dns(char *ip4, unsigned char *result);

