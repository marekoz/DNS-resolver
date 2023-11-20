// author: Marek Kozumplik, xkozum08
#pragma once
#include "dns.hpp"

/// @brief Converts domain name to dns format. Example: www.example.com to 3www7example3com0
/// @param hostname
/// @param result
void convert_domain_to_dns(char *hostname, unsigned char *result);

/// @brief converts IPv4 address to dns format. For -x
/// @param ip4
/// @param result
void convert_ip4_to_dns(char *ip4, unsigned char *result);

/// @brief Converts IPv6 to dns format for reverse query. Only works for full IPv6
/// @param ip6
/// @param result
void convert_ip6_to_dns(char *ip6, unsigned char *result);