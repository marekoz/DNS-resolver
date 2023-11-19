#include "encoder.hpp"


/// @brief Converts domain name to dns format. Example: www.example.com to 3www7example3com0
/// @param hostname 
/// @param result 
void convert_domain_to_dns(char *hostname, unsigned char *result)
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
