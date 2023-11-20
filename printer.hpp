// author: Marek Kozumplik, xkozum08
#pragma once
#include "dns.hpp"

/// @brief Prints domain at the pointer
/// @param buf_pointer
void print_domain(unsigned char buf[65536], unsigned char *buf_pointer);

/// @brief prints the ip6 address at the pointer
/// @param buf_pointer
void print_ip6(unsigned char *buf_pointer);

/// @brief prints the ip4 address at the pointer
/// @param buf_pointer
void print_ip4(unsigned char *buf_pointer);

/// @brief prints answer error codes before exiting
/// @param rcode
void print_rcode(int rcode);

/// @brief prints type of answer/question
/// @param type
void print_type(int type);

/// @brief prints the question section. Always only once because we can only ask 1 question
/// @param buf
/// @param offset
/// @param args
void print_question_section(unsigned char buf[65536], int *offset, struct parsed_arguments *args);

/// @brief Prints the i-th answer/authority/additional section
/// @param buf buffer with answer
/// @param offset current offset (sum of data_len of previous sectoins)
/// @param args
/// @param i i-th section
void print_answer_section(unsigned char buf[65536], int *offset, struct parsed_arguments *args, int i);

/// @brief Prints all sections from Answer to Additional
/// @param buf
/// @param args
void print_all_sections(unsigned char buf[65536], struct parsed_arguments *args);
