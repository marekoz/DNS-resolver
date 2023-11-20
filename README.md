# ISA - DNS Resolver
Author: Marek Kozumplik

Login: xkozum08

Date: 20th Nov 2023

## Summary

Command-line application that sends DNS queries to specified DNS servers. After receiving answer from the server, the application will parse the answer and output the information in specified format. Written in C++.



### How to run
To download dependencies, use: ```make dependencies```

To build the project, use: ```make```

To run tests, use : ```make test```


To run the project, use: ```./dns [-r] [-x] [-6] -s server [-p port] address```

Where:

    -r : Recursion desired
    -x : Reverse query
    -6 : AAAA query instead of A
    -s : IP address or domain name of the DNS server
    -p : port (default is 53)
    address : requested address (or domain name if -x)
    -h: prints help


## List of files
Makefile, README.md, manual.pdf

dns.hpp, dns.cpp, arg_parser.hpp, arg_parser.cpp, encoder.hpp, encoder.cpp, printer.hpp, printer.cpp

Folder tests with .in and .out files, tests.py
## Sources

[RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) - Information on DNS servers, resolvers, queries, DNS header format, format of DNS question and answer

[RFC 3596 - DNS Extensions to Support IP Version 6](https://datatracker.ietf.org/doc/html/rfc3596)

[Binarytides.com, Silver Moon, May 18, 2020 - DNS Query Code in C with Linux sockets](https://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/) - Example of how to send DNS query using socket, sendto, recvfrom. Example of struct of DNS header based on RFC1035

[Whatsmydns.net - Reverse DNS generator](https://www.whatsmydns.net/reverse-dns-generator) - Tutorial on how to create reverse DNS query for IPv4 and IPv6

[Python Subprocess: The Simple Beginner’s Tutorial (2023)](https://www.dataquest.io/blog/python-subprocess) -  Subprocess in python for testing

[GeeksforGeeks Aakash\_Pancha, 10 Nov, 2021 - std::setbase, std::setw , std::setfill in C++](https://www.geeksforgeeks.org/stdsetbase-stdsetw-stdsetfill-in-cpp) -  For printing IPv6 address in a nice format