build:	
	g++ dns.cpp  -Wall -o dns
dependencies:
	sudo apt update
	sudo apt install g++
clean:
	rm dns