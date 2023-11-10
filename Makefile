build:	
	g++ dns.cpp -o dns
dependencies:
	sudo apt update
	sudo apt install g++
clean:
	rm ipk-sniffer