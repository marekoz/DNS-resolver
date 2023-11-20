#author: Marek Kozumplik, xkozum08
build:	
	g++ dns.cpp  -Wall -o dns
dependencies:
	sudo apt update
	sudo apt install g++
test:
	python3 tests.py
clean:
	rm dns