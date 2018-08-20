all: netfilter_test

netfilter_test: main.o
	g++ -o netfilter_test main.o -lnetfilter_queue
main.o:
	g++ -c -o main.o main.cpp
clean:
	rm -f netfilter_test
	rm -f *.o
