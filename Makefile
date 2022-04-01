traceroute: main.o
	gcc -Wall -Wextra -std=gnu17 -o traceroute main.o

main.o: main.c
	gcc -Wall -Wextra -std=gnu17 -c main.c

clean:
	rm main.o

cleandist:
	rm main.o traceroute
