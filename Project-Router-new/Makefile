CC=gcc
target=main
$(target):main.o get_interface.o callback_arp.o ip_file.o arp_link.o callback_1.o -lpthread
	$(CC) main.o get_interface.o callback_arp.o ip_file.o arp_link.o callback_1.o -o $(target) -lpthread
%*.o:%*.c
	$(CC) -c $^ -o $@
clean:
	rm -rf *.o $(target)