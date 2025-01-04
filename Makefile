all: icmp 

icmp: icmp.c
	x86_64-w64-mingw32-gcc -o icmp.exe icmp.c -lws2_32 -liphlpapi
	
	#-Os -s -Qn -nostdlib -Wl,-s,--exclude-all-symbols

clean:
	@rm *.o
