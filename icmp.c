#include <stdio.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#pragma comment(lib, "iphlpapi.lib")

// NOTE: I haven't looked into the ICMP full specs
// so there could be other options/values that are set by the host's `ping` command
// however looking at the packets I'm not able to differentiate which is which.
// TLDR. Do your own research.

// match the default ping command's data
#define ICMP_ECHO_DATA "abcdefghijklmnopqrstuvwabdcefghi"
#define ICMP_REPLY_SIZE sizeof(ICMP_ECHO_REPLY) + sizeof(ICMP_ECHO_DATA)

#define ICMP_TIMEOUT 3000 // in ms

// passing a handle to the hIcmpFile here so it can be reused
// probably not threadsafe tbh
DWORD ping_ip(HANDLE hIcmpFile, IPAddr ip, PICMP_ECHO_REPLY reply) {

    IP_OPTION_INFORMATION options = {0};
    options.Ttl = 128; // match the default ping command's ttl

    return IcmpSendEcho(
        hIcmpFile,
        ip,
	ICMP_ECHO_DATA,
        sizeof(ICMP_ECHO_DATA)-1, // cant remember why you need -1 here
        &options, 
        reply,
        ICMP_REPLY_SIZE,
	(DWORD) ICMP_TIMEOUT
    );
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <IP Address> <IP Address>\n", argv[0]);
        return 1;
    }

    HANDLE hIcmpFile;
    char replyBuffer[ICMP_REPLY_SIZE];
    PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)replyBuffer;

    const char *ipAddress = argv[1];
    IPAddr ipAddr = inet_addr(ipAddress);
    if (ipAddr == INADDR_NONE) {
        printf("Invalid IP address: %s\n", ipAddress);
        return 1;
    }

    const char *ipAddress2 = argv[2];
    IPAddr ipAddr2 = inet_addr(ipAddress2);
    if (ipAddr2 == INADDR_NONE) {
        printf("Invalid IP address: %s\n", ipAddress2);
        return 1;
    }

    // Open a handle for ICMP
    hIcmpFile = IcmpCreateFile();
    if (hIcmpFile == INVALID_HANDLE_VALUE) {
        printf("Unable to open ICMP handle. Error: %ld\n", GetLastError());
        return 1;
    }

    DWORD dwRetVal = ping_ip(hIcmpFile, ipAddr, reply);

    if (dwRetVal == 0) {
	    printf("Ping failed. Error: %ld\n", GetLastError());
    } else {
	    printf("Reply from %s: bytes=%ld time=%ldms TTL=%d\n",
			    ipAddress,
			    reply->DataSize,
			    reply->RoundTripTime,
			    reply->Options.Ttl);
    }

    dwRetVal = ping_ip(hIcmpFile, ipAddr2, reply);

    if (dwRetVal == 0) {
	    printf("Ping failed. Error: %ld\n", GetLastError());
    } else {
	    printf("Reply from %s: bytes=%ld time=%ldms TTL=%d\n",
			    ipAddress2,
			    reply->DataSize,
			    reply->RoundTripTime,
			    reply->Options.Ttl);
    }

    // Cleanup
    IcmpCloseHandle(hIcmpFile);
    return 0;
}

