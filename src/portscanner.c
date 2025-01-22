#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <lm.h>


#include <time.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Netapi32.lib")

#ifndef BOF
#include "parser.h"
#endif

#ifdef BOF
#include "beacon.h"
#include "portscanner-bof-inc.h"
#include "trustedsec-bof-print.h"

// cute hack
#include "parser.c" 

#include "trustedsec-bof-print.c" 

#include "utils.c"
#endif

int isPortOpen(char *target, int port) {

    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    char buffer[1024];
    int result;

    // connect timeout
    int ctimeout = 100; // Timeout in milliseconds (5 seconds)
    fd_set writefds;
    struct timeval tv;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        return 0;
    }

    // receive timeout
    DWORD timeout = 100; // ms
    if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout)) {
        printf("setsockopt failed: %d\n", WSAGetLastError());
        closesocket(sock);
        return 0;
    }

    if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof timeout)) {
        printf("setsockopt failed: %d\n", WSAGetLastError());
        closesocket(sock);
        return 0;
    }

    // set socket to non-blocking mode
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) != NO_ERROR) {
        printf("ioctlsocket failed: %d\n", WSAGetLastError());
        closesocket(sock);
        return 0;
    }

    struct in_addr addr;
    addr.s_addr = inet_addr(target); // Convert string to in_addr

    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // basically convert struct in_addr type to struct sockaddr_in type
    memcpy(&server.sin_addr, &addr, sizeof(server.sin_addr));

    // TODO: https://stackoverflow.com/questions/29358443/c-using-select-to-monitor-two-sockets
    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            // Use select to wait for the connection
            FD_ZERO(&writefds);
            FD_SET(sock, &writefds);
            tv.tv_sec = ctimeout / 1000;
            tv.tv_usec = (ctimeout % 1000) * 1000;

            int result = select(0, NULL, &writefds, NULL, &tv);
            if (!(result > 0 && FD_ISSET(sock, &writefds))) {
                //printf("Connect timed out or failed: %d\n", WSAGetLastError());
                closesocket(sock);
                return 1;
            }
        } else {
            //fprintf(stderr, "Could not connect to %s on port %d: %d\n", target, port, WSAGetLastError());
            closesocket(sock);
            return 1;
        }
    }
    
    // Set back to blocking mode 
    // needed so we can receive on the socket
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);

    // Receive and print the response
    result = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (result > 0) {
        buffer[result] = '\0'; // Null-terminate the received data
    } else {
        *buffer = '\0';
    }

    WCHAR  wtarget[256];
    const size_t WCHARBUF = strlen(target)+1;
    mbstowcs(wtarget, target, WCHARBUF);
    
    // if port == 445 and we got no header, assume its smb and request workstation info
    if (port == 445 && result <= 0) get_server_info(wtarget, buffer);
    
    trimws(buffer);

    if (strlen(buffer))
        printf("%s:%d (%s)\n", target, port, buffer);
    else
        printf("%s:%d\n",target, port);

    closesocket(sock);

    return 1;
}

void testPortsOnIp(char* target, Prt* ports) {
    Prt* curr = ports;
    do {

        for(u_int i = curr->start; i <= curr->end; i++) 
            isPortOpen(target, (int)i);

    } while ((curr=curr->next) != NULL);
}

int portscan(char *targetsStr, char *portsStr) {

    Hst* hosts = parse_hosts(targetsStr);
    Hst* hcurr = hosts;
    Prt* ports = parse_ports(portsStr);

    if (hosts == NULL || ports == NULL) {
        fprintf(stderr, "Couldn't parse ports or hosts\n");
        return EXIT_FAILURE;
    }

    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        printf("WSAStartup failed with error: %d\n", err);
        return EXIT_FAILURE;
    }

    do {
        if (hcurr->type == HIT_RANGE) {
            uint32_t start = ntohl(((HstIPRange*)(hcurr->hst))->start_addr.s_addr);
            uint32_t end = ntohl(((HstIPRange*)(hcurr->hst))->end_addr.s_addr);

            struct in_addr tmp;
            char ipAddressStr[INET_ADDRSTRLEN];

            for (uint32_t i = start; i <= end; i++) {
                tmp.s_addr = htonl(i);
                inet_ntop(AF_INET, &tmp, ipAddressStr, INET_ADDRSTRLEN);

                testPortsOnIp(ipAddressStr, ports);
            }
        } else if (hcurr->type == HIT_IPHOST) {

            HstIPHost *r = (HstIPHost*)(hcurr->hst);
            char *hostname = ((HstIPHost*)(hcurr->hst))->name;
            char ipAddressStr[INET_ADDRSTRLEN];

            for (struct addrinfo *p = r->res; p != NULL; p = p->ai_next) {
                void *addr;
                if (p->ai_family == AF_INET) {  // IPv4
                    struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                    addr = &(ipv4->sin_addr);
                } else {
                    continue;
                }

                inet_ntop(p->ai_family, addr, ipAddressStr, sizeof(ipAddressStr));

                testPortsOnIp(ipAddressStr, ports);
            }
        }
    } while((hcurr = hcurr->next) != NULL);

    free_hosts(hosts);
    free_ports(ports);

    WSACleanup();
}

#ifdef BOF
int go(char *argv, int argc) {
    if(!bofstart()) return 1; // init trustedsec output

    char *targets;
    int targets_len = -1;
    char *ports;
    int ports_len = -1;
    datap parser;
    BeaconDataParse(&parser, argv, argc);
    targets = BeaconDataExtract(&parser, &targets_len);
    ports = BeaconDataExtract(&parser, &ports_len);

	if (targets_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No targets provided\n");
		return 1;
	}

	if (ports_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No ports provided\n");
		return 1;
	}

    BeaconPrintf(CALLBACK_OUTPUT, "[.] portscanner: Scanning %s %s\n", targets, ports);

    portscan(targets, ports);

    printoutput(TRUE);

    return EXIT_SUCCESS;
}

#else

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <IP/Hostname> <Port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    time_t start_time, end_time;

    // Record start time
    time(&start_time);
    printf("Program started at: %s", ctime(&start_time));

    if (portscan(argv[1], argv[2]) == EXIT_FAILURE) return EXIT_FAILURE;

    // Record end time
    time(&end_time);
    printf("Program ended at: %s", ctime(&end_time));

    // Optionally, calculate elapsed time
    double elapsed_time = difftime(end_time, start_time);
    printf("Elapsed time: %.2f seconds\n", elapsed_time);

    return EXIT_SUCCESS;
}

#endif
