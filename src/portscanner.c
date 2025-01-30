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
    
#define MAX_NUM_SOCKETS 128
#define BUFFER_LEN 1024
#define CONN_TIMEOUT 100
#define READ_TIMEOUT 500

int isPortOpen(char *target, int port) {

    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    char buffer[1024];
    int result;

    // connect timeout
    int ctimeout = 5000; // Timeout in milliseconds (5 seconds)
    fd_set writefds;
    fd_set readfds;
    struct timeval tv;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        return 0;
    }

    // receive timeout
    DWORD timeout = 1000; // ms
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
            FD_ZERO(&readfds);
            FD_SET(sock, &writefds);
            FD_SET(sock, &readfds);
            tv.tv_sec = ctimeout / 1000;
            tv.tv_usec = (ctimeout % 1000) * 1000;

            // writefds will be available first 
            // readfds may timeout if no data is sent by the socket even if it connected
            //int result = select(0, NULL, &writefds, NULL, &tv);
            int result = select(sock+1, &readfds, &writefds, NULL, &tv);
            //int result = select(sock+1, &writefds, NULL, NULL, &tv);
            printf("isset %d %d\n", FD_ISSET(sock, &readfds), FD_ISSET(sock, &writefds));
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
    //mode = 0;
    //ioctlsocket(sock, FIONBIO, &mode);


    // Receive and print the response
    while((result = recv(sock, buffer, sizeof(buffer) - 1, 0)) == -1 
        && WSAGetLastError() == WSAEWOULDBLOCK) {
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        tv.tv_sec = ctimeout / 1000;
        tv.tv_usec = (ctimeout % 1000) * 1000;

        int result2 = select(0, &writefds, NULL, NULL, &tv);
        break;
        if (!(result2 > 0 && FD_ISSET(sock, &writefds))) {
            break;
        }
    }

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



void connectOrTimeout2(SOCKET *sockets, int socket_count) {
    WSAPOLLFD pollFd[MAX_NUM_SOCKETS];
    int numSockets = socket_count;
    char buffer[BUFFER_LEN];

    // Initialize the pollFd array
    for (int i = 0; i < numSockets; i++) {
        pollFd[i].fd = INVALID_SOCKET;
        pollFd[i].events = 0;
        pollFd[i].revents = 0;
    }

    // Add sockets to the pollFd array
    for (int i = 0; i < numSockets; i++) {
        pollFd[i].fd = sockets[i];
        pollFd[i].events = POLLOUT; // Specify POLLIN for reading
    }

    // Poll the sockets
    int result = WSAPoll(pollFd, numSockets, CONN_TIMEOUT);
    if (result > 0) {
        // Check the revents field for each socket
        for (int i = 0; i < numSockets; i++) {
            if (!(pollFd[i].revents & POLLOUT)) {
                pollFd[i].fd = INVALID_SOCKET;
                pollFd[i].events = 0;
                pollFd[i].revents = 0;
            } else {
                pollFd[i].revents = 0;
                pollFd[i].events = POLLIN; // Specify POLLIN for reading
            }
        }

        int result = WSAPoll(pollFd, numSockets, READ_TIMEOUT);
            // Check the revents field for each socket
        for (int i = 0; i < numSockets; i++) {
            if (pollFd[i].fd == INVALID_SOCKET) continue;

            *buffer = '\0';

            // get ip and port
            struct sockaddr_in peerAddress;
            int peerAddressLen = sizeof(peerAddress);
            getpeername(sockets[i], (struct sockaddr*)&peerAddress, &peerAddressLen);

            char target[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peerAddress.sin_addr, target, INET_ADDRSTRLEN);
            int port = ntohs(peerAddress.sin_port);


            if (pollFd[i].revents & POLLIN) {
                int bytesRead = recv(sockets[i], buffer, BUFFER_LEN, 0);
                if (bytesRead > 0) {
                    buffer[bytesRead] = '\0'; // Null-terminate the received data
                }
            } else if (port == 445) {
                WCHAR  wtarget[256];
                const size_t WCHARBUF = strlen(target)+1;
                mbstowcs(wtarget, target, WCHARBUF);
                get_server_info(wtarget, buffer);
            }

            trimws(buffer);
            if (strlen(buffer))
                printf("%s:%d (%s)\n", target, port, buffer);
            else
                printf("%s:%d\n",target, port);
        }
    }
}

void connectOrTimeout(SOCKET *sockets, int socket_count) {
    SOCKET max_sock = INVALID_SOCKET;
    fd_set writefds;
    fd_set originfds;
    FD_ZERO(&writefds);
    for(int i=0; i<socket_count; i++) {
        FD_SET(sockets[i], &writefds);
        if (max_sock == INVALID_SOCKET || max_sock < sockets[i]) {
            max_sock = sockets[i];
        }
    }
    originfds = writefds;

    struct timeval tv;
    int ctimeout = 250; // Timeout in milliseconds (5 seconds)
    //
    tv.tv_sec = ctimeout / 1000;
    tv.tv_usec = (ctimeout % 1000) * 1000;
    int c = 0;
    int result;
    while((result = select(0, NULL, &writefds, NULL, &tv)) != -1) {
        if (result == 0) break; // timeout

        printf("scount -> %d | result -> %d\n", socket_count, result);
        for(int i=0; i<socket_count; i++) {
            printf("isset %d\n", FD_ISSET(sockets[i], &writefds));
            if (FD_ISSET(sockets[i], &originfds)) {
                FD_CLR(sockets[i], &originfds);
            }

        }
        writefds = originfds;
    }
    printf("F: scount -> %d | result -> %d\n", socket_count, result);
    printf("error: %d\n", WSAGetLastError());
}

/*
void processTCPSockets(SOCKET *sockets, int socket_count) {
    // connect to socket and return only the ones that are open
    fd_set writefds;
    connectTCPSockets(sockets, socket_count, &writefds);
    for(int i=0; i<socket_count; i++) {
        if (FD_ISSET(sockets[i], &writefds)) {
            printf("Sockets[%d] is set\n",i);
        }
        closesocket(sockets[i]);
    }

}*/

int connectTCPSocket(SOCKET sock, char *target, int port) {

    struct in_addr addr;
    addr.s_addr = inet_addr(target); // Convert string to in_addr

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    // basically convert struct in_addr type to struct sockaddr_in type
    memcpy(&server.sin_addr, &addr, sizeof(server.sin_addr));

    // TODO: https://stackoverflow.com/questions/29358443/c-using-select-to-monitor-two-sockets
    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
        return (WSAGetLastError() == WSAEWOULDBLOCK);

    return 1;

}

SOCKET createTCPSocket() {
    SOCKET sock = INVALID_SOCKET;
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    // set socket to non-blocking mode
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) != NO_ERROR) {
        printf("ioctlsocket failed: %d\n", WSAGetLastError());
        closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

void closeAllSockets(SOCKET *sockets, int *socket_count) {
    for (int i=0;i<*socket_count;i++) closesocket(sockets[i]);
    *socket_count = 0;
}

void testPortsOnIp2(char* target, Prt* ports) {
    SOCKET sockets[MAX_NUM_SOCKETS]; 
    int socket_count = 0;

    Prt* curr = ports;
    do {
        for(u_int i = curr->start; i <= curr->end; i++) {
            // create TCP Socket
            SOCKET s = createTCPSocket();
            if (s == INVALID_SOCKET) {
                // soemthing went wrong
                printf("[error] while allocating sockets\n");
                closeAllSockets(sockets, &socket_count);
                return;
            }

            // connect to socket
            if (!connectTCPSocket(s, target, (int) i)) {
                closesocket(s);
                continue;
            }

            sockets[socket_count] = s;
            socket_count++;

            if (socket_count != MAX_NUM_SOCKETS) continue;
            connectOrTimeout2(sockets, socket_count);
            // close sockets 
            closeAllSockets(sockets, &socket_count);
        }

    } while ((curr=curr->next) != NULL);
    connectOrTimeout2(sockets, socket_count);
    closeAllSockets(sockets, &socket_count);
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

                testPortsOnIp2(ipAddressStr, ports);
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

                testPortsOnIp2(ipAddressStr, ports);
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
