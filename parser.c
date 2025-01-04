#include "parser.h"

int is_port_valid(int p) {
	return MIN_PORT <= p && p <= MAX_PORT;
}

Prt* parse_ports(char *input) {
    Prt * first_port = NULL;
    Prt * current = NULL;

    char *token = strtok(input, ","); // Split input by commas
    while (token != NULL) {
    	unsigned int start_port, end_port;
        printf("%s\n", token);
	
	if (strchr(token, '-') != NULL) {
		if (!sscanf(token, "%d-%d", &start_port, &end_port)
		    || !(is_port_valid(start_port) && is_port_valid(end_port))) {
			printf("wrong input provided: %s\n", token);
			continue;
		}
	} else {
		if (!sscanf(token, "%d", &start_port)
		    || !is_port_valid(start_port)) {
			printf("wrong input provided: %s\n", token);
			continue;
		}
		end_port = start_port;
	}

	if (end_port < start_port) {
		unsigned int tmp;
		tmp = end_port;
		end_port = start_port;
		start_port = tmp;
	}
	
        token = strtok(NULL, ",");

	if (first_port == NULL) { 
		first_port = (Prt *)malloc(sizeof(Prt));
		current = first_port;
		current->start = start_port;
		current->end = end_port;
		continue;
	}

	current->next = (Prt *)malloc(sizeof(Prt));
	current = current->next;
	current->start = start_port;
	current->end = end_port;
    }

    return first_port;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <comma-separated values>\n", argv[0]);
		return 1;
	}

	Prt* ports = parse_and_print(argv[1]);

	Prt* p;
	p = ports;

	while(p != NULL) {
		printf("->%u\t%u\n",p->start,p->end);
		p = p->next;
	}

	return 0;
}
