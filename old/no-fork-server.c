/* 
	No-fork-server HTTP daemon. 

	This is the no-forking variant of "server.c". Can only serve one connection at a time.

	This is a simplified server, and is less secure as it doesn't chroot or drop privs.

	Its main goal is to show how a simple web server can be written in C.

	by David Shoon

	Licensed under GNU GPLv3.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netdb.h>
#include <netinet/in.h>

#include <arpa/inet.h>

char *strip_newline(char *s)
{
	char *p = strpbrk(s, "\r\n");
	if (p) *p = '\0';
	return s;
}

void child(int fd)
{
	FILE *fp_in, *fp_out;
	char buf[1024];
	FILE *fp;

	fp_in = fdopen(fd, "r");
	fp_out = fdopen(fd, "w");

	if (!fp_in || !fp_out) {
		perror("fdopen");
		return;
	}

	while (fgets(buf, sizeof(buf), fp_in)) {
		strip_newline(buf);
		printf("Received: %s\n", buf);

		if (strlen(buf) == 0)
			break;
	}

	printf("Sending...\n");

	fp = fopen("index.html", "rb");
	if (!fp) { goto close_fd; }

	fprintf(fp_out, "HTTP/1.1 200 OK\n");
	fprintf(fp_out, "Content-Type: text/html; charset=utf-8\n\n");

	while (fgets(buf, sizeof(buf), fp)) {
		fprintf(fp_out, "%s", buf);
	}

	fflush(fp_out);
	fclose(fp);

close_fd:
	printf("Closing fd...\n");

	fclose(fp_in);
	fclose(fp_out);
	close(fd);
	return;
}

int main(int argc, char **argv)
{
	int server_fd;
	int fd;
	int r, x;
	struct sockaddr_in server;
	pid_t pid;
	int port;

	if (argc < 2) {
		printf("Syntax: <listen port>\n");
		exit(1);
	}

	port = atoi(argv[1]);

	server_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) { perror("socket"); exit(1); }

	x = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(r)) < 0) {
		perror("setsockopt");
		exit(1);
	}

	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = INADDR_ANY;
	if (bind(server_fd, (void *) &server, sizeof(server)) < 0) {
		perror("bind");
		exit(1);
	}

	if (listen(server_fd, 5) < 0) { perror("listen"); exit(1); }

	while (1) {
		r = sizeof(server);
		fd = accept(server_fd, (void *) &server, &r);
		if (fd < 0) { perror("accept"); exit(1); }

		printf("Connected IP: %d.%d.%d.%d\n", 
			server.sin_addr.s_addr & 0x000000ff, 
			(server.sin_addr.s_addr & 0x0000ff00) >> 8, 
			(server.sin_addr.s_addr & 0x00ff0000) >> 16, 
			(server.sin_addr.s_addr & 0xff000000) >> 24 );

		child(fd);
	}
}
