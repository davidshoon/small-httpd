/* 
	Small HTTP daemon. 

	Based off "Example TCP server" in "icebox/originals"

	by David Shoon

	Licensed under GNU GPLv3.

	This program chroots and drops privileges (setuid()) after listening to the port.
*/

/* Set chroot to current directory, otherwise must chdir() to directory as well (not done) */
#define CHROOT_DIR "."

/* Setuid to nobody */
#define SETUID_TO_USER "nobody"

#define BUFFER_SIZE 1024

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

#include <pwd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

void my_strlcpy(char *dest, const char *src, int len)
{
	int i;

	for (i = 0; i < len - 1; i++) {
		dest[i] = src[i];

		if (src[i] == '\0')
			break;
	}

	dest[i] = '\0';

	return;

	/* NB: if you return the strlen(src), on unterminated src fields, it could overrun */
	/* We don't return strlen(src), cause we want to take extra precautions against unterminated src fields, and we don't care about truncation. */
}

char *strip_newline(char *s)
{
	char *p = strpbrk(s, "\r\n");
	if (p) *p = '\0';
	return s;
}

void child(int fd)
{
	FILE *fp_in, *fp_out;
	char buf[BUFFER_SIZE];
	int received_get_request_for_index_html = 0;
	FILE *fp;
	char target_file[BUFFER_SIZE];

	fp_in = fdopen(fd, "r");
	fp_out = fdopen(fd, "w");

	if (!fp_in || !fp_out) {
		perror("fdopen");
		return;
	}

	if (fgets(buf, sizeof(buf), fp_in)) {
		strip_newline(buf);
		printf("Received: %s\n", buf);
		{
			char *t = strtok(buf, " "); /* strtok 1st time */

			if (t && (strcmp(t, "GET") == 0)) {
				printf("Found GET!\n");
				t = strtok(NULL, " "); /* strtok 2nd time */
				if (t) {
					char d[BUFFER_SIZE], *p;
					/* need a copy of 't' so that we can eliminate the question mark and compare, without altering the token 't' in strtok */
					my_strlcpy(d, t, sizeof(d)); /* should be safe regardless, since we're using the same buffer sizes */
					p = strchr(d, '?');
					if (p) *p = '\0';
					if ((strcmp(d, "/") == 0) || (strcmp(d, "/index.htm") == 0) || (strcmp(d, "/index.html") == 0)) {
						t = strtok(NULL, " "); /* strtok 3rd time */
						if (t && 
							(
								(strcmp(t, "HTTP/1.1") == 0) 
							|| 
								(strcmp(t, "HTTP/1.0") == 0)
							)
						) {
							printf("Found HTTP request for index.html\n");
							received_get_request_for_index_html = 1;
						}
					}
					else {
						p = strchr(d, ' ');
						if (p) *p = '\0';
						my_strlcpy(target_file, d, sizeof(target_file));
						printf("Requesting file: %s\n", target_file);
					}
				}
			}
		}
	}

	while (fgets(buf, sizeof(buf), fp_in)) {
		strip_newline(buf);
		printf("Received: %s\n", buf);

		if (strlen(buf) == 0)
			break;
	}

	printf("Sending...\n");

	if (received_get_request_for_index_html) {
		fp = fopen("index.html", "rb");
		if (!fp) {
			fprintf(fp_out, "HTTP/1.1 404 Not Found\n");
			fprintf(fp_out, "Content-Type: text/html; charset=utf-8\n\n");
			fprintf(fp_out, "<HTML><BODY>File not found</BODY></HTML>\n");
			fflush(fp_out);
			goto close_fd;
		}
		else {
			fprintf(fp_out, "HTTP/1.1 200 OK\n");
			fprintf(fp_out, "Content-Type: text/html; charset=utf-8\n\n");

			while (fgets(buf, sizeof(buf), fp)) {
				fprintf(fp_out, "%s", buf);
			}

			fflush(fp_out);
			fclose(fp);
		}
	}
	else {
		fp = fopen(target_file, "rb");
		if (!fp) {
			fprintf(fp_out, "HTTP/1.1 404 Not Found\n");
			fprintf(fp_out, "Content-Type: text/html; charset=utf-8\n\n");
			fprintf(fp_out, "<HTML><BODY>File not found</BODY></HTML>\n");
			fflush(fp_out);
			goto close_fd;
		}
		else {
			char readbuf[1024];
			int r;
			struct stat statbuf;

			// we want to follow symlinks...
			stat(target_file, &statbuf);

			fprintf(fp_out, "HTTP/1.1 200 OK\n");
//			fprintf(fp_out, "Content-Type: image/png\n\n");
			fprintf(fp_out, "Content-Length: %ld\n\n", statbuf.st_size);

			do {
				r = fread(readbuf, 1, sizeof(readbuf), fp);
				fwrite(readbuf, 1, r, fp_out);
			} while (r == sizeof(readbuf));

			fflush(fp_out);
			fclose(fp);
		}
	}


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
	int x;
	struct sockaddr_in server;
	pid_t pid;
	int port;
	struct passwd *p_pwd;

	if (argc < 2) {
		printf("Syntax: <listen port>\n");
		exit(1);
	}

	errno = 0;
	p_pwd = getpwnam(SETUID_TO_USER);
	if (!p_pwd) {
		perror("getpwnam");
		exit(1);
	}

	chroot(CHROOT_DIR);

	port = atoi(argv[1]);

	server_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) { perror("socket"); exit(1); }

	x = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &x, sizeof(x)) < 0) {
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

	if (setuid(p_pwd->pw_uid) < 0) { perror("setuid"); exit(1); }

	while (1) {
		socklen_t r = sizeof(server);
		fd = accept(server_fd, (void *) &server, &r);
		if (fd < 0) { perror("accept"); exit(1); }

		printf("Connected IP: %s\n", inet_ntoa(server.sin_addr));

		pid = fork();
		if (pid < 0) { perror("fork"); exit(1); }

		// child
		if (pid == 0) {
			child(fd);
			exit(0);
		}
		// parent
		else {
			close(fd);
			// clear up all the children.
			while (waitpid(-1, NULL, WNOHANG) > 0) ;
		}
	}
}
