/*
	Small HTTP daemon.

	Based off "Example TCP server" in "icebox/originals"

	by David Shoon

	Licensed under GNU GPLv3.

	This program chroots and drops privileges (setuid()) after listening to the port.

	Also has "stack canary" protection, useful for platforms that don't have this.
	This should prevent stack buffer overflow attacks.

	This program avoids using the heap. If you want to change this code to using heap (malloc, etc)
	I would suggest that you wrap malloc to use mmap(), and mprotect() the boundary pages so that
	it triggers a SEGFAULT signal when overrun.
*/

/*========================== SECURITY SETTINGS -- YOU SHOULDN'T NEED TO CHANGE THIS =======================*/

/* Set chroot to current directory, otherwise must chdir() to directory as well (not done) */
#define CHROOT_DIR "."

/* Setuid to nobody */
#define SETUID_TO_USER "nobody"

/* Our own canary protection, for compilers that don't have this available. */
#define CANARY_PROTECTION


/*========================== DEFAULT SPLIT STRING LIMITS =======================*/

/* string buffer size -- i.e. per split word */
#define BUFFER_SIZE 1024

/* maximum number of words (tokens) returned from split() */
#define MAX_SPLITS 100

/*========================== LOGGING MACROS =======================*/

#define LOGERR(x, ...) printf("ERROR: " x, ##__VA_ARGS__)
#define LOGINFO(x, ...) printf("INFO: " x, ##__VA_ARGS__)
#define LOG printf

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

#include <time.h>


#ifdef CANARY_PROTECTION
int main_canary = 0;
	#define ENTER int canary = main_canary
	#define RETURN(x) if (canary == main_canary) return x; else abort()
#else
	#define ENTER
	#define RETURN(x) return x
#endif

struct split_string
{
	char str[BUFFER_SIZE];
};


// my_strlcpy - like OpenBSD's strlcpy(), but slightly different. Doesn't return strlen(src).
void my_strlcpy(char *dest, const char *src, int len)
{
	ENTER;
	int i;

	for (i = 0; i < len - 1; i++) {
		dest[i] = src[i];

		if (src[i] == '\0')
			break;
	}

	dest[i] = '\0';

	RETURN();

	/* NB: if you return the strlen(src), on unterminated src fields, it could overrun */
	/* We don't return strlen(src), cause we want to take extra precautions against unterminated src fields, and we don't care about truncation. */
}

// split - splits a "src" string by delimiter "delim", with destination "dst" and total number of "split words" defined by "split_string_size".
// returns number of "split words"
int split(char *src, char *delim, struct split_string *dst, int split_string_size)
{
	ENTER;
	int i;
	char *p = src;

	LOGINFO("Splitting: [%s]\n", src);

	if (strlen(src) >= BUFFER_SIZE) {
		LOGERR("Error with split, strlen(src) >= BUFFER_SIZE\n");
		RETURN(0);
	}

	for (i = 0; i < split_string_size; i++) {
		char *t = strpbrk(p, delim);
		if (t) {
			my_strlcpy(dst[i].str, p, t - p + 1); // length = t - p ( + 1 for null terminator)
			LOGINFO("Split: [%s]\n", dst[i].str);
			p = t + 1;
		}
		else {
			my_strlcpy(dst[i].str, p, strlen(p) + 1); // copy till the end of the string p, since it's the final round. (+1 for null terminator)
			LOGINFO("Final split: [%s]\n", dst[i].str);
			i++; // increment so that we have the total "split_string_size" before breaking out of this loop
			break;
		}
	}

	RETURN(i);
}

// strip_newline -- strips newline character "\r\n" from string "s".
// Returns string "s".
char *strip_newline(char *s)
{
	ENTER;
	char *p = strpbrk(s, "\r\n");
	if (p) *p = '\0';
	RETURN(s);
}

// http_send_file -- sends a file named "filename", to "fp_out" (which is presumably a socket).
// Returns number of bytes sent.
int http_send_file(int http_version, const char *filename, FILE *fp_out)
{
	ENTER;
	FILE *fp;
	int total_size;
	char readbuf[1024];
	int r, s;
	struct stat statbuf;

	fp = fopen(filename, "rb");
	if (!fp) {
		LOGERR("File not found: %s\n", filename);
		fprintf(fp_out, "HTTP/1.%d 404 Not Found\n", http_version);
		fprintf(fp_out, "Content-Type: text/html; charset=utf-8\n\n");
		fprintf(fp_out, "<HTML><BODY>File not found</BODY></HTML>\n");
		fflush(fp_out);
		RETURN(-1);
	}

	else {
		// we want to follow symlinks... so use stat() instead of lstat()
		stat(filename, &statbuf);

		fprintf(fp_out, "HTTP/1.%d 200 OK\n", http_version);
		fprintf(fp_out, "Content-Length: %ld\n\n", statbuf.st_size);

		total_size = 0;

		do {
			r = fread(readbuf, 1, sizeof(readbuf), fp);
			s = fwrite(readbuf, 1, r, fp_out);
			if (r != s) {
				LOGERR("Writing buffer to fp_out is not the same size as reading from file\n");
				RETURN(-1);
			}

			total_size += s;
		} while (r == sizeof(readbuf));

		fflush(fp_out);
		fclose(fp);
	}

	RETURN(total_size);
}

// child - child process... the main functionality of the child process resides here.
void child(int fd)
{
	ENTER;
	FILE *fp_in, *fp_out;
	char buf[BUFFER_SIZE];
	char target_file[BUFFER_SIZE];
	int i, r;
	int http_version;
	struct split_string first_pass[MAX_SPLITS];
	int first_pass_splits;
	struct split_string second_pass[MAX_SPLITS];
	int second_pass_splits;

	fp_in = fdopen(fd, "r");
	fp_out = fdopen(fd, "w");

	if (!fp_in || !fp_out) {
		LOGERR("Unable to use fdopen() to convert sockets to FILE *\n");
		perror("fdopen");
		RETURN();
	}

	if (fgets(buf, sizeof(buf), fp_in)) {
		strip_newline(buf);
		LOG("Received (first line): %s\n", buf);

		first_pass_splits = split(buf, " ", first_pass, MAX_SPLITS);
		LOGINFO("First pass: Splits = %d\n", first_pass_splits);

		if ((first_pass_splits == 3) && (strcmp(first_pass[0].str, "GET") == 0)) {
			if (strcmp(first_pass[2].str, "HTTP/1.1") == 0) {
				http_version = 1;
			}
			else if (strcmp(first_pass[2].str, "HTTP/1.0") == 0) {
				http_version = 0;
			}
			else {
				http_version = -1;
			}

			second_pass_splits = split(first_pass[1].str, "?", second_pass, MAX_SPLITS);
			LOGINFO("Second pass: Splits = %d\n", second_pass_splits);

			if (second_pass_splits > 0) {
				if ((strcmp(second_pass[0].str, "/") == 0) || (strcmp(second_pass[0].str, "/index.htm") == 0) || (strcmp(second_pass[0].str, "/index.html") == 0)) {
					LOG("Found HTTP request for index.html\n");
					my_strlcpy(target_file, "/index.html", sizeof(target_file));
				}
				else {
					my_strlcpy(target_file, second_pass[0].str, sizeof(target_file));
					LOG("Requesting file: %s\n", target_file);
				}
			}
			for (i = 1; i < second_pass_splits; i++) {
				LOGINFO("Second pass split[%d]: ?%s\n", i, second_pass[i].str);	// we include the question mark -- to show that it was a URL parameter, since split() removes delimiters.
			}
		}
	}

	while (fgets(buf, sizeof(buf), fp_in)) {
		strip_newline(buf);
		LOG("Received (subsequent lines): %s\n", buf);

		if (strlen(buf) == 0)
			break;
	}

	if (http_version >= 0) {
		LOGINFO("Sending file: %s\n", target_file);

		r = http_send_file(http_version, target_file, fp_out);
		if (r >= 0) {
			LOGINFO("Succeeded sending file.\n");
		}
		else {
			LOGINFO("Failed to send file.\n");
		}
	}

	fflush(stdout); // flush all logs before exiting child process. Possible bug on OpenBSD not flushing buffers on exit(). Works fine on Linux.

	fclose(fp_in);
	fclose(fp_out);
	close(fd);
	RETURN();
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

	srand(time(NULL));


	if (argc < 2) {
		printf("Syntax: <listen port>\n");
		exit(1);
	}

	time_t now = time(NULL);
	LOG("Starting server... [%s]\n", strip_newline(ctime(&now)));

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
		if (fd < 0) {
			perror("accept");
			LOG("Attempted Connection from IP: %s [%s]\n", inet_ntoa(server.sin_addr), strip_newline(ctime(&now)));
			continue;
		}

		now = time(NULL);
		LOG("Connected IP: %s [%s]\n", inet_ntoa(server.sin_addr), strip_newline(ctime(&now)));
		fflush(stdout);

		pid = fork();
		if (pid < 0) { perror("fork"); exit(1); }

		// child
		if (pid == 0) {
#ifdef CANARY_PROTECTION
			main_canary = rand();
#endif
			alarm(10); // allow 10 seconds before terminating the connection / child process.

			child(fd); // main child process function.

			alarm(0); // reset alarm to zero.
			exit(0); // exit child process.
		}
		// parent
		else {
			close(fd);
			// clear up all the children.
			while (waitpid(-1, NULL, WNOHANG) > 0) ;
		}

		fflush(stdout);
	}
}
