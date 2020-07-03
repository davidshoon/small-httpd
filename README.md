# small-httpd
A small, yet (hopefully!) secure, HTTP daemon.

## To compile:

cd src

gcc test.c

## To run (must run as root):
cd www

../src/a.out 80 

It will bind to port 80, chroot to current directory (i.e. www/), and drop privileges to "nobody".

## Notes
It now has a built-in stack canary protection, for platforms that don't have non-exec stack protection, or propolice or similar. This should prevent stack buffer overflow attacks, such as executing on stack (shellcode) and Return-Oriented-Programming. It randomises the canary for the child process.

It avoids using the heap, since to protect that it would require wrapping malloc() with calls to mmap() and mprotect(), which increases the complexity and thus increasing "attack surface".
