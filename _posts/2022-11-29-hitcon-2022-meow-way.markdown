---
layout: single
title:  "HITCON CTF 2022 - Meow Way"
date:   2022-11-29  18:04:10 -0500
categories: ctf
excerpt: Flag checker using Heaven's Gate
---

## Overview

We are given a Windows executable. Looking at it in Binary Ninja, we can immediately see that the program runs some kind of a checking function on each byte of the flag, then compares it to a given array at the end.

![](https://i.imgur.com/feWxnNg.png)

Theoretically, this should be pretty simple, but when we look at the checking function we can see some strange behavior:

![](https://i.imgur.com/ahVV8GT.png)

When we look at the disassembly for the subroutine being called by the checking function, it doesn't quite seem to make sense:

![](https://i.imgur.com/RMKgV2M.png)

Running the program in x32dbg also produces some unexpected behavior -  `sub_4031c0` should be calling `sub_4013cc`, but the debugger skips over the call completely when stepping through.

## The "Heaven's Gate" technique

I eventually noticed that the checking function was making a far call - a call to a different segment. The argument `0x33` is the new value of the segment register, which tells us which segment we're in.

As it turns out, changing the segment register to `0x33` triggers a switch from 32-bit to 64-bit code. This technique is usually referred to as "Heaven's Gate", and it is often used by malware to hide its behavior. You can find a more detailed writeup of how the process works [here](https://reverseengineering.stackexchange.com/questions/16200/how-to-investigate-windows-32-64bit-wow64-transition).

That explains why our disassembly was wrong: we were trying to disassemble 64-bit code as 32-bit! Looking at the corrected 64-bit disassembly, we finally have our checking function:

![](https://i.imgur.com/iH21hlH.png)

This makes much more sense: we're adding the first two arguments to the function, then XORing with a constant value.

## Solve

The checking function for each byte of the flag is almost the same. It either adds or subtracts a constant value to the byte, then XORs the result with a different constant. All we need to do is extract the constants, and we'll be able to get the flag.

Since each checking function includes only a single XOR with an immediate value, we can extract it from the disassembly:

```python
def get_xor(func):
    disas = Cs(CS_ARCH_X86, CS_MODE_64)
    disas.detail = True
    for inst in disas.disasm(func, 0):
        if 'xor' in inst.mnemonic: 
            for op in inst.operands:
                if op.type == X86_OP_IMM: return op.value.imm            
```
Similarly, we can determine whether each checking function adds its second argument to the flag byte or subtracts it:

```python
def add_or_sub(func):
    disas = Cs(CS_ARCH_X86, CS_MODE_64)
    for inst in disas.disasm(func, 0):
        print(inst.mnemonic, ' ', inst.op_str)
        if 'add' in inst.mnemonic or 'sub' in inst.mnemonic:
            print(inst.mnemonic)
            return inst.mnemonic
```

Once we've done that, we can reverse the encoding.

```python
xors = [0xba, 0x2f, 0xcd, 0xf6, 0x9f, 0xd0, 0x22, 0xf7, 0xd0, 0x1f, 0xa8, 0x3d, 0xc7, 0xa5, 0x47, 0x68, 0xd7, 0x4a, 0x96, 0x91, 0x2e, 0x19, 0xc5, 0xe3, 0x88, 0xbd, 0x4e, 0x93, 0x13, 0xf1, 0xcc, 0x47, 0xab, 0xc9, 0x48, 0x2b, 9, 0x50, 0x4f, 0xe9, 0xc0, 0x5e, 0xef, 0x8b, 0x85, 0xcb, 0x55, 0x70]
adds = [0xc4, 0x16, 0x8e, 0x77, 0x5, 0xb9, 0xd, 0x6b, 0x24, 0x55, 0x12, 0x35, 0x76, 0xe7, 0xfb, 0xa0,0xda, 0x34, 0x84, 0xb4, 0xc8, 0x9b, 0xef, 0xb4, 0xb9, 0xa, 0x57, 0x5c, 0xfe, 0xc5, 0x6a, 0x73, 0x49,0xbd, 0x11, 0xd6, 0x8f, 0x6b, 0xa, 0x97, 0xab, 0x4e, 0xed, 0xfe, 0x97, 0xf9, 0x98, 0x65]
target  = [0x96, 0x50, 0xcf, 0x2c, 0xeb, 0x9b, 0xaa, 0xfb, 0x53, 0xab, 0x73, 0xdd, 0x6c, 0x9e, 0xdb, 0xbc, 0xee, 0xab, 0x23, 0xd6, 0x16, 0xfd, 0xf1, 0xf0, 0xb9, 0x75, 0xc3, 0x28, 0xa2, 0x74, 0x7d, 0xe3, 0x27, 0xd5, 0x95, 0x5c, 0xf5, 0x76, 0x75, 0xc9, 0x8c, 0xfb, 0x42, 0x0e, 0xbd, 0x51, 0xa2, 0x98]
ops = ['add', 'add', 'add', 'add', 'add', 'sub', 'add', 'sub', 'add', 'add', 'sub', 'sub', 'add', 'add', 'sub', 'add', 'add', 'sub', 'add', 'sub', 'add', 'add', 'add', 'add', 'add', 'sub', 'add', 'add', 'sub', 'sub', 'add', 'add', 'add', 'add', 'sub', 'sub', 'add', 'sub', 'add', 'sub', 'sub', 'add', 'sub', 'sub', 'sub', 'sub', 'add', 'sub']

flag = ""
results = []
for i in range(len(target)):
    if ops[i] == 'add': decoded = ((target[i] ^ xors[i]) - adds[i])&0xff
    else: decoded = (-(target[i] ^ xors[i]) + adds[i])
    results.append(decoded)
    flag += chr(decoded & 0xff)
print(flag)
```
This gets us the flag:

```hitcon{___7U5T_4_S1mpIE_xB6_M@G1C_4_mE0w_W@y___}```
