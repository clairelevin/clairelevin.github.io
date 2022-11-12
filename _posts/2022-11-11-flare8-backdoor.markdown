---
layout: post
title:  "Flare-On 9 writeup: 08 - backdoor"
date:   2022-11-11 23:51:08 -0500
categories: ctf flareon
---

This year, I attempted Flare-On for the first time and solved all 11 challenges. Of these, challenge 8 was by far the hardest, taking me much longer to solve than any of the others. I started this challenge with literally no knowledge of .NET, so I learned a lot by the end.

## Overview

Challenge description:
> I'm such a backdoor, decompile me why don't you...

Looking at the program in dnSpy, we immediately notice several things:
*  We have 74 functions with a name beginning with `flare` and 70 with a name beginning with `flared`.
*  None of the functions beginning with `flared` can be decompiled, and all throw an exception when called.
*  Nearly every function beginning with `flare` attempts to call one of the `flared` functions in a `try` block, seemingly throwing an exception on purpose. The stack trace of that exception is passed in as an argument to the function called in the `catch` block.
*  Most of the functions have little to no actual code in the body of the method, so it isn't immediately clear how anything is actually being called.
*  The executable has a large number of sections, most of which have names consisting of 8 hexadecimal digits.

Since this program was supposedly a backdoor, I first tried running it using REMnux's [fakedns](https://github.com/SocialExploits/fakedns/blob/main/fakedns.py) and [inetsim](https://www.inetsim.org/) packages to intercept any network traffic the program might produce. I found that the program made several DNS requests to seemingly random subdomains of flare-on.com, but it didn't seem to do anything after that. 

![](https://i.imgur.com/21cEJbw.png)

Looking at the strings in the program, I found several base64 strings that decoded to what appeared to be PowerShell commands, such as

```
$(ping -n 1 10.65.45.3 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.4.52 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.31.155 | findstr /i ttl) -eq $null;$(ping -n 1 flare-on.com | findstr /i ttl) -eq $null

ping -n 1 10.65.45.18 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.28.41 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.36.13 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.51.10 | findstr /i ttl) -eq $null

nslookup flare-on.com | findstr /i Address;nslookup webmail.flare-on.com | findstr /i Address

$(ping -n 1 10.65.4.50 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.4.51 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.65.65 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.53.53 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.21.200 | findstr /i ttl) -eq $null

Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select-Object "LocalAddress", "LocalPort", "RemoteAddress", "RemotePort"

[System.Environment]::OSVersion.VersionString
```

However, these commands weren't being run: I wasn't capturing pings to any of the addresses mentioned in the commands. Clearly, I would need to send the program some kind of signal in order to get it to do anything.

From here, I'll be splitting this writeup into two main parts. The first will focus on how I figured out what methods were being called and how I reversed the obfuscation protecting most of the program. The second will focus on how I figured out the logic the program was following, which eventually allowed me to reconstruct the program's C2 server and obtain the flag.

## Part 1: Disassembly and Deobfuscation

### Dynamic Methods

![](https://i.imgur.com/WFzZv4j.png)


After taking another look at dnSpy, I found out how most of the program's functions were being called. In the `flare_71` method, we can see calls to  `dynamicILInfo.SetCode` and `dynamicMethod.Invoke`, revealing that a dynamic method is being constructed from an array of bytecode. Since dynamic methods are generated at runtime, dnSpy can't decompile them, which means we'll have to find another way to figure out what's being called. The `flare_71` method takes two arguments: `m` and `b`. I found that `b` corresponded to the actual bytecode of the dynamic method being called, and `m` was a dictionary containing all of the metadata tokens used in the dynamic method and the locations where they were used. (For those who haven't worked with .NET before, metadata tokens are basically references to functions, classes, methods, and fields.)

The `flare_74` function initialized several arrays (`gs_b`, `gh_b`, `cl_b`, `rt_b`, `wl_b`, `d_b`, `pe_b`) that were then passed to `flare_71`.  For the actual disassembly, I used the Python package [dncil](https://github.com/mandiant/dncil). The bytecode arrays were missing headers, but I managed to reconstruct them by modifying the sample headers that appeared in dncil's test cases. Once we have that, getting the disassembly is easy.

```python
from dncil.cil.body import reader
def print_il(header, il_code):
    body = reader.read_method_body_from_bytes(header + il_code)
    for i in body.instructions: print(i)
```

And here's an example of the output:

```
000C    00                  nop
000D    73 02 00 00 06      newobj         token(0x06000002)
0012    25                  dup
0013    1f 58               ldc.i4.s       88
0015    16                  ldc.i4.0
0016    6f 03 00 00 06      callvirt       token(0x06000003)
...
```


I still didn't know which metadata tokens corresponded to which function calls, so it was difficult to tell what most of these dynamic methods were doing. However, after running the program in dnSpy and examining the arguments passed to each dynamic method, I was able to get a rough idea as to what was happening:

* `gh` returns a string representation of a hexadecimal number, with the first 8 digits being equal to the name of a section from the executable.
* `gs` takes in the string obtained from `gh` and passes it to `pe`, which retrieves the executable section with the name matching the string. The executable section contains obfuscated bytecode.
* `d` takes in the obfuscated bytecode and somehow deobfuscates it.
* The now-deobfuscated bytecode is passed to `cl` and `wl`, which eventually results in a dynamic method being called.

### Deobfuscation

I decided to take a look at the dynamic method `d`, as it was deobfuscating the sections of the executable. The method takes two arguments: the code to be deobfuscated, and a key to be used in the deobfuscation. I recreated the deobfuscation algorithm with the following script:

```python
def decrypt_section(to_decrypt):
	#initialize key arr
	key = [0x12, 0x78, 0xab, 0xdf]
	key_arr = [0] * 256
	for i in range(256):
		key_arr[i] = key[i % 4]

	#initialize index arr
	index_arr = [i for i in range(256)]

        #first swap
	offset = 0
	for i in range(256):
		offset += key_arr[i] + index_arr[i]
		offset &= 0xff
		
		tmp = index_arr[i]
		index_arr[i] = index_arr[offset]
		index_arr[offset] = tmp

	#swap again and add
	offset = 0

	b = b''

	for j in range(1, len(to_decrypt)):
		i = j % 256	
		offset += index_arr[i]
		offset &= 0xff
		
		tmp = index_arr[i]
		index_arr[i] = index_arr[offset]
		index_arr[offset] = tmp

		xor_val = (index_arr[(index_arr[i] + index_arr[offset]) & 0xff])
		b += ((xor_val ^ to_decrypt[j-1]).to_bytes(1, 'big'))

	return b
```

The same key of `[0x12, 0x78, 0xab, 0xdf]` was used for every section, so I extracted each section of the executable using pedump and deobfuscated each one. However, when I attempted to disassemble them, there was another problem: none of the metadata tokens used in the disassembly were actually valid, with values such as `0xA698A6A0`. Clearly, there was another level of obfuscation protecting the tokens.

Based on the values I was seeing in the debugger, the most likely location for the deobfuscation was `cl`. Looking at `cl`, there was an XOR instruction that stood out:

```
0BD6    08                  ldloc.2
0BD7    20 bd a6 98 a2      ldc.i4         -1567054147
0BDC    61                  xor
0BDD    0c                  stloc.2
```

Converting the constant to an unsigned hexadecimal value, we obtain `0xA298A6BD`. This was very close to the invalid token values, so I XORed each of the tokens with this constant. Sure enough, the resulting token values were all valid.

Some of the functions still contained invalid instructions after disassembly, so there was clearly another level of obfuscation being used here. However, there were few enough of these functions that I was able to deal with the issue by setting breakpoints and dumping the deobfuscated code from dnSpy's debugger right before the dynamic method was invoked.

### Retreiving the Token Values

The disassembly now contained the correct tokens, but dncil didn't have a way of showing me which functions and fields these tokens corresponded to. I ended up dealing with this problem in a very hacky way - basically, I wrote another script to add comments to the disassembly with the correct function names.

Looking back at dnSpy, I found that the values of the metadata tokens were stored in the `Tables` stream of the executable (except for tokens corresponding to strings, which are stored in a separate table for some reason).

I then copied the tokens and their values into a text file. 

```
RID	Token	Offset	Flags	Name	Signature	Info
1	0x04000001	0x0001B91C	0x36	0x8B6	0x24	<>9
2	0x04000002	0x0001B922	0x16	0x10D	0x28	<>9__6_0
3	0x04000003	0x0001B928	0x16	0x2066	0x39	min_alive_delay
4	0x04000004	0x0001B92E	0x16	0x2076	0x39	max_alive_delay
5	0x04000005	0x0001B934	0x16	0x20A6	0x39	min_comm_delay
...
```

We can see that each token has a human-readable name for the function or object that it corresponds to. After modifying the disassembly to contain these names, we finally have something we can analyze:

```
000C    00                  nop
000D    73 02 00 00 06      newobj         token(0x06000002)      .ctor
0012    25                  dup
0013    1f 58               ldc.i4.s       88
0015    16                  ldc.i4.0
0016    6f 03 00 00 06      callvirt       token(0x06000003)      Add
...
```

### Control Flow

It still wasn't clear which dynamic methods were being called in which order. Somehow, each of the `flare` functions figured out which section of the executable to retrieve and which dynamic method to call.

I was never able to figure out the details of how the control flow worked, so it didn't end up being useful for my analysis. However, if you're curious, my best guess is that it works something like this:

* Each `flare` function calls one of the `flared` functions, which is guaranteed to throw an exception. The stack trace of that exception is then passed as an argument to the function called in the `catch` block.
* Several substrings of the stack trace are concatenated together with some of the bytecode from the function that threw an exception. Then, the SHA256 hash of the result is taken.
* Then, the string representation of the hash value is taken. This is the string that is passed as an argument to the `gs` dynamic method, which takes the first 8 characters and retrieves the section of the executable with a matching name. This section contains the obfuscated bytecode of the method that will be called next.

## Part 2: Program Logic and C2 Emulation

### First Observations

When I first traced through the program with dnSpy's debugger, it didn't seem to do much. The program generated a seemingly random string of four characters, then made a DNS request using that string as a subdomain of `flare-on.com`. The resulting IP address was stored, then passed as an argument to several functions. If a file called `flare.agent.id` didn't already exist, it would be created, and the last octet of the IP address would be written to the file along with a random number.

Afterward, the program would sleep for a long period of time, then eventually repeat the same process again. I guessed that there was probably some kind of check being performed on the IP address returned by the DNS request, and that I was probably failing this check.

To figure out what checks were being made, I would need to figure out how the IP address was being stored. I got stuck on this for a while, but I eventually found it by looking at the static fields.

As far as I know, there's no way to show static fields in the Locals window. However, when you set a breakpoint in dnSpy, you can add a logging message that prints the values of different variables, and those messages *can* display static fields.

![](https://i.imgur.com/f6s5aKh.png)


Once I figured out how to view static fields, I found that the `FLARE05` enum was being used to store information about the DNS requests. `A` was storing the subdomain of `flare-on.com`, `B` was storing the number of requests that had been made so far, and `C` was storing the IP address. I didn't know what the other members were for yet, but I'll get to that later.

Tracing through with the debugger to find when `FLARE05.C` was referenced,  I found a check in section `f9a758d3` that took the first octet as an argument. It seemed to be checking whether the value was greater than 128.

I had initially been using the IP `10.0.0.1` for fakedns, so I had been failing this check. I modified the first octet to be greater than 128, and I finally started seeing some variation in the DNS requests:

![](https://i.imgur.com/H8ZlmYD.png)


### _Send, _Receive, and _DoTask

Before, every DNS request sent by the program was for a subdomain that was 4 characters long. Now, the program was sending requests of varying lengths. Though the characters used in the requests were at least partially randomly generated, the lengths of the subdomains seemed to correlate with different behaviors.

This difference can be observed in the parameter passed to `flare_31`. One of the arguments fo `flare_31` is a function, and a different function is passed for each subdomain length.

![](https://i.imgur.com/FrBVSsy.png)


| # of characters in subdomain | Function called |
| ----------- | ----------- |
| 4      | _Alive |
| 8  | _Receive |
| 31  | _Send |
| 12 | _SendAndReceive |

I found that when _Receive or _SendAndReceive was called, the program created a text file called `flare.agent.recon`. It appeared that the program was trying and failing to run a command:

![](https://i.imgur.com/f1Ri7jS.png)

But what commands was the program capable of running? At first, none of my disassembly appeared to contain any code responsible for handling this, but I eventually found that the program was calling a function called `_DoTask` in section `4ea4cf8d` of the executable.

I initially had trouble finding `_DoTask`, as it didn't seem to appear anywhere in dnSpy's decompilation, nor did it correspond to any of the obfuscated sections of the executable. In the end, I found it by calculating its location in memory.

![](https://i.imgur.com/iqWZm8b.png)


The offset of the method can be calculated using the formula 

```
(relative virtual address of method) - (virtual address of section) + (pointer to raw data of section).
```

In this case, the RVA of _DoTask is 0x5058, the virtual address of the .text section is 0x2000, and the pointer to raw data of the .text section is 0x9000. So the address we need is 0x5058 - 0x2000 + 0x9000 is 0xc058. 

### A Closer Look at _DoTask

To understand what _DoTask does, we first need to look at section `4ea4cf8d`, where its arguments are constructed. The `ListData` parameter used here is a list of arrays, which each array storing the octets of an IP address. 

Normally, this list only contains one array corresponding to a single IP address, so the value being stored to  `taskType` is the first octet:

```
003C    7e 97 a7 98 a6      ldsfld         token(0xA698A797)      0x0400012A      ListData
0041    16                  ldc.i4.0       
0042    6f 24 a6 98 a8      callvirt       token(0xA898A624)      0x0A000099      get_Item
0047    0d                  stloc.3        
0048    08                  ldloc.2        
0049    09                  ldloc.3        
004A    16                  ldc.i4.0       
004B    91                  ldelem.u1      
004C    7d 96 a7 98 a6      stfld          token(0xA698A796)      0x0400012B      taskType
```

Each of the remaining octets of the IP address is then converted to a character in a string. This string is stored to the field `cmd` before _DoTask is called.

```
0145    11 04               ldloc.s        local(0x0004)
0147    6f 2e a6 98 a8      callvirt       token(0xA898A62E)      0x0A000093      GetString
014C    7d 90 a7 98 a6      stfld          token(0xA698A790)      0x0400012D      cmd
0151    11 0b               ldloc.s        local(0x000B)
0153    fe 06 1d a6 98 a4   ldftn          token(0xA498A61D)      0x060000A0      <_DoTask>b__0
```

Knowing this, we can figure out what _DoTask does. First, it compares `taskType` to 43:

```
001A    7b 2b 01 00 04      ldfld          token(0x0400012B)      0x0400012B      taskType
001F    1f 2b               ldc.i4.s       43
0021    fe 01               ceq 
```

If it is 43, `cmd` is then compared to a string. Each string comparison follows the same format:

```
0093    72 3d 03 00 70      ldstr          string token(0x7000033D)      0x7000033D
0098    28 4a 00 00 0a      call           token(0x0A00004A)      0x0A00004A      op_Equality
009D    13 09               stloc.s        local(0x0009)
009F    11 09               ldloc.s        local(0x0009)
00A1    2c 3e               brfalse.s      225
00A3    00                  nop            
00A4    06                  ldloc.0        
00A5    28 3e 00 00 0a      call           token(0x0A00003E)      0x0A00003E      Parse
00AA    72 43 03 00 70      ldstr          string token(0x70000343)      0x70000343
00AF    28 98 00 00 06      call           token(0x06000098)      0x06000098      flare_56
00B4    00                  nop            
00B5    72 4b 03 00 70      ldstr          string token(0x7000034B)      0x7000034B
00BA    28 09 00 00 06      call           token(0x06000009)      0x06000009      flare_04
```

There are 21 possibilities for `cmd`: the string representations of the numbers 1 through 22, excluding 6. If `cmd` matches one of these values, one of the base64-encoded PowerShell commands is passed to `flare_04`, which then runs it. If `taskType` is 43 and `cmd` doesn't match one of these values, the program simply tries to call it as an argument to the command line, followed by `&& exit`. If `taskType` is *not* 43, then no command is passed to the command line and `&& exit` is run by itself, resulting in the `&& was unexpected at this time` message we were seeing earlier.


Once the PowerShell command is run, its output is written to a `flare.agent.recon` file. As the name "recon" suggests, most of these commands seem to be intended to collect data from the victim. For example, this command lists information about what is installed on the device:

![](https://i.imgur.com/LdbPI4i.png)


I also noticed that a second string token was being loaded. Each command has a different string associated with it, with seemingly random values such as `3c9974` and `8e6`. Every time a command is run, the corresponding string is concatentated to the static field `sh`. This doesn't seem to directly have anything to do with the commands being run, so we can guess that it has to do with the flag.

At this point, we finally have some idea of what we have to do: we need to run a sequence of commands in a particular order, which will construct the correct value of `sh`, which will probably allow us to obtain the flag.

### Choosing IP Addresses

At first, it wasn't clear how to generate a `cmd` string that matched one of the command numbers. It definitely seemed like the characters of the string were based on the octets of the IP address, but in order for the comparison to work, I also needed to generate a string of the correct length. How was the length being decided?

The key to figuring this out was the fact that _DoTask was only called every other DNS request, which meant that the IP addresses from the remaining requests were being used for something else. It turned out that the last three octets of these IP addresses were being used to decide how many bytes of data would be stored from the next IP address. 

Knowing this, we can construct a sequence of IP addresses to run any of the commands. For example, if we respond with an address of the form `*.0.0.3`, then the first three octets of the next address will be saved. If the next address is `43.49.48.0`, then the task type of 43 will be saved, along with the bytes 49 and 48, which are the characters '1' and '0'. The string comparison will succeed, and command 10 will be run.

### Finding the Flag

The last step is to figure out the order of commands to run. I could see in the debugger that a string was being concatenated to `sh` after each command, so I searched for the function that was doing this, which turned out to be section `33d51cd2`. I could also see that something was being XORed with 248 and compared to a value in `FLARE15.c`:

```
0019    7e 81 a7 98 a6      ldsfld         token(0xA698A781)      0x0400013C      c
001E    16                  ldc.i4.0       
001F    6f 2b a6 98 a8      callvirt       token(0xA898A62B)      0x0A000096      get_Item
0024    02                  ldarg.0        
0025    20 f8 00 00 00      ldc.i4         248
002A    61                  xor            
002B    fe 01               ceq     
```

I XORed each value in `FLARE15.c` with 248, which gave me `[2,10,8,19,11,1,15,13,22,16,5,12,21,3,18,17,20,14,9,7,4]`.

Since each of the command numbers appeared exactly once in this sequence, it was obvious that this was the command order I was looking for. To run these commands, I responded to the program with the following list of IP addresses:

```
['143.0.0.2',
 '43.50.0.0',
 '143.0.0.3',
 '43.49.48.0',
 '143.0.0.2',
 '43.56.0.0',
 '143.0.0.3',
 '43.49.57.0',
 '143.0.0.3',
 '43.49.49.0',
 '143.0.0.2',
 '43.49.0.0',
 '143.0.0.3',
 '43.49.53.0',
 '143.0.0.3',
 '43.49.51.0',
 '143.0.0.3',
 '43.50.50.0',
 '143.0.0.3',
 '43.49.54.0',
 '143.0.0.2',
 '43.53.0.0',
 '143.0.0.3',
 '43.49.50.0',
 '143.0.0.3',
 '43.50.49.0',
 '143.0.0.2',
 '43.51.0.0',
 '143.0.0.3',
 '43.49.56.0',
 '143.0.0.3',
 '43.49.55.0',
 '143.0.0.3',
 '43.50.48.0',
 '143.0.0.3',
 '43.49.52.0',
 '143.0.0.2',
 '43.57.0.0',
 '143.0.0.2',
 '43.55.0.0',
 '143.0.0.2',
 '43.52.0.0']
```

Once this was done, the program opened an image.

![](https://i.imgur.com/qrf2i7Q.png)


This gets us our flag: `W3_4re_Kn0wn_f0r_b31ng_Dyn4m1c@flare-on.com`.

## Conclusion

Looking at the official solutions of this challenge, I now see that there's a lot I could have done better. I was only able to disassemble the code, but the intended solution actually decompiled it by patching the file at the correct offsets. When I started working on this challenge, I had no idea how .NET executables were structured, so I didn't know how to patch it in this way. I eventually ended up with a pretty good understanding of how to calculate the locations of different functions and values, but by then I was most of the way through the challenge! I guess I'll know for next time.

While I definitely did this challenge the hard way, it was incredibly interesting and I learned a lot. The idea of using IP addresses to encode commands was very clever, and I could easily see real malware using similar strategies to go unnoticed. I'm definitely going to attempt Flare-On 10 next year, and now that I have a better idea of what to expect, maybe I'll be able to finish a little faster.




