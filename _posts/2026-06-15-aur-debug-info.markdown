---
layout: post
title:  "Source code strings in the AUR malware"
date:   2026-06-15 18:30:00 -0400
categories: malware
excerpt: Analyzing debug info in eBPF binaries
---

A few days ago, hundreds of AUR packages were [compromised](https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/), with a malicious npm package called `atomic-lockfile` being added to the dependencies. As reported by [ioctl.fail](https://ioctl.fail/preliminary-analysis-of-aur-malware/), the package runs a malicious ELF executable called `deps`. 

The focus of this blog post is an embedded eBPF ELF binary that `deps` loads using a call to `bpf_object__open_mem`. When I looked at this binary, I immediately noticed that the strings contained a great deal of debug information. Specifically, I saw what looked like full lines of source code, complete with comments:

```
20 20 20 20 20 20 20 20 20 20 20 63 2d 3e 70 72  |           c->pr|
65 76 5f 6f 66 66 20 20 3d 20 63 2d 3e 6f 66 66  |ev_off  = c->off|
3b 00 20 20 20 20 20 20 20 20 20 20 20 20 20 20  |;.              |
20 20 63 2d 3e 70 72 65 76 5f 72 6c 65 6e 20 3d  |  c->prev_rlen =|
20 6d 65 72 67 65 64 3b 00 20 20 20 20 20 20 20  | merged;.       |
20 20 20 20 20 20 20 20 20 63 2d 3e 6f 66 66 20  |         c->off |
20 20 20 20 20 2b 3d 20 6e 65 78 74 5f 72 6c 65  |     += next_rle|
6e 3b 20 2f 2f 20 62 6f 74 74 6f 6d 20 61 64 64  |n; // bottom add|
73 20 72 6c 65 6e 20 e2 86 92 20 74 6f 74 61 6c  |s rlen â.. total|
```

I decided to investigate how these strings might have gotten there and how much of the source code was actually present, which turned out to be a bit of a rabbit hole. This writeup is focused on the debug info itself and doesn't really go into the malicious functionality of the code.

## Initial investigations

At first glance, if we print out all the strings from this region of the code in order, it really does look like the malware is embedding its full source code. For instance, this almost looks like a reasonable implementation of a function to convert a string to an integer.

```c
static __attribute__((noinline)) u32 name_to_pid(const char *name)
        u8 c = (u8)name[i];
        if (c == 0) break;
        if (c < '0' || c > '9') return 0;
        n = n * 10 + (c - '0');
```

However, what we're seeing clearly isn't the exact source code. Some lines are missing, like the initialization of the loop and the opening bracket after the function name.

There are also lines that occasionally appear out of order: the line `(void *)(c->buf + c->off + 16)) < 0 || rlen == 0)` here should come after `if (bpf_probe_read_user(&rlen, sizeof(rlen),`, not before.

```c
    u16 rlen = 0;
                            (void *)(c->buf + c->off + 16)) < 0 || rlen == 0)
    if (bpf_probe_read_user(&rlen, sizeof(rlen),
    char name[16] = {};
```

In order to ensure the lines were correctly ordered and get an idea of how many lines were missing, I would need to figure out how to parse the file format where the debug strings were stored.

### DWARF

I initially assumed this was DWARF info and went on a wild goose chase trying to use various DWARF parsing tools to read it. It turns out it isn't DWARF, but I'll document what I looked for anyway in the hopes that it's helpful to somebody.

The thing that threw me off initially is that DWARF *does* allow source embedding. In DWARF 5, the `DW_LNCT_source` field was introduced, which stores the full source code of the binary as a string. Clang [supports it](https://reviews.llvm.org/D42765#change-Lg43B1hAXkki) with the `-gembed-source` flag.

When I compiled a test binary with `-gembed-source`, though, the format didn't match. The AUR malware stores each line as its own null-terminated string, but the DWARF info stored the source code as a single string with newlines included. Additionally, while `llvm-dwarfdump` didn't show any source information for the malware, it did for the test binary:

```
file_names[  0]:  
          name:  .debug_line_str[0x0000002a] = "embedded_source.c"  
     dir_index: 0  
  md5_checksum: 22f3183556b123a4d647cadec6ef7675  
        source:  .debug_line_str[0x0000003c] = "#include <stdio.h>\n\nint main(int argc, char** argv) {\n    pri  
ntf(\"test embedded source\\n\");\n    return 0;\n}\n"
```

Evidently, the malware strings had nothing to do with the DWARF feature. (In retrospect, it's unlikely a malware developer would ever go out of their way to compile with `-gembed-source`, a compiler flag most people have never heard of.)

### BTF

After googling a bunch of variations of "ebpf debug info", I eventually caught on that BPF has its own debug info format called [BTF](https://docs.ebpf.io/concepts/btf/). I compiled a debug build of a test BPF binary (`clang -target bpf -g -c test.c -o test.o`), and sure enough, source code strings appeared in the binary.

```
000001d0: 7374 2e63 0069 6e74 2066 756e 6328 2920  st.c.int func()    
000001e0: 7b00 2020 2020 7265 7475 726e 2030 3b00  {.    return 0;.
```

Unfortunately, I wasn't able to find a tool to display these strings. `bpftool btf dump` prints out a lot of type info, but it ignores the source code lines entirely.

```
[1] PTR '(anon)' type_id=3
[2] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED
[3] ARRAY '(anon)' type_id=2 index_type_id=4 nr_elems=1
[4] INT '__ARRAY_SIZE_TYPE__' size=4 bits_offset=0 nr_bits=32 encoding=(none)

// [...]

[98] DATASEC 'license' size=0 vlen=1
	type_id=96 offset=0 size=4 (VAR 'LICENSE')
```

`llvm-objdump` understands the BTF format in theory, but `llvm-objdump -S` ignores the embedded source strings. Instead, it searches for the source file on disk and complains about not being able to find it.

```
0000000000000000 <walk_dirent>:  
llvm-objdump: warning: 'bpf.elf': failed to find source /cloud/scales/agent/../ebpf/scales.bpf.c
```

## The BTF format

Eventually I gave up on finding a tool and decided to analyze the file format to see if I could write a parser script myself. Luckily, the Linux kernel's [documentation](https://docs.kernel.org/bpf/btf.html) of the format is pretty good. (All of the struct definitions referenced here are taken from this documentation.)
### `.BTF` and `.BTF.ext`

The BTF information is split up into two sections of the ELF: `.BTF` and `.BTF.ext`. The table of source code strings is stored in `.BTF`, and the corresponding line numbers are stored in `.BTF.ext`.

The `.BTF` section starts with the following header:

```c
struct btf_header {
    __u16   magic;
    __u8    version;
    __u8    flags;
    __u32   hdr_len;

    /* All offsets are in bytes relative to the end of this header */
    __u32   type_off;       /* offset of type section       */
    __u32   type_len;       /* length of type section       */
    __u32   str_off;        /* offset of string section     */
    __u32   str_len;        /* length of string section     */
};
```

`str_off` and `str_len` tell us the offset and length of the string table, which is just an array of null-terminated strings. This table stores the source code lines as well as any other strings that are relevant to the debug info, such as filenames, function names, and type names.

The`.BTF.ext` function isn't nearly as straightforward. It starts with this header:

```c
struct btf_ext_header {
    __u16   magic;
    __u8    version;
    __u8    flags;
    __u32   hdr_len;

    /* All offsets are in bytes relative to the end of this header */
    __u32   func_info_off;
    __u32   func_info_len;
    __u32   line_info_off;
    __u32   line_info_len;

    /* optional part of .BTF.ext header */
    __u32   core_relo_off;
    __u32   core_relo_len;
};
```

The relevant fields here are `line_info_off` and `line_info_len`, which point to the part of the debug info that stores the source line numbers.

The Linux kernel docs give us the following definition for `line_info`:

> The line_info is organized as below.:
>
>```
>line_info_rec_size              /* __u32 value */
>btf_ext_info_sec for section #1 /* line_info for section #1 */
>btf_ext_info_sec for section #2 /* line_info for section #2 */
>...
>```

Unfortunately, the `btf_ext_info_sec` struct is more mysterious, and it's not obvious what it has to do with line numbers.

```c
struct btf_ext_info_sec {
   __u32   sec_name_off; /* offset to section name */
   __u32   num_info;
   /* Followed by num_info * record_size number of bytes */
   __u8    data[0];
};
```

The example disassembly makes this a little clearer. We can see that the information for each line number is stored as a set of four values, and that an array of these structures appear after the metadata at the start of the `line_info` section.

```
.long   16                      # LineInfo
.long   1                       # LineInfo section string offset=1
.long   2
.long   .Ltmp0
.long   7
.long   33
.long   7182                    # Line 7 Col 14
.long   .Ltmp3
.long   7
.long   58
.long   8206                    # Line 8 Col 14
```

As it turns out, the structures are `bpf_line_info` structures, which are defined in the following way:

```c
struct bpf_line_info {
    __u32   insn_off; /* [0, insn_cnt - 1] */
    __u32   file_name_off; /* offset to string table for the filename */
    __u32   line_off; /* offset to string table for the source line */
    __u32   line_col; /* line number and column number */
};
```

The only non-obvious field here is `line_col`, which stores the column in the low 10 bits and the line number in the high 12 bits.

```c
#define BPF_LINE_INFO_LINE_NUM(line_col)        ((line_col) >> 10)
#define BPF_LINE_INFO_LINE_COL(line_col)        ((line_col) & 0x3ff)
```

I think what's going on here is that the `btf_ext_info_sec` structure can store arbitrary structures in the `data` field, and in this case it happens to store `bpf_line_info` structures. In this case, `line_info_rec_size` is `sizeof(bpf_line_info) = 16`, so a `btf_ext_info_sec` struct stores `16 * num_info` bytes in its `data` field.

This is the example `line_info` with every value annotated according to its field:

```
 .long   16                      # line_info_rec_size
 .long   1                       # btf_ext_info_sec.sec_name_off
 .long   2                       # btf_ext_info_sec.num_info
 .long   .Ltmp0                  # 1st line info - bpf_line_info.insn_off
 .long   7                       # 1st line info - bpf_line_info.file_name_off
 .long   33                      # 1st line info - bpf_line_info.line_off
 .long   7182                    # 1st line info - bpf_line_info.line_col
 .long   .Ltmp3                  # 2nd line info - bpf_line_info.insn_off
 .long   7                       # 2nd line info - bpf_line_info.file_name_off
 .long   58                      # 2nd line info - bpf_line_info.line_off
 .long   8206                    # 2nd line info - bpf_line_info.line_col
```

In this example there's only one `btf_ext_info_sec` structure, but the malware had one for each function. I guess that's what a "section" means in this context.

### Parser script

Ultimately, to figure out which source lines go where, the only things we need to extract are the line number and string table offset. This script reads the `line_off` value from each of the `bpf_line_info` structures and retrieves the null-terminated string at that offset in the string table. It then matches that to the line number extracted from the `line_col` value of the `bpf_line_info`.

```python
from ctypes import *
import lief
import io

class btf_header(Structure):
    _fields_ = [
        ('magic', c_uint16),
        ('version', c_uint8),
        ('flags', c_uint8),
        ('hdr_len', c_uint32),
        ('type_off', c_uint32),
        ('type_len', c_uint32),
        ('str_off', c_uint32),
        ('str_len', c_uint32)
    ]

class btf_ext_header(Structure):
    _fields_ = [
        ('magic', c_uint16),
        ('version', c_uint8),
        ('flags', c_uint8),
        ('func_info_off', c_uint32),
        ('func_info_len', c_uint32),
        ('line_info_off', c_uint32),
        ('line_info_len', c_uint32),
        ('core_relo_off', c_uint32),
        ('core_relo_len', c_uint32)
    ]

class bpf_line_info(Structure):
    _fields_ = [
        ('insn_off', c_uint32),
        ('file_name_off', c_uint32),
        ('line_off', c_uint32),
        ('line_col', c_uint32)
    ]

elf: lief.ELF.Binary = lief.ELF.parse('bpf.elf')

for section in elf.sections:
    if section.name == '.BTF':
        btf = section.content.tobytes()
    if section.name == '.BTF.ext':
        btf_ext = section.content.tobytes()

header = btf_header.from_buffer_copy(btf)

type_offset = header.type_off + sizeof(btf_header)
str_offset = header.str_off + sizeof(btf_header)

string_table = btf[str_offset:str_offset + header.str_len]

ext_header = btf_ext_header.from_buffer_copy(btf_ext)
line_info_offset = ext_header.line_info_off + sizeof(btf_ext_header)

# this should really go from line_info_offset - line_info_offset + ext_header.line_info_len, but the value of line_info_len is wrong for some reason
line_stream = io.BytesIO(btf_ext[line_info_offset:])

unknown = line_stream.read(8)

lines = {}
max_line = 0

while True:
    unknown2 = line_stream.read(4)
    num_infos = int.from_bytes(line_stream.read(4), 'little')
    
    # this is a hack to stop reading once we hit the end of line_info, since line_info_len is wrong
    if num_infos == 0:
        break

    for i in range(num_infos):
        buf = line_stream.read(sizeof(bpf_line_info))
        if len(buf) < sizeof(bpf_line_info):
            break

        info = bpf_line_info.from_buffer_copy(buf)
        line_no = info.line_col >> 10
        if line_no > max_line:
            max_line = line_no

        # read a null terminated string from the string table
        line_str = string_table[info.line_off:string_table.find(b'\x00', info.line_off)]
        lines[line_no] = line_str
        print(line_str)

for i in range(max_line):
    if i in lines:
        print(lines[i].decode('utf-8'))
    else:
        print('/* missing line */')
```

The full output of the script can be found [here](/assets/aur_debug_lines.txt).

## The reassembled source lines

Unfortunately, the debug info doesn't contain as much of the source code as I would've hoped. In a couple of places, there are gaps consisting of more than a hundred lines, suggesting that entire functions may be missing debug info. However, it may still be useful for analysis, especially when compared against the disassembly or decompilation of the eBPF bytecode. Some functions are nearly complete, except for the lines that contain things like whitespace or single curly braces.

```c
int net_exit_openat(struct sys_exit_ctx *ctx)
/* missing line */
    u64 id = bpf_get_current_pid_tgid();
    if (!bpf_map_lookup_elem(&net_open_temp, &id)) return 0;
    bpf_map_delete_elem(&net_open_temp, &id);
    long fd = ctx->ret;
    if (fd < 0) return 0;
    u32 tgid = (u32)(id >> 32);
    u64 key  = ((u64)tgid << 32) | (u32)fd;
    u8 val = 1;
    bpf_map_update_elem(&net_fds, &key, &val, BPF_ANY);
/* missing line */
}
```

I plan on doing some follow-up posts describing what the eBPF binary actually does, along with some analysis of the main malware executable.
