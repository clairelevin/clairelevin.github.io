---
layout: post
title:  "Experimenting with Binary Ninja IL rewriting"
date:   2026-01-25 10:10:00 -0400
categories: ctf
excerpt: Trying (and failing) to solve a crackme with the IL modification API
---

Every year after Flare-On ends, I tell myself that I should really take the time to learn more about deobfuscation. One of the projects I've been meaning to do for a while is to figure out how to use Binary Ninja's [IL modification API](https://docs.binary.ninja/dev/bnil-modifying.html), so I decided to pick out a challenge from crackmes.one and see if I could improve the decompilation by modifying ILs.

The crackme I used was [The Obfuscator's Riddle](https://crackmes.one/crackme/684917e72b84be7ea77437c1), an obfuscated binary of medium difficulty. My goal was to solve the crackme entirely statically by using IL modification to produce a clean decompilation. Unfortunately, I didn't succeed at doing this, but there are so few writeups on IL modification that it's still probably helpful to document everything that I tried. Also, I want to come back to this project at some point, and if I write it all down in a blog post I'll at least have a prayer of remembering what I was doing.

I did manage to deobfuscate the binary, but it was through binary patching, not IL modification. The patching script and the solution to the crackme are included at the end ofthe writeup.

## Challenge Overview

As usual for these types of challenges, we're prompted for a password:

```c
140001081        write_console("Enter password: ", 0x10)
140001091        int128_t buffer = zx.o(0)
140001099        uint32_t numberOfCharsRead[0x6]
140001099        numberOfCharsRead[0] = 0
1400010ad        uint64_t rbx = 0x10
1400010c1        ReadConsoleA(hConsoleInput: GetStdHandle(nStdHandle: STD_INPUT_HANDLE), 
1400010c1            lpBuffer: &buffer, nNumberOfCharsToRead: 0x10, 
1400010c1            lpNumberOfCharsRead: &numberOfCharsRead, pInputControl: nullptr)
```

However, after the password prompt we're faced with a long switch statement that has 0xef different cases. At the end of each case, the variable `rax_2` is set to a different value between 0 and 0xef, followed by a jump to a "dispatcher" block at `0x31b8`. Weirdly, Binary Ninja didn't decompile the switch case at first, but rebasing to a base address of 0 fixed it. 

```c
0000119d            switch (rcx_5)
000011ca                case 1
000011ca                    rax_2.b = 0xbe
000011cc                    goto label_31b8
0000211b                case 3
0000211b                    rax_2.b = 0xb5
0000211d                    goto label_31b8
00001d9c                case 4
00001d9c                    rax_2.b = 0xe7
00001d9e                    goto label_31b8
00002d8e                case 5
00002d8e                    rax_2.b = 0x2b
00002d90                    goto label_31b8
000015e8                case 6
000015e8                    rax_2.b = 0x15
000015ea                    goto label_31b8
```

This is a classic case of control flow flattening. `rax_2` stores a state variable that's used as an offset into a jump table, and the dispatcher at `0x31b8` jumps to the address stored at `[jumptable base address] + 4 * rax_2`. Since the decompiler doesn't understand how the state variable is used by the dispatcher to calculate where to jump next, it can't reconstruct the control flow graph of the binary, leading to a "flattened" view where every basic block ends with a jump to the dispatcher. (If you're unfamiliar with control flow flattening, there are a lot of detailed writeups on different forms of it, like this one from  [OLLVM](https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening) or this one from [Tigress](https://tigress.cs.arizona.edu/transformPage/docs/flatten/index.html).)

## Binary Ninja IL Modification

### Patching with JUMP instructions

My first thought was to look through the MLIL for jumps to the dispatcher block, then replace them with direct jumps to the target address that would be calculated within the dispatcher block based on the state variable. Finding the jumps was easy, as the jumps to the dispatcher block followed a predictable pattern of setting the `al` register to the next state value, followed by a jump to the dispatcher:

```
70 @ 000011b5  rax_2.al = 0x2c
71 @ 000011b7  goto 1026 @ 0x31b8
```

This made it relatively easy to write a function to check whether a set of two MLIL instructions corresponded to a CFF-obfuscated jump.

```python
def is_cff(first, second):
    if len(first.operands) < 3 or len(second.operands) < 1:
        return False
    if second.operands[0] != DISPATCHER_LOC:
        return False
    if type(first) != MediumLevelILSetVarField or type(second) != MediumLevelILGoto:
        return False
    if type(first.operands[0]) != Variable or type(first.operands[2]) != MediumLevelILConst:
        return False
    return True
```

I then tried searching through the MLIL to find all instances of the CFF pattern, using the `replace_expr` function to replace the jumps to the dispatcher with jumps to the target address. (Like a lot of the other IL modification functions, the instruction to be replaced by `replace_expr` is specified by its "expression index". Notably, the expression index of an instruction is *not* the index where the instruction appears in the IL: the first MLIL instruction in the crackme binary has expression index 4, not 0. The expression indices 0 through 3 are actually assigned to the the operands of the first instruction, which are themselves expressions.)

```python
for block in analysis_context.mlil.basic_blocks:
    for i in range(len(block) - 1):
        first = block[i]
        second = block[i + 1]

        if is_cff(first, second):
            idx = first.operands[2]
            jump_target = JUMPTABLE_ADDR + bv.read_int(JUMPTABLE_ADDR + 4 * idx.value.value, 4)
            log_info(f'Found jump offset {hex(idx.value.value)} at address {hex(first.address)}')

            analysis_context.mlil.replace_expr(second.expr_index, analysis_context.mlil.jump(analysis_context.mlil.const(8, jump_target)))
            log_info(f'Replaced jump at {hex(second.address)} with jump to {hex(jump_target)}')
```

I then added the modification function as a step in the analysis workflow so that it would be called whenever a function was analyzed. Most of the examples of MLIL modification suggest inserting the modification step right after `core.function.generateMediumLevelIL`, but when I tried to do this, I got an exception in `core.function.analyzeIndirectBranches` step with the message `invalid access to LLIL instruction`. I'm not sure why this happened, but I'm guessing it's because the new MLIL instructions inserted into the function aren't actually backed by any underlying LLIL instructions. Inserting the modification function after `core.function.analyzeIndirectBranches` fixed the issue. 

```python
wf = Workflow("core.function.metaAnalysis").clone("core.function.metaAnalysis")

wf.register_activity(Activity(
    configuration=json.dumps({
        "name": "extension.fix_cff",
        "title": "Fix CFF",
        "description": "Replace control flow flattening instructions with direct jumps.",
        "eligibility": {
            "auto": {
                "default": True
            }
        }
    }),
    action=fix_cff
))

wf.insert_after("core.function.analyzeIndirectBranches", [
    "extension.fix_cff"
])

wf.register()
```

In general, it seems like IL modification is somewhat experimental, with very little error handling when things go wrong. I ran into some difficult-to-diagnose errors, especially when I tried modifying LLIL rather than MLIL - sometimes Binary Ninja would segfault, and other times the analysis workflow appeared to get stuck in an infinite loop of analyzing and reanalyzing. My guess is a lot of these problems have to do with the fact that my IL modifications resulted in major changes to the control flow, and that IL modification might work better if I used it to clean up data-level obfuscation (e.g., opaque constants) as opposed to control flow obfuscation.

This was the working script that I ended up with:

```python
DISPATCHER_LOC = 380
JUMPTABLE_ADDR = 0x418c

def is_cff(first, second):
    if len(first.operands) < 3 or len(second.operands) < 1:
        return False
    if second.operands[0] != DISPATCHER_LOC:
        return False
    if type(first) != MediumLevelILSetVarField or type(second) != MediumLevelILGoto:
        return False
    if type(first.operands[0]) != Variable or type(first.operands[2]) != MediumLevelILConst:
        return False
    return True
 
def fix_cff(analysis_context: AnalysisContext):
    log_info(f"Starting CFF replacement for function {analysis_context.function}")

    for block in analysis_context.mlil.basic_blocks:
        for i in range(len(block) - 1):
            first = block[i]
            second = block[i + 1]

            if is_cff(first, second):
                idx = first.operands[2]
                jump_target = JUMPTABLE_ADDR + bv.read_int(JUMPTABLE_ADDR + 4 * idx.value.value, 4)
                log_info(f'Found jump offset {hex(idx.value.value)} at address {hex(first.address)}')

                analysis_context.mlil.replace_expr(second.expr_index, analysis_context.mlil.jump(analysis_context.mlil.const(8, jump_target)))
                log_info(f'Replaced jump at {hex(second.address)} with jump to {hex(jump_target)}')

    analysis_context.mlil.finalize()
    analysis_context.mlil.generate_ssa_form()


wf = Workflow("core.function.metaAnalysis").clone("core.function.metaAnalysis")

wf.register_activity(Activity(
    configuration=json.dumps({
        "name": "extension.fix_cff",
        "title": "Fix CFF",
        "description": "Replace control flow flattening instructions with direct jumps.",
        "eligibility": {
            "auto": {
                "default": True
            }
        }
    }),
    action=fix_cff
))

wf.insert_after("core.function.analyzeIndirectBranches", [
    "extension.fix_cff"
])

wf.register()
```

While this script did, in fact, successfully replace the jumps to the dispatcher with jumps to the target address, it didn't produce an unflattened decompilation. The long switch case was still there, and it was full of jumps to hard-coded addresses, e.g, `jump(0x2209)`:

```c
0000119d            switch (jump_table_14000418c[zx.q(rcx_5 - 1)])
0000119d                case 0xffffcff2
0000119d                    continue
000011a0                case 0xffffd014
000011a0                    rax_2 = 0
000031b8                label_31b8:
000031b8                    rcx_4 = rbp_1
000031ba                    rdx_1 = r14_1
000031bd                    continue
000031bd                    continue
000011a7                case 0xffffd01b
000011a7                    rax_2.b = 0xe8
00003214                    jump(0x2209)
000011ae                case 0xffffd022
000011ae                    rax_2.b = 0x33
00003214                    jump(0x14db)
000011b5                case 0xffffd029
```

As it turns out, the primary instructions used in MLIL control flow are not `JUMP` instructions, but `GOTO` instructions. A `JUMP` instruction targets a specific memory address, whereas a `GOTO` targets an MLIL expression index. Since the documentation on IL modification mentioned that adding new `GOTO` expressions can be more complicated than adding other types of IL instructiions, I had hoped that it would be possible to get a good result by using a `JUMP` in place of a `GOTO`, but apparently not.

### Patching with GOTO instructions

#### Labels

The Binary Ninja documentation gives the following explanation of how to add new `GOTO` IL instructions:

> When you are trying to insert *LIL_GOTO, *LIL_IF, and *LIL_JUMP_TO instructions, you will need to specify the IL destination as a *LevelILLabel. Your destination must be a properly marked label, which is actually rather tricky to obtain. This is because there is currently no way to get a label for already-emitted IL Instructions, so if you want to modify the control flow of a function, you will need to do a [Copy Transformation](https://docs.binary.ninja/dev/bnil-modifying.html#adding-instructions-and-replacing-multiple-instructions-copy-transformation) as described above. This may change in future versions.

I was a little confused about what exactly this meant, but I eventually came across [this GitHub issue](https://github.com/Vector35/binaryninja-api/issues/7189) that clarified things slightly:

> The general idea is that you need to mark labels at the start of basic blocks and have the goto target those labels. If the goto is emitted before the label though, what do you do? In that case, make the label ahead of time and mark it when you get to the block.

Unfortunately, there aren't many examples that demonstrate the correct use of labels, but after some experimenting I was eventually able to figure out the following:

* IL basic blocks are constructed by emitting one instruction at a time. It's not possible to insert new IL instructions at arbitrary locations in a basic block, which is why any modification more complicated than replacing one IL instruction with one other IL instruction requires a completely new basic block to be constructed.
* Any IL instruction that can be targeted by a direct branch (`GOTO`, `JUMP_TO`) or an indirect branch (`IF`) needs to have a "label" attached to it. When a branch instruction is constructed, the label needs to be passed to it to specify the destination of the branch.
* Labels need to be "emitted" just like instructions. You can't attach a label to an arbitrary IL instruction, the label has to be attached to the instruction _at the same time the instruction is being emitted._
* It's possible to construct a label without immediately specifying the location that the label points to. The `mark_label()` function associates a label with a particular IL location, and it can be called anytime after a label is created. When `mark_label()` is called on a label, the label points to the next IL instruction to be emitted.
* What happens if the branch instruction comes before the branch target in the basic block? Since the target instruction hasn't been emitted yet, there's no label that can be used to construct the branch instruction. In this case, you need to create a new label without marking it, then keep track of that label and call `mark_label()` on it later when the target instruction is emitted.

According to the documentation, when copying an IL function, we're supposed to be able to use the function `MediumLevelILFunction.get_label_for_source_instruction()` to obtain a label that corresponds to the start of a basic block. In practice, however, this function often returned `None` without giving me much indication as to why. I ultimately didn't end up using `get_label_for_source_instruction()` in my script.

#### Writing the replacement script

An MLIL `GOTO` expression takes a label for a basic block as its target, but a jump table is just a list of memory addresses. In order to figure out the equivalent `GOTO` instruction to construct for each jump in the jump table, I needed to figure out which MLIL instructions were present at each of the targeted addresses. Since the dispatcher is represented in MLIL as a long switch case targeting each location in the jump table, I figured I could construct a map from addresses to MLIL just by finding the target address of each case in the switch statement.

```python
blocks = {}
dispatcher = old_func.get_basic_block_at(DISPATCHER_LOC)
for e in dispatcher.outgoing_edges:
    insn = e.target[0]
    blocks[insn.address] = insn.expr_index
```

However, in my initial attempt at writing the script I ran into an issue where some of the jump target addresses weren't the addresses of any MLIL instructions. This has to do with how addresses get assigned to more complex MLIL instructions like `if`/`then`/`else`. For instance, the following MLIL instruction is assigned an address of `0x12a9`:

```
1542 @ 000012a9  if (rdx_4 == i_23) then 1650 @ 0x2db2 else 1652 @ 0x12af
```

However, looking at the disassembly that was lifted into this MLIL instruction, it actually begins at `0x12a7`. If a jump table were to jump there, it would jump to `0x12a7`, not `0x12a9`.

```
000012a7  cmp     edx, ecx
000012a9  je      0x2dad
```

The issue here is that an `if`/`then`/`else` MLIL instruction is lifted from two instructions: a comparison and a branch. The comparison comes before the branch, but it's the address of the branch instruction that's considered to be the "address" of the MLIL instruction. More generally, MLIL instructions can be constructed out of complicated trees of expressions and sub-expressions, and the underlying disassembly behind those instructions can come from completely different locations in memory. As a result of this, it doesn't necessarily make sense to talk about "the address" of an MLIL instruction, so the approach I took to figure out jump targets probably wasn't a very good one. 

The hacky workaround I used in my script was to iterate through the operands of each of the MLIL instructions and associate their addresses with the MLIL instruction as well. In the case of the comparison above, for example, its first operand is the `MediumLevelILCmpE` expression `rdx_4 == i_23`. Since it's lifted from the `cmp edx, ecx` instruction, its address is `0x12a7`.

```python
mlil_addresses = {}
for i in range(len(old_func)):
    insn = old_func[i]
    if insn.address not in mlil_addresses:
        mlil_addresses[insn.address] = insn.address
    for op in insn.operands:
        try:
            if op.address not in mlil_addresses:
                mlil_addresses[op.address] = insn.address
        except:
            pass
```

Having (mostly) associated the MLIL instructions with their addresses, it was then possible to construct a new IL function. The jumps to the dispatcher were replaced with GOTO instructions that pointed to the jump target, and all other MLIL instructions were copied over unchanged. While copying each instruction, I maintained a dictionary called `labels` that associated each label with the memory address it targeted.

```python
if is_cff(first, second, dispatcher[0].expr_index):
    idx = first.operands[2]
    jump_target = JUMPTABLE_ADDR + bv.read_int(JUMPTABLE_ADDR + 4 * (idx.value.value - 1), 4)
    if jump_target in mlil_addresses:
        jump_target = mlil_addresses[jump_target]

    if jump_target not in labels:
        label = MediumLevelILLabel()
        labels[jump_target] = label
    else:
        label = labels[jump_target]

    new_expr = new_func.goto(label, loc=ILSourceLocation.from_instruction(second))
    new_func.append(new_expr, ILSourceLocation.from_instruction(second))
    log_info(f'Replaced jump at {hex(second.address)} with jump to {hex(jump_target)}')
else:
    try:
        emit_insn(new_func, second, labels)
    except Exception as e:
        log_warn(f'Could not emit instruction: {e}. Emitting NOP instead.')
        new_func.append(new_func.nop(ILSourceLocation.from_instruction(second)), ILSourceLocation.from_instruction(second))
```

To copy MLIL instructions, I defined a function called `emit_insn`. Before copying each instruction, the function checked to see if its address was associated with an existing label that needed to be marked. If so, it marked the label, otherwise it created a new label for the instruction and marked it immediately. In this way, all of the newly created `GOTO` instructions ended up with correctly marked labels once the new MLIL was done being emitted.

```python
def emit_insn(new_func, insn, labels):
    if insn.address in labels:
        new_func.mark_label(labels[insn.address])
    else:
        label = MediumLevelILLabel()
        labels[insn.address] = label
        new_func.mark_label(labels[insn.address])
    
    new_func.append(insn.copy_to(new_func), ILSourceLocation.from_instruction(insn))
```

The full script:

```python
DISPATCHER_LOC = 380
JUMPTABLE_ADDR = 0x418c

# Look for the following pattern:
# state.al = [next state]
# goto 380 @ 0x31b8
def is_cff(first, second, dispatcher):
    if len(first.operands) < 3 or len(second.operands) < 1:
        return False
    if second.operands[0] != DISPATCHER_LOC:
        return False
    if type(first) != MediumLevelILSetVarField or type(second) != MediumLevelILGoto:
        return False
    if type(first.operands[0]) != Variable or type(first.operands[2]) != MediumLevelILConst:
        return False
    return True

def emit_insn(new_func, insn, labels):
    if insn.address in labels:
        new_func.mark_label(labels[insn.address])
    else:
        label = MediumLevelILLabel()
        labels[insn.address] = label
        new_func.mark_label(labels[insn.address])
    
    new_func.append(insn.copy_to(new_func), ILSourceLocation.from_instruction(insn))

def fix_cff(analysis_context: AnalysisContext):
    labels = {}
    
    old_func = analysis_context.mlil
    new_func = MediumLevelILFunction(old_func.arch, low_level_il=analysis_context.llil)

    blocks = {}
    dispatcher = old_func.get_basic_block_at(DISPATCHER_LOC)
    for e in dispatcher.outgoing_edges:
        insn = e.target[0]
        blocks[insn.address] = insn.expr_index

    # Deal with instructions like if/then/else where the operands are at a different memory address than the MLIL instruction itself
    mlil_addresses = {}
    for i in range(len(old_func)):
        insn = old_func[i]
        if insn.address not in mlil_addresses:
            mlil_addresses[insn.address] = insn.address
        for op in insn.operands:
            try:
                if op.address not in mlil_addresses:
                    mlil_addresses[op.address] = insn.address
            except:
                pass

    new_func.prepare_to_copy_function(old_func)

    for old_block in old_func.basic_blocks:
        new_func.prepare_to_copy_block(old_block)

        first_insn = old_block[0]
        new_func.set_current_address(first_insn.address, old_block.arch)
        emit_insn(new_func, first_insn, labels)

        for i in range(1, len(old_block)):
            first: MediumLevelILInstruction = old_block[i - 1]
            second: MediumLevelILInstruction = old_block[i]  
            new_func.set_current_address(second.address, old_block.arch)

            if is_cff(first, second, dispatcher[0].expr_index):
                idx = first.operands[2]
                jump_target = JUMPTABLE_ADDR + bv.read_int(JUMPTABLE_ADDR + 4 * (idx.value.value - 1), 4)
                if jump_target in mlil_addresses:
                    jump_target = mlil_addresses[jump_target]

                if jump_target not in labels:
                    label = MediumLevelILLabel()
                    labels[jump_target] = label
                else:
                    label = labels[jump_target]

                new_expr = new_func.goto(label, loc=ILSourceLocation.from_instruction(second))
                new_func.append(new_expr, ILSourceLocation.from_instruction(second))
                log_info(f'Replaced jump at {hex(second.address)} with jump to {hex(jump_target)}')
            else:
                try:
                    emit_insn(new_func, second, labels)
                except Exception as e:
                    log_warn(f'Could not emit instruction: {e}. Emitting NOP instead.')
                    new_func.append(new_func.nop(ILSourceLocation.from_instruction(second)), ILSourceLocation.from_instruction(second))

    new_func.finalize()
    new_func.generate_ssa_form()

    analysis_context.mlil = new_func

wf = Workflow("core.function.metaAnalysis").clone("core.function.metaAnalysis")

wf.register_activity(Activity(
    configuration=json.dumps({
        "name": "extension.fix_cff",
        "title": "Fix CFF",
        "description": "Replace control flow flattening instructions with direct jumps.",
        "eligibility": {
            "auto": {
                "default": True
            }
        }
    }),
    action=fix_cff
))

wf.insert_after("core.function.analyzeIndirectBranches", [
    "extension.fix_cff",
])

wf.register()
```

Unfortunately, this script wasn't any more successful than the previous one at getting me an unflattened binary. As a reminder, this is what the decompilation looked like before running the script:

```c
0000119d            switch (rcx_5)
000011ca                case 1
000011ca                    rax_2.b = 0xbe
000011cc                    goto label_31b8
0000211b                case 3
0000211b                    rax_2.b = 0xb5
0000211d                    goto label_31b8
00001d9c                case 4
00001d9c                    rax_2.b = 0xe7
00001d9e                    goto label_31b8
// [...]
```

And this is what it looked like after:

```c
0000119d            switch (jump_table_14000418c[zx.q(rcx_5 - 1)])
0000119d                case 0xffffcff2
0000119d                    continue
0000119d                case 0xffffd014
0000119d                    goto label_11a0
0000119d                case 0xffffd01b
0000119d                    goto label_11a7
0000119d                case 0xffffd022
0000119d                    goto label_11ae
// [...]
```

The long switch case is still there, even though all the GOTO instructions have been changed. There were a few CFF blocks that my script missed, so it's possible the decompilation would've worked better if I'd managed to detect and rewrite them. However, it's also possible that swapping out individual MLIL instructions doesn't do much to rewrite the control flow graph, and I would've had to do a much more substantial rewrite of the function in order to get rid of the dispatcher block entirely. Additionally, I'm not sure exactly where in the analysis process Binary Ninja tries to simplify the control flow graph, so maybe the script runs too late in the workflow to be able to make a difference (although, one of the official [examples](https://github.com/Vector35/binaryninja-api/blob/2f1d09c6b714a9f2664eab0a9dbef79e3cbd8919/python/examples/wf_unflatten.py) of the API performs unflattening at the MLIL level, so that's unlikely). 

At this point, my script had gotten kind of hacky and unmanageable, so I decided to stop trying to solve the crackme this way. I still think IL rewriting has a lot of promise as a deobfuscation technique, but it's probably easier to use in situations that don't involve drastic modification to the control flow. In addition, as the script got to be longer and more complicated, it probably would've been better to switch to using the C++ or Rust APIs. I think the C++ API is the most supported way of doing this, so maybe I'll try that next time.

## Binary Patching

I did eventually manage to get a nice-looking decompilation, but it was with binary patching using keystone and capstone. This is a much more well-documented topic than IL modification, so I'm not going to go through the script line by line, but I'll still provide it here for reference. Essentially, it replaces jumps to the dispatcher with jumps to the real target address, and it replaces the `cmove`/`cmovne`/`cmovb` instructions that set the state with the corresponding conditional jump instructions.

I looked for jumps to the dispatcher by using capstone to search for the pattern `mov al, ??; jmp 0x31b8`, which worked *almost* all of the time but wasn't quite perfect. The manual patches in the script were to deal with dispatcher jumps that didn't quite fit the pattern. For example, `mov al, 0x9f; xor edi, edi; jmp     0x31b8` wasn't detected as a jump to be unflattened because of the extra `xor edi, edi` in the middle. There's probably a better way to do this than trying to match exact sequences of instructions, which will likely be the topic of a future blog post once I look into it more.

The script:

```python
import struct
import pefile
from capstone import *
from capstone.x86 import *
from keystone import *

baseaddr = 0x0
dispatcher_rva = baseaddr + 0x31b8
jumptable_rva = baseaddr + 0x418c
pe = pefile.PE('crackme.exe')
mapped =  bytearray(pe.get_memory_mapped_image())
text = mapped[0x1000:0x3250]

def get_jump_target(idx):
    jump_offset = jumptable_rva + (idx - 1) * 4 - baseaddr
    target = struct.unpack('<i', mapped[jump_offset:jump_offset+4])[0] + jumptable_rva
    return target

def get_cond_targets(cmov, first_op, second_op):
    if first_op.operands[0].reg == X86_REG_EAX:
        eax_target = get_jump_target(first_op.operands[1].imm)
        other_target = get_jump_target(second_op.operands[1].imm)
    else:
        eax_target = get_jump_target(second_op.operands[1].imm)
        other_target = get_jump_target(first_op.operands[1].imm)

    return f'{cond_mappings[cmov.mnemonic]} {hex(other_target)}; jmp {hex(eax_target)}'

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True

ks = Ks(KS_ARCH_X86, KS_MODE_64)

cond_mappings = {'cmove': 'je', 'cmovne': 'jne', 'cmovb': 'jb'}

# disassemble the entire .text section
instructions = []
for i in md.disasm(text, baseaddr+0x1000):
    instructions.append(i)

# find all the jumps to the dispatcher
dispatcher_jmps = []
for i in range(len(instructions)):
    insn = instructions[i]
    if insn.mnemonic == 'jmp':
        for op in insn.operands:
            if op.type == X86_OP_IMM:
                if op.imm == dispatcher_rva:
                    dispatcher_jmps.append(i)

compare_locs = {}
for jmp_loc in dispatcher_jmps:
    insn = instructions[jmp_loc]
    prev = instructions[jmp_loc - 1]
    equiv = None

    # Patch direct jumps to dispatcher:
    # 00002c30  b0d1               mov     al, 0xd1
    # 00002c32  e981050000         jmp     0x31b8
    if prev.mnemonic == 'mov':
        patch_len = insn.size + prev.size
        patch_loc = prev.address
        target = get_jump_target(prev.operands[1].imm)
        equiv = f'jmp {hex(target)}'

    # Patch conditional jumps to dispatcher:
    # 00002c1e  b936000000         mov     ecx, 0x36
    # 00002c23  b8c8000000         mov     eax, 0xc8
    # 00002c28  0f45c1             cmovne  eax, ecx  {0x36}
    # 00002c2b  e988050000         jmp     0x31b8
    elif 'cmov' in prev.mnemonic:
        compare_locs[prev.address] = jmp_loc - 1
        first_op = instructions[jmp_loc - 3]
        second_op = instructions[jmp_loc - 2]
        patch_len = insn.size + prev.size + first_op.size + second_op.size
        patch_loc = first_op.address

        equiv = get_cond_targets(prev, first_op, second_op)
        
    if equiv is not None:
        patch_opcodes = ks.asm(equiv, as_bytes=True, addr=patch_loc)[0]
        padded = patch_opcodes + b'\x90' * (patch_len - len(patch_opcodes))
        pe.set_bytes_at_rva(patch_loc - baseaddr, padded)

# Find the conditional mov instructions reached by a jump, ex:
# 00001267  483b5c2438         cmp     rbx, qword [rsp+0x38 {var_e0}]
# 0000126c  b999000000         mov     ecx, 0x99
# 00001271  b8cd000000         mov     eax, 0xcd
# 00001276  e96e0e0000         jmp     0x20e9
# [...]
# 000020e9  0f42c1             cmovb   eax, ecx
# 000020ec  e9c7100000         jmp     0x31b8
compare_jumps = {}
for i in range(len(instructions)):
    insn = instructions[i]
    if insn.mnemonic == 'jmp':
        for op in insn.operands:
            if op.type == X86_OP_IMM:
                if op.imm in compare_locs:
                    compare_jumps[i] = compare_locs[op.imm]

for i, compare_loc in compare_jumps.items():
    insn = instructions[i]
    first_op = instructions[i - 2]
    second_op = instructions[i - 1]

    patch_len = insn.size + first_op.size + second_op.size
    patch_loc = first_op.address

    cmov = instructions[compare_loc]
    equiv = get_cond_targets(cmov, first_op, second_op)
    patch_opcodes = ks.asm(equiv, as_bytes=True, addr=patch_loc)[0]

    padded = patch_opcodes + b'\x90' * (patch_len - len(patch_opcodes))
    pe.set_bytes_at_rva(patch_loc - baseaddr, padded)

# Patch the last few cases where the instruction pattern is different from the others
# Ex., an extra instruction between the mov and the jump to the dispatcher:
# 000024cf  b09f               mov     al, 0x9f
# 000024d1  31ff               xor     edi, edi  {0x0}
# 000024d3  e9e00c0000         jmp     0x31b8
pe.set_bytes_at_rva(0x1272, b'\xe9\x6a\x03\x00\x00')
pe.set_bytes_at_rva(0x1381, b'\xe9\x48\x0d\x00\x00')
pe.set_bytes_at_rva(0x1518, b'\xe9\x89\x0e\x00\x00')
pe.set_bytes_at_rva(0x24d3, b'\xe9\x16\xf6\xff\xff')
pe.set_bytes_at_rva(0x28eb, b'\xe9\xf2\xeb\xff\xff')

# Insert a mov ebp, ecx instruction after the XOR loop, since we're not reaching the mov in the dispatcher
pe.set_bytes_at_rva(0x28e6, b'\x89\xcd')

pe.write('patched_cs.exe')
```

## Solving The Crackme

With the control flow flattening removed, we obtain the following decompilation:

```c  
1400014f1        while (true)
1400014f1            input = var_58
1400014f6            int32_t state = -0x5a4c3827
1400014fc            rax_2.b = 0x78
1400014fe            int64_t i = 0
140001505            int64_t var_e8_1 = 0
14000281c            BOOL input_char
14000281c            int32_t or_chars
14000281c            input_char, or_chars = IsDebuggerPresent()
14000281c            
140002824            if (input_char == 0)
140001b95                if (rcx_3 != 0)
14000126c                    for (; i u< rcx_3; i += 1)
1400024b4                        uint8_t xored
1400024b4                        
1400024b4                        if (i u< 0x10)
1400024ba                            input_char.b = input[i]
1400017e8                            uint64_t substituted
1400017e8                            substituted.b = sbox[zx.q(input_char.b)]
1400012d7                            xored = (state u>> 8).b ^ substituted.b
1400012d7                        
1400012be                        if (i u>= 0x10 || i u>= 0x10)
1400031f3                            fail()
1400031f3                            noreturn
1400031f3                        
1400012c4                        xor_buf[i] = xored
14000264b                        state = (zx.d(xored) << 8 ^ state) * 0xc2b2ae3d + 0x1f2e3d4c
14000264b                    
14000140f                    while (i_1 u< 0x10)
1400028ca                        if (i_1 u>= 0x10)
140003200                            fail()
140003200                            noreturn
140003200                        
1400028d7                        or_chars.b = target[i_1]
1400028db                        or_chars.b ^= xor_buf[i_1]
1400028e0                        or_chars.b |= or_chars_1.b
1400028e3                        i_1 += 1
1400028e6                        or_chars_1 = or_chars
1400028e6                    
140002878                    input_char.b = or_chars_1.b == 0
140002878                    
140002c1e                    if ((input_char.b & 1) != 0)
14000137f                        input_char.b = 0xe0
14000137f                        
1400012e6                        for (; i_2 u< 0x20; i_2 += 1)
140002a9f                            if (i_2 u>= 0x20)
140003214                            label_140003214:
140003214                                fail()
140003214                                noreturn
140003214                            
140002ab1                            console_msg[i_2] = access_granted[i_2] ^ 0xcd
140002ab1                        
14000278b                        write_console(check_alnum(&console_msg, 0x20), 0x20)
140002790                        continue
140002790                
1400024cf                input_char.b = 0x9f
1400024cf                
1400020df                for (i_2 = 0; i_2 u< 0xe; i_2 += 1)
140001f85                    if (i_2 u>= 0xe)
140001f85                        goto label_140003214
140001f85                    
140001f97                    console_msg[i_2] = access_denied[i_2] ^ 0xcd
140001f97                
1400017c9                write_console(check_alnum(&console_msg, 0xe), 0xe)
```

After all that, it turns out the validation function is very simple. First, there's a debugger check, which we don't care about since we're solving everything statically. Then, each character of the input is encrypted using a custom algorithm that uses a substitution box followed by an XOR with a running keystream generated by an LCG. The encrypted input is XORed with the target value `8b4bb25cd9a29e4a009aac337f6d359d`, and each byte of the result is ORed together and compared to 0, a way of checking if all bytes in the XORed result are 0. If the comparison to the target value succeeds, the string `Congratulations, Access granted` is XOR decoded with the key `0xcd` and printed to the console.

The encryption algorithm is the following:

```python
MASK32 = 0xffff_ffff

sbox = bytearray.fromhex("""51c25966c4e9e36c1e1a19cab4db17717241fa3b3739c626a8e8f99502da556f
702449b957d9de69a4150386bd625d6553fdfe6d892dd56bf7ec21a1602c22f4
18c5cb807f4c52768442f5932b48835bb18e0fba081661f8bf0d05dc1f9e9b0e
df38e1c3b7999d7e5aeabba340ac3eab00f0b690964acf63bc27ce3faf752ff1
cc58aa44f6740c28871bed2e68ad4b8c01097d46368288d4549a50a2d37847d2
6e0a7c8def35a9dda025d710e6f3b23381d0ee731cfb8556ffc1113cd177310b
6406290713d82a98325cc9794f9f8fb5e4b36aeb91b8ae7b43cdfc5f8b30e7d6
c05e4da6453d7a141d679c2092e5f2344e94a7c7be97c8a5e023b0048ae23a12""")

def encrypt(data):
    state = 0xa5b3c7d9
    xored = bytearray()

    for i in data:
        substituted = sbox[i] 
        xored_char = ((state >> 8) & 0xff) ^ substituted
        xored.append(xored_char)
        state = ((((i << 8 ^ state) * 0xc2b2ae3d) & MASK32) + 0x1f2e3d4c) & MASK32

    return xored
```

Inverting the algorithm is straightforward. The generation of the keystream from the LCG is the same for encryption and decryption, so we just need to run the ciphertext through an inverse S-box and apply the XOR with the keystream again.

```python
inv_sbox = bytearray(b'\x00'*0x100)
for i in range(len(sbox)):
    inv_sbox[sbox[i]] = i

def decrypt(data):
    state = 0xa5b3c7d9
    xored = bytearray()

    for i in data:
        xored_char = ((state >> 8) & 0xff) ^ i
        xored.append(inv_sbox[xored_char])
        state = ((((i << 8 ^ state) * 0xc2b2ae3d) & MASK32) + 0x1f2e3d4c) & MASK32

    return xored
```

Applying the decryption function to the target sequence of bytes `8b4bb25cd9a29e4a009aac337f6d359d`, we obtain the password: `ElementaryMyDr!!`.
