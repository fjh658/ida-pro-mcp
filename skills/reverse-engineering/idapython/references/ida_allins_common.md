# Common ida_allins Instruction Constants

## x86 / x86_64 (prefix: `NN_`)

### Data Movement
| Constant | Instruction | Notes |
|----------|-------------|-------|
| `NN_mov` | MOV | General move |
| `NN_push` | PUSH | Push to stack |
| `NN_pop` | POP | Pop from stack |
| `NN_lea` | LEA | Load effective address |
| `NN_xchg` | XCHG | Exchange |
| `NN_movzx` | MOVZX | Move with zero-extend |
| `NN_movsx` | MOVSX | Move with sign-extend |
| `NN_movsxd` | MOVSXD | Move with sign-extend (32→64) |

### Arithmetic & Logic
| Constant | Instruction | Notes |
|----------|-------------|-------|
| `NN_add` | ADD | Addition |
| `NN_sub` | SUB | Subtraction |
| `NN_imul` | IMUL | Signed multiply |
| `NN_idiv` | IDIV | Signed divide |
| `NN_and` | AND | Bitwise AND |
| `NN_or` | OR | Bitwise OR |
| `NN_xor` | XOR | Bitwise XOR |
| `NN_shl` | SHL | Shift left |
| `NN_shr` | SHR | Logical shift right |
| `NN_sar` | SAR | Arithmetic shift right |
| `NN_neg` | NEG | Two's complement |
| `NN_not` | NOT | One's complement |
| `NN_inc` | INC | Increment |
| `NN_dec` | DEC | Decrement |

### Comparison & Test
| Constant | Instruction | Notes |
|----------|-------------|-------|
| `NN_cmp` | CMP | Compare (SUB without storing) |
| `NN_test` | TEST | Test (AND without storing) |

### Conditional Jumps (Jcc)
Jcc instructions come in complementary pairs with itype difference of 1:

| Constant | Instruction | Complement |
|----------|-------------|------------|
| `NN_jo` | JO (overflow) | `NN_jno` |
| `NN_jno` | JNO | `NN_jo` |
| `NN_jb` | JB / JNAE / JC | `NN_jnb` |
| `NN_jnb` | JNB / JAE / JNC | `NN_jb` |
| `NN_jz` | JZ / JE | `NN_jnz` |
| `NN_jnz` | JNZ / JNE | `NN_jz` |
| `NN_jbe` | JBE / JNA | `NN_ja` |
| `NN_ja` | JA / JNBE | `NN_jbe` |
| `NN_js` | JS (sign) | `NN_jns` |
| `NN_jns` | JNS | `NN_js` |
| `NN_jp` | JP / JPE (parity) | `NN_jnp` |
| `NN_jnp` | JNP / JPO | `NN_jp` |
| `NN_jl` | JL / JNGE | `NN_jge` |
| `NN_jge` | JGE / JNL | `NN_jl` |
| `NN_jle` | JLE / JNG | `NN_jg` |
| `NN_jg` | JG / JNLE | `NN_jle` |

**Complementary pair detection**: `abs(insn1.itype - insn2.itype) == 1`

### Unconditional Control Flow
| Constant | Instruction | Notes |
|----------|-------------|-------|
| `NN_jmp` | JMP | Unconditional jump |
| `NN_jmpni` | JMP near indirect | Jump through register/memory |
| `NN_call` | CALL | Function call |
| `NN_retn` | RETN | Near return |
| `NN_retf` | RETF | Far return |
| `NN_nop` | NOP | No operation |
| `NN_int` | INT | Software interrupt |
| `NN_int3` | INT3 | Breakpoint |

---

## ARM64 / AArch64 (prefix: `ARM_`)

### Data Movement
| Constant | Instruction | Notes |
|----------|-------------|-------|
| `ARM_mov` | MOV | General move |
| `ARM_movz` | MOVZ | Move with zero |
| `ARM_movn` | MOVN | Move with NOT |
| `ARM_movk` | MOVK | Move keep (patch 16-bit field) |
| `ARM_ldr` | LDR | Load register |
| `ARM_str` | STR | Store register |
| `ARM_ldp` | LDP | Load pair |
| `ARM_stp` | STP | Store pair (common in prologues: `STP X29, X30, [SP, #-N]!`) |
| `ARM_adr` | ADR | PC-relative address |
| `ARM_adrp` | ADRP | Page-relative address |

### Arithmetic & Logic
| Constant | Instruction | Notes |
|----------|-------------|-------|
| `ARM_add` | ADD | Addition |
| `ARM_sub` | SUB | Subtraction |
| `ARM_mul` | MUL | Multiply |
| `ARM_and` | AND | Bitwise AND |
| `ARM_orr` | ORR | Bitwise OR |
| `ARM_eor` | EOR | Bitwise XOR |
| `ARM_lsl` | LSL | Logical shift left |
| `ARM_lsr` | LSR | Logical shift right |
| `ARM_asr` | ASR | Arithmetic shift right |
| `ARM_neg` | NEG | Negate |
| `ARM_mvn` | MVN | Bitwise NOT |

### Comparison & Test (Flag Setters)
| Constant | Instruction | Notes |
|----------|-------------|-------|
| `ARM_cmp` | CMP | Compare (alias for SUBS with ZR dest) |
| `ARM_cmn` | CMN | Compare negative (alias for ADDS with ZR dest) |
| `ARM_tst` | TST | Test bits (alias for ANDS with ZR dest) |

### Control Flow
| Constant | Instruction | Notes |
|----------|-------------|-------|
| `ARM_b` | B | Unconditional branch |
| `ARM_bl` | BL | Branch with link (call) |
| `ARM_br` | BR | Branch to register (indirect) |
| `ARM_blr` | BLR | Branch with link to register |
| `ARM_ret` | RET | Return |
| `ARM_cbz` | CBZ | Compare and branch if zero |
| `ARM_cbnz` | CBNZ | Compare and branch if not zero |
| `ARM_tbz` | TBZ | Test bit and branch if zero |
| `ARM_tbnz` | TBNZ | Test bit and branch if not zero |

### B.cond (Conditional Branch)
ARM64 conditional branches use a single `B.cond` encoding where the condition code is in the
lowest 4 bits of the instruction word. The `itype` in IDA maps to condition-specific variants,
but condition code complement detection still requires reading raw encoding:

```python
# Decode condition code from B.cond instruction
val = ida_bytes.get_dword(ea)
if (val & 0xFF000010) == 0x54000000:  # B.cond encoding
    cond_code = val & 0xF
    complement = cond_code ^ 1  # Flip lowest bit
```

### Special
| Constant | Instruction | Notes |
|----------|-------------|-------|
| `ARM_nop` | NOP | No operation (`D503201F`) |
| `ARM_svc` | SVC | Supervisor call (syscall) |
| `ARM_brk` | BRK | Breakpoint |
| `ARM_ldrsw` | LDRSW | Load register signed word (watch for literal pool loads) |

## Architecture-Independent Detection

Prefer SDK functions over itype checks when possible:

```python
import ida_idp, ida_ua

insn = ida_ua.insn_t()
if ida_ua.decode_insn(insn, ea) > 0:
    ida_idp.is_ret_insn(insn)              # Any RET variant
    ida_idp.is_call_insn(insn)             # Any CALL variant
    ida_idp.is_indirect_jump_insn(insn)    # JMP reg / BR Xn
    ida_idp.is_basic_block_end(insn)       # Terminates a basic block
```
