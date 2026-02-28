# Complete mcode_t Opcode Reference

## Opcode Encoding Convention

Microcode instructions follow a consistent pattern:
- **Unary**: `opcode l → d` (one source, one destination)
- **Binary**: `opcode l, r → d` (two sources, one destination)
- **Control flow**: `opcode l(, r)(, d)` where d is typically a block reference
- **Memory**: `ldx seg, off → d` and `stx val, seg, off`

Operand sizes are tracked per-operand via `mop_t.size` (in bytes).

## Full Opcode List

### No Operation
| Opcode | Value | Format | Description |
|--------|-------|--------|-------------|
| `m_nop` | 0x00 | — | No operation; placeholder |

### Data Movement
| Opcode | Format | Description |
|--------|--------|-------------|
| `m_stx` | stx l, r, d | Store: *[r+d] = l |
| `m_ldx` | ldx l, r → d | Load: d = *[l+r] |
| `m_ldc` | ldc l → d | Load constant into d |
| `m_mov` | mov l → d | Move: d = l |

### Unary Arithmetic / Logic
| Opcode | Format | Description |
|--------|--------|-------------|
| `m_neg` | neg l → d | Two's complement: d = -l |
| `m_lnot` | lnot l → d | Logical NOT: d = !l (0 or 1) |
| `m_bnot` | bnot l → d | Bitwise NOT: d = ~l |

### Size Conversion
| Opcode | Format | Description |
|--------|--------|-------------|
| `m_xds` | xds l → d | Sign-extend l to d.size bytes |
| `m_xdu` | xdu l → d | Zero-extend l to d.size bytes |
| `m_low` | low l → d | Truncate: keep low d.size bytes of l |
| `m_high` | high l → d | Extract: keep high d.size bytes of l |

### Binary Arithmetic
| Opcode | Format | Description |
|--------|--------|-------------|
| `m_add` | add l, r → d | d = l + r |
| `m_sub` | sub l, r → d | d = l - r |
| `m_mul` | mul l, r → d | d = l * r |
| `m_udiv` | udiv l, r → d | d = l / r (unsigned) |
| `m_sdiv` | sdiv l, r → d | d = l / r (signed) |
| `m_umod` | umod l, r → d | d = l % r (unsigned) |
| `m_smod` | smod l, r → d | d = l % r (signed) |

### Binary Bitwise
| Opcode | Format | Description |
|--------|--------|-------------|
| `m_or` | or l, r → d | d = l \| r |
| `m_and` | and l, r → d | d = l & r |
| `m_xor` | xor l, r → d | d = l ^ r |

### Shift
| Opcode | Format | Description |
|--------|--------|-------------|
| `m_shl` | shl l, r → d | d = l << r (logical shift left) |
| `m_shr` | shr l, r → d | d = l >> r (logical shift right, zero-fill) |
| `m_sar` | sar l, r → d | d = l >> r (arithmetic shift right, sign-fill) |

### Comparison (set condition)
| Opcode | Format | Description |
|--------|--------|-------------|
| `m_sets` | sets l → d | d = (l with sign flag) |
| `m_seto` | seto l, r → d | d = overflow(l, r) |
| `m_setp` | setp l, r → d | d = parity(l, r) |
| `m_setnz` | setnz l, r → d | d = (l != r) ? 1 : 0 |
| `m_setz` | setz l, r → d | d = (l == r) ? 1 : 0 |
| `m_setae` | setae l, r → d | d = (l >= r unsigned) ? 1 : 0 |
| `m_setb` | setb l, r → d | d = (l < r unsigned) ? 1 : 0 |
| `m_seta` | seta l, r → d | d = (l > r unsigned) ? 1 : 0 |
| `m_setbe` | setbe l, r → d | d = (l <= r unsigned) ? 1 : 0 |
| `m_setg` | setg l, r → d | d = (l > r signed) ? 1 : 0 |
| `m_setge` | setge l, r → d | d = (l >= r signed) ? 1 : 0 |
| `m_setl` | setl l, r → d | d = (l < r signed) ? 1 : 0 |
| `m_setle` | setle l, r → d | d = (l <= r signed) ? 1 : 0 |

### Conditional Jumps
| Opcode | Format | Description |
|--------|--------|-------------|
| `m_jcnd` | jcnd l, d | if l then goto block d |
| `m_jnz` | jnz l, r, d | if l != r goto block d |
| `m_jz` | jz l, r, d | if l == r goto block d |
| `m_jae` | jae l, r, d | if l >= r (unsigned) goto block d |
| `m_jb` | jb l, r, d | if l < r (unsigned) goto block d |
| `m_ja` | ja l, r, d | if l > r (unsigned) goto block d |
| `m_jbe` | jbe l, r, d | if l <= r (unsigned) goto block d |
| `m_jg` | jg l, r, d | if l > r (signed) goto block d |
| `m_jge` | jge l, r, d | if l >= r (signed) goto block d |
| `m_jl` | jl l, r, d | if l < r (signed) goto block d |
| `m_jle` | jle l, r, d | if l <= r (signed) goto block d |

### Unconditional Control Flow
| Opcode | Format | Description |
|--------|--------|-------------|
| `m_goto` | goto l | Unconditional jump to block l.b |
| `m_jtbl` | jtbl l, r | Jump table (switch statement) |
| `m_ijmp` | ijmp l | Indirect jump: goto address in l |

### Function Calls
| Opcode | Format | Description |
|--------|--------|-------------|
| `m_call` | call l, d | Direct call: d = func(args) |
| `m_icall` | icall l, d | Indirect call: d = (*l)(args) |
| `m_ret` | ret | Return from function |

### Stack Operations
| Opcode | Format | Description |
|--------|--------|-------------|
| `m_push` | push l | Push l onto stack |
| `m_pop` | pop d | Pop from stack into d |

## Implementation Notes for Constant Propagation

When implementing a constant propagation engine, these are the opcodes you typically need:

**Must handle** (core data flow):
`m_mov`, `m_ldx`, `m_stx`, `m_ldc`

**Should handle** (common arithmetic):
`m_add`, `m_sub`, `m_mul`, `m_xor`, `m_and`, `m_or`, `m_shl`, `m_shr`, `m_sar`

**Good to handle** (size conversions — frequently emitted):
`m_xdu`, `m_xds`, `m_low`, `m_high`

**Nice to have** (unary, division):
`m_neg`, `m_bnot`, `m_lnot`, `m_udiv`, `m_sdiv`, `m_umod`, `m_smod`

**Special handling**:
- `m_stx` with `mop_r` destination: check if the register points to a stack address (via LEA/address-of tracking)
- `m_ldx` with `mop_S` or resolved stack address: read from stack state
- `m_ldx` with `mop_v` or resolved global address: read from IDB via `ida_bytes`
