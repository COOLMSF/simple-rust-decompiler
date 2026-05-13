# simple-decompiler

An x86/x86_64 binary decompiler written in Rust that produces C code.

## Features

- **Binary loading**: ELF and PE format support via `goblin`
- **Disassembly**: x86/x86_64 decoding via `iced-x86`
- **IR lifting**: x86 instructions → custom intermediate representation
- **Analysis**: Control flow graph, dominator tree, loop detection
- **Code generation**: Structured C code with if/else, while loops, function calls

## Build

```bash
cargo build --release
```

## Usage

```bash
# List all discovered functions
decomp -l input_binary

# Decompile all functions to stdout
decomp input_binary

# Decompile specific functions (by name or address)
decomp -f add -f factorial input_binary

# Write output to file
decomp -o output.c input_binary

# Verbose mode
decomp -v input_binary
```

## Architecture

```
src/
├── main.rs          # CLI entry point (clap)
├── binary/mod.rs    # ELF/PE loader (goblin)
├── disasm/mod.rs    # x86 disassembler (iced-x86)
├── ir/
│   ├── mod.rs       # IR type definitions
│   └── lift.rs      # x86 → IR lifting
├── analysis/mod.rs  # CFG, dominators, loops
└── codegen/mod.rs   # IR → C code generation
```

## Pipeline

1. **Load** binary (ELF/PE) → sections, symbols, entry point
2. **Discover** functions from symbols + CALL targets
3. **Disassemble** each function into x86 instructions
4. **Lift** x86 instructions to IR (virtual registers, basic blocks)
5. **Analyze** control flow (CFG, dominator tree, loop detection)
6. **Generate** structured C code from IR

## Limitations

- Produces low-level C (virtual register assignments, not high-level expressions)
- No type inference beyond uint32_t/uint64_t
- No variable name recovery
- Limited handling of indirect calls/jumps
- x86/x86_64 only (no ARM support)
