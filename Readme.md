
# Asm

A runtime Assembly (Shellcode) Development and Analysis Tool

## Overview

This is a Assembly REPL (Read-Eval-Print Loop) tool for assembling, analyzing, and executing x86-64 assembly code and shellcode in real-time.

## Features

- Disassembly with syntax highlighting
- Interactive shellcode development
- Symbol resolution and analysis
- File save/load functionality
- Hex and Assembly input modes
- Code execution

## Installation

### Prerequisites

Ensure you have the following dependencies installed:

- **Nasm**: Netwide Assembler
- **Capstone**: Disassembler library
- **Readline**: Command-line editing library

### Compilation

```bash
git clone https://github.com/x3ric/asm
cd asm
make
```

### Run

```bash
make run
```

## Commands

### Assembling
- `h` / `hex`: Enter shellcode as hexadecimal
- `a` / `asm`: Enter shellcode in assembly language

### Execution
- `r` / `run`: Execute the assembled code
- `s` / `show`: Disassemble and display the code
- `d` / `dump`: Hex dump the raw shellcode bytes
- `c` / `clear`: Clear the shellcode buffer

### File Operations
- `sv` / `save`: Save asm/shellcode to a file
- `ld` / `load`: Load asm/shellcode from a file

### Settings
- `b` / `base`: Set the base address
- `sy` / `syntax`: Toggle between Intel/AT&T syntax

### Symbol Analysis
- `sm` / `symbols`: List all symbols
- `sg` / `symgrep`: Search symbols by pattern
- `so` / `symoffset`: Get offset from main
- `sr` / `symraw`: Generate shellcode for an offset

### Help
- `?` / `help`: Display help message
- `q` / `exit`: Quit the program

## Shellcode Resources

- [ShellStorm](https://shell-storm.org/shellcode/index.html)

