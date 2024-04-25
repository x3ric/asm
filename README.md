<div align="center">

#### Overview

Basic assembly language programs and a build script tailored for Arch Linux for simplified installation.

#### Files

**build**: This is the build script for automating the build process on Arch Linux.

**lib**: Placeholder directory for any libraries or external dependencies with custom calls.

**print.asm**: Assembly program to demonstrate basic printing functionality.

**pwd.asm**: Assembly program to display the current working directory.

**system.asm**: Assembly program to execute system commands.

#### Usage

**Clone the Repository:**
   
<pre>
 git clone https://github.com/x3ric/asm
 cd asm
</pre>

**Build the Programs:**
   
   Run the build script to assemble and link the assembly programs.
   
<pre>
 ./build
</pre>

**Execute the Programs:**
   
   After successful compilation, you can execute the generated binary files.

#### Dependencies

**NASM**: NASM (Netwide Assembler) is required to assemble the assembly language programs.

**FZF**: FZF is required in the build script.

#### Notes

This repository is tailored for Arch Linux. If not on Arch Linux, install `fzf` and `asm` for compatibility.

Feel free to expand the repository with more assembly programs or enhance existing ones.

</p><a href="https://archlinux.org"><img alt="Arch Linux" src="https://img.shields.io/badge/Arch_Linux-1793D1?style=for-the-badge&logo=arch-linux&logoColor=D9E0EE&color=000000&labelColor=97A4E2"/></a><br>
