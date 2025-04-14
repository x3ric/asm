#include <capstone/capstone.h>
#include <sys/ioctl.h>

int hex_to_val(char c) {
    if ('0'<=c&&c<='9') return c-'0';
    if ('a'<=c&&c<='f') return 10+c-'a';
    if ('A'<=c&&c<='F') return 10+c-'A';
    return -1;
}

int parse_hex(const char *input) {
    int len = 0;
    const char *p = input;
    while (*p&&len<MAX_CODE_LEN) {
        while (*p&&(isspace(*p)||*p=='\\'||*p=='x'||*p=='X')) p++;
        if (*p=='0'&&(*(p+1)=='x'||*(p+1)=='X')) p+=2;
        if (!*p||!*(p+1)) break;
        if (!isxdigit(*p)||!isxdigit(*(p+1))) {p++; continue;}
        int hi=hex_to_val(*p), lo=hex_to_val(*(p+1));
        if (hi<0||lo<0) {p++; continue;}
        code[len++]=(hi<<4)|lo;
        p+=2;
    }
    return len;
}

void hex_dump() {
    if (!code_len) {printf("%sNo code%s\n", C_R, C_0); return;}
    for (int i=0; i<code_len; i++) {
        if (i%16==0) printf("\n%s%04x:%s ", C_G, i, C_0);
        printf("%s%02x%s%s", C_G, code[i], (i%2)?" ":"", C_0);
    }
    printf("\n\n%s\\x%s", C_Y, C_0);
    for (int i=0; i<code_len; i++) printf("%02x", code[i]);
    printf("\n");
}

void show_stats(size_t count, cs_insn *insn) {
    int cats[8] = {0};
    char *labels[] = {"Jump/Call", "Data", "Math", "Logic", "Sys", "Cmp", "Other"};
    for (size_t i=0; i<count; i++) {
        char* mnem = insn[i].mnemonic;
        if (strstr(mnem,"jmp")||strstr(mnem,"call")||strstr(mnem,"ret")||strncmp(mnem,"j",1)==0) cats[0]++;
        else if (strstr(mnem,"mov")||strstr(mnem,"lea")||strstr(mnem,"push")||strstr(mnem,"pop")) cats[1]++;
        else if (strstr(mnem,"add")||strstr(mnem,"sub")||strstr(mnem,"mul")||strstr(mnem,"div")) cats[2]++;
        else if (strstr(mnem,"and")||strstr(mnem,"or")||strstr(mnem,"xor")||strstr(mnem,"not")) cats[3]++;
        else if (strstr(mnem,"syscall")||strstr(mnem,"int")) cats[4]++;
        else if (strstr(mnem,"cmp")||strstr(mnem,"test")) cats[5]++;
        else cats[6]++;
    }
    printf("\n");
    for (int i=0; i<7; i++)
        if (cats[i]) printf("%s%s%s:%d ", instr_color(labels[i]), labels[i], C_0, cats[i]);
    printf("\n");
}

void show_asm() {
    if (!code_len) {printf("%sNo code%s\n", C_R, C_0); return;}
    csh handle;
    cs_insn *insn;
    size_t count;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)!=CS_ERR_OK) {
        printf("%sFailed disassembly%s\n", C_R, C_0);
        return;
    }
    cs_option(handle, CS_OPT_SYNTAX, syntax_mode ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL);
    count = cs_disasm(handle, code, code_len, base_addr, 0, &insn);
    if (count>0) {
        printf("%s%db/%dI:%s\n", C_G, code_len, (int)count, C_0);
        for (size_t i=0; i<count; i++) {
            printf("%s%04lx:%s%s%-7s%s%s\n", 
                  C_G, insn[i].address, C_0, 
                  instr_color(insn[i].mnemonic), insn[i].mnemonic, C_0, insn[i].op_str);
        }
        show_stats(count, insn);
        cs_free(insn, count);
    } else printf("%sFailed disassembly%s\n", C_R, C_0);
    cs_close(&handle);
}

int assemble_asm(const char *asm_code) {
    char temp_asm[] = "/tmp/asmXXXXXX";
    char temp_obj[] = "/tmp/objXXXXXX";
    int asm_fd = mkstemp(temp_asm);
    if (asm_fd == -1) {
        perror("mkstemp (asm source)");
        return 0;
    }
    int obj_fd = mkstemp(temp_obj);
    if (obj_fd == -1) {
        perror("mkstemp (obj output)");
        close(asm_fd);
        remove(temp_asm);
        return 0;
    }
    close(obj_fd);
    remove(temp_obj);
    while (*asm_code && isspace(*asm_code))
        asm_code++;
    if (!*asm_code) {
        close(asm_fd);
        remove(temp_asm);
        return 0;
    }
    write(asm_fd, asm_code, strlen(asm_code));
    close(asm_fd);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nasm -f bin -o %s %s 2>/tmp/nasm_err", temp_obj, temp_asm);
    int ret = system(cmd);
    if (ret != 0) {
        printf("%sAsm failed:%s\n", C_R, C_0);
        FILE *err = fopen("/tmp/nasm_err", "r");
        if (err) {
            char buf[256];
            while (fgets(buf, sizeof(buf), err))
                printf("%s", buf);
            fclose(err);
        }
        printf("Preprocessed Assembly:\n%s\n", asm_code);
        remove(temp_asm);
        remove(temp_obj);
        remove("/tmp/nasm_err");
        return 0;
    }
    FILE *obj = fopen(temp_obj, "rb");
    if (!obj) {
        perror("Obj file");
        remove(temp_asm);
        remove(temp_obj);
        return 0;
    }
    code_len = fread(code, 1, MAX_CODE_LEN, obj);
    fclose(obj);
    remove(temp_asm);
    remove(temp_obj);
    remove("/tmp/nasm_err");
    return code_len;
}

void save_code() {
    if (!code_len) {
        printf("%sNo code to save%s\n", C_R, C_0);
        return;
    }
    if (filename[0] == '\0') {
        char input[256];
        printf("File: ");
        if (!fgets(input, sizeof(input), stdin))
            return;
        input[strcspn(input, "\r\n")] = 0;
        if (input[0] == '\0') {
            printf("%sNo filename provided%s\n", C_R, C_0);
            return;
        }
        strcpy(filename, input);
    }
    char *ext = strrchr(filename, '.');
    if (ext && (strcasecmp(ext, ".asm") == 0)) {
        FILE *f = fopen(filename, "w");
        if (!f) {
            perror("File");
            return;
        }
        csh handle;
        cs_insn *insn;
        size_t count;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            printf("%sFailed to initialize disassembler%s\n", C_R, C_0);
            fclose(f);
            return;
        }
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
        count = cs_disasm(handle, code, code_len, 0, 0, &insn);
        if (count > 0) {
            int has_jmp_call = 0;
            int has_write_syscall = 0;
            int has_string_data = 0;
            size_t string_start = 0;
            size_t jmp_idx = 0, call_idx = 0;
            for (size_t i = 0; i < count; i++) {
                if (strcmp(insn[i].mnemonic, "jmp") == 0) {
                    jmp_idx = i;
                    has_jmp_call = 1;
                }
                if (has_jmp_call && strcmp(insn[i].mnemonic, "call") == 0) {
                    call_idx = i;
                }
                if (strcmp(insn[i].mnemonic, "mov") == 0 && 
                    strstr(insn[i].op_str, "rax") && 
                    strstr(insn[i].op_str, "1")) {
                    has_write_syscall = 1;
                }
            }
            if (has_write_syscall) {
                for (size_t i = 0; i < count; i++) {
                    if (strncmp(insn[i].mnemonic, "ins", 3) == 0 ||
                        strncmp(insn[i].mnemonic, "outs", 4) == 0 ||
                        strcmp(insn[i].mnemonic, "and") == 0 ||
                        strcmp(insn[i].mnemonic, "jae") == 0) {
                        int weird_count = 0;
                        for (size_t j = i; j < count && j < i + 5; j++) {
                            if (strncmp(insn[j].mnemonic, "ins", 3) == 0 ||
                                strncmp(insn[j].mnemonic, "outs", 4) == 0 ||
                                strcmp(insn[j].mnemonic, "and") == 0 ||
                                strncmp(insn[j].mnemonic, "j", 1) == 0) {
                                weird_count++;
                            }
                        }
                        if (weird_count >= 2) {
                            has_string_data = 1;
                            string_start = insn[i].address;
                            break;
                        }
                    }
                }
            }
            fprintf(f, "BITS 64\nsection .text\nglobal _start\n\n_start:\n");
            if (has_jmp_call && call_idx > jmp_idx) {
                for (size_t i = 0; i < count; i++) {
                    if (has_string_data && insn[i].address >= string_start) {
                        continue;
                    }
                    char hex_bytes[64] = {0};
                    char *hex_ptr = hex_bytes;
                    for (uint8_t j = 0; j < insn[i].size; j++)
                        hex_ptr += sprintf(hex_ptr, "%02x ", insn[i].bytes[j]);
                    char fixed_op_str[256];
                    strcpy(fixed_op_str, insn[i].op_str);
                    char *ptr_pos = strstr(fixed_op_str, " ptr ");
                    if (ptr_pos)
                        memmove(ptr_pos, ptr_pos + 5, strlen(ptr_pos + 5) + 1);
                    char *rip_pos = strstr(fixed_op_str, "[rip");
                    if (rip_pos) {
                        char offset[32] = {0};
                        if (sscanf(rip_pos, "[rip + %[^]]", offset) == 1) {
                            sprintf(rip_pos, "[rel $+%s]", offset);
                        } else {
                            strcpy(rip_pos, "[rel $]");
                        }
                    }
                    if (i == jmp_idx) {
                        fprintf(f, "    jmp end         ; %s\n", hex_bytes);
                        if (i + 1 < count) {
                            fprintf(f, "start:\n");
                        }
                    } else if (i == call_idx) {
                        fprintf(f, "end:\n");
                        fprintf(f, "    call start      ; %s\n", hex_bytes);
                    } else {
                        fprintf(f, "    %s %s ; %s\n", insn[i].mnemonic, fixed_op_str, hex_bytes);
                    }
                }
                size_t last_instr_addr = insn[count-1].address;
                size_t last_instr_size = insn[count-1].size;
                size_t data_start = last_instr_addr + last_instr_size;
                if (data_start < code_len) {
                    fprintf(f, "    db ");
                    for (size_t i = data_start; i < code_len; i++) {
                        fprintf(f, "0x%02x", code[i]);
                        if (i < code_len - 1)
                            fprintf(f, ", ");
                    }
                    fprintf(f, "\n");
                }
            } else if (has_write_syscall && has_string_data) {
                for (size_t i = 0; i < count; i++) {
                    if (insn[i].address >= string_start) {
                        continue;
                    }
                    char hex_bytes[64] = {0};
                    char *hex_ptr = hex_bytes;
                    for (uint8_t j = 0; j < insn[i].size; j++)
                        hex_ptr += sprintf(hex_ptr, "%02x ", insn[i].bytes[j]);
                    char fixed_op_str[256];
                    strcpy(fixed_op_str, insn[i].op_str);
                    char *ptr_pos = strstr(fixed_op_str, " ptr ");
                    if (ptr_pos)
                        memmove(ptr_pos, ptr_pos + 5, strlen(ptr_pos + 5) + 1);
                    if (strcmp(insn[i].mnemonic, "lea") == 0 && strstr(fixed_op_str, "rsi") && strstr(fixed_op_str, "[rip")) {
                        fprintf(f, "    lea rsi, [rel message] ; %s\n", hex_bytes);
                    } else {
                        fprintf(f, "    %s %s ; %s\n", insn[i].mnemonic, fixed_op_str, hex_bytes);
                    }
                }
                fprintf(f, "message:\n");
                fprintf(f, "    db ");
                int is_printable = 1;
                for (size_t i = string_start; i < code_len; i++) {
                    unsigned char c = code[i];
                    if ((c < 32 || c > 126) && c != 10 && c != 13 && c != 9) {
                        is_printable = 0;
                        break;
                    }
                }
                if (is_printable) {
                    fprintf(f, "'");
                    for (size_t i = string_start; i < code_len; i++) {
                        unsigned char c = code[i];
                        if (c == '\n') fprintf(f, "', 0x0a");
                        else if (c == '\r') fprintf(f, "', 0x0d");
                        else if (c == '\t') fprintf(f, "', 0x09");
                        else if (c == '\'') fprintf(f, "', \"'\", '");
                        else fprintf(f, "%c", c);
                    }
                    if (code[code_len-1] != '\n' && code[code_len-1] != '\r' && code[code_len-1] != '\t')
                        fprintf(f, "'");
                } else {
                    for (size_t i = string_start; i < code_len; i++) {
                        fprintf(f, "0x%02x", code[i]);
                        if (i < code_len - 1)
                            fprintf(f, ", ");
                    }
                }
                fprintf(f, "\n");
            } else {
                for (size_t i = 0; i < count; i++) {
                    char hex_bytes[64] = {0};
                    char *hex_ptr = hex_bytes;
                    for (uint8_t j = 0; j < insn[i].size; j++)
                        hex_ptr += sprintf(hex_ptr, "%02x ", insn[i].bytes[j]);
                    char fixed_op_str[256];
                    strcpy(fixed_op_str, insn[i].op_str);
                    char *ptr_pos = strstr(fixed_op_str, " ptr ");
                    if (ptr_pos)
                        memmove(ptr_pos, ptr_pos + 5, strlen(ptr_pos + 5) + 1);
                    char *rip_pos = strstr(fixed_op_str, "[rip");
                    if (rip_pos) {
                        char offset[32] = {0};
                        if (sscanf(rip_pos, "[rip + %[^]]", offset) == 1) {
                            sprintf(rip_pos, "[rel $+%s]", offset);
                        } else {
                            strcpy(rip_pos, "[rel $]");
                        }
                    }
                    fprintf(f, "    %s %s ; %s\n", insn[i].mnemonic, fixed_op_str, hex_bytes);
                }
                size_t disassembled_size = 0;
                for (size_t i = 0; i < count; i++) {
                    disassembled_size += insn[i].size;
                }
                if (disassembled_size < code_len) {
                    fprintf(f, "    db ");
                    for (size_t i = disassembled_size; i < code_len; i++) {
                        fprintf(f, "0x%02x", code[i]);
                        if (i < code_len - 1)
                            fprintf(f, ", ");
                    }
                    fprintf(f, "\n");
                }
            }
            cs_free(insn, count);
            fclose(f);
            printf("%sSaved %zu instructions to %s%s\n", C_G, count, filename, C_0);
        } else {
            printf("%sFailed to disassemble code%s\n", C_R, C_0);
            fclose(f);
        }
        cs_close(&handle);
    } else {
        FILE *f = fopen(filename, "wb");
        if (!f) {
            perror("File");
            return;
        }
        if (ext && (strcasecmp(ext, ".txt") == 0)) {
            fprintf(f, "shellcode = \"");
            for (int i = 0; i < code_len; i++)
                fprintf(f, "\\x%02x", code[i]);
            fprintf(f, "\"\n");
        } else {
            size_t written = fwrite(code, 1, code_len, f);
            if (written != code_len)
                printf("%sError writing entire file%s\n", C_R, C_0);
        }
        fclose(f);
        printf("%sSaved %d bytes to %s%s\n", C_G, code_len, filename, C_0);
    }
    filename[0] = '\0';
}

void load_file_wrapper(const char *filename) {
    char *ext = strrchr(filename, '.');
    if (ext && (strcasecmp(ext, ".asm") == 0)) {
        FILE *f = fopen(filename, "r");
        if (!f) {
            perror("File");
            return;
        }
        
        // First, read the entire file to analyze it
        char file_content[MAX_CODE_LEN * 4] = {0};
        size_t file_size = 0;
        char line[1024];
        
        while (fgets(line, sizeof(line), f) && file_size < sizeof(file_content) - 1) {
            strcat(file_content, line);
            file_size += strlen(line);
        }
        rewind(f);
        
        // Check for jump-call pattern 
        int has_jmp_end = strstr(file_content, "jmp end") != NULL;
        int has_call_start = strstr(file_content, "call start") != NULL;
        int has_start_label = strstr(file_content, "start:") != NULL;
        int has_end_label = strstr(file_content, "end:") != NULL;
        
        char cleaned_input[MAX_CODE_LEN * 4] = {0};
        char *cleaned_ptr = cleaned_input;
        
        // Add standard headers
        strcpy(cleaned_ptr, "BITS 64\nsection .text\nglobal _start\n\n_start:\n");
        cleaned_ptr += strlen(cleaned_ptr);
        
        if (has_jmp_end && has_call_start && has_start_label && has_end_label) {
            // This is a jump-call pattern shellcode, rearrange correctly
            // First add the jmp end instruction
            while (fgets(line, sizeof(line), f)) {
                char *start = line;
                while (*start && isspace(*start)) 
                    start++;
                
                if (*start == '\0' || *start == ';' || *start == '#')
                    continue;
                
                // Remove ptr keyword
                char *ptr_pos = strstr(start, " ptr ");
                if (ptr_pos)
                    memmove(ptr_pos, ptr_pos + 5, strlen(ptr_pos + 5) + 1);
                
                // Skip headers we've already added
                if (strncmp(start, "BITS", 4) == 0 ||
                    strncmp(start, "section", 7) == 0 ||
                    strncmp(start, "global", 6) == 0 ||
                    strstr(start, "_start:"))
                    continue;
                
                // When we find jmp end, add it and break to process the rest in order
                if (strstr(start, "jmp end")) {
                    // Remove any trailing comments
                    char *comment = strchr(start, ';');
                    if (comment) *comment = '\0';
                    
                    sprintf(cleaned_ptr, "    jmp end\n");
                    cleaned_ptr += strlen(cleaned_ptr);
                    break;
                }
            }
            
            // Now add the start label and all code until end:
            sprintf(cleaned_ptr, "start:\n");
            cleaned_ptr += strlen(cleaned_ptr);
            
            int found_end_label = 0;
            while (fgets(line, sizeof(line), f)) {
                char *start = line;
                while (*start && isspace(*start)) 
                    start++;
                
                if (*start == '\0' || *start == ';' || *start == '#')
                    continue;
                
                // Remove ptr keyword
                char *ptr_pos = strstr(start, " ptr ");
                if (ptr_pos)
                    memmove(ptr_pos, ptr_pos + 5, strlen(ptr_pos + 5) + 1);
                
                // Fix movabs instruction
                char *movabs_pos = strstr(start, "movabs");
                if (movabs_pos) {
                    memmove(movabs_pos + 3, movabs_pos + 6, strlen(movabs_pos + 6) + 1);
                }
                
                // Check for end label
                if (strstr(start, "end:")) {
                    found_end_label = 1;
                    break;
                }
                
                // Skip start label, we've already added it
                if (strstr(start, "start:"))
                    continue;
                
                // Remove any trailing comments
                char *comment = strchr(start, ';');
                if (comment) *comment = '\0';
                
                // Trim trailing whitespace
                char *end = start + strlen(start) - 1;
                while (end > start && isspace(*end))
                    *end-- = '\0';
                
                // Add the instruction with proper indentation
                sprintf(cleaned_ptr, "    %s\n", start);
                cleaned_ptr += strlen(cleaned_ptr);
            }
            
            // Now add the end label and call start
            if (found_end_label) {
                sprintf(cleaned_ptr, "end:\n");
                cleaned_ptr += strlen(cleaned_ptr);
                
                // Find and add the call start instruction
                rewind(f);
                while (fgets(line, sizeof(line), f)) {
                    char *start = line;
                    while (*start && isspace(*start)) 
                        start++;
                    
                    if (strstr(start, "call start")) {
                        // Remove any trailing comments
                        char *comment = strchr(start, ';');
                        if (comment) *comment = '\0';
                        
                        sprintf(cleaned_ptr, "    call start\n");
                        cleaned_ptr += strlen(cleaned_ptr);
                        break;
                    }
                }
            }
            
            // Look for any data bytes after call
            rewind(f);
            while (fgets(line, sizeof(line), f)) {
                char *start = line;
                while (*start && isspace(*start)) 
                    start++;
                
                if (strncmp(start, "db", 2) == 0) {
                    // Remove any trailing comments
                    char *comment = strchr(start, ';');
                    if (comment) *comment = '\0';
                    
                    sprintf(cleaned_ptr, "    %s\n", start);
                    cleaned_ptr += strlen(cleaned_ptr);
                }
            }
        } else {
            // Standard assembly file, process line by line
            while (fgets(line, sizeof(line), f)) {
                char *start = line;
                while (*start && isspace(*start)) 
                    start++;
                
                if (*start == '\0' || *start == ';' || *start == '#')
                    continue;
                
                // Remove ptr keyword
                char *ptr_pos = strstr(start, " ptr ");
                if (ptr_pos)
                    memmove(ptr_pos, ptr_pos + 5, strlen(ptr_pos + 5) + 1);
                
                // Fix movabs instruction
                char *movabs_pos = strstr(start, "movabs");
                if (movabs_pos) {
                    memmove(movabs_pos + 3, movabs_pos + 6, strlen(movabs_pos + 6) + 1);
                }
                
                // Skip headers we've already added
                if (strncmp(start, "BITS", 4) == 0 ||
                    strncmp(start, "section", 7) == 0 ||
                    strncmp(start, "global", 6) == 0 ||
                    strstr(start, "_start:"))
                    continue;
                
                // Process label definitions
                if (strchr(start, ':')) {
                    sprintf(cleaned_ptr, "%s\n", start);
                    cleaned_ptr += strlen(cleaned_ptr);
                    continue;
                }
                
                // Remove any trailing comments
                char *comment = strchr(start, ';');
                if (comment) *comment = '\0';
                
                // Trim trailing whitespace
                char *end = start + strlen(start) - 1;
                while (end > start && isspace(*end))
                    *end-- = '\0';
                
                // Add proper indentation for instructions
                sprintf(cleaned_ptr, "    %s\n", start);
                cleaned_ptr += strlen(cleaned_ptr);
            }
        }
        fclose(f);
        
        int len = assemble_asm(cleaned_input);
        if (len > 0) {
            printf("%sLoaded %d bytes from %s%s\n", C_G, len, filename, C_0);
            show_asm();
        } else {
            printf("%sFailed to assemble %s%s\n", C_R, filename, C_0);
            printf("Cleaned Assembly:\n%s\n", cleaned_input);
        }
    } else {
        FILE *f = fopen(filename, "rb");
        if (!f) {
            perror("File");
            return;
        }
        code_len = fread(code, 1, MAX_CODE_LEN, f);
        fclose(f);
        printf("%sLoaded %d bytes from %s%s\n", C_G, code_len, filename, C_0);
        show_asm();
    }
}

void load_file() {
    if (filename[0] == '\0') {
        char input[256];
        printf("File: ");
        if (!fgets(input, sizeof(input), stdin))
            return;
        input[strcspn(input, "\r\n")] = 0;
        if (input[0] == '\0') {
            printf("%sNo filename provided%s\n", C_R, C_0);
            return;
        }
        strcpy(filename, input);
    }
    load_file_wrapper(filename);
    filename[0] = '\0';
}

void sighandler(int sig) {
    printf("\n%sSig %d%s\n", C_R, sig, C_0);
    _exit(1);
}

void run_code() {
    if (!code_len) {
        printf("%sNo code%s\n", C_R, C_0);
        return;
    }
    clock_t start = clock();
    signal(SIGSEGV, sighandler);
    signal(SIGILL, sighandler);
    void *mem = mmap(NULL, code_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return;
    }
    memcpy(mem, code, code_len);
    printf("%sExec...%s\n", C_G, C_0);
    fflush(stdout);
    ((void(*)())mem)();
    munmap(mem, code_len);
    double ms = ((double)(clock() - start)) / CLOCKS_PER_SEC * 1000;
    printf("\n%sDone %.2f ms%s\n", C_G, ms, C_0);
}

void run_asm() {
    printf("ASM code to run (empty to end):\n");
    char input[MAX_CODE_LEN*4] = {0}, line[1024];
    size_t total = 0;
    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == '\n') break;
        strncat(input, line, sizeof(input) - total - 1);
        total += strlen(line);
        if (total >= sizeof(input) - 1) break;
    }
    int len = assemble_asm(input);
    if (len > 0) {
        printf("%s%d bytes assembled%s\n", C_G, len, C_0);
        show_asm();
        run_code();
    } else {
        printf("%sFailed to assemble input%s\n", C_R, C_0);
    }
}

void run_asm_code(const char *asm_code) {
    int len = assemble_asm(asm_code);
    if (len > 0) {
        printf("%s%d bytes assembled%s\n", C_G, len, C_0);
        show_asm();
        run_code();
    } else {
        printf("%sFailed to assemble input%s\n", C_R, C_0);
    }
}

void run_asm_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("File");
        return;
    }
    char asm_code[MAX_CODE_LEN*4] = {0};
    size_t bytes_read = fread(asm_code, 1, sizeof(asm_code)-1, f);
    fclose(f);
    if (bytes_read > 0) {
        int len = assemble_asm(asm_code);
        if (len > 0) {
            printf("%sAssembled %d bytes from %s%s\n", C_G, len, filename, C_0);
            show_asm();
            run_code();
        } else {
            printf("%sFailed to assemble file: %s%s\n", C_R, filename, C_0);
        }
    } else {
        printf("%sEmpty or invalid file: %s%s\n", C_R, filename, C_0);
    }
}

void run_with_args(char *args) {
    if (!args || !*args) {
        printf("%sNo arguments provided%s\n", C_R, C_0);
        return;
    }
    char *args_clean = strdup(args);
    if (!args_clean) {
        printf("%sMemory allocation failed%s\n", C_R, C_0);
        return;
    }
    for (char *p = args_clean; *p; p++) {
        if (*p < 32 || *p > 126) *p = ' ';
    }
    char *trimmed = args_clean;
    while (*trimmed && isspace(*trimmed)) trimmed++;
    char *end = trimmed + strlen(trimmed) - 1;
    while (end > trimmed && isspace(*end)) *end-- = '\0';
    if (strstr(trimmed, ".asm") && access(trimmed, F_OK) == 0) {
        FILE *f = fopen(trimmed, "r");
        if (f) {
            char asm_code[MAX_CODE_LEN*4] = {0};
            size_t bytes_read = fread(asm_code, 1, sizeof(asm_code)-1, f);
            fclose(f);
            if (bytes_read > 0) {
                int len = assemble_asm(asm_code);
                if (len > 0) {
                    printf("%sAssembled %d bytes from %s%s\n", C_G, len, trimmed, C_0);
                    show_asm();
                    run_code();
                } else {
                    printf("%sFailed to assemble file: %s%s\n", C_R, trimmed, C_0);
                }
            } else {
                printf("%sEmpty or invalid file: %s%s\n", C_R, trimmed, C_0);
            }
            free(args_clean);
            return;
        }
    }
    if (access(trimmed, F_OK) == 0) {
        FILE *f = fopen(trimmed, "rb");
        if (f) {
            code_len = fread(code, 1, MAX_CODE_LEN, f);
            fclose(f);
            printf("%sLoaded %d bytes from %s%s\n", C_G, code_len, trimmed, C_0);
            show_asm();
            run_code();
            free(args_clean);
            return;
        }
    }
    if (strchr(trimmed, '/') || strchr(trimmed, '.')) {
        printf("%sFile not found: %s%s\n", C_R, trimmed, C_0);
        free(args_clean);
        return;
    }
    code_len = 0;
    char hex_input[MAX_CODE_LEN*4] = {0};
    char *args_copy = strdup(trimmed);
    if (args_copy) {
        char *token = strtok(args_copy, " ");
        while (token) {
            if (token[0] == '\\' && (token[1] == 'x' || token[1] == 'X')) {
                token += 2;
            }
            strcat(hex_input, token);
            token = strtok(NULL, " ");
        }
        free(args_copy);
        code_len = parse_hex(hex_input);
        if (code_len > 0) {
            printf("%sLoaded %d bytes%s\n", C_G, code_len, C_0);
            show_asm();
            run_code();
        } else {
            printf("%sInvalid input: '%s'%s\n", C_R, trimmed, C_0);
        }
    } else {
        printf("%sMemory allocation failed%s\n", C_R, C_0);
    }
    free(args_clean);
}

void set_addr() {
    char input[32];
    printf("Addr (hex): ");
    if (!fgets(input, sizeof(input), stdin)) return;
    input[strcspn(input, "\r\n")] = 0;
    uint64_t addr;
    if (sscanf(input, "%lx", &addr) == 1) {
        base_addr = addr;
        printf("%sBase: 0x%lx%s\n", C_G, base_addr, C_0);
    } else {
        printf("%sInvalid addr%s\n", C_R, C_0);
    }
}

void toggle_syntax() {
    syntax_mode = !syntax_mode;
    printf("%s%s syntax%s\n", C_G, syntax_mode ? "AT&T" : "Intel", C_0);
}

void enter_hex() {
    printf("> ");
    char input[MAX_CODE_LEN*4];
    if (!fgets(input, sizeof(input), stdin)) return;
    code_len = parse_hex(input);
    if (code_len > 0) {
        printf("%s%d bytes%s\n", C_G, code_len, C_0);
        show_asm();
    } else printf("%sInvalid hex%s\n", C_R, C_0);
}

void enter_asm() {
    printf("ASM (empty to end):\n");
    char input[MAX_CODE_LEN*4] = {0}, line[1024];
    size_t total = 0;
    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == '\n') break;
        strncat(input, line, sizeof(input) - total - 1);
        total += strlen(line);
        if (total >= sizeof(input) - 1) break;
    }
    int len = assemble_asm(input);
    if (len > 0) {
        printf("%s%d bytes%s\n", C_G, len, C_0);
        show_asm();
    }
}

int get_terminal_width() {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    return w.ws_col > 0 ? w.ws_col : 80;
}

void clear_code() {
    code_len = 0;
    printf("%sCleared%s\n", C_Y, C_0);
}