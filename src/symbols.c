#include <gelf.h>

typedef struct {
    char name[64];
    uintptr_t addr;
} symbol_info_t;

typedef struct {
    symbol_info_t *symbols;
    int count;
    int capacity;
} symbol_table_t;

typedef struct {
    uintptr_t base_addr;
    int count;
} symbol_table;

symbol_table symbols = {0};
int template_count = 0;

int main(int argc, char **argv);

static int init_elf_once() {
    static int initialized = 0;
    if (!initialized) {
        if (elf_version(EV_CURRENT) == EV_NONE) {
            fprintf(stderr, "ELF library initialization failed\n");
            return 0;
        }
        initialized = 1;
    }
    return 1;
}

symbol_table_t* extract_all_symbols() {
    if (!init_elf_once())
        return NULL;
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return NULL;
    }
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
        close(fd);
        return NULL;
    }
    symbol_table_t *symtab = malloc(sizeof(symbol_table_t));
    if (!symtab) {
        elf_end(elf);
        close(fd);
        return NULL;
    }
    symtab->capacity = 256;
    symtab->count = 0;
    symtab->symbols = malloc(symtab->capacity * sizeof(symbol_info_t));
    if (!symtab->symbols) {
        free(symtab);
        elf_end(elf);
        close(fd);
        return NULL;
    }
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        fprintf(stderr, "elf_getshdrstrndx failed: %s\n", elf_errmsg(-1));
        free(symtab->symbols);
        free(symtab);
        elf_end(elf);
        close(fd);
        return NULL;
    }
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            continue;
        }
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            Elf_Data *data = elf_getdata(scn, NULL);
            if (!data) continue;
            int symbol_count = shdr.sh_size / shdr.sh_entsize;
            for (int i = 0; i < symbol_count; i++) {
                GElf_Sym sym;
                if (gelf_getsym(data, i, &sym) != &sym) {
                    continue;
                }
                char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (!name || !*name) continue;
                if (symtab->count >= symtab->capacity) {
                    symtab->capacity *= 2;
                    symbol_info_t *new_symbols = realloc(symtab->symbols, symtab->capacity * sizeof(symbol_info_t));
                    if (!new_symbols) {
                        free(symtab->symbols);
                        free(symtab);
                        elf_end(elf);
                        close(fd);
                        return NULL;
                    }
                    symtab->symbols = new_symbols;
                }
                strncpy(symtab->symbols[symtab->count].name, name, 63);
                symtab->symbols[symtab->count].name[63] = '\0';
                symtab->symbols[symtab->count].addr = sym.st_value;
                symtab->count++;
            }
        }
    }
    elf_end(elf);
    close(fd);
    return symtab;
}

void free_symbol_table(symbol_table_t *symtab) {
    if (symtab) {
        if (symtab->symbols) {
            free(symtab->symbols);
        }
        free(symtab);
    }
}

void resolve_symbols_with_nm(void) {
    symbol_table_t *symtab = extract_all_symbols();
    if (!symtab) {
        printf("Failed to extract symbols\n");
        symbols.count = 0;
        return;
    }
    symbols.count = symtab->count;
    free_symbol_table(symtab);
}

void scan_for_templates(const char *filename) {
    printf("Template scanning from %s is disabled\n", filename);
    template_count = 0;
}

void dump_templates(void) {
    printf("Template dump is disabled\n");
    printf("No templates available\n");
}

uintptr_t get_symbol_value(symbol_table_t *symtab, const char *name) {
    if (!symtab || !name) return 0;
    for (int i = 0; i < symtab->count; i++) {
        if (strcmp(symtab->symbols[i].name, name) == 0) {
            return symtab->symbols[i].addr;
        }
    }
    return 0;
}

void grep_symbols(const char *pattern) {
    symbol_table_t *symtab = extract_all_symbols();
    if (!symtab) {
        printf("Failed to extract symbols\n");
        return;
    }
    printf("Searching for symbols matching: %s\n", pattern);
    int found = 0;
    uintptr_t main_addr = get_symbol_value(symtab, "main");
    for (int i = 0; i < symtab->count; i++) {
        if (strstr(symtab->symbols[i].name, pattern)) {
            uintptr_t offset = 0;
            if (main_addr) {
                offset = symtab->symbols[i].addr - main_addr;
            }
            printf("%-20s 0x%-14lx", symtab->symbols[i].name, symtab->symbols[i].addr);
            if (main_addr) {
                printf(" 0x%-14lx", offset);
            }
            printf("\n");
            found++;
        }
    }
    if (!found) {
        printf("No symbols found matching: %s\n", pattern);
    } else {
        printf("Found %d matching symbols\n", found);
    }
    free_symbol_table(symtab);
}

uintptr_t get_symbol_offset(symbol_table_t *symtab, const char *symbol, const char *base_symbol) {
    uintptr_t sym_addr = get_symbol_value(symtab, symbol);
    uintptr_t base_addr = get_symbol_value(symtab, base_symbol);
    if (sym_addr && base_addr) {
        return sym_addr - base_addr;
    }
    return 0;
}

uintptr_t get_offset_from_main(const char *symbol_name) {
    symbol_table_t *symtab = extract_all_symbols();
    if (!symtab) return 0;
    uintptr_t offset = get_symbol_offset(symtab, symbol_name, "main");
    free_symbol_table(symtab);
    return offset;
}

void generate_shellcode(const char *name, char *output, size_t output_size) {
    uintptr_t offset = get_offset_from_main(name);
    if (offset) {
        if (offset <= 0xFFFF) {
            // Can use 16-bit mov for small offsets
            snprintf(output, output_size, "\\x48\\x31\\xc0\\x66\\xb8%02x%02x\\xff\\xe0",
                    (unsigned char)(offset & 0xFF),
                    (unsigned char)((offset >> 8) & 0xFF));
        } else {
            // Use 32-bit mov for larger offsets (dynamic format)
            snprintf(output, output_size, "\\x48\\x31\\xc0\\x66\\xb8(64(base+\\x%02x\\x%02x))\\xff\\xe0",
                    (unsigned char)(offset & 0xFF),
                    (unsigned char)((offset >> 8) & 0xFF));
        }
    } else {
        snprintf(output, output_size, "Symbol '%s' not found", name);
    }
}

int parse_dynamic_shellcode(const char *input, unsigned char *output, size_t *output_len, uintptr_t base_address) {
    *output_len = 0;
    const char *p = input;
    while (*p) {
        while (*p && isspace(*p)) p++;
        if (!*p) break;
        // Check for dynamic part pattern (64(base+OFFSET))
        if (strstr(p, "(64(base+") == p) {
            p += 9;
            unsigned int offset = 0;
            int bytes_read = 0;
            while (*p && *p != ')') {
                if (*p == '\\' && *(p+1) == 'x' && isxdigit(*(p+2)) && isxdigit(*(p+3))) {
                    int hi = hex_to_val(*(p+2));
                    int lo = hex_to_val(*(p+3));
                    if (hi >= 0 && lo >= 0) {
                        offset = (offset << 8) | ((hi << 4) | lo);
                        bytes_read++;
                    }
                    p += 4;
                } else {
                    p++;
                }
            }
            while (*p && *p != '\\') p++;
            uintptr_t addr = base_address + offset;
            // For 16-bit value
            if (bytes_read <= 2) {
                output[(*output_len)++] = (unsigned char)(addr & 0xFF);
                output[(*output_len)++] = (unsigned char)((addr >> 8) & 0xFF);
            } 
            // For 32-bit value
            else if (bytes_read <= 4) {
                output[(*output_len)++] = (unsigned char)(addr & 0xFF);
                output[(*output_len)++] = (unsigned char)((addr >> 8) & 0xFF);
                output[(*output_len)++] = (unsigned char)((addr >> 16) & 0xFF);
                output[(*output_len)++] = (unsigned char)((addr >> 24) & 0xFF);
            }
            continue;
        }
        // Handle normal hex format \xNN
        if (*p == '\\' && *(p+1) == 'x' && isxdigit(*(p+2)) && isxdigit(*(p+3))) {
            int hi = hex_to_val(*(p+2));
            int lo = hex_to_val(*(p+3));
            if (hi >= 0 && lo >= 0) {
                output[(*output_len)++] = (hi << 4) | lo;
            }
            p += 4;
        } else {
            p++;
        }
    }
    
    return *output_len;
}

uintptr_t get_raw_symbol(const char *name) {
    symbol_table_t *symtab = extract_all_symbols();
    if (!symtab) return 0;
    
    uintptr_t addr = get_symbol_value(symtab, name);
    free_symbol_table(symtab);
    return addr;
}

void generate_offset_shellcode(uintptr_t offset, char *output, size_t output_size) {
    snprintf(output, output_size, "\\x48\\x31\\xc0\\x66\\xb8%02x%02x\\xff\\xe0",
             (unsigned char)(offset & 0xFF),
             (unsigned char)((offset >> 8) & 0xFF));
}

void show_base_addr() {
    printf("%sBase address:%s 0x%lx\n", B, C_C, symbols.base_addr );
}

void init_symbol_resolver() {
    uintptr_t main_offset = get_offset_from_main("main");
    uintptr_t main_addr = (uintptr_t)main;
    symbols.base_addr = main_addr - main_offset;
    resolve_symbols_with_nm();
    printf("Loaded %d symbols\n", symbols.count);
}

void dump_symbol_offsets() {
    symbol_table_t *symtab = extract_all_symbols();
    if (!symtab) {
        printf("%sFailed to extract symbols%s\n", C_R, C_0);
        return;
    }
    uintptr_t main_addr = get_symbol_value(symtab, "main");
    if (!main_addr) {
        printf("%sMain symbol not found%s\n", C_R, C_0);
        free_symbol_table(symtab);
        return;
    }
    uintptr_t base = symbols.base_addr;
    printf("%sBase address: 0x%lx%s\n", B, base, C_0);
    printf("%s%-20s %-16s %-16s%s\n", B, "SYMBOL", "BASE+OFFSET", "OFFSET", C_0);
    printf("%-20s %-16s %-16s\n", "--------------------", "----------------", "----------------");
    for (int i = 0; i < symtab->count; i++) {
        uintptr_t addr = symtab->symbols[i].addr;
        if (addr == 0) continue;
        if (symtab->symbols[i].name[0] == '_' || 
            strchr(symtab->symbols[i].name, '@')) continue;
        uintptr_t offset = addr - main_addr;
        uintptr_t base_offset = base + offset;
        char offset_str[32];
        if ((int64_t)offset < 0) {
            snprintf(offset_str, sizeof(offset_str), "-0x%lx", -((int64_t)offset));
        } else {
            snprintf(offset_str, sizeof(offset_str), "0x%lx", offset);
        }
        char *color = strchr(symtab->symbols[i].name, '_') ? C_Y : C_G;
        printf("%s%-20.20s%s 0x%-14lx %-16s\n", color, symtab->symbols[i].name, C_0, base_offset, offset_str);
    }
    free_symbol_table(symtab);
}

void sym_grep(void) {
    char pattern[64];
    printf("Pattern: ");
    if (!fgets(pattern, sizeof(pattern), stdin)) return;
    pattern[strcspn(pattern, "\r\n")] = 0;
    if (pattern[0]) {
        grep_symbols(pattern);
    } else {
        printf("%sProvide a search pattern%s\n", C_R, C_0);
    }
}

void sym_offset(void) {
    char name[64];
    printf("Symbol name: ");
    if (!fgets(name, sizeof(name), stdin)) return;
    name[strcspn(name, "\r\n")] = 0;
    if (name[0]) {
        uintptr_t offset = get_offset_from_main(name);
        if (offset) {
            printf("Offset from main to %s: 0x%lx\n", name, offset);
            char shellcode[128];
            generate_offset_shellcode(offset, shellcode, sizeof(shellcode));
            printf("Shellcode: %s\n", shellcode);
            printf("Copy to code buffer? [y/N]: ");
            char confirm = getchar();
            while (getchar() != '\n');
            if (confirm == 'y' || confirm == 'Y') {
                code_len = parse_hex(shellcode);
                printf("%s%d bytes%s\n", C_G, code_len, C_0);
                show_asm();
            }
        } else {
            printf("Symbol %s not found\n", name);
        }
    } else {
        uintptr_t offset = symbols.base_addr;
        printf("Main offset: 0x%lx\n", offset);
        printf("This is the value that replaces hardcoded 0x3d3e\n");
    }
}

void sym_raw(void) {
    char offset_str[64];
    printf("Offset (hex): ");
    if (!fgets(offset_str, sizeof(offset_str), stdin)) return;
    offset_str[strcspn(offset_str, "\r\n")] = 0;
    if (offset_str[0]) {
        uintptr_t offset;
        if (offset_str[0] == '0' && (offset_str[1] == 'x' || offset_str[1] == 'X')) {
            offset = strtoul(offset_str, NULL, 16);
        } else {
            offset = strtoul(offset_str, NULL, 10);
        }
        if (offset) {
            char shellcode[128];
            generate_offset_shellcode(offset, shellcode, sizeof(shellcode));
            printf("Shellcode for offset 0x%lx: %s\n", offset, shellcode);
            uintptr_t target_addr = symbols.base_addr + offset;
            printf("Runtime address: 0x%lx\n", target_addr);
            printf("Copy to code buffer? [y/N]: ");
            char confirm = getchar();
            while (getchar() != '\n');
            if (confirm == 'y' || confirm == 'Y') {
                code_len = parse_hex(shellcode);
                printf("%s%d bytes%s\n", C_G, code_len, C_0);
                show_asm();
            }
        } else {
            printf("%sInvalid offset%s\n", C_R, C_0);
        }
    } else {
        printf("%sProvide an offset value%s\n", C_R, C_0);
    }
}