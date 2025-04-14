#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <dlfcn.h>

#include "colors.c"

#define MAX_CODE_LEN 8192
unsigned char code[MAX_CODE_LEN];
int code_len = 0;
uint64_t base_addr = 0x1000;
int syntax_mode = 0; // 0=Intel, 1=AT&T
char filename[256];
char name[64];

typedef struct {char *name, *alias; void (*func)(void);} cmd_t;

#include "utils.c"
#include "symbols.c"

void show_help() {
    printf("%sAssemble:%s\n", B, C_0);
    printf("  %sh%s / %shex%s        - Enter shellcode as hexadecimal\n", C_Y, C_0, C_Y, C_0);
    printf("  %sa%s / %sasm%s        - Enter shellcode in assembly language\n", C_Y, C_0, C_Y, C_0);
    printf("  %sr%s / %srun%s        - Execute the assembled code\n", C_Y, C_0, C_Y, C_0);
    printf("  %ss%s / %sshow%s       - Disassemble and display the code\n", C_Y, C_0, C_Y, C_0);
    printf("  %sd%s / %sdump%s       - Hex dump the raw shellcode bytes\n", C_Y, C_0, C_Y, C_0);
    printf("  %sc%s / %sclear%s      - Clear the shellcode buffer\n", C_Y, C_0, C_Y, C_0);
    printf("\n%sFile:%s\n", B, C_0);
    printf("  %ssv%s / %ssave%s      - Save shellcode/asm to a file\n", C_Y, C_0, C_Y, C_0);
    printf("  %sld%s / %sload%s      - Load shellcode/asm from a file\n", C_Y, C_0, C_Y, C_0);
    printf("\n%sSettings:%s\n", B, C_0);
    printf("  %sb%s / %sbase%s       - Set the base address\n", C_Y, C_0, C_Y, C_0);
    printf("  %ssy%s / %ssyntax%s    - Toggle between Intel/AT&T syntax\n", C_Y, C_0, C_Y, C_0);
    printf("\n%sHelp:%s\n", B, C_0);
    printf("  %s?%s  / %shelp%s      - Display this help message\n", C_Y, C_0, C_Y, C_0);
    printf("  %sq%s / %sexit%s       - Quit the program\n", C_Y, C_0, C_Y, C_0);
    printf("\n%sSymbols:%s\n", B, C_0);
    printf("  %ssm%s / %ssymbols%s   - List all symbols\n", C_Y, C_0, C_Y, C_0);
    printf("  %ssg%s / %ssymgrep%s   - Search symbols by pattern\n", C_Y, C_0, C_Y, C_0);
    printf("  %sso%s / %ssymoffset%s - Get offset from main\n", C_Y, C_0, C_Y, C_0);
    printf("  %ssr%s / %ssymraw%s    - Generate shellcode for an offset\n", C_Y, C_0, C_Y, C_0);
}

cmd_t commands[] = {
    {"hex",       "h",   enter_hex},
    {"asm",       "a",   enter_asm},
    {"run",       "r",   run_code},
    {"show",      "s",   show_asm},
    {"dump",      "d",   hex_dump},
    {"clear",     "c",   clear_code},
    {"save",      "sv",  save_code},
    {"load",      "ld",  load_file},
    {"base",      "b",   show_base_addr},
    {"syntax",    "sy",  toggle_syntax},
    {"symbols",   "sm",  dump_symbol_offsets},
    {"symgrep",   "sg",  sym_grep},
    {"symoffset", "so",  sym_offset},
    {"symraw",    "sr",  sym_raw},
    {"help",      "?",   show_help},
    {"exit",      "q",   NULL},
    {0}
};

int main(int argc, char **argv) {
    get_base_addr();
    init_symbol_resolver();
    if (argc > 1) {
        if (argc > 2 && (strcasecmp(argv[1], "h") == 0 || strcasecmp(argv[1], "hex") == 0)) {
            char combined_args[MAX_CODE_LEN*4] = {0};
            for (int i = 2; i < argc; i++) {
                if (i > 2) strcat(combined_args, " ");
                strcat(combined_args, argv[i]);
            }
            code_len = 0;
            char hex_input[MAX_CODE_LEN*4] = {0};
            char *args_copy = strdup(combined_args);
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
                if (argc > 3) {
                    for (int i = 3; i < argc; i++) {
                        if (strcasecmp(argv[i], "r") == 0 || strcasecmp(argv[i], "run") == 0) {
                            run_code();
                        } else if (strcasecmp(argv[i], "s") == 0 || strcasecmp(argv[i], "show") == 0) {
                            show_asm();
                        } else if (strcasecmp(argv[i], "d") == 0 || strcasecmp(argv[i], "dump") == 0) {
                            hex_dump();
                        } else if (strcasecmp(argv[i], "sv") == 0 || strcasecmp(argv[i], "save") == 0) {
                            if (i + 1 < argc && argv[i+1][0] != '-') {
                                strcpy(filename, argv[i+1]);
                                save_code();
                                i++;
                            } else {
                                printf("%sFilename required for save command%s\n", C_R, C_0);
                            }
                        }
                    }
                }
            } else {
                printf("%sInvalid hex input%s\n", C_R, C_0);
            }
            return 0;
        }
        else if (argc > 2 && (strcasecmp(argv[1], "r") == 0 || strcasecmp(argv[1], "run") == 0)) {
            run_with_args(argv[2]);
            if (argc > 3) {
                for (int i = 3; i < argc; i++) {
                    if (strcasecmp(argv[i], "s") == 0 || strcasecmp(argv[i], "show") == 0) {
                        show_asm();
                    } else if (strcasecmp(argv[i], "d") == 0 || strcasecmp(argv[i], "dump") == 0) {
                        hex_dump();
                    } else if (strcasecmp(argv[i], "sv") == 0 || strcasecmp(argv[i], "save") == 0) {
                        if (i + 1 < argc && argv[i+1][0] != '-') {
                            strcpy(filename, argv[i+1]);
                            save_code();
                            i++;
                        } else {
                            printf("%sFilename required for save command%s\n", C_R, C_0);
                        }
                    }
                }
            }
            return 0;
        }
        else if (argc > 2 && (strcasecmp(argv[1], "ld") == 0 || strcasecmp(argv[1], "load") == 0)) {
            load_file_wrapper(argv[2]);
            if (argc > 3) {
                for (int i = 3; i < argc; i++) {
                    if (strcasecmp(argv[i], "r") == 0 || strcasecmp(argv[i], "run") == 0) {
                        run_code();
                    } else if (strcasecmp(argv[i], "s") == 0 || strcasecmp(argv[i], "show") == 0) {
                        show_asm();
                    } else if (strcasecmp(argv[i], "d") == 0 || strcasecmp(argv[i], "dump") == 0) {
                        hex_dump();
                    } else if (strcasecmp(argv[i], "sv") == 0 || strcasecmp(argv[i], "save") == 0) {
                        if (i + 1 < argc && argv[i+1][0] != '-') {
                            strcpy(filename, argv[i+1]);
                            save_code();
                            i++;
                        } else {
                            printf("%sFilename required for save command%s\n", C_R, C_0);
                        }
                    }
                }
            }
            return 0;
        }
        else if (argc > 2 && (strcasecmp(argv[1], "a") == 0 || strcasecmp(argv[1], "asm") == 0)) {
            FILE *f = fopen(argv[2], "r");
            if (f) {
                char asm_code[MAX_CODE_LEN*4] = {0};
                size_t bytes_read = fread(asm_code, 1, sizeof(asm_code)-1, f);
                fclose(f);
                if (bytes_read > 0) {
                    run_asm_code(asm_code);
                    if (argc > 3) {
                        for (int i = 3; i < argc; i++) {
                            if (strcasecmp(argv[i], "s") == 0 || strcasecmp(argv[i], "show") == 0) {
                                show_asm();
                            } else if (strcasecmp(argv[i], "d") == 0 || strcasecmp(argv[i], "dump") == 0) {
                                hex_dump();
                            } else if (strcasecmp(argv[i], "sv") == 0 || strcasecmp(argv[i], "save") == 0) {
                                if (i + 1 < argc && argv[i+1][0] != '-') {
                                    strcpy(filename, argv[i+1]);
                                    save_code();
                                    i++;
                                } else {
                                    printf("%sFilename required for save command%s\n", C_R, C_0);
                                }
                            }
                        }
                    }
                }
            } else {
                printf("%sCould not open file: %s%s\n", C_R, argv[2], C_0);
            }
            return 0;
        }
        else {
            run_with_args(argv[1]);
            if (argc > 2) {
                for (int i = 2; i < argc; i++) {
                    if (strcasecmp(argv[i], "s") == 0 || strcasecmp(argv[i], "show") == 0) {
                        show_asm();
                    } else if (strcasecmp(argv[i], "d") == 0 || strcasecmp(argv[i], "dump") == 0) {
                        hex_dump();
                    } else if (strcasecmp(argv[i], "sv") == 0 || strcasecmp(argv[i], "save") == 0) {
                        if (i + 1 < argc && argv[i+1][0] != '-') {
                            strcpy(filename, argv[i+1]);
                            save_code();
                            i++;
                        } else {
                            printf("%sFilename required for save command%s\n", C_R, C_0);
                        }
                    }
                }
            }
            return 0;
        }
    }
    rl_bind_key('\t', rl_complete);
    while (1) {
        char *cmd = readline("\033[32m>\033[0m ");
        if (!cmd) break;
        if (cmd[0]) add_history(cmd);
        if (!cmd[0]) {
            free(cmd);
            continue;
        }
        char *args = strchr(cmd, ' ');
        if (args) {
            *args++ = '\0';
            while (*args && isspace(*args)) args++;
        } else {
            args = NULL;
        }
        int found = 0;
        for (int i=0; commands[i].name; i++) {
            if (!strcasecmp(cmd, commands[i].name) || !strcasecmp(cmd, commands[i].alias)) {
                found = 1;
                if (commands[i].func) {
                    if (commands[i].func == enter_hex) {
                        if (args) {
                            code_len = 0;
                            char hex_input[MAX_CODE_LEN*4] = {0};
                            char *token = strtok(args, " ");
                            while (token) {
                                if (token[0] == '\\' && (token[1] == 'x' || token[1] == 'X')) {
                                    token += 2;
                                }
                                strcat(hex_input, token);
                                token = strtok(NULL, " ");
                            }
                            code_len = parse_hex(hex_input);
                            if (code_len > 0) {
                                printf("%sLoaded %d bytes%s\n", C_G, code_len, C_0);
                                show_asm();
                            } else {
                                printf("%sInvalid hex input%s\n", C_R, C_0);
                            }
                        } else {
                            (commands[i].func)();
                        }
                        free(cmd);
                    }
                    else if (commands[i].func == run_code) {
                        if (args) {
                            char *clean_args = strdup(args);
                            if (!clean_args) {
                                printf("%sMemory allocation failed%s\n", C_R, C_0);
                                free(cmd);
                                continue;
                            }
                            for (char *p = clean_args; *p; p++) {
                                if (*p < 32 || *p > 126) *p = ' ';
                            }
                            char *trimmed = clean_args;
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
                                    free(clean_args);
                                    free(cmd);
                                    continue;
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
                                    free(clean_args);
                                    free(cmd);
                                    continue;
                                }
                            }
                            if (strchr(trimmed, '/') || strchr(trimmed, '.')) {
                                printf("%sFile not found: %s%s\n", C_R, trimmed, C_0);
                                free(clean_args);
                                free(cmd);
                                continue;
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
                            }
                            free(clean_args);
                            free(cmd);
                        } else {
                            free(cmd);
                            (commands[i].func)();
                        }
                    }
                    else if (commands[i].func == load_file) {
                        if (args) {
                            load_file_wrapper(args);
                            free(cmd);
                        } else {
                            free(cmd);
                            load_file();
                        }
                    }
                    else if (commands[i].func == save_code) {
                        if (args) {
                            strcpy(filename, args);
                            save_code();
                            free(cmd);
                        } else {
                            free(cmd);
                            save_code();
                        }
                    }
                    else if (commands[i].func == sym_grep || 
                             commands[i].func == sym_offset || 
                             commands[i].func == sym_raw) {
                        if (args) {
                            strcpy(name, args);
                            if (commands[i].func == sym_grep) sym_grep();
                            else if (commands[i].func == sym_offset) sym_offset();
                            else sym_raw();
                            free(cmd);
                        } else {
                            free(cmd);
                            (commands[i].func)();
                        }
                    }
                    else {
                        free(cmd);
                        (commands[i].func)();
                    }
                }
                else {
                    free(cmd);
                    return 0;
                }
                break;
            }
        }
        if (!found) {
            printf("%s?%s\n", C_R, C_0);
            free(cmd);
        }
    }
    return 0;
}