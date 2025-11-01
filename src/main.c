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
int code_len=0;
uint64_t base_addr=0x1000;
int syntax_mode=0;
char filename[256];
char name[64];

typedef struct {char *name,*alias;void (*func)(void);} cmd_t;

#include "utils.c"
#include "symbols.c"

void show_help() {
    printf("%sAssemble:%s\n",B,C_0);
    printf("  h/hex       - Hex shellcode\n");
    printf("  a/asm       - Assembly code\n");
    printf("  r/run       - Execute\n");
    printf("  s/show      - Disasm\n");
    printf("  d/dump      - Hex dump\n");
    printf("  c/clear     - Clear buffer\n");
    printf("\n%sFile:%s\n",B,C_0);
    printf("  sv/save     - Save to file\n");
    printf("  ld/load     - Load from file\n");
    printf("\n%sSettings:%s\n",B,C_0);
    printf("  b/base      - Base address\n");
    printf("  sy/syntax   - Toggle syntax\n");
    printf("\n%sSymbols:%s\n",B,C_0);
    printf("  sm/symbols  - List symbols\n");
    printf("  sg/symgrep  - Search symbols\n");
    printf("  so/symoffset- Get offset\n");
    printf("  sr/symraw   - Raw shellcode\n");
    printf("\n?/help - Help | q/exit - Exit\n");
}

cmd_t commands[]={
    {"hex","h",enter_hex},{"asm","a",enter_asm},{"run","r",run_code},
    {"show","s",show_asm},{"dump","d",hex_dump},{"clear","c",clear_code},
    {"save","sv",save_code},{"load","ld",load_file},{"base","b",show_base_addr},
    {"syntax","sy",toggle_syntax},{"symbols","sm",dump_symbol_offsets},
    {"symgrep","sg",sym_grep},{"symoffset","so",sym_offset},{"symraw","sr",sym_raw},
    {"help","?",show_help},{"exit","q",NULL},{0}
};

void proc_cmd(char *c,char *a) {
    if (!c||!c[0]) return;
    
    if (a) {
        char *start=a;
        while (*start&&isspace(*start)) start++;
        char *end=start+strlen(start)-1;
        while (end>start&&isspace(*end)) *end--=0;
        a=start;
    }
    
    for (int i=0;commands[i].name;i++) {
        if (!strcasecmp(c,commands[i].name)||!strcasecmp(c,commands[i].alias)) {
            if (!commands[i].func) exit(0);
            if (commands[i].func==enter_hex&&a) {
                code_len=parse_hex(a);
                if (code_len>0) {
                    printf("%sLoaded %d bytes%s\n",C_G,code_len,C_0);
                    show_asm();
                } else printf("%sInvalid%s\n",C_R,C_0);
            }
            else if (commands[i].func==load_file&&a) load_file_wrapper(a);
            else if (commands[i].func==save_code&&a) {strcpy(filename,a);save_code();}
            else if (commands[i].func==run_code&&a) run_with_args(a);
            else if (commands[i].func==sym_grep||commands[i].func==sym_offset||commands[i].func==sym_raw) {
                if(a) strcpy(name,a);
                commands[i].func();
            }
            else commands[i].func();
            return;
        }
    }
    printf("%s?%s\n",C_R,C_0);
}

int main(int argc,char **argv) {
    init_symbol_resolver();
    if (argc>1) {
        char ca[MAX_CODE_LEN*4]={0};
        for (int i=2;i<argc;i++) {if(i>2)strcat(ca," ");strcat(ca,argv[i]);}
        proc_cmd(argv[1],ca);
        return 0;
    }
    
    while (1) {
        char *input=readline("\033[32m>\033[0m ");
        if (!input) break;
        if (input[0]) add_history(input);
        if (!input[0]) {free(input);continue;}
        
        char *args=strchr(input,' ');
        if (args) {
            *args++=0;
            while (*args&&isspace(*args)) args++;
        }
        proc_cmd(input,args);
        free(input);
    }
    return 0;
}