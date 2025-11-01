#include <sys/ioctl.h>
#include <stdio.h>

int hex_to_val(char c) {
    if ('0'<=c&&c<='9') return c-'0';
    if ('a'<=c&&c<='f') return 10+c-'a';
    if ('A'<=c&&c<='F') return 10+c-'A';
    return -1;
}

int parse_hex(const char *input) {
    int len=0;
    const char *p=input;
    while (*p&&len<MAX_CODE_LEN) {
        while (*p&&(isspace(*p)||*p=='\\'||*p=='x'||*p=='X')) p++;
        if (*p=='0'&&(*(p+1)=='x'||*(p+1)=='X')) p+=2;
        if (!*p||!*(p+1)) break;
        if (!isxdigit(*p)||!isxdigit(*(p+1))) {p++;continue;}
        int hi=hex_to_val(*p),lo=hex_to_val(*(p+1));
        if (hi<0||lo<0) {p++;continue;}
        code[len++]=(hi<<4)|lo;
        p+=2;
    }
    return len;
}

void hex_dump() {
    if (!code_len) {printf("%sNo code%s\n",C_R,C_0);return;}
    for (int i=0;i<code_len;i++) {
        if (i%16==0) printf("\n%s%04x:%s ",C_G,i,C_0);
        printf("%s%02x%s%s",C_G,code[i],(i%2)?" ":"",C_0);
    }
    printf("\n\n%s\\x%s",C_Y,C_0);
    for (int i=0;i<code_len;i++) printf("%02x",code[i]);
    printf("\n");
}

void show_stats(const char *out) {
    int cats[7]={0};
    char *labels[]={"Jump/Call","Data","Math","Logic","Sys","Cmp","Other"};
    const char *p=out;
    while (*p) {
        const char *le=strchr(p,'\n');
        if (!le) le=p+strlen(p);
        const char *m=p;
        while (m<le&&!isspace(*m)) m++;
        while (m<le&&isspace(*m)) m++;
        while (m<le&&!isspace(*m)) m++;
        while (m<le&&isspace(*m)) m++;
        if (m<le) {
            char w[32]={0};
            int wl=0;
            while (m+wl<le&&!isspace(*(m+wl))&&wl<31) {
                w[wl]=*(m+wl);
                wl++;
            }
            if (strstr(w,"jmp")||strstr(w,"call")||strstr(w,"ret")||w[0]=='j') cats[0]++;
            else if (strstr(w,"mov")||strstr(w,"lea")||strstr(w,"push")||strstr(w,"pop")) cats[1]++;
            else if (strstr(w,"add")||strstr(w,"sub")||strstr(w,"mul")||strstr(w,"div")) cats[2]++;
            else if (strstr(w,"and")||strstr(w,"or")||strstr(w,"xor")||strstr(w,"not")) cats[3]++;
            else if (strstr(w,"syscall")||strstr(w,"int")) cats[4]++;
            else if (strstr(w,"cmp")||strstr(w,"test")) cats[5]++;
            else cats[6]++;
        }
        if (!*le) break;
        p=le+1;
    }
    printf("\n");
    for (int i=0;i<7;i++)
        if (cats[i]) printf("%s%s%s:%d ",instr_color(labels[i]),labels[i],C_0,cats[i]);
    printf("\n");
}

void show_asm() {
    if (!code_len) {printf("%sNo code%s\n",C_R,C_0);return;}
    char temp_bin[]="/tmp/binXXXXXX";
    int fd=mkstemp(temp_bin);
    if (fd==-1) {printf("%sFailed temp%s\n",C_R,C_0);return;}
    write(fd,code,code_len);
    close(fd);
    
    char cmd[256];
    snprintf(cmd,sizeof(cmd),"ndisasm -b 64 %s 2>/dev/null",temp_bin);
    FILE *p=popen(cmd,"r");
    if (!p) {printf("%sFailed ndisasm%s\n",C_R,C_0);remove(temp_bin);return;}
    
    printf("%s%db/%dI:%s\n",C_G,code_len,0,C_0);
    char line[512],out[MAX_CODE_LEN*8]={0};
    int cnt=0;
    while (fgets(line,sizeof(line),p)) {
        char *m=line;
        while (*m&&!isspace(*m)) m++;
        while (*m&&isspace(*m)) m++;
        while (*m&&!isspace(*m)) m++;
        while (*m&&isspace(*m)) m++;
        if (!*m||*m=='\n') continue;
        char mnem[32]={0};
        char *sp=strchr(m,' '),*nl=strchr(m,'\n');
        int len=(sp&&(!nl||sp<nl))?sp-m:(nl?nl-m:strlen(m));
        if (len>31) len=31;
        strncpy(mnem,m,len);
        if (nl) *nl='\0';
        printf("%s%04x:%s%s%-7s%s%s\n",C_G,cnt++,C_0,instr_color(mnem),mnem,C_0,sp?sp:"");
        strncat(out,line,sizeof(out)-strlen(out)-1);
    }
    pclose(p);
    remove(temp_bin);
    show_stats(out);
}

int assemble_asm(const char *asm_code) {
    char temp_asm[]="/tmp/asmXXXXXX",temp_obj[]="/tmp/objXXXXXX";
    int afd=mkstemp(temp_asm),ofd=mkstemp(temp_obj);
    if (afd==-1||ofd==-1) {
        if(afd!=-1)close(afd);
        if(ofd!=-1){close(ofd);remove(temp_obj);}
        remove(temp_asm);
        return 0;
    }
    close(ofd);
    remove(temp_obj);
    while (*asm_code&&isspace(*asm_code)) asm_code++;
    if (!*asm_code) {close(afd);remove(temp_asm);return 0;}
    write(afd,asm_code,strlen(asm_code));
    close(afd);
    char cmd[256];
    snprintf(cmd,sizeof(cmd),"nasm -f bin -o %s %s 2>/tmp/nasm_err",temp_obj,temp_asm);
    int ret=system(cmd);
    if (ret!=0) {
        printf("%sAsm failed:%s\n",C_R,C_0);
        FILE *e=fopen("/tmp/nasm_err","r");
        if (e) {
            char b[256];
            while (fgets(b,sizeof(b),e)) printf("%s",b);
            fclose(e);
        }
        remove(temp_asm);
        remove(temp_obj);
        remove("/tmp/nasm_err");
        return 0;
    }
    FILE *o=fopen(temp_obj,"rb");
    if (!o) {remove(temp_asm);remove(temp_obj);return 0;}
    code_len=fread(code,1,MAX_CODE_LEN,o);
    fclose(o);
    remove(temp_asm);
    remove(temp_obj);
    remove("/tmp/nasm_err");
    return code_len;
}

void save_code() {
    if (!code_len) {printf("%sNo code%s\n",C_R,C_0);return;}
    if (!filename[0]) {
        printf("File: ");
        if (!fgets(filename,sizeof(filename),stdin)) return;
        filename[strcspn(filename,"\r\n")]=0;
        if (!filename[0]) {printf("%sNo file%s\n",C_R,C_0);return;}
    }
    char *ext=strrchr(filename,'.');
    if (ext&&strcasecmp(ext,".asm")==0) {
        FILE *f=fopen(filename,"w");
        if (!f) {perror("File");return;}
        char tb[]="/tmp/binXXXXXX";
        int fd=mkstemp(tb);
        if (fd==-1) {fclose(f);return;}
        write(fd,code,code_len);
        close(fd);
        char cmd[256];
        snprintf(cmd,sizeof(cmd),"ndisasm -b 64 %s 2>/dev/null",tb);
        FILE *p=popen(cmd,"r");
        if (!p) {fclose(f);remove(tb);return;}
        fprintf(f,"BITS 64\nsection .text\nglobal _start\n_start:\n");
        char line[512];
        int cnt=0;
        while (fgets(line,sizeof(line),p)) {
            char *m=line;
            while (*m&&!isspace(*m)) m++;
            while (*m&&isspace(*m)) m++;
            while (*m&&!isspace(*m)) m++;
            while (*m&&isspace(*m)) m++;
            if (!*m||*m=='\n') continue;
            char *nl=strchr(m,'\n');
            if (nl) *nl='\0';
            fprintf(f,"    %s\n",m);
            cnt++;
        }
        pclose(p);
        remove(tb);
        fclose(f);
        printf("%sSaved %d instr to %s%s\n",C_G,cnt,filename,C_0);
    } else {
        FILE *f=fopen(filename,"wb");
        if (!f) {perror("File");return;}
        if (ext&&strcasecmp(ext,".txt")==0) {
            fprintf(f,"shellcode=\"");
            for (int i=0;i<code_len;i++) fprintf(f,"\\x%02x",code[i]);
            fprintf(f,"\"\n");
        } else {
            fwrite(code,1,code_len,f);
        }
        fclose(f);
        printf("%sSaved %d bytes to %s%s\n",C_G,code_len,filename,C_0);
    }
    filename[0]=0;
}

void load_file_wrapper(const char *fn) {
    if (!fn||!fn[0]) {printf("%sNo file%s\n",C_R,C_0);return;}
    
    char *ext=strrchr(fn,'.');
    if (ext&&strcasecmp(ext,".asm")==0) {
        FILE *f=fopen(fn,"r");
        if (!f) {printf("%sFile not found: %s%s\n",C_R,fn,C_0);return;}
        char fc[MAX_CODE_LEN*4]={0},line[1024],cl[MAX_CODE_LEN*4]={0};
        while (fgets(line,sizeof(line),f))
            strncat(fc,line,sizeof(fc)-strlen(fc)-1);
        strcpy(cl,"BITS 64\nsection .text\nglobal _start\n_start:\n");
        rewind(f);
        int jmp=strstr(fc,"jmp end")!=NULL,call=strstr(fc,"call start")!=NULL;
        if (jmp&&call) {
            while (fgets(line,sizeof(line),f)) {
                char *p=line;
                while (*p&&isspace(*p)) p++;
                if (!*p||*p==';'||*p=='#') continue;
                if (strncmp(p,"BITS",4)==0||strncmp(p,"section",7)==0||strncmp(p,"global",6)==0||strstr(p,"_start:")) continue;
                char *pt=strstr(p," ptr ");
                if (pt) memmove(pt,pt+5,strlen(pt+5)+1);
                if (strstr(p,"jmp end")) {
                    char *c=strchr(p,';');
                    if (c) *c=0;
                    strcat(cl,"    jmp end\n");
                    break;
                }
            }
            strcat(cl,"start:\n");
            while (fgets(line,sizeof(line),f)) {
                char *p=line;
                while (*p&&isspace(*p)) p++;
                if (!*p||*p==';'||*p=='#'||strstr(p,"end:")) break;
                if (strstr(p,"start:")) continue;
                char *pt=strstr(p," ptr ");
                if (pt) memmove(pt,pt+5,strlen(pt+5)+1);
                char *ma=strstr(p,"movabs");
                if (ma) memmove(ma+3,ma+6,strlen(ma+6)+1);
                char *c=strchr(p,';');
                if (c) *c=0;
                char *e=p+strlen(p)-1;
                while (e>p&&isspace(*e)) *e--=0;
                strcat(cl,"    ");strcat(cl,p);strcat(cl,"\n");
            }
            strcat(cl,"end:\n");
            rewind(f);
            while (fgets(line,sizeof(line),f)) {
                char *p=line;
                while (*p&&isspace(*p)) p++;
                if (strstr(p,"call start")) {
                    char *c=strchr(p,';');
                    if (c) *c=0;
                    strcat(cl,"    call start\n");
                    break;
                }
            }
        } else {
            rewind(f);
            while (fgets(line,sizeof(line),f)) {
                char *p=line;
                while (*p&&isspace(*p)) p++;
                if (!*p||*p==';'||*p=='#'||strncmp(p,"BITS",4)==0||strncmp(p,"section",7)==0||strncmp(p,"global",6)==0||strstr(p,"_start:")) continue;
                char *pt=strstr(p," ptr ");
                if (pt) memmove(pt,pt+5,strlen(pt+5)+1);
                char *ma=strstr(p,"movabs");
                if (ma) memmove(ma+3,ma+6,strlen(ma+6)+1);
                char *c=strchr(p,';');
                if (c) *c=0;
                char *e=p+strlen(p)-1;
                while (e>p&&isspace(*e)) *e--=0;
                if (strchr(p,':')) strcat(cl,p);
                else {strcat(cl,"    ");strcat(cl,p);}
                strcat(cl,"\n");
            }
        }
        fclose(f);
        int len=assemble_asm(cl);
        if (len>0) {
            printf("%sLoaded %d bytes from %s%s\n",C_G,len,fn,C_0);
            show_asm();
        } else {
            printf("%sFailed to assemble%s\n",C_R,C_0);
        }
    } else {
        FILE *f=fopen(fn,"rb");
        if (!f) {printf("%sFile not found: %s%s\n",C_R,fn,C_0);return;}
        code_len=fread(code,1,MAX_CODE_LEN,f);
        fclose(f);
        printf("%sLoaded %d bytes from %s%s\n",C_G,code_len,fn,C_0);
        show_asm();
    }
}

void load_file() {
    if (!filename[0]) {
        printf("File: ");
        if (!fgets(filename,sizeof(filename),stdin)) return;
        filename[strcspn(filename,"\r\n")]=0;
        if (!filename[0]) {printf("%sNo file%s\n",C_R,C_0);return;}
    }
    load_file_wrapper(filename);
    filename[0]=0;
}

void sighandler(int s) {printf("\n%sSig %d%s\n",C_R,s,C_0);_exit(1);}

void run_code() {
    if (!code_len) {printf("%sNo code%s\n",C_R,C_0);return;}
    signal(SIGSEGV,sighandler);
    signal(SIGILL,sighandler);
    void *m=mmap(NULL,code_len,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (m==MAP_FAILED) {perror("mmap");return;}
    memcpy(m,code,code_len);
    printf("%sExec...%s\n",C_G,C_0);
    fflush(stdout);
    clock_t st=clock();
    ((void(*)())m)();
    munmap(m,code_len);
    double ms=((double)(clock()-st))/CLOCKS_PER_SEC*1000;
    printf("\n%sDone %.2f ms%s\n",C_G,ms,C_0);
}

void run_asm_code(const char *a) {
    int l=assemble_asm(a);
    if (l>0) {
        printf("%s%d bytes%s\n",C_G,l,C_0);
        show_asm();
        run_code();
    } else {
        printf("%sFailed%s\n",C_R,C_0);
    }
}

void run_with_args(char *a) {
    if (!a||!*a) {printf("%sNo args%s\n",C_R,C_0);return;}
    char *cl=strdup(a);
    for (char *p=cl;*p;p++)
        if (*p<32||*p>126) *p=' ';
    char *tr=cl;
    while (*tr&&isspace(*tr)) tr++;
    char *e=tr+strlen(tr)-1;
    while (e>tr&&isspace(*e)) *e--=0;
    if (strstr(tr,".asm")&&access(tr,F_OK)==0) {
        FILE *f=fopen(tr,"r");
        if (f) {
            char ac[MAX_CODE_LEN*4]={0};
            size_t br=fread(ac,1,sizeof(ac)-1,f);
            fclose(f);
            if (br>0) run_asm_code(ac);
        }
        free(cl);
        return;
    }
    if (access(tr,F_OK)==0) {
        FILE *f=fopen(tr,"rb");
        if (f) {
            code_len=fread(code,1,MAX_CODE_LEN,f);
            fclose(f);
            printf("%sLoaded %d bytes%s\n",C_G,code_len,C_0);
            show_asm();
            run_code();
            free(cl);
            return;
        }
    }
    code_len=parse_hex(tr);
    if (code_len>0) {
        printf("%sLoaded %d bytes%s\n",C_G,code_len,C_0);
        show_asm();
        run_code();
    } else {
        printf("%sInvalid%s\n",C_R,C_0);
    }
    free(cl);
}

void toggle_syntax() {
    syntax_mode=!syntax_mode;
    printf("%s%s syntax%s\n",C_G,syntax_mode?"AT&T":"Intel",C_0);
}

void enter_hex() {
    printf("> ");
    char i[MAX_CODE_LEN*4];
    if (fgets(i,sizeof(i),stdin)) {
        code_len=parse_hex(i);
        if (code_len>0) {
            printf("%s%d bytes%s\n",C_G,code_len,C_0);
            show_asm();
        } else {
            printf("%sInvalid%s\n",C_R,C_0);
        }
    }
}

void enter_asm() {
    printf("ASM:\n");
    char i[MAX_CODE_LEN*4]={0},l[1024];
    size_t t=0;
    while (fgets(l,sizeof(l),stdin)) {
        if (l[0]=='\n') break;
        strncat(i,l,sizeof(i)-t-1);
        t+=strlen(l);
        if (t>=sizeof(i)-1) break;
    }
    int ln=assemble_asm(i);
    if (ln>0) {
        printf("%s%d bytes%s\n",C_G,ln,C_0);
        show_asm();
    } else {
        printf("%sFailed%s\n",C_R,C_0);
    }
}

void clear_code() {
    code_len=0;
    printf("%sCleared%s\n",C_Y,C_0);
}

int get_terminal_width() {
    struct winsize w;
    ioctl(STDOUT_FILENO,TIOCGWINSZ,&w);
    return w.ws_col>0?w.ws_col:80;
}