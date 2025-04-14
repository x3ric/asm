#define C_R "\x1b[31m"
#define C_G "\x1b[32m"
#define C_Y "\x1b[33m"
#define C_B "\x1b[34m"
#define C_M "\x1b[35m"
#define C_C "\x1b[36m"
#define C_W "\x1b[37m"
#define C_0 "\x1b[0m"
#define B "\x1b[1m"

char* instr_color(const char* mnem) {
    if (strstr(mnem,"jmp")||strstr(mnem,"call")||strstr(mnem,"ret")||strncmp(mnem,"j",1)==0) return C_R;
    if (strstr(mnem,"mov")||strstr(mnem,"lea")||strstr(mnem,"push")||strstr(mnem,"pop")) return C_B;
    if (strstr(mnem,"add")||strstr(mnem,"sub")||strstr(mnem,"mul")||strstr(mnem,"div")||strstr(mnem,"inc")||strstr(mnem,"dec")) return C_G;
    if (strstr(mnem,"and")||strstr(mnem,"or")||strstr(mnem,"xor")||strstr(mnem,"not")||strstr(mnem,"shl")||strstr(mnem,"shr")||strstr(mnem,"rol")||strstr(mnem,"ror")) return C_Y;
    if (strstr(mnem,"syscall")||strstr(mnem,"int")) return C_M;
    if (strstr(mnem,"cmp")||strstr(mnem,"test")) return C_C;
    return C_W;
}