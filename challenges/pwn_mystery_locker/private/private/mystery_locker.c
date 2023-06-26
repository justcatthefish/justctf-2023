#include "md5.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>



#define FAIL(a)    \
    do             \
    {              \
        perror(a); \
        exit(1);   \
    } while (0)

#define FAIL2(a) \
    do           \
    {            \
        puts(a); \
        exit(1); \
    } while (0)

#define ENSURE_FILE_DOES_NOT_EXIST(a)              \
    do                                             \
    {                                              \
        struct stat st = {0};                      \
        if (stat(a, &st) >= 0)                     \
        {                                          \
            printf("file %s already exists\n", a); \
            return;                                \
        }                                          \
    } while (0)

#define ENSURE_FILE_EXISTS(a)                      \
    do                                             \
    {                                              \
        struct stat st = {0};                      \
        if (stat(a, &st) == -1)                    \
        {                                          \
            printf("file %s does not exist\n", a); \
            return;                                \
        }                                          \
    } while (0)

int read_int(const char *prompt)
{
    printf("%s", prompt);
    int ret = 0;
    if (scanf("%10d%*c", &ret) == 1)
        return ret;

    return 0;
}

char *read_str(const char *prompt, int max_read) {
    printf("%s", prompt);
    int max_read_2 = MIN((uint32_t)max_read, 0x400);
    int read_idx = 0;
    char *buf = malloc(max_read_2);
    while (1)
    {
        uint8_t c;
        int n = read_idx < max_read_2 && read(STDIN_FILENO, &c, 1);
        if (!n) break;
        if (n < 0) FAIL("read");
        if (c == 0) break;

        buf[read_idx] = c;
        read_idx += n;
    }
    buf[max_read] = 0;
    return buf;
}

char fs_path[0x20];
int get_path(char *fname, char *dest, size_t dest_size) {
    uint8_t fname_md5[16] = {0};
    md5String(fname, fname_md5);

    int formatted = snprintf(dest, dest_size - 1, "%s", fs_path);
    for (unsigned int i = 0; i < 16; ++i)
        formatted += snprintf(&dest[formatted], dest_size - 1, "%02x", fname_md5[i]);
    
    return formatted;
}

void create_file() {
    int fname_size = read_int("fname size: ");
    if (fname_size <= 0) FAIL2("invalid fname size");

    char dest[0x60];
    char *fname = read_str("fname: ", fname_size);
    get_path(fname, dest, sizeof(dest));
    ENSURE_FILE_DOES_NOT_EXIST(dest);

    int contents_len = read_int("contents len: ");
    if (contents_len <= 0) FAIL2("invalid contents size");

    // BUG, read_str should return number of characters read, it is possible to leak some adjacent heap data
    char *file_contents = read_str("contents: ", contents_len);

    int fd;
    if((fd = creat(dest, 0600)) < 0) FAIL("creat");
    if(write(fd, file_contents, strlen(file_contents)) < 0) FAIL("write");
    if(close(fd) < 0) FAIL("close");

    printf("Data saved to: %s\n", dest);

    free(file_contents);
    free(fname);
}

void rename_file() {
    int fname_size = read_int("fname size: ");
    if (fname_size <= 0) FAIL2("invalid fname size");

    char dest[0x60];
    char *fname = read_str("fname: ", fname_size);
    get_path(fname, dest, sizeof(dest));
    ENSURE_FILE_EXISTS(dest);

    int new_fname_size = read_int("new fname size: ");
    if (new_fname_size <= 0) FAIL2("invalid fname size");

    char new_dest[0x60];
    char * new_fname = read_str("new fname: ", new_fname_size);
    get_path(new_fname, new_dest, sizeof(new_dest));
    ENSURE_FILE_DOES_NOT_EXIST(new_dest);

    if (rename(dest, new_dest) < 0) FAIL("rename");

    // BUG - free not called if file does not exist
    free(fname);
    free(new_fname);
}

void delete_file() {
    int fname_size = read_int("fname size: ");
    if (fname_size == 0) // BUG - heap null write
        FAIL2("invalid fname size");

    char dest[0x60];
    char *fname = read_str("fname: ", fname_size);
    get_path(fname, dest, sizeof(dest));
    ENSURE_FILE_EXISTS(dest);
    if(remove(dest) < 0) FAIL("remove");
    printf("File: %s removed\n", dest);

    // BUG - free not called if file does not exist
    free(fname);
}

void print_file() {
    int fname_size = read_int("fname size: ");
    if (fname_size <= 0) FAIL2("invalid fname size");

    char *fname = read_str("fname: ", fname_size);
    char dest[0x60];
    get_path(fname, dest, sizeof(dest));
    ENSURE_FILE_EXISTS(dest);
    
    int fd;
    if((fd = open(dest, O_RDONLY)) < 0) FAIL("open");

    int contents_len;
    if((contents_len = lseek(fd, 0, SEEK_END)) < 0) FAIL("lseek");
    if(lseek(fd, 0, SEEK_SET) < 0) FAIL("lseek");

    char *file_contents = malloc(contents_len);
    if(read(fd, file_contents, contents_len) < 0) FAIL("read");
    if(close(fd) < 0) FAIL("close");
    if(write(STDOUT_FILENO, file_contents, contents_len) < 0) FAIL("write");
    explicit_bzero(file_contents, contents_len);

    printf("Contents len: %d\n", contents_len);

    free(fname);
    free(file_contents);
}

void menu(){
    puts("0. create");
    puts("1. rename");
    puts("2. print");
    puts("3. delete");
    puts("4. exit");
    printf("> ");
}

void nothing() {}

void stop() {
    puts("Bye!");
    exit(0);
}

void **setup_functions(){
    void **fn_ptrs = calloc(5, sizeof(void *));
    fn_ptrs[0] = &stop;
    fn_ptrs[1] = &delete_file;
    fn_ptrs[2] = &print_file;
    fn_ptrs[3] = &rename_file;
    fn_ptrs[4] = &create_file;
    return fn_ptrs;
}

void *select_option(void **fn_ptrs){
    uint8_t opt = read_int("");
    if (opt > 4){
        puts("Invalid option");
        return &nothing;
    }

    return fn_ptrs[4 - opt];
}

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    struct stat st = {0};
    char *fs = getenv("FS_PATH");
    if(fs == NULL)
        snprintf(fs_path, sizeof(fs_path), "fs/");
    else{
        snprintf(fs_path, sizeof(fs_path), "%s", fs);
    }
    if (stat(fs_path, &st) == -1)
        if(mkdir(fs_path, 0777) < 0) FAIL("mkdir");
}

int main() {
    setup();
    void **fn_ptrs = setup_functions();

    while (1){
        menu();
        int (*func)() = select_option(fn_ptrs);
        func();
    }

    free(fn_ptrs);
    return 0;
}
