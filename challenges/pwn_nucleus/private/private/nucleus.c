#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gnu/libc-version.h>

void info() {
    printf("Nucleus (Pied Piper clone) 0.1-dev\n");
    printf("Copyright 2023 Hooli LLC\n\n");
    printf("Built on %s at %s\n", __DATE__, __TIME__);
}

size_t read_bytes(char *ptr, int size) {
  size_t count=0;
  for (int i = 0; i != size; i++, ptr++, count++) {
    read(0, ptr, 1);
    if (*ptr == '\n') break;
  }
  return count;
}

int is_digit(char c) {
    return (c >= '0' && c <= '9');
}

size_t get_int(){
    char input[16];

    read(0, input, 16);
    return strtoul(input, 0, 0);
}

char* compress(const char* input, char* output) {
    size_t input_len = strlen(input);
    size_t output_len = 0;

    for (size_t i = 0; i < input_len; ) {
        char c = input[i];
        size_t j = i + 1;
        while (j < input_len && input[j] == c) {
            j++;
        }
        int count = j - i;
        if (count > 1) {
            output[output_len++] = '$'; // use $ as marker for repeated characters
            output_len += sprintf(&output[output_len], "%d", count); // add count as string
        }
        if (c != ' ') { // ignore spaces
            output[output_len++] = c;
        } else { // keep spaces in their original position
            output[output_len++] = ' ';
        }
        i = j;
    }
    output[output_len] = '\0';
    return output;
}

char* decompress(char* input, int len, char* output) {
    int output_len = 0;
    int i = 0;
    while (i < len) {
        if (input[i] == '$' && input[i+1] == '$') {
            output[output_len++] = '\n';
            i += 2;
        } else if (input[i] == '$' && is_digit(input[i+1])) {
            int repeat = 0;
            i++;
            while (is_digit(input[i])) {
                repeat = repeat * 10 + (input[i] - '0');
                i++;
            }
            for (int j = 0; j < repeat; j++) {
                output[output_len++] = input[i];
            }
            i++;
	} else {
            output[output_len++] = input[i];
            i++;
        }
    }
    output[output_len] = '\0';
    return output;
}

int main() {
    size_t bytes, idx, x, i=0, d=0, c=0;
    char chr;
    char *input = malloc(1024);
    char *dptrs[1024] = {NULL}, *cptrs[1024] = {NULL}, *decompressed, *compressed;

    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    info();

    while(1) {
        i++;
        printf("1. Compress\n");
        printf("2. Decompress\n");
        printf("3. Cleanup\n");
        printf("4. Exit\n");
        printf("> ");
        idx = get_int();

        switch(idx) {
        case 1: 
            printf("Enter text: ");
            bytes = read_bytes(input,1023);
            cptrs[c] = malloc(bytes * 2);
            if (cptrs[c] == NULL) {
                printf("Error: Failed to allocate memory.\n");
                return 1;
            }
            compressed = compress(input, cptrs[c]);
            printf("[cid:%ld, ratio: %.2f] compressed text: %s\n\n", c, (float) strlen(compressed) / strlen(input), compressed);
            c++;
            break;
        case 2: 
            printf("Enter compressed text: ");
            bytes = read_bytes(input,1023);
            dptrs[d] = malloc(bytes * 2);
            if (dptrs[d] == NULL) {
                printf("Error: Failed to allocate memory.\n");
                return 1;
            }
            decompressed = decompress(input, bytes, dptrs[d]);
            printf("[did:%ld] decompressed text: %s\n\n", d, (char*)dptrs[d]);
            d++;
            break;
        case 3:
            printf("Compress or decompress slot? (c/d): ");
            scanf(" %c", &chr);
            getchar();

            printf("Idx: ");
            x = get_int();
            if (x >= 0 && x <= d && chr == 'd') {
                free(dptrs[x]);
            } else if (x >= 0 && x <= c && chr == 'c') {
                free(cptrs[x]);
            }
            else {
                printf("Invalid choice\n");
                exit(-1);
            }
            break;
        case 4:
            printf("Bye");
            exit(0);
        case 5:
            printf("Idx: ");
            x = get_int();
            printf("content: %s\n",cptrs[x]);
            break;
        default:
            printf("Invalid choice\n");
            exit(-1);
        }
        if (c + d > 8) {
            exit(0);
        }
    }
    free(compressed);
    free(decompressed);
    return 0;
}