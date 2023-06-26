#include <stdio.h>
#include <errno.h>
#include <stdint.h>

#define FLAG_LEN 0x20

void dump(uint32_t *data, uint32_t len){
    for (size_t i = 0; i < len; i++)
    {
        printf("0x%02x ", data[i]);
    }
    puts("");
}

int main() {
    uint8_t flag_buf[0x40];
    FILE *file = fopen("../../flag.txt", "rb");
    if(!file){
        perror("fopen");
        return 1;
    }

    fread(flag_buf, sizeof(char), FLAG_LEN, file);
    fclose(file);

    uint32_t flag[FLAG_LEN];
    for (size_t i = 0; i < FLAG_LEN; i++)
    {
        flag[i] = flag_buf[i];
    }

    uint32_t a[FLAG_LEN];
    uint32_t b[FLAG_LEN];
    uint32_t d[FLAG_LEN];

    for (size_t i = 0; i < FLAG_LEN; i++)
    {
        a[i] = ((flag[i] + flag[(i+1) % FLAG_LEN] + flag[(i+2) % FLAG_LEN]) + 0x1337);
    }

    for (size_t i = 0; i < FLAG_LEN; i++)
    {
        b[i] = (flag[i] + flag[(i+1) % FLAG_LEN]) / 0x3;
    }

    for (size_t i = 0; i < FLAG_LEN; i++)
    {
        d[i] = (a[i] ^ b[i]) & 0xFF;
    }

    dump(d, FLAG_LEN);
}
