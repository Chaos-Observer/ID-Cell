/* v0.11 C<->Python 差分向量工具：从 stdin 接收命令，向 stdout 返回单行结果。 */
#include "idcell_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *s, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = 0;
    if (strcmp(s, "-") == 0) {
        *out_len = 0;
        return 1;
    }
    while (s[0] && s[1]) {
        int hi, lo;
        if (n >= cap) return 0;
        hi = nibble(s[0]); lo = nibble(s[1]);
        if (hi < 0 || lo < 0) return 0;
        out[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    if (*s) return 0;
    *out_len = n;
    return 1;
}

static void print_hex(const uint8_t *p, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    if (len == 0) {
        putchar('-');
        return;
    }
    for (i = 0; i < len; i++) {
        putchar(hex[p[i] >> 4]);
        putchar(hex[p[i] & 15]);
    }
}

static const char *status_name(int rc)
{
    switch (rc) {
    case IDCELL_FRAME_NEED_MORE: return "NEED_MORE";
    case IDCELL_FRAME_BAD_SYNC: return "BAD_SYNC";
    case IDCELL_FRAME_BAD_LENGTH: return "BAD_LENGTH";
    case IDCELL_FRAME_BAD_VERSION: return "BAD_VERSION";
    case IDCELL_FRAME_BAD_PROFILE: return "BAD_PROFILE";
    case IDCELL_FRAME_BAD_TYPE: return "BAD_TYPE";
    case IDCELL_FRAME_BAD_TRAILER: return "BAD_TRAILER";
    case IDCELL_FRAME_BAD_CRC: return "BAD_CRC";
    case IDCELL_FRAME_BAD_AUTH: return "BAD_AUTH";
    case IDCELL_FRAME_E_CAPACITY: return "E_CAPACITY";
    default: return "E_INTERNAL";
    }
}

static int fields(char **v, int count, char *line)
{
    int n = 0;
    char *p = strtok(line, " \t\r\n");
    while (p && n < count) {
        v[n++] = p;
        p = strtok(NULL, " \t\r\n");
    }
    return n;
}

static void encode_command(char **v)
{
    idcell_frame_t f;
    uint8_t key[256], wire[IDCELL_MAX_FRAME];
    size_t keylen = 0, payload_len = 0, wire_len = 0;
    int rc;

    memset(&f, 0, sizeof(f));
    if (!parse_hex(v[1], key, sizeof(key), &keylen)) {
        printf("ERR BAD_COMMAND\n");
        return;
    }
    f.ver = (uint8_t)strtoul(v[2], NULL, 0);
    f.prof = (uint8_t)strtoul(v[3], NULL, 0);
    f.flags = (uint8_t)strtoul(v[4], NULL, 0);
    f.type = (uint8_t)strtoul(v[5], NULL, 0);
    f.seq = (uint16_t)strtoul(v[6], NULL, 0);
    f.txn = (uint16_t)strtoul(v[7], NULL, 0);
    if (!parse_hex(v[8], f.src.b, 8, &payload_len) || payload_len != 8 ||
        !parse_hex(v[9], f.dst.b, 8, &payload_len) || payload_len != 8 ||
        !parse_hex(v[12], f.payload, sizeof(f.payload), &payload_len)) {
        printf("ERR BAD_COMMAND\n");
        return;
    }
    f.group = (uint16_t)strtoul(v[10], NULL, 0);
    f.ts_us = (uint64_t)strtoull(v[11], NULL, 0);
    f.payload_len = (uint16_t)payload_len;

    if (keylen)
        rc = idcell_frame_encode_auth(&f, key, keylen, wire, sizeof(wire), &wire_len);
    else
        rc = idcell_frame_encode(&f, wire, sizeof(wire), &wire_len);
    if (rc != IDCELL_FRAME_OK) {
        printf("ERR %s\n", status_name(rc));
        return;
    }
    printf("OK ");
    print_hex(wire, wire_len);
    putchar('\n');
}

static void decode_command(char **v)
{
    idcell_frame_t f;
    uint8_t key[256], wire[IDCELL_MAX_FRAME * 2];
    size_t keylen = 0, wire_len = 0, consumed = 0;
    int rc;

    if (!parse_hex(v[1], key, sizeof(key), &keylen) ||
        !parse_hex(v[2], wire, sizeof(wire), &wire_len)) {
        printf("ERR BAD_COMMAND\n");
        return;
    }
    if (keylen)
        rc = idcell_frame_decode_auth(wire, wire_len, key, keylen, &f, &consumed);
    else
        rc = idcell_frame_decode(wire, wire_len, &f, &consumed);
    if (rc != IDCELL_FRAME_OK) {
        printf("ERR %s\n", status_name(rc));
        return;
    }
    printf("OK %s %lu 0x%02x 0x%02x 0x%02x 0x%02x 0x%04x 0x%04x %u ",
           f.prof == 1 ? "OK_RT" : "OK_STD", (unsigned long)consumed,
           f.ver, f.prof, f.flags, f.type, f.seq, f.txn, (unsigned)f.payload_len);
    print_hex(f.src.b, 8); putchar(' ');
    print_hex(f.dst.b, 8);
    printf(" 0x%04x %llu ", f.group, (unsigned long long)f.ts_us);
    print_hex(f.payload, f.payload_len); putchar(' ');
    print_hex(f.auth_tag, (f.flags & IDCELL_FLAG_AUTH) ? IDCELL_AUTH_TAG_LEN : 0);
    putchar('\n');
}

int main(void)
{
    char line[8192];
    while (fgets(line, sizeof(line), stdin)) {
        char *v[16];
        int n = fields(v, 16, line);
        if (n == 0) continue;
        if (strcmp(v[0], "ENCODE") == 0 && n == 13) encode_command(v);
        else if (strcmp(v[0], "DECODE") == 0 && n == 3) decode_command(v);
        else printf("ERR BAD_COMMAND\n");
        fflush(stdout);
    }
    return 0;
}
