/*
 * ID-CELL · SHA-256 / HMAC-SHA256（零依赖实现）
 *
 * 用于 AUTHORIZE 段的挑战-响应（FR-022）：响应 MUST NOT 携带可重放的静态
 * 明文凭证，同一挑战的响应 MUST 只被接受一次。本实现把 nonce、时间戳、
 * 源/目的 DID 与事务号一并纳入 HMAC 输入，使同一响应无法在另一会话重放。
 */
#include "idcell_internal.h"

static const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(idcell_sha256_t *c, const uint8_t *p)
{
    uint32_t w[64];
    uint32_t a, b, cc, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19)  ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a=c->state[0]; b=c->state[1]; cc=c->state[2]; d=c->state[3];
    e=c->state[4]; f=c->state[5]; g=c->state[6];  h=c->state[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        t1 = h + S1 + ch + K[i] + w[i];
        t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }

    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g;  c->state[7]+=h;
}

void idcell_sha256_init(idcell_sha256_t *c)
{
    c->state[0]=0x6a09e667u; c->state[1]=0xbb67ae85u;
    c->state[2]=0x3c6ef372u; c->state[3]=0xa54ff53au;
    c->state[4]=0x510e527fu; c->state[5]=0x9b05688cu;
    c->state[6]=0x1f83d9abu; c->state[7]=0x5be0cd19u;
    c->bitlen = 0;
    c->buflen = 0;
}

void idcell_sha256_update(idcell_sha256_t *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t i;

    for (i = 0; i < len; i++) {
        c->buf[c->buflen++] = p[i];
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->bitlen += 512;
            c->buflen = 0;
        }
    }
}

void idcell_sha256_final(idcell_sha256_t *c, uint8_t out[32])
{
    size_t i = c->buflen;
    int k;

    if (i < 56) {
        c->buf[i++] = 0x80;
        while (i < 56) c->buf[i++] = 0x00;
    } else {
        c->buf[i++] = 0x80;
        while (i < 64) c->buf[i++] = 0x00;
        sha256_block(c, c->buf);
        memset(c->buf, 0, 56);
        i = 56;
    }
    c->bitlen += (uint64_t)c->buflen * 8;
    idcell_put_u64(c->buf + 56, c->bitlen);
    sha256_block(c, c->buf);
    for (k = 0; k < 8; k++) idcell_put_u32(out + k*4, c->state[k]);
}

void idcell_sha256(const void *data, size_t len, uint8_t out[32])
{
    idcell_sha256_t c;
    idcell_sha256_init(&c);
    idcell_sha256_update(&c, data, len);
    idcell_sha256_final(&c, out);
}

void idcell_hmac_sha256(const uint8_t *key, size_t keylen,
                        const uint8_t *msg, size_t msglen, uint8_t out[32])
{
    uint8_t k[64], ipad[64], opad[64], inner[32];
    idcell_sha256_t c;
    int i;

    memset(k, 0, sizeof(k));
    if (keylen > 64) idcell_sha256(key, keylen, k);
    else memcpy(k, key, keylen);

    for (i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5C; }

    idcell_sha256_init(&c);
    idcell_sha256_update(&c, ipad, 64);
    idcell_sha256_update(&c, msg, msglen);
    idcell_sha256_final(&c, inner);

    idcell_sha256_init(&c);
    idcell_sha256_update(&c, opad, 64);
    idcell_sha256_update(&c, inner, 32);
    idcell_sha256_final(&c, out);
}

void idcell_session_key_derive(const uint8_t cred[IDCELL_CRED_LEN],
                               const uint8_t nonce[16],
                               const idcell_did_t *a, const idcell_did_t *b,
                               uint16_t auth_txn, uint32_t binding_id,
                               uint64_t session_id, uint8_t out[32])
{
    static const char extract_domain[] = "IDCELL-AUTH-EXTRACT-V1";
    static const char expand_domain[] = "IDCELL-SESSION-KEY-V1";
    uint8_t extract[sizeof(extract_domain) - 1 + 16];
    uint8_t info[sizeof(expand_domain) - 1 + 16 + 2 + 4 + 8 + 1];
    uint8_t prk[32];
    size_t pos = 0;
    int a_first = (memcmp(a->b, b->b, 8) <= 0);

    memcpy(extract, extract_domain, sizeof(extract_domain) - 1);
    memcpy(extract + sizeof(extract_domain) - 1, nonce, 16);
    idcell_hmac_sha256(cred, IDCELL_CRED_LEN, extract, sizeof(extract), prk);

    memcpy(info + pos, expand_domain, sizeof(expand_domain) - 1);
    pos += sizeof(expand_domain) - 1;
    memcpy(info + pos, a_first ? a->b : b->b, 8); pos += 8;
    memcpy(info + pos, a_first ? b->b : a->b, 8); pos += 8;
    idcell_put_u16(info + pos, auth_txn); pos += 2;
    idcell_put_u32(info + pos, binding_id); pos += 4;
    idcell_put_u64(info + pos, session_id); pos += 8;
    info[pos++] = 1; /* HKDF 式单块 Expand，输出严格为 32B。 */
    idcell_hmac_sha256(prk, sizeof(prk), info, pos, out);
    memset(prk, 0, sizeof(prk));
    memset(extract, 0, sizeof(extract));
    memset(info, 0, sizeof(info));
}
