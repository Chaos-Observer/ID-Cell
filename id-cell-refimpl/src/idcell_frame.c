/*
 * ID-CELL · L2 帧编解码（§09.1 帧字段表 · §08.12 帧结构）
 *
 * 帧布局（全部多字节字段为大端序，跨大小端平台结果一致）：
 *   SYNC(2) VER(1) PROF(1) FLAGS(1) TYPE(1) SEQ(2) TXN(2) LEN(2)
 *   SRC(8) DST(8) GROUP(2) TS(6) | PAYLOAD(LEN) | AUTH_TAG(0/16) | CRC16(2) TRAILER(2)
 */
#include "idcell_internal.h"

/* ------------------------------------------------------------------ 字节序 */

void idcell_put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}

void idcell_put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

void idcell_put_u64(uint8_t *p, uint64_t v)
{
    idcell_put_u32(p, (uint32_t)(v >> 32));
    idcell_put_u32(p + 4, (uint32_t)v);
}

void idcell_put_f64(uint8_t *p, double v)
{
    uint64_t bits;
    memcpy(&bits, &v, sizeof(bits));
    idcell_put_u64(p, bits);
}

uint16_t idcell_get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

uint32_t idcell_get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

uint64_t idcell_get_u64(const uint8_t *p)
{
    return ((uint64_t)idcell_get_u32(p) << 32) | idcell_get_u32(p + 4);
}

double idcell_get_f64(const uint8_t *p)
{
    uint64_t bits = idcell_get_u64(p);
    double v;
    memcpy(&v, &bits, sizeof(v));
    return v;
}

/* ------------------------------------------------------------------ CRC-16 */

/*
 * CRC-16/CCITT-FALSE：poly=0x1021, init=0xFFFF, refin=false, refout=false,
 * xorout=0x0000。v0.11 覆盖 36B 头 + payload + 可选 AUTH_TAG。
 */
uint16_t idcell_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    size_t i;
    int b;

    for (i = 0; i < len; i++) {
        crc ^= (uint16_t)((uint16_t)data[i] << 8);
        for (b = 0; b < 8; b++) {
            if (crc & 0x8000) crc = (uint16_t)((crc << 1) ^ 0x1021);
            else               crc = (uint16_t)(crc << 1);
        }
    }
    return crc;
}

/* ------------------------------------------------------------------ TLV */

/*
 * TLV 结构：IDX(2) SUB(1) TYPE(1) LEN(2) VALUE(LEN)。
 * LEN 以字节计，value 本身不再内嵌长度。
 */
int idcell_tlv_put(uint8_t *buf, uint16_t cap, uint16_t *pos,
                   uint16_t idx, uint8_t sub, uint8_t type,
                   const void *val, uint16_t len)
{
    uint16_t p = *pos;

    if ((uint32_t)p + IDCELL_TLV_HDR_LEN + len > cap) return -1;
    idcell_put_u16(buf + p, idx);
    buf[p + 2] = sub;
    buf[p + 3] = type;
    idcell_put_u16(buf + p + 4, len);
    if (len && val) memcpy(buf + p + IDCELL_TLV_HDR_LEN, val, len);
    *pos = (uint16_t)(p + IDCELL_TLV_HDR_LEN + len);
    return 0;
}

int idcell_tlv_next(const uint8_t *buf, uint16_t len, uint16_t *pos, idcell_tlv_t *out)
{
    uint16_t p = *pos;

    if (p == len) return 1;                 /* 正常结束 */
    if ((uint32_t)p + IDCELL_TLV_HDR_LEN > len) return -1;  /* 截断 */

    out->idx = idcell_get_u16(buf + p);
    out->sub = buf[p + 2];
    out->type = buf[p + 3];
    out->len = idcell_get_u16(buf + p + 4);
    if ((uint32_t)p + IDCELL_TLV_HDR_LEN + out->len > len) return -1;
    out->val = buf + p + IDCELL_TLV_HDR_LEN;
    *pos = (uint16_t)(p + IDCELL_TLV_HDR_LEN + out->len);
    return 0;
}

/* ------------------------------------------------------------------ 帧 */

#define SYNC0 0xA5
#define SYNC1 0xA5
#define TRAIL0 0x5A
#define TRAIL1 0xA5

#define OFF_SYNC   0
#define OFF_VER    2
#define OFF_PROF   3
#define OFF_FLAGS  4
#define OFF_TYPE   5
#define OFF_SEQ    6
#define OFF_TXN    8
#define OFF_LEN    10
#define OFF_SRC    12
#define OFF_DST    20
#define OFF_GROUP  28
#define OFF_TS     30

static int frame_version_ok(uint8_t ver)
{
    return (ver >> 4) == IDCELL_VERSION_MAJOR;
}

/* C 标准 TYPE 表为 1..24；25 预留给可选 RT_DATA。编码与解码共用同一判据。 */
static int frame_type_ok(uint8_t type)
{
    return type >= IDCELL_FT_DISCOVER && type <= 25;
}

int idcell_frame_encode_auth(const idcell_frame_t *f, const uint8_t *key, size_t keylen,
                             uint8_t *out, size_t cap, size_t *out_len)
{
    size_t tag_len, total, crc_at;
    uint16_t crc;
    uint8_t mac[32];

    if (out_len) *out_len = 0;
    if (!f || !out || !out_len) return IDCELL_FRAME_E_CAPACITY;
    if (!frame_version_ok(f->ver)) return IDCELL_FRAME_BAD_VERSION;
    if (f->prof > 1) return IDCELL_FRAME_BAD_PROFILE;
    if (!frame_type_ok(f->type)) return IDCELL_FRAME_BAD_TYPE;

    tag_len = (f->flags & IDCELL_FLAG_AUTH) ? IDCELL_AUTH_TAG_LEN : 0;
    if (f->payload_len > IDCELL_MAX_PAYLOAD ||
        (tag_len && f->payload_len > IDCELL_MAX_AUTH_PAYLOAD))
        return IDCELL_FRAME_BAD_LENGTH;
    if (tag_len && (!key || keylen == 0)) return IDCELL_FRAME_BAD_AUTH;

    total = IDCELL_HDR_LEN + f->payload_len + tag_len + IDCELL_TRAILER_LEN;
    if (cap < total) return IDCELL_FRAME_E_CAPACITY;

    out[OFF_SYNC + 0] = SYNC0;
    out[OFF_SYNC + 1] = SYNC1;
    out[OFF_VER]      = f->ver;
    out[OFF_PROF]     = f->prof;
    out[OFF_FLAGS]    = f->flags;
    out[OFF_TYPE]     = f->type;
    idcell_put_u16(out + OFF_SEQ, f->seq);
    idcell_put_u16(out + OFF_TXN, f->txn);
    idcell_put_u16(out + OFF_LEN, f->payload_len);
    memcpy(out + OFF_SRC, f->src.b, 8);
    memcpy(out + OFF_DST, f->dst.b, 8);
    idcell_put_u16(out + OFF_GROUP, f->group);
    idcell_put_u32(out + OFF_TS, (uint32_t)(f->ts_us >> 16));
    idcell_put_u16(out + OFF_TS + 4, (uint16_t)(f->ts_us & 0xFFFF));

    if (f->payload_len) memcpy(out + IDCELL_HDR_LEN, f->payload, f->payload_len);
    if (tag_len) {
        idcell_hmac_sha256(key, keylen, out, IDCELL_HDR_LEN + f->payload_len, mac);
        memcpy(out + IDCELL_HDR_LEN + f->payload_len, mac, tag_len);
    }

    crc_at = IDCELL_HDR_LEN + f->payload_len + tag_len;
    crc = idcell_crc16(out, crc_at);
    idcell_put_u16(out + crc_at, crc);
    out[crc_at + 2] = TRAIL0;
    out[crc_at + 3] = TRAIL1;

    *out_len = total;
    return IDCELL_FRAME_OK;
}

int idcell_frame_encode(const idcell_frame_t *f, uint8_t *out, size_t cap, size_t *out_len)
{
    return idcell_frame_encode_auth(f, NULL, 0, out, cap, out_len);
}

int idcell_frame_decode_auth(const uint8_t *in, size_t len, const uint8_t *key, size_t keylen,
                             idcell_frame_t *out, size_t *consumed)
{
    uint16_t payload_len;
    size_t tag_len, total, tag_at, crc_at;
    uint8_t mac[32];
    uint8_t diff = 0;
    size_t i;

    if (consumed) *consumed = 0;
    if (!in || !out) return IDCELL_FRAME_BAD_LENGTH;
    if (len == 0) return IDCELL_FRAME_NEED_MORE;
    if (in[OFF_SYNC] != SYNC0) return IDCELL_FRAME_BAD_SYNC;
    if (len == 1) return IDCELL_FRAME_NEED_MORE;
    if (in[OFF_SYNC + 1] != SYNC1) return IDCELL_FRAME_BAD_SYNC;
    if (len < IDCELL_HDR_LEN) return IDCELL_FRAME_NEED_MORE;

    payload_len = idcell_get_u16(in + OFF_LEN);
    tag_len = (in[OFF_FLAGS] & IDCELL_FLAG_AUTH) ? IDCELL_AUTH_TAG_LEN : 0;
    /* 必须在计算总长度、复制或物化 payload 之前拒绝非法 LEN。 */
    if (payload_len > IDCELL_MAX_PAYLOAD ||
        (tag_len && payload_len > IDCELL_MAX_AUTH_PAYLOAD))
        return IDCELL_FRAME_BAD_LENGTH;
    if (!frame_version_ok(in[OFF_VER])) return IDCELL_FRAME_BAD_VERSION;
    if (in[OFF_PROF] > 1) return IDCELL_FRAME_BAD_PROFILE;
    if (!frame_type_ok(in[OFF_TYPE])) return IDCELL_FRAME_BAD_TYPE;

    total = IDCELL_HDR_LEN + payload_len + tag_len + IDCELL_TRAILER_LEN;
    if (len < total) return IDCELL_FRAME_NEED_MORE;
    if (in[total - 2] != TRAIL0 || in[total - 1] != TRAIL1)
        return IDCELL_FRAME_BAD_TRAILER;

    crc_at = total - IDCELL_TRAILER_LEN;
    if (idcell_get_u16(in + crc_at) != idcell_crc16(in, crc_at))
        return IDCELL_FRAME_BAD_CRC;

    tag_at = IDCELL_HDR_LEN + payload_len;
    if (tag_len) {
        if (!key || keylen == 0) return IDCELL_FRAME_BAD_AUTH;
        idcell_hmac_sha256(key, keylen, in, tag_at, mac);
        for (i = 0; i < tag_len; i++) diff |= (uint8_t)(in[tag_at + i] ^ mac[i]);
        if (diff != 0) return IDCELL_FRAME_BAD_AUTH;
    }

    out->ver   = in[OFF_VER];
    out->prof  = in[OFF_PROF];
    out->flags = in[OFF_FLAGS];
    out->type  = in[OFF_TYPE];
    out->seq   = idcell_get_u16(in + OFF_SEQ);
    out->txn   = idcell_get_u16(in + OFF_TXN);
    memcpy(out->src.b, in + OFF_SRC, 8);
    memcpy(out->dst.b, in + OFF_DST, 8);
    out->group = idcell_get_u16(in + OFF_GROUP);
    out->ts_us = ((uint64_t)idcell_get_u32(in + OFF_TS) << 16) |
                 idcell_get_u16(in + OFF_TS + 4);
    out->payload_len = payload_len;
    if (payload_len) memcpy(out->payload, in + IDCELL_HDR_LEN, payload_len);
    memset(out->auth_tag, 0, sizeof(out->auth_tag));
    if (tag_len) memcpy(out->auth_tag, in + tag_at, tag_len);
    if (consumed) *consumed = total;
    return IDCELL_FRAME_OK;
}

int idcell_frame_decode(const uint8_t *in, size_t len, idcell_frame_t *out, size_t *consumed)
{
    return idcell_frame_decode_auth(in, len, NULL, 0, out, consumed);
}
