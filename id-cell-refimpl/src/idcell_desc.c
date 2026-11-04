/*
 * ID-CELL · 能力描述符 / 需求描述符的序列化（§09.2 · FR-011）
 *
 * 描述符在帧里以嵌套 TLV 承载：
 *   外层 TLV: IDX=index, SUB=sub, TYPE=CAP_DESC, VALUE=内层 TLV 序列
 *   内层 TLV: TYPE=IDCELL_CF_*, VALUE=字段值
 * 这样扩展字段只需新增一个内层 TLV 类型，不改帧头，也不改外层结构。
 */
#include "idcell_internal.h"

static int put_str(uint8_t *buf, uint16_t cap, uint16_t *pos, uint8_t type, const char *s)
{
    uint16_t n = 0;
    if (s) n = (uint16_t)strlen(s);
    if (n > 255) n = 255;
    return idcell_tlv_put(buf, cap, pos, 0, 0, type, s ? (const uint8_t *)s : (const uint8_t *)"", n);
}

static void get_str(const uint8_t *val, uint16_t len, char *out, size_t out_cap)
{
    size_t n = len;
    if (n >= out_cap) n = out_cap - 1;
    if (n) memcpy(out, val, n);
    out[n] = '\0';
}

static void get_u8(const uint8_t *val, uint16_t len, uint8_t *out)
{
    *out = len >= 1 ? val[0] : 0;
}

static void get_u16v(const uint8_t *val, uint16_t len, uint16_t *out)
{
    *out = len >= 2 ? idcell_get_u16(val) : 0;
}

static void get_u32v(const uint8_t *val, uint16_t len, uint32_t *out)
{
    *out = len >= 4 ? idcell_get_u32(val) : 0;
}

static void get_f64v(const uint8_t *val, uint16_t len, double *out)
{
    *out = len >= 8 ? idcell_get_f64(val) : 0.0;
}

/* ---------------------------------------------------------------- 能力描述符 */

int idcell_desc_encode(const idcell_capability_t *c, uint8_t *buf, uint16_t cap)
{
    uint16_t pos = 0;
    uint8_t b8;
    uint8_t b16[2];
    uint8_t b32[4];
    uint8_t b64[8];
    int i;

    if (put_str(buf, cap, &pos, IDCELL_CF_LABEL, c->label) < 0) return -1;

    b8 = (uint8_t)c->kind;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_KIND, &b8, 1);
    b8 = (uint8_t)c->dir;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_DIR, &b8, 1);
    b8 = (uint8_t)c->perm;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_PERM, &b8, 1);

    /* v0.8：量种 ID（u8）取代原自由字符串 dim（§24.2） */
    b8 = (uint8_t)c->qty;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_DIM, &b8, 1);

    put_str(buf, cap, &pos, IDCELL_CF_UNIT, c->unit);

    for (i = 0; i < c->accept_count && i < IDCELL_MAX_ACCEPT; i++)
        put_str(buf, cap, &pos, IDCELL_CF_ACCEPT, c->accept_units[i]);

    b8 = (uint8_t)c->conv_class;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_CONV, &b8, 1);

    /* v0.8：数据类型与定点缩放（§24.4） */
    b8 = (uint8_t)c->dtype;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_DTYPE, &b8, 1);
    b8 = c->scale_exp;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_SCALE, &b8, 1);

    /* v0.9：可接受值类型（§24.8），每项 2 字节 (dtype, scale_exp) */
    for (i = 0; i < c->accept_type_count && i < IDCELL_MAX_ACCEPT_TYPES; i++) {
        uint8_t pair[2];
        pair[0] = (uint8_t)c->accept_types[i].dtype;
        pair[1] = c->accept_types[i].scale_exp;
        idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_ACCEPT_T, pair, 2);
    }
    for (i = 0; i < c->schema_count && i < IDCELL_MAX_SCHEMA_SET; i++) {
        idcell_put_u64(b64, c->schema_set[i]);
        idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_SCHEMA, b64, 8);
    }

    idcell_put_f64(b64, c->range[0]);
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_RANGE, b64, 8);
    idcell_put_f64(b64, c->range[1]);
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_RANGE, b64, 8);

    idcell_put_f64(b64, c->precision);
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_PRECISION, b64, 8);

    put_str(buf, cap, &pos, IDCELL_CF_FRAME, c->frame_ref);

    b8 = c->invertible ? 1 : 0;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_INVERT, &b8, 1);

    idcell_put_u32(b32, c->min_sync_ms);
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_MINSYNC, b32, 4);
    idcell_put_u32(b32, c->stale_ms);
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_STALE, b32, 4);
    idcell_put_u32(b32, c->load_cap);
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_LOADCAP, b32, 4);

    b8 = (uint8_t)c->trigger;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_TRIGGER, &b8, 1);
    b8 = c->hold_semantics;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_HOLD, &b8, 1);
    b8 = (uint8_t)c->fail_action;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_FAIL, &b8, 1);
    b8 = (uint8_t)c->provenance;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_PROV, &b8, 1);

    put_str(buf, cap, &pos, IDCELL_CF_ESCALATE, c->escalate);

    for (i = 0; i < c->dep_count && i < IDCELL_MAX_DEPS; i++) {
        idcell_put_u16(b16, c->deps[i]);
        idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_CF_DEPS, b16, 2);
    }

    return pos;
}

int idcell_desc_decode(const uint8_t *buf, uint16_t len, idcell_cap_store_t *out)
{
    uint16_t pos = 0;
    int range_seen = 0, range_i = 0;
    idcell_tlv_t t;
    int rc;

    memset(out, 0, sizeof(*out));

    while ((rc = idcell_tlv_next(buf, len, &pos, &t)) == 0) {
        switch (t.type) {
        case IDCELL_CF_LABEL:    get_str(t.val, t.len, out->label, sizeof(out->label)); break;
        case IDCELL_CF_KIND:     get_u8(t.val, t.len, &out->kind); break;
        case IDCELL_CF_DIR:      get_u8(t.val, t.len, &out->dir); break;
        case IDCELL_CF_PERM:     get_u8(t.val, t.len, &out->perm); break;
        case IDCELL_CF_DIM:      get_u8(t.val, t.len, &out->qty); break;
        case IDCELL_CF_UNIT:     get_str(t.val, t.len, out->unit, sizeof(out->unit)); break;
        case IDCELL_CF_ACCEPT:
            if (out->accept_count < IDCELL_MAX_ACCEPT)
                get_str(t.val, t.len, out->accept[out->accept_count++], sizeof(out->accept[0]));
            break;
        case IDCELL_CF_CONV:     get_u8(t.val, t.len, &out->conv); break;
        case IDCELL_CF_DTYPE:    get_u8(t.val, t.len, &out->dtype); break;
        case IDCELL_CF_SCALE:    get_u8(t.val, t.len, &out->scale_exp); break;
        case IDCELL_CF_ACCEPT_T:
            if (out->accept_type_count < IDCELL_MAX_ACCEPT_TYPES && t.len >= 2) {
                out->accept_types[out->accept_type_count].dtype =
                    (idcell_dtype_t)t.val[0];
                out->accept_types[out->accept_type_count].scale_exp = t.val[1];
                out->accept_type_count++;
            }
            break;
        case IDCELL_CF_SCHEMA:
            if (out->schema_count < IDCELL_MAX_SCHEMA_SET && t.len == 8)
                out->schema_set[out->schema_count++] = idcell_get_u64(t.val);
            break;
        case IDCELL_CF_RANGE:
            if (range_i < 2) get_f64v(t.val, t.len, &out->range[range_i]);
            range_i++; range_seen++;
            break;
        case IDCELL_CF_PRECISION:get_f64v(t.val, t.len, &out->precision); break;
        case IDCELL_CF_FRAME:    get_str(t.val, t.len, out->frame_ref, sizeof(out->frame_ref)); break;
        case IDCELL_CF_INVERT:   get_u8(t.val, t.len, &out->invertible); break;
        case IDCELL_CF_MINSYNC:  get_u32v(t.val, t.len, &out->min_sync_ms); break;
        case IDCELL_CF_STALE:    get_u32v(t.val, t.len, &out->stale_ms); break;
        case IDCELL_CF_LOADCAP:  get_u32v(t.val, t.len, &out->load_cap); break;
        case IDCELL_CF_TRIGGER:  get_u8(t.val, t.len, &out->trigger); break;
        case IDCELL_CF_HOLD:     get_u8(t.val, t.len, &out->hold_semantics); break;
        case IDCELL_CF_FAIL:     get_u8(t.val, t.len, &out->fail_action); break;
        case IDCELL_CF_PROV:     get_u8(t.val, t.len, &out->provenance); break;
        case IDCELL_CF_ESCALATE: get_str(t.val, t.len, out->escalate, sizeof(out->escalate)); break;
        case IDCELL_CF_DEPS:
            if (out->dep_count < IDCELL_MAX_DEPS)
                get_u16v(t.val, t.len, &out->deps[out->dep_count++]);
            break;
        default: break;
        }
    }
    if (rc < 0) return -1;
    if (!range_seen) { out->range[0] = 0.0; out->range[1] = 0.0; }
    return 0;
}

/* ---------------------------------------------------------------- 公共/授权描述分离 */

static int desc_string_ok(const idcell_tlv_t *t, size_t cap)
{
    return t->len < cap && (t->len == 0 || memchr(t->val, 0, t->len) == NULL);
}

static int public_field_bit(uint8_t type)
{
    switch (type) {
    case IDCELL_CF_LABEL:   return 0;
    case IDCELL_CF_KIND:    return 1;
    case IDCELL_CF_DIR:     return 2;
    case IDCELL_CF_DIM:     return 3;
    case IDCELL_CF_UNIT:    return 4;
    case IDCELL_CF_CONV:    return 5;
    case IDCELL_CF_DTYPE:   return 6;
    case IDCELL_CF_SCALE:   return 7;
    case IDCELL_CF_MINSYNC: return 8;
    case IDCELL_CF_STALE:   return 9;
    case IDCELL_CF_LOADCAP: return 10;
    case IDCELL_CF_TRIGGER: return 11;
    default: return -1;
    }
}

int idcell_public_desc_encode(const idcell_capability_t *c, uint8_t *buf, uint16_t cap)
{
    uint16_t pos = 0;
    uint8_t b8, b32[4];
    int i;
#define PUBLIC_PUT(type, value, len) do { \
        if (idcell_tlv_put(buf, cap, &pos, 0, 0, (type), (value), (len)) < 0) return -1; \
    } while (0)
    if (!c || !buf) return -1;
    if (put_str(buf, cap, &pos, IDCELL_CF_LABEL, c->label) < 0) return -1;
    b8 = (uint8_t)c->kind; PUBLIC_PUT(IDCELL_CF_KIND, &b8, 1);
    b8 = (uint8_t)c->dir; PUBLIC_PUT(IDCELL_CF_DIR, &b8, 1);
    b8 = (uint8_t)c->qty; PUBLIC_PUT(IDCELL_CF_DIM, &b8, 1);
    if (put_str(buf, cap, &pos, IDCELL_CF_UNIT, c->unit) < 0) return -1;
    for (i = 0; i < c->accept_count && i < IDCELL_MAX_ACCEPT; i++)
        if (put_str(buf, cap, &pos, IDCELL_CF_ACCEPT, c->accept_units[i]) < 0) return -1;
    b8 = (uint8_t)c->conv_class; PUBLIC_PUT(IDCELL_CF_CONV, &b8, 1);
    b8 = (uint8_t)c->dtype; PUBLIC_PUT(IDCELL_CF_DTYPE, &b8, 1);
    b8 = c->scale_exp; PUBLIC_PUT(IDCELL_CF_SCALE, &b8, 1);
    for (i = 0; i < c->accept_type_count && i < IDCELL_MAX_ACCEPT_TYPES; i++) {
        uint8_t pair[2];
        pair[0] = (uint8_t)c->accept_types[i].dtype;
        pair[1] = c->accept_types[i].scale_exp;
        PUBLIC_PUT(IDCELL_CF_ACCEPT_T, pair, 2);
    }
    idcell_put_u32(b32, c->min_sync_ms); PUBLIC_PUT(IDCELL_CF_MINSYNC, b32, 4);
    idcell_put_u32(b32, c->stale_ms); PUBLIC_PUT(IDCELL_CF_STALE, b32, 4);
    idcell_put_u32(b32, c->load_cap); PUBLIC_PUT(IDCELL_CF_LOADCAP, b32, 4);
    b8 = (uint8_t)c->trigger; PUBLIC_PUT(IDCELL_CF_TRIGGER, &b8, 1);
#undef PUBLIC_PUT
    return pos;
}

static int public_field_rank(uint8_t type)
{
    switch (type) {
    case IDCELL_CF_LABEL: return 0;
    case IDCELL_CF_KIND: return 1;
    case IDCELL_CF_DIR: return 2;
    case IDCELL_CF_DIM: return 3;
    case IDCELL_CF_UNIT: return 4;
    case IDCELL_CF_ACCEPT: return 5;
    case IDCELL_CF_CONV: return 6;
    case IDCELL_CF_DTYPE: return 7;
    case IDCELL_CF_SCALE: return 8;
    case IDCELL_CF_ACCEPT_T: return 9;
    case IDCELL_CF_MINSYNC: return 10;
    case IDCELL_CF_STALE: return 11;
    case IDCELL_CF_LOADCAP: return 12;
    case IDCELL_CF_TRIGGER: return 13;
    default: return -1;
    }
}

int idcell_public_desc_validate(const uint8_t *buf, uint16_t len)
{
    uint16_t pos = 0;
    uint32_t seen = 0;
    int previous = -1, rank;
    idcell_tlv_t t;
    int rc, bit;
    while ((rc = idcell_tlv_next(buf, len, &pos, &t)) == 0) {
        rank = public_field_rank(t.type);
        if (rank < 0 || rank < previous) return -1;
        previous = rank;
        if (t.type == IDCELL_CF_ACCEPT) {
            if (!desc_string_ok(&t, IDCELL_MAX_UNIT)) return -1;
            continue;
        }
        if (t.type == IDCELL_CF_ACCEPT_T) {
            if (t.len != 2) return -1;
            continue;
        }
        bit = public_field_bit(t.type);
        if (bit < 0 || (seen & (1u << bit))) return -1;
        if ((t.type == IDCELL_CF_LABEL && !desc_string_ok(&t, IDCELL_MAX_LABEL)) ||
            (t.type == IDCELL_CF_UNIT && !desc_string_ok(&t, IDCELL_MAX_UNIT))) return -1;
        if (t.type == IDCELL_CF_LABEL || t.type == IDCELL_CF_UNIT) {
            if (!t.len) return -1;
        } else if (t.type == IDCELL_CF_MINSYNC || t.type == IDCELL_CF_STALE ||
                   t.type == IDCELL_CF_LOADCAP) {
            if (t.len != 4) return -1;
        } else if (t.len != 1) return -1;
        seen |= 1u << bit;
    }
    return (rc < 0 || seen != 0x0FFFu) ? -1 : 0;
}

static int authorized_field_bit(uint8_t type)
{
    switch (type) {
    case IDCELL_CF_LABEL: return 0;
    case IDCELL_CF_KIND: return 1;
    case IDCELL_CF_DIR: return 2;
    case IDCELL_CF_PERM: return 3;
    case IDCELL_CF_DIM: return 4;
    case IDCELL_CF_UNIT: return 5;
    case IDCELL_CF_CONV: return 6;
    case IDCELL_CF_DTYPE: return 7;
    case IDCELL_CF_SCALE: return 8;
    case IDCELL_CF_PRECISION: return 9;
    case IDCELL_CF_FRAME: return 10;
    case IDCELL_CF_INVERT: return 11;
    case IDCELL_CF_MINSYNC: return 12;
    case IDCELL_CF_STALE: return 13;
    case IDCELL_CF_LOADCAP: return 14;
    case IDCELL_CF_TRIGGER: return 15;
    case IDCELL_CF_HOLD: return 16;
    case IDCELL_CF_FAIL: return 17;
    case IDCELL_CF_PROV: return 18;
    case IDCELL_CF_ESCALATE: return 19;
    default: return -1;
    }
}

static int authorized_field_rank(uint8_t type)
{
    switch (type) {
    case IDCELL_CF_LABEL: return 0;
    case IDCELL_CF_KIND: return 1;
    case IDCELL_CF_DIR: return 2;
    case IDCELL_CF_PERM: return 3;
    case IDCELL_CF_DIM: return 4;
    case IDCELL_CF_UNIT: return 5;
    case IDCELL_CF_ACCEPT: return 6;
    case IDCELL_CF_CONV: return 7;
    case IDCELL_CF_DTYPE: return 8;
    case IDCELL_CF_SCALE: return 9;
    case IDCELL_CF_ACCEPT_T: return 10;
    case IDCELL_CF_SCHEMA: return 11;
    case IDCELL_CF_RANGE: return 12;
    case IDCELL_CF_PRECISION: return 13;
    case IDCELL_CF_FRAME: return 14;
    case IDCELL_CF_INVERT: return 15;
    case IDCELL_CF_MINSYNC: return 16;
    case IDCELL_CF_STALE: return 17;
    case IDCELL_CF_LOADCAP: return 18;
    case IDCELL_CF_TRIGGER: return 19;
    case IDCELL_CF_HOLD: return 20;
    case IDCELL_CF_FAIL: return 21;
    case IDCELL_CF_PROV: return 22;
    case IDCELL_CF_ESCALATE: return 23;
    case IDCELL_CF_DEPS: return 24;
    default: return -1;
    }
}

int idcell_authorized_desc_validate(const uint8_t *buf, uint16_t len)
{
    uint16_t pos = 0;
    uint32_t seen = 0;
    unsigned ranges = 0;
    int previous = -1, rank;
    idcell_tlv_t t;
    int rc, bit;
    while ((rc = idcell_tlv_next(buf, len, &pos, &t)) == 0) {
        rank = authorized_field_rank(t.type);
        if (rank < 0 || rank < previous) return -1;
        previous = rank;
        if (t.type == IDCELL_CF_ACCEPT || t.type == IDCELL_CF_ACCEPT_T ||
            t.type == IDCELL_CF_SCHEMA || t.type == IDCELL_CF_RANGE ||
            t.type == IDCELL_CF_DEPS) {
            if (t.type == IDCELL_CF_ACCEPT && !desc_string_ok(&t, IDCELL_MAX_UNIT)) return -1;
            if (t.type == IDCELL_CF_ACCEPT_T && t.len != 2) return -1;
            if (t.type == IDCELL_CF_SCHEMA && t.len != 8) return -1;
            if (t.type == IDCELL_CF_DEPS && t.len != 2) return -1;
            if (t.type == IDCELL_CF_RANGE && (t.len != 8 || ++ranges > 2)) return -1;
            continue;
        }
        bit = authorized_field_bit(t.type);
        if (bit < 0 || (seen & (1u << bit))) return -1;
        if ((t.type == IDCELL_CF_LABEL && !desc_string_ok(&t, IDCELL_MAX_LABEL)) ||
            ((t.type == IDCELL_CF_UNIT || t.type == IDCELL_CF_FRAME ||
              t.type == IDCELL_CF_ESCALATE) && !desc_string_ok(&t, IDCELL_MAX_UNIT))) return -1;
        if (t.type == IDCELL_CF_LABEL || t.type == IDCELL_CF_UNIT) {
            if (!t.len) return -1;
        } else if (t.type == IDCELL_CF_PRECISION) {
            if (t.len != 8) return -1;
        } else if (t.type == IDCELL_CF_MINSYNC || t.type == IDCELL_CF_STALE ||
                   t.type == IDCELL_CF_LOADCAP) {
            if (t.len != 4) return -1;
        } else if (t.type != IDCELL_CF_FRAME && t.type != IDCELL_CF_ESCALATE && t.len != 1)
            return -1;
        seen |= 1u << bit;
    }
    if (rc < 0 || seen != 0x0FFFFFu || ranges != 2) return -1;
    return 0;
}

void idcell_descriptor_digest(int public_desc, const uint8_t *canonical_tlvs,
                              size_t len, uint8_t out[32])
{
    static const char public_domain[] = "IDCELL-PUBLIC-DESC-V1";
    static const char auth_domain[] = "IDCELL-AUTHORIZED-DESC-V1";
    const char *domain = public_desc ? public_domain : auth_domain;
    idcell_sha256_t sha;
    idcell_sha256_init(&sha);
    idcell_sha256_update(&sha, domain, strlen(domain));
    if (len) idcell_sha256_update(&sha, canonical_tlvs, len);
    idcell_sha256_final(&sha, out);
}

/* ---------------------------------------------------------------- 需求描述符 */

int idcell_req_encode(const idcell_requirement_t *r, uint8_t *buf, uint16_t cap)
{
    uint16_t pos = 0;
    uint8_t b8;
    uint8_t b16[2];
    uint8_t b32[4];
    uint8_t b64[8];
    int i;

    put_str(buf, cap, &pos, IDCELL_RF_LABEL, r->label);
    /* v0.8：量种 ID（u8）取代原自由字符串 dim */
    b8 = (uint8_t)r->qty;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_RF_DIM, &b8, 1);
    put_str(buf, cap, &pos, IDCELL_RF_UNIT, r->unit);
    for (i = 0; i < r->accept_count && i < IDCELL_MAX_ACCEPT; i++)
        put_str(buf, cap, &pos, IDCELL_RF_ACCEPT, r->accept_units[i]);

    /* v0.9：可接受值类型（§24.8），每项 2 字节 (dtype, scale_exp) */
    for (i = 0; i < r->accept_type_count && i < IDCELL_MAX_ACCEPT_TYPES; i++) {
        uint8_t pair[2];
        pair[0] = (uint8_t)r->accept_types[i].dtype;
        pair[1] = r->accept_types[i].scale_exp;
        idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_RF_ACCEPT_T, pair, 2);
    }
    for (i = 0; i < r->schema_count && i < IDCELL_MAX_SCHEMA_SET; i++) {
        idcell_put_u64(b64, r->schema_set[i]);
        idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_RF_SCHEMA, b64, 8);
    }

    b8 = (uint8_t)r->perm;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_RF_PERM, &b8, 1);
    idcell_put_u16(b16, r->index);
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_RF_INDEX, b16, 2);
    idcell_put_u32(b32, r->want_ms);
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_RF_WANT, b32, 4);
    idcell_put_u32(b32, r->stale_ms);
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_RF_STALE, b32, 4);
    idcell_put_f64(b64, r->range[0]);
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_RF_RANGE, b64, 8);
    idcell_put_f64(b64, r->range[1]);
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_RF_RANGE, b64, 8);
    b8 = (uint8_t)r->kind;
    idcell_tlv_put(buf, cap, &pos, 0, 0, IDCELL_RF_KIND, &b8, 1);

    return pos;
}

int idcell_req_decode(const uint8_t *buf, uint16_t len, idcell_requirement_t *out)
{
    uint16_t pos = 0;
    int range_i = 0;
    idcell_tlv_t t;
    int rc;

    memset(out, 0, sizeof(*out));
    out->index = 0xFFFF;
    out->perm = IDCELL_PERM_P1;

    while ((rc = idcell_tlv_next(buf, len, &pos, &t)) == 0) {
        switch (t.type) {
        case IDCELL_RF_LABEL: get_str(t.val, t.len, out->label, sizeof(out->label)); break;
        case IDCELL_RF_DIM:   get_u8(t.val, t.len, (uint8_t *)&out->qty); break;
        case IDCELL_RF_UNIT:  get_str(t.val, t.len, out->unit, sizeof(out->unit)); break;
        case IDCELL_RF_ACCEPT:
            if (out->accept_count < IDCELL_MAX_ACCEPT)
                get_str(t.val, t.len, out->accept_units[out->accept_count++],
                        sizeof(out->accept_units[0]));
            break;
        case IDCELL_RF_ACCEPT_T:
            if (out->accept_type_count < IDCELL_MAX_ACCEPT_TYPES && t.len >= 2) {
                out->accept_types[out->accept_type_count].dtype =
                    (idcell_dtype_t)t.val[0];
                out->accept_types[out->accept_type_count].scale_exp = t.val[1];
                out->accept_type_count++;
            }
            break;
        case IDCELL_RF_SCHEMA:
            if (out->schema_count < IDCELL_MAX_SCHEMA_SET && t.len == 8)
                out->schema_set[out->schema_count++] = idcell_get_u64(t.val);
            break;
        case IDCELL_RF_PERM:  get_u8(t.val, t.len, (uint8_t *)&out->perm); break;
        case IDCELL_RF_INDEX: get_u16v(t.val, t.len, &out->index); break;
        case IDCELL_RF_WANT:  get_u32v(t.val, t.len, &out->want_ms); break;
        case IDCELL_RF_STALE: get_u32v(t.val, t.len, &out->stale_ms); break;
        case IDCELL_RF_RANGE:
            if (range_i < 2) get_f64v(t.val, t.len, &out->range[range_i]);
            range_i++;
            break;
        case IDCELL_RF_KIND:  get_u8(t.val, t.len, (uint8_t *)&out->kind); break;
        default: break;
        }
    }
    return (rc < 0) ? -1 : 0;
}
