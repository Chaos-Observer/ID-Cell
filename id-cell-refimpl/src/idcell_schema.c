/* P0-3：schema 注册、结构生命周期与重启围栏快照。 */
#include "idcell_internal.h"
#include <stdio.h>

static const char *dtype_name(idcell_dtype_t dt)
{
    static const char *names[] = {
        "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64",
        "f32", "f64", "bool", "string", "bytes"
    };
    return ((int)dt >= 0 && (int)dt < (int)(sizeof(names) / sizeof(names[0])))
           ? names[(int)dt] : NULL;
}

uint64_t idcell_schema_id(uint32_t name_space, uint64_t local_id)
{
    if (name_space > 0xFFFFFFu || local_id > 0xFFFFFFFFFFULL) return 0;
    return ((uint64_t)name_space << 40) | local_id;
}

static int bounded_text(const char *s, size_t cap, size_t *len)
{
    const char *nul;
    if (!s) return 0;
    nul = (const char *)memchr(s, '\0', cap);
    if (!nul) return 0;
    *len = (size_t)(nul - s);
    return 1;
}

static void digest_field(idcell_sha256_t *sha, const void *data, size_t len)
{
    uint8_t b[2];
    idcell_put_u16(b, (uint16_t)len);
    idcell_sha256_update(sha, b, 2);
    idcell_sha256_update(sha, data, len);
}

void idcell_schema_digest(idcell_schema_def_t *def)
{
    idcell_sha256_t sha;
    uint16_t i;
    idcell_sha256_init(&sha);
    for (i = 0; i < def->field_count; i++) {
        idcell_schema_field_t *f = &def->fields[i];
        uint8_t b[3];
        size_t name_len = 0, type_len = 0, unit_len = 0;
        if (!bounded_text(f->name, sizeof(f->name), &name_len) ||
            !bounded_text(f->value_type, sizeof(f->value_type), &type_len) ||
            !bounded_text(f->unit, sizeof(f->unit), &unit_len)) continue;
        digest_field(&sha, f->name, name_len);
        digest_field(&sha, f->value_type, type_len);
        digest_field(&sha, f->unit, unit_len);
        b[0] = f->scale_exp;
        b[1] = f->critical ? 1 : 0;
        b[2] = f->required ? 1 : 0;
        idcell_sha256_update(&sha, b, 3);
    }
    idcell_sha256_final(&sha, def->digest);
}

int idcell_schema_standard(idcell_dtype_t dtype, uint8_t scale_exp,
                           const char *unit, idcell_schema_def_t *out)
{
    const char *tn = dtype_name(dtype);
    uint64_t id = 0;
    size_t unit_len;
    if (!out || !tn || !bounded_text(unit, IDCELL_MAX_UNIT, &unit_len)) return IDCELL_E_NODEV;
    if (dtype == IDCELL_DTYPE_F64 && scale_exp == 0 && strcmp(unit, "Cel") == 0)
        id = IDCELL_SCHEMA_STD_F64_CEL;
    else if (dtype == IDCELL_DTYPE_I16 && scale_exp == 2 && strcmp(unit, "Cel") == 0)
        id = IDCELL_SCHEMA_STD_I16_CEL_2;
    else if (dtype == IDCELL_DTYPE_F64 && scale_exp == 0 && strcmp(unit, "m/s2") == 0)
        id = IDCELL_SCHEMA_STD_F64_ACCEL;
    else if (dtype == IDCELL_DTYPE_I32 && scale_exp == 3 && strcmp(unit, "m/s2") == 0)
        id = IDCELL_SCHEMA_STD_I32_ACCEL_3;
    else if (dtype == IDCELL_DTYPE_I32 && scale_exp == 3 && strcmp(unit, "Cel") == 0)
        id = IDCELL_SCHEMA_STD_I32_CEL_3;
    else
        return IDCELL_E_NODEV;
    memset(out, 0, sizeof(*out));
    out->schema_id = id;
    out->field_count = 1;
    snprintf(out->fields[0].name, sizeof(out->fields[0].name), "value");
    snprintf(out->fields[0].value_type, sizeof(out->fields[0].value_type), "%s", tn);
    memcpy(out->fields[0].unit, unit, unit_len + 1);
    out->fields[0].scale_exp = scale_exp;
    out->fields[0].critical = 1;
    out->fields[0].required = 1;
    idcell_schema_digest(out);
    return IDCELL_OK;
}

static int schema_semantics_valid(const idcell_schema_def_t *def)
{
    size_t a, b, c;
    const idcell_schema_field_t *f;
    if (!def || def->field_count != 1) return 0;
    f = &def->fields[0];
    if (!bounded_text(f->name, sizeof(f->name), &a) ||
        !bounded_text(f->value_type, sizeof(f->value_type), &b) ||
        !bounded_text(f->unit, sizeof(f->unit), &c)) return 0;
    if (f->critical && strcmp(f->name, "value") != 0) return 0;
    if (strcmp(f->name, "value") != 0) return 0;
    {
        int dt;
        for (dt = IDCELL_DTYPE_I8; dt <= IDCELL_DTYPE_BYTES; dt++)
            if (strcmp(f->value_type, dtype_name((idcell_dtype_t)dt)) == 0) return 1;
    }
    return 0;
}

static int field_same(const idcell_schema_field_t *a, const idcell_schema_field_t *b)
{
    return strcmp(a->name, b->name) == 0 &&
           strcmp(a->value_type, b->value_type) == 0 &&
           strcmp(a->unit, b->unit) == 0 &&
           a->scale_exp == b->scale_exp && a->critical == b->critical &&
           a->required == b->required;
}

static int schema_same(const idcell_schema_def_t *a, const idcell_schema_def_t *b)
{
    return a->schema_id == b->schema_id && a->field_count == 1 &&
           b->field_count == 1 && field_same(&a->fields[0], &b->fields[0]) &&
           memcmp(a->digest, b->digest, 32) == 0;
}

static int standard_definition_allowed(const idcell_schema_def_t *def)
{
    idcell_schema_def_t standard;
    idcell_dtype_t dt;
    uint8_t scale;
    const char *unit;
    if ((def->schema_id >> 40) != 0) return 1; /* 非标准 namespace 为显式扩展。 */
    if (def->schema_id == IDCELL_SCHEMA_STD_F64_CEL ||
        def->schema_id == IDCELL_SCHEMA_STD_F64_ACCEL) {
        dt = IDCELL_DTYPE_F64; scale = 0;
    } else if (def->schema_id == IDCELL_SCHEMA_STD_I16_CEL_2) {
        dt = IDCELL_DTYPE_I16; scale = 2;
    } else if (def->schema_id == IDCELL_SCHEMA_STD_I32_ACCEL_3 ||
               def->schema_id == IDCELL_SCHEMA_STD_I32_CEL_3) {
        dt = IDCELL_DTYPE_I32; scale = 3;
    } else return 0;
    unit = (def->schema_id == IDCELL_SCHEMA_STD_F64_CEL ||
            def->schema_id == IDCELL_SCHEMA_STD_I16_CEL_2 ||
            def->schema_id == IDCELL_SCHEMA_STD_I32_CEL_3) ? "Cel" : "m/s2";
    return idcell_schema_standard(dt, scale, unit, &standard) == IDCELL_OK &&
           schema_same(&standard, def);
}

int idcell_node_register_schema(idcell_node_t *n, const idcell_schema_def_t *def)
{
    idcell_schema_def_t copy;
    int i;
    if (!n || !def || !def->schema_id) return IDCELL_E_RANGE;
    if (!schema_semantics_valid(def)) return IDCELL_E_UNSAFE;
    copy = *def;
    idcell_schema_digest(&copy);
    for (i = 0; i < IDCELL_MAX_SCHEMAS; i++) {
        if (!n->schema_used[i] || n->schemas[i].schema_id != copy.schema_id) continue;
        return schema_same(&n->schemas[i], &copy) ? IDCELL_OK : IDCELL_E_IDCONFLICT;
    }
    if (!standard_definition_allowed(&copy)) return IDCELL_E_UNSAFE;
    for (i = 0; i < IDCELL_MAX_SCHEMAS; i++) {
        if (!n->schema_used[i]) {
            n->schemas[i] = copy;
            n->schema_used[i] = 1;
            return IDCELL_OK;
        }
    }
    return IDCELL_E_RANGE;
}

int idcell_node_schema(const idcell_node_t *n, uint64_t schema_id,
                       idcell_schema_def_t *out)
{
    int i;
    if (!n || !out || !schema_id) return IDCELL_E_NODEV;
    for (i = 0; i < IDCELL_MAX_SCHEMAS; i++) {
        if (n->schema_used[i] && n->schemas[i].schema_id == schema_id) {
            *out = n->schemas[i];
            return IDCELL_OK;
        }
    }
    return IDCELL_E_NODEV;
}

int idcell_schema_check_change(const idcell_schema_def_t *old_def,
                               const idcell_schema_def_t *new_def,
                               int renegotiated)
{
    idcell_schema_def_t a, b;
    uint16_t i;
    if (!old_def || !new_def) return IDCELL_E_NODEV;
    if (!schema_semantics_valid(old_def) || !schema_semantics_valid(new_def))
        return IDCELL_E_UNSAFE;
    a = *old_def;
    b = *new_def;
    idcell_schema_digest(&a);
    idcell_schema_digest(&b);
    for (i = 0; i < b.field_count; i++) {
        if (b.fields[i].critical && strcmp(b.fields[i].name, "value") != 0)
            return IDCELL_E_UNSAFE;
    }
    if (memcmp(a.digest, b.digest, 32) == 0) return IDCELL_OK;
    if (a.schema_id == b.schema_id) return IDCELL_E_IDCONFLICT;
    return renegotiated ? IDCELL_OK : IDCELL_E_NEGOTIATE;
}

static int schema_encoding_ok(const idcell_schema_def_t *def,
                              idcell_type_t type, const char *unit)
{
    const char *tn = dtype_name(type.dtype);
    if (!def || def->field_count == 0 || !tn || !unit) return 0;
    return strcmp(def->fields[0].name, "value") == 0 &&
           strcmp(def->fields[0].value_type, tn) == 0 &&
           def->fields[0].scale_exp == type.scale_exp &&
           strcmp(def->fields[0].unit, unit) == 0;
}

int node_schema_select(idcell_node_t *n, const idcell_capability_t *cap,
                       const idcell_requirement_t *req, idcell_type_t type,
                       const char *unit, uint64_t *schema_id)
{
    idcell_schema_def_t standard;
    int i, j;
    if (!n || !cap || !req || !schema_id) return IDCELL_E_NODEV;
    if (cap->schema_count || req->schema_count) {
        if (!cap->schema_count || !req->schema_count) return IDCELL_E_NEGOTIATE;
        for (i = 0; i < cap->schema_count && i < IDCELL_MAX_SCHEMA_SET; i++) {
            for (j = 0; j < req->schema_count && j < IDCELL_MAX_SCHEMA_SET; j++) {
                idcell_schema_def_t def;
                if (cap->schema_set[i] != req->schema_set[j]) continue;
                if (idcell_node_schema(n, cap->schema_set[i], &def) != IDCELL_OK)
                    return IDCELL_E_UNSAFE;
                if (!schema_encoding_ok(&def, type, unit)) continue;
                *schema_id = def.schema_id;
                return IDCELL_OK;
            }
        }
        return IDCELL_E_NEGOTIATE;
    }
    if (idcell_schema_standard(type.dtype, type.scale_exp, unit, &standard) != IDCELL_OK)
        return IDCELL_E_CONV;
    *schema_id = standard.schema_id;
    return idcell_node_register_schema(n, &standard);
}

int node_schema_verify(idcell_node_t *n, uint64_t schema_id,
                       idcell_type_t type, const char *unit)
{
    idcell_schema_def_t def;
    if (!n || !schema_id) return IDCELL_E_UNSAFE;
    if (idcell_schema_standard(type.dtype, type.scale_exp, unit, &def) == IDCELL_OK &&
        def.schema_id == schema_id)
        return idcell_node_register_schema(n, &def);
    if (idcell_node_schema(n, schema_id, &def) != IDCELL_OK)
        return IDCELL_E_UNSAFE;
    return schema_encoding_ok(&def, type, unit) ? IDCELL_OK : IDCELL_E_UNSAFE;
}

uint64_t idcell_contract_fingerprint(const idcell_contract_t *contract)
{
    uint64_t h = 0xCBF29CE484222325ULL;
    const uint8_t *p;
    size_t i, len;
    if (!contract) return 0;
    p = (const uint8_t *)contract;
    len = offsetof(idcell_contract_t, pt) +
          (size_t)contract->pt_count * sizeof(contract->pt[0]);
    for (i = 0; i < len; i++) { h ^= p[i]; h *= 0x100000001B3ULL; }
    p = (const uint8_t *)&contract->session_id;
    len = sizeof(contract->session_id) + sizeof(contract->grant_epoch) +
          sizeof(contract->authority_id) + sizeof(contract->authority_epoch) +
          sizeof(contract->member_epoch);
    for (i = 0; i < len; i++) { h ^= p[i]; h *= 0x100000001B3ULL; }
    return h ? h : 1;
}

int idcell_node_snapshot(const idcell_node_t *n, idcell_snapshot_t *out)
{
    if (!n || !out) return IDCELL_E_NODEV;
    memset(out, 0, sizeof(*out));
    out->magic = IDCELL_SNAPSHOT_MAGIC;
    out->version = IDCELL_SNAPSHOT_VERSION;
    out->authority_id = n->trusted_authority_id ? n->trusted_authority_id : n->authority_id;
    out->authority_epoch = n->authority_epoch_floor;
    out->member_epoch = n->member_epoch_floor;
    out->grant_epoch_floor = n->grant_epoch_counter;
    out->grant_fingerprint = n->grant_fingerprint;
    return IDCELL_OK;
}

int idcell_node_restore(idcell_node_t *n, const idcell_snapshot_t *snapshot)
{
    if (!n || !snapshot || snapshot->magic != IDCELL_SNAPSHOT_MAGIC ||
        snapshot->version != IDCELL_SNAPSHOT_VERSION)
        return IDCELL_E_VER;
    /* 恢复的是新执行器：所有租约、会话、token 与 pending 状态立即失效。 */
    memset(n->peers, 0, sizeof(n->peers));
    memset(n->completed, 0, sizeof(n->completed));
    memset(n->grants, 0, sizeof(n->grants));
    memset(n->write_queue, 0, sizeof(n->write_queue));
    n->write_queue_count = 0;
    n->rx_len = 0;
    n->command_age = 0;
    if (snapshot->grant_epoch_floor > n->grant_epoch_counter)
        n->grant_epoch_counter = snapshot->grant_epoch_floor;
    if (snapshot->authority_epoch > n->authority_epoch_floor)
        n->authority_epoch_floor = snapshot->authority_epoch;
    if (snapshot->member_epoch > n->member_epoch_floor)
        n->member_epoch_floor = snapshot->member_epoch;
    if (snapshot->authority_id) n->trusted_authority_id = snapshot->authority_id;
    n->grant_fingerprint = snapshot->grant_fingerprint;
    n->rnd ^= snapshot->grant_fingerprint ^ (snapshot->grant_epoch_floor << 32) ^
              0x9E3779B97F4A7C15ULL;
    return IDCELL_OK;
}
