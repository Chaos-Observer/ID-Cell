/* P0-3 契约与写安全：真实节点行为测试及 C<->Python 行为向量。 */
#include "idcell_internal.h"
#include "idcell_wire_probe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass, g_fail;
static void ok(int cond, const char *name)
{
    if (cond) { g_pass++; printf("PASS %s\n", name); }
    else { g_fail++; printf("FAIL %s\n", name); }
}
static void eq(int got, int want, const char *name)
{
    if (got == want) { g_pass++; printf("PASS %s\n", name); }
    else { g_fail++; printf("FAIL %s got=%d want=%d\n", name, got, want); }
}

typedef struct {
    double temp, accel;
    uint64_t tick;
    int set_calls, read_calls;
} device_state_t;

static int value_fn(void *ud, uint16_t index, uint8_t sub,
                    double *value, uint64_t *ts, idcell_prov_t *prov)
{
    device_state_t *s = (device_state_t *)ud;
    (void)sub;
    s->read_calls++;
    if (index == 0x0200) *value = s->temp;
    else if (index == 0x0100) *value = s->accel;
    else return IDCELL_E_NODEV;
    *ts = ++s->tick * 1000;
    *prov = IDCELL_PROV_MEASURED;
    return IDCELL_OK;
}

static int set_fn(void *ud, uint16_t index, uint8_t sub,
                  double value, const char *intent, uint32_t owner)
{
    device_state_t *s = (device_state_t *)ud;
    (void)sub; (void)intent; (void)owner;
    s->set_calls++;
    if (index == 0x0200) s->temp = value;
    return IDCELL_OK;
}

typedef struct {
    idcell_loopback_t *lb;
    idwp_link_t dev_wire, host_wire;
    idcell_node_t *dev, *host;
    device_state_t state;
    int data_calls, write_results, last_write_err;
    idcell_did_t dev_did, host_did;
    uint32_t now;
} scene_t;

static void data_fn(void *ud, const idcell_did_t *peer, uint16_t index, uint8_t sub,
                    double value, uint64_t ts, idcell_prov_t prov, idcell_quality_t quality)
{
    scene_t *s = (scene_t *)ud;
    (void)peer; (void)index; (void)sub; (void)value; (void)ts; (void)prov; (void)quality;
    s->data_calls++;
}

static void write_result_fn(void *ud, const idcell_did_t *peer, uint16_t index, uint8_t sub,
                            const idcell_write_result_t *res)
{
    scene_t *s = (scene_t *)ud;
    (void)peer; (void)index; (void)sub;
    s->write_results++;
    s->last_write_err = res->err;
}

static void fill_cap(idcell_capability_t *c, uint16_t index, idcell_qty_t qty,
                     const char *unit, idcell_dir_t dir, idcell_perm_t perm,
                     double lo, double hi)
{
    memset(c, 0, sizeof(*c));
    c->index = index;
    snprintf(c->label, sizeof(c->label), "point.%04x", index);
    c->kind = IDCELL_KIND_STATE;
    c->dir = dir;
    c->perm = perm;
    c->qty = qty;
    snprintf(c->unit, sizeof(c->unit), "%s", unit);
    c->accept_count = 1;
    snprintf(c->accept_units[0], sizeof(c->accept_units[0]), "%s", unit);
    c->conv_class = IDCELL_CONV_T1;
    c->dtype = IDCELL_DTYPE_F64;
    idcell_type_list_add(c->accept_types, &c->accept_type_count, IDCELL_DTYPE_F64, 0);
    c->range[0] = lo; c->range[1] = hi;
    c->min_sync_ms = 20; c->stale_ms = 1000;
    c->fail_action = IDCELL_FAIL_HOLD;
}

static void scene_init(scene_t *s, int writable)
{
    idcell_transport_t a, b;
    idcell_node_cfg_t cfg;
    idcell_capability_t cap;
    idcell_requirement_t req;
    memset(s, 0, sizeof(*s));
    s->lb = idcell_loopback_new();
    idcell_loopback_endpoints(s->lb, &a, &b);
    idwp_link_init(&s->dev_wire, &a);
    idwp_link_init(&s->host_wire, &b);
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0xC001, &cfg.did);
    memset(cfg.cred, 0x42, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 100;
    cfg.lease_ttl_ms = 1000;
    snprintf(cfg.model, sizeof(cfg.model), "contract-device");
    s->dev = idcell_node_new(&cfg);
    idcell_node_set_transport(s->dev, &s->dev_wire.tap);
    fill_cap(&cap, 0x0200, IDCELL_QTY_TEMPERATURE, "Cel", IDCELL_DIR_RW,
             IDCELL_PERM_P2, -40, 85);
    idcell_node_register_capability(s->dev, &cap);
    fill_cap(&cap, 0x0100, IDCELL_QTY_ACCELERATION, "m/s2", IDCELL_DIR_R,
             IDCELL_PERM_P1, -160, 160);
    idcell_node_register_capability(s->dev, &cap);
    s->state.temp = 20; s->state.accel = 1;
    idcell_node_set_value_source(s->dev, value_fn, &s->state);
    idcell_node_set_setter(s->dev, set_fn, &s->state);

    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0xC002, &cfg.did);
    memset(cfg.cred, 0x42, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 100;
    cfg.lease_ttl_ms = 1000;
    snprintf(cfg.model, sizeof(cfg.model), "contract-host");
    s->host = idcell_node_new(&cfg);
    idcell_node_set_transport(s->host, &s->host_wire.tap);
    idcell_node_set_data_sink(s->host, data_fn, s);
    idcell_node_set_write_result_sink(s->host, write_result_fn, s);
    memset(&req, 0, sizeof(req));
    req.index = 0xFFFF;
    req.kind = IDCELL_KIND_STATE;
    req.want_ms = 20; req.stale_ms = 1000;
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
    if (writable) {
        req.qty = IDCELL_QTY_TEMPERATURE;
        snprintf(req.unit, sizeof(req.unit), "Cel");
        req.perm = IDCELL_PERM_P2;
    } else {
        req.qty = IDCELL_QTY_ACCELERATION;
        snprintf(req.unit, sizeof(req.unit), "m/s2");
        req.perm = IDCELL_PERM_P1;
    }
    req.accept_count = 1;
    snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "%s", req.unit);
    idcell_node_register_requirement(s->host, &req);
    s->dev_did = idcell_node_did(s->dev);
    s->host_did = idcell_node_did(s->host);
}

static void scene_free(scene_t *s)
{
    if (s->dev) idcell_node_free(s->dev);
    if (s->host) idcell_node_free(s->host);
    if (s->lb) idcell_loopback_free(s->lb);
    memset(s, 0, sizeof(*s));
}

static void scene_step(scene_t *s)
{
    idcell_node_poll(s->dev, s->now);
    idcell_node_poll(s->host, s->now);
    s->now += 10;
}

static int scene_bind(scene_t *s)
{
    int i;
    idcell_contract_t c;
    for (i = 0; i < 500; i++) {
        scene_step(s);
        if (idcell_node_get_contract(s->host, &s->dev_did, &c) == IDCELL_OK &&
            idcell_node_get_contract(s->dev, &s->host_did, &c) == IDCELL_OK)
            return 1;
    }
    return 0;
}

static idcell_contract_point_t *point(idcell_contract_t *c, uint16_t index, uint8_t sub)
{
    int i;
    for (i = 0; i < c->pt_count; i++)
        if (c->pt[i].index == index && c->pt[i].sub == sub) return &c->pt[i];
    return NULL;
}

static void put64(uint8_t *p, uint16_t *pos, uint8_t type, uint64_t v)
{
    uint8_t b[8]; idcell_put_u64(b, v);
    idcell_tlv_put(p, IDCELL_MAX_PAYLOAD, pos, 0, 0, type, b, 8);
}
static void put32(uint8_t *p, uint16_t *pos, uint8_t type, uint32_t v)
{
    uint8_t b[4]; idcell_put_u32(b, v);
    idcell_tlv_put(p, IDCELL_MAX_PAYLOAD, pos, 0, 0, type, b, 4);
}
static void put16(uint8_t *p, uint16_t *pos, uint8_t type, uint16_t v)
{
    uint8_t b[2]; idcell_put_u16(b, v);
    idcell_tlv_put(p, IDCELL_MAX_PAYLOAD, pos, 0, 0, type, b, 2);
}
static void put8(uint8_t *p, uint16_t *pos, uint8_t type, uint8_t v)
{
    idcell_tlv_put(p, IDCELL_MAX_PAYLOAD, pos, 0, 0, type, &v, 1);
}

static void put_pending_point(idcell_frame_t *f, uint16_t *pos,
                              const idcell_pt_t *pt, uint64_t schema_delta)
{
    uint8_t v[96];
    uint16_t n = 0, ul = (uint16_t)strlen(pt->unit);
    v[n++] = pt->perm; v[n++] = pt->degrade; v[n++] = pt->prov;
    v[n++] = pt->dtype; v[n++] = pt->scale_exp;
    idcell_put_u64(v + n, pt->schema_id + schema_delta); n += 8;
    idcell_put_u16(v + n, pt->schema_ref); n += 2;
    memcpy(v + n, pt->schema_digest, 32); n += 32;
    idcell_put_u32(v + n, pt->t_pub_ms); n += 4;
    idcell_put_u32(v + n, pt->ttl_ms); n += 4;
    v[n++] = (uint8_t)ul; memcpy(v + n, pt->unit, ul); n += ul;
    idcell_tlv_put(f->payload, sizeof(f->payload), pos, pt->cap_index, pt->sub,
                   IDCELL_TLV_BIND_POINT, v, n);
}

static void make_prepared(scene_t *s, idcell_frame_t *f, uint64_t schema_delta)
{
    const idcell_contract_t *c = &s->dev->peers[0].pending_contract;
    uint16_t pos = 0;
    int i;
    memset(f, 0, sizeof(*f)); f->ver = IDCELL_PROTO_VER_BYTE; f->type = IDCELL_FT_BIND;
    f->src = s->dev_did; f->dst = s->host_did; f->txn = 77;
    put8(f->payload, &pos, IDCELL_TLV_BIND_PHASE, IDCELL_BIND_PHASE_PREPARED);
    put32(f->payload, &pos, IDCELL_TLV_BIND_ID, c->binding_id);
    put32(f->payload, &pos, IDCELL_TLV_DESC_VER, c->desc_version);
    put32(f->payload, &pos, IDCELL_TLV_TTL, c->lease_ttl_ms);
    put32(f->payload, &pos, IDCELL_TLV_ARB, c->arb_domain);
    put32(f->payload, &pos, IDCELL_TLV_OWNER, c->owner_token);
    put8(f->payload, &pos, IDCELL_TLV_PERM, (uint8_t)c->perm);
    put64(f->payload, &pos, IDCELL_TLV_SESSION_ID, c->session_id);
    put64(f->payload, &pos, IDCELL_TLV_GRANT_EPOCH, c->grant_epoch);
    put64(f->payload, &pos, IDCELL_TLV_AUTHORITY_ID, c->authority_id);
    put64(f->payload, &pos, IDCELL_TLV_AUTHORITY_EPOCH, c->authority_epoch);
    put64(f->payload, &pos, IDCELL_TLV_MEMBER_EPOCH, c->member_epoch);
    for (i = 0; i < s->dev->peers[0].pending_pt_count; i++)
        put_pending_point(f, &pos, &s->dev->peers[0].pending_pts[i], schema_delta);
    f->payload_len = pos;
}

static void make_write(scene_t *s, idcell_frame_t *f, uint16_t index, uint8_t sub,
                       double value, uint64_t command, uint32_t valid_for)
{
    idcell_contract_t c;
    idcell_contract_point_t *cp;
    uint16_t pos = 0;
    uint8_t b[8];
    memset(&c, 0, sizeof(c));
    idcell_node_get_contract(s->host, &s->dev_did, &c);
    cp = point(&c, index, sub);
    memset(f, 0, sizeof(*f));
    f->ver = IDCELL_PROTO_VER_BYTE; f->type = IDCELL_FT_WRITE;
    f->src = s->host_did; f->dst = s->dev_did; f->txn = (uint16_t)command;
    idcell_put_f64(b, value);
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, index, sub,
                   IDCELL_TLV_VALUE, b, 8);
    put16(f->payload, &pos, IDCELL_TLV_SCHEMA_REF, cp ? cp->schema_ref : 1);
    put32(f->payload, &pos, IDCELL_TLV_BIND_ID, c.binding_id);
    put64(f->payload, &pos, IDCELL_TLV_SESSION_ID, c.session_id);
    put64(f->payload, &pos, IDCELL_TLV_GRANT_EPOCH, c.grant_epoch);
    put64(f->payload, &pos, IDCELL_TLV_AUTHORITY_ID, c.authority_id);
    put64(f->payload, &pos, IDCELL_TLV_AUTHORITY_EPOCH, c.authority_epoch);
    put64(f->payload, &pos, IDCELL_TLV_MEMBER_EPOCH, c.member_epoch);
    put64(f->payload, &pos, IDCELL_TLV_COMMAND_ID, command);
    put32(f->payload, &pos, IDCELL_TLV_VALID_FOR, valid_for);
    put32(f->payload, &pos, IDCELL_TLV_OWNER, c.owner_token);
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0,
                   IDCELL_TLV_INTENT, "contract-test", 13);
    f->payload_len = pos;
}

static int patch_field(idcell_frame_t *f, uint8_t type, uint64_t value, int width)
{
    uint16_t pos = 0;
    while (pos + 6 <= f->payload_len) {
        uint16_t len = idcell_get_u16(f->payload + pos + 4);
        if (pos + 6 + len > f->payload_len) return 0;
        if (f->payload[pos + 3] == type) {
            if (width == 2) idcell_put_u16(f->payload + pos + 6, (uint16_t)value);
            else if (width == 4) idcell_put_u32(f->payload + pos + 6, (uint32_t)value);
            else if (width == 8) idcell_put_u64(f->payload + pos + 6, value);
            else return 0;
            return 1;
        }
        pos = (uint16_t)(pos + 6 + len);
    }
    return 0;
}

static int tamper_bind_digest(idcell_frame_t *f)
{
    uint16_t pos = 0;
    while (pos + 6 <= f->payload_len) {
        uint16_t len = idcell_get_u16(f->payload + pos + 4);
        if (pos + 6 + len > f->payload_len) return 0;
        if (f->payload[pos + 3] == IDCELL_TLV_BIND_POINT && len >= 47) {
            f->payload[pos + 6 + 15] ^= 1;
            return 1;
        }
        pos = (uint16_t)(pos + 6 + len);
    }
    return 0;
}

static void test_schema(void)
{
    idcell_schema_def_t a, b, out;
    idcell_node_cfg_t cfg;
    idcell_node_t *n;
    printf("[schema]\n");
    ok(idcell_schema_id(7, 9) == (((uint64_t)7 << 40) | 9), "schema u24/u40 layout");
    ok(idcell_schema_id(0xFFFFFF, 0xFFFFFFFFFFULL) == UINT64_MAX, "schema id boundary");
    ok(idcell_schema_id(0x1000000, 1) == 0 && idcell_schema_id(1, 0x10000000000ULL) == 0,
       "out-of-range schema ids rejected without mask aliases");
    eq(idcell_schema_standard(IDCELL_DTYPE_F64, 0, "Cel", &a), IDCELL_OK, "standard f64 schema");
    eq(idcell_schema_standard(IDCELL_DTYPE_I16, 2, "Cel", &b), IDCELL_OK, "standard i16 schema");
    ok(a.schema_id == IDCELL_SCHEMA_STD_F64_CEL && b.schema_id == IDCELL_SCHEMA_STD_I16_CEL_2 &&
       (a.schema_id >> 40) == 0 && (b.schema_id >> 40) == 0,
       "standard schemas use fixed namespace-zero assignments");
    eq(idcell_schema_standard(IDCELL_DTYPE_F32, 0, "Cel", &out), IDCELL_E_NODEV,
       "unknown standard combination requires explicit extension");
    ok(a.schema_id != b.schema_id, "dtype/scale change selects new schema id");
    eq(idcell_schema_check_change(&a, &b, 0), IDCELL_E_NEGOTIATE, "new structure requires renegotiation");
    eq(idcell_schema_check_change(&a, &b, 1), IDCELL_OK, "new id plus renegotiation accepted");
    b = a; snprintf(b.fields[0].value_type, sizeof(b.fields[0].value_type), "i16");
    eq(idcell_schema_check_change(&a, &b, 1), IDCELL_E_IDCONFLICT, "same id different structure rejected");
    b = a; snprintf(b.fields[0].name, sizeof(b.fields[0].name), "unknown");
    eq(idcell_schema_check_change(&a, &b, 1), IDCELL_E_UNSAFE, "unknown critical field rejected");
    memset(&cfg, 0, sizeof(cfg)); idcell_did_generate(0xD001, &cfg.did);
    n = idcell_node_new(&cfg);
    eq(idcell_node_register_schema(n, &a), IDCELL_OK, "register custom schema");
    eq(idcell_node_register_schema(n, &a), IDCELL_OK, "identical schema registration idempotent");
    b = a; b.fields[0].required = 0;
    eq(idcell_node_register_schema(n, &b), IDCELL_E_IDCONFLICT, "registry rejects same id new fingerprint");
    eq(idcell_node_schema(n, a.schema_id, &out), IDCELL_OK, "schema query");
    b = a; b.field_count = 2;
    eq(idcell_node_register_schema(n, &b), IDCELL_E_UNSAFE, "multi-field schema rejected by scalar codec");
    b = a; memset(b.fields[0].name, 'x', sizeof(b.fields[0].name));
    eq(idcell_node_register_schema(n, &b), IDCELL_E_UNSAFE, "non-NUL schema string rejected");
    b = a; snprintf(b.fields[0].name, sizeof(b.fields[0].name), "unknown");
    eq(idcell_node_register_schema(n, &b), IDCELL_E_UNSAFE, "unknown critical registration rejected");
    b = a;
    memset(b.fields, 0xA5, sizeof(b.fields));
    snprintf(b.fields[0].name, sizeof(b.fields[0].name), "value");
    snprintf(b.fields[0].value_type, sizeof(b.fields[0].value_type), "f64");
    snprintf(b.fields[0].unit, sizeof(b.fields[0].unit), "Cel");
    b.fields[0].scale_exp = 0; b.fields[0].critical = 1; b.fields[0].required = 1;
    eq(idcell_node_register_schema(n, &b), IDCELL_OK,
       "tail bytes and padding excluded from semantic digest/compare");
    idcell_node_free(n);
}

static void test_bind_lifecycle(void)
{
    scene_t s;
    idcell_contract_t c;
    int i, prepared = 0;
    printf("[bind prepare/abort]\n");
    scene_init(&s, 1);
    for (i = 0; i < 500 && !prepared; i++) {
        idcell_node_poll(s.dev, s.now);
        if (s.dev->peers[0].bind_phase == IDCELL_BIND_PREPARED) prepared = 1;
        else { idcell_node_poll(s.host, s.now); s.now += 10; }
    }
    ok(prepared, "provider reaches prepared");
    eq(idcell_node_get_contract(s.dev, &s.host_did, &c), IDCELL_E_NODEV, "prepared provider not active");
    eq(idcell_node_get_contract(s.host, &s.dev_did, &c), IDCELL_E_NODEV, "prepared consumer not active");
    eq(idcell_node_bind_abort(s.dev, &s.host_did), IDCELL_OK, "abort prepared binding");
    for (i = 0; i < 8; i++) scene_step(&s);
    eq(idcell_node_get_contract(s.dev, &s.host_did, &c), IDCELL_E_NODEV, "abort leaves no provider residue");
    eq(idcell_node_get_contract(s.host, &s.dev_did, &c), IDCELL_E_NODEV, "abort leaves no consumer residue");
    scene_free(&s);

    printf("[bind commit visibility]\n");
    scene_init(&s, 1);
    prepared = 0;
    for (i = 0; i < 500 && !prepared; i++) {
        scene_step(&s);
        if (s.host->peers[0].bind_phase == IDCELL_BIND_COMMIT_SENT) prepared = 1;
    }
    ok(prepared, "consumer sent commit");
    eq(idcell_node_get_contract(s.host, &s.dev_did, &c), IDCELL_E_NODEV, "commit sent is not active");
    eq(idcell_node_get_contract(s.dev, &s.host_did, &c), IDCELL_E_NODEV, "commit not received provider inactive");
    idcell_node_poll(s.dev, s.now);
    eq(idcell_node_get_contract(s.dev, &s.host_did, &c), IDCELL_OK, "provider activates on commit");
    eq(idcell_node_get_contract(s.host, &s.dev_did, &c), IDCELL_E_NODEV, "consumer waits committed");
    idcell_node_poll(s.host, s.now);
    eq(idcell_node_get_contract(s.host, &s.dev_did, &c), IDCELL_OK, "consumer activates on committed");
    ok(c.session_id && c.grant_epoch && c.authority_epoch && c.member_epoch,
       "active contract carries session and all epochs");
    scene_free(&s);

    printf("[bind schema tamper]\n");
    scene_init(&s, 1);
    prepared = 0;
    for (i = 0; i < 500 && !prepared; i++) {
        idcell_node_poll(s.dev, s.now);
        if (s.dev->peers[0].bind_phase == IDCELL_BIND_PREPARED) prepared = 1;
        else { idcell_node_poll(s.host, s.now); s.now += 10; }
    }
    ok(prepared, "prepared state ready for schema tamper vector");
    {
        idcell_frame_t bad;
        make_prepared(&s, &bad, 0);
        ok(tamper_bind_digest(&bad), "mutate digest without changing schema id");
        node_test_handle_frame(s.host, &bad);
        eq(s.host->peers[0].bind_phase, IDCELL_BIND_NONE,
           "tampered PREPARED explicitly aborts pending instance");
        idcell_node_poll(s.dev, s.now);
        eq(s.dev->peers[0].pending_contract.binding_id, 0,
           "provider observes ABORT and clears prepared instance");
        bad.payload[3] = IDCELL_BIND_PHASE_COMMIT;
        bad.src = s.host_did; bad.dst = s.dev_did;
        node_test_handle_frame(s.dev, &bad);
        eq(idcell_node_get_contract(s.dev, &s.host_did, &c), IDCELL_E_NODEV,
           "COMMIT after rejected schema still cannot activate");
    }
    eq(idcell_node_get_contract(s.host, &s.dev_did, &c), IDCELL_E_NODEV,
       "tampered BIND schema cannot activate contract");
    scene_free(&s);
}

static void test_contract_and_write(void)
{
    scene_t s;
    idcell_contract_t c;
    idcell_frame_t w, x;
    idcell_write_options_t opt;
    double value;
    int before;
    printf("[cap_list and write safety]\n");
    scene_init(&s, 1);
    ok(scene_bind(&s), "bind writable scene");
    eq(idcell_node_write(s.host, 0x0100, 0, 2, 1, "outside"), IDCELL_E_PERM,
       "wrong token remains permission error");
    idcell_node_get_contract(s.host, &s.dev_did, &c);
    eq(idcell_node_write(s.host, 0x0100, 0, 2, c.owner_token, "outside"), IDCELL_E_NODEV,
       "requester rejects write outside cap_list");
    eq(idcell_node_read(s.host, &s.dev_did, 0x0100, 0, &value), IDCELL_E_NODEV,
       "requester rejects read outside cap_list");
    before = s.state.set_calls;
    make_write(&s, &w, 0x0100, 0, 2, 10, s.now + 100);
    node_test_handle_frame(s.dev, &w);
    eq(s.state.set_calls, before, "provider rejects write outside cap_list before callback");
    before = s.state.read_calls;
    {
        idcell_frame_t r;
        uint16_t pos = 0;
        memset(&r, 0, sizeof(r)); r.ver = IDCELL_PROTO_VER_BYTE; r.type = IDCELL_FT_READ;
        r.src = s.host_did; r.dst = s.dev_did;
        idcell_tlv_put(r.payload, sizeof(r.payload), &pos, 0x0100, 0, IDCELL_TLV_VALUE, NULL, 0);
        put32(r.payload, &pos, IDCELL_TLV_BIND_ID, c.binding_id);
        put64(r.payload, &pos, IDCELL_TLV_SESSION_ID, c.session_id);
        put64(r.payload, &pos, IDCELL_TLV_GRANT_EPOCH, c.grant_epoch);
        r.payload_len = pos;
        node_test_handle_frame(s.dev, &r);
    }
    eq(s.state.read_calls, before, "provider rejects read outside cap_list before value callback");

    before = s.state.set_calls;
    make_write(&s, &w, 0x0200, 0, 24, 20, s.now + 100);
    node_test_handle_frame(s.dev, &w);
    eq(s.state.set_calls, before + 1, "valid session/grant write executes once");
    node_test_handle_frame(s.dev, &w);
    eq(s.state.set_calls, before + 1, "duplicate command returns completion without second side effect");
    x = w; idcell_put_f64(x.payload + 6, 25.0);
    node_test_handle_frame(s.dev, &x);
    eq(s.state.set_calls, before + 1, "same command key different payload rejected");

    make_write(&s, &w, 0x0200, 0, 24, 21, 0);
    node_test_handle_frame(s.dev, &w);
    eq(s.state.set_calls, before + 1, "expired command does not execute");
    make_write(&s, &w, 0x0200, 0, 24, 22, s.now + 100);
    x = w; patch_field(&x, IDCELL_TLV_SESSION_ID, c.session_id + 1, 8);
    node_test_handle_frame(s.dev, &x);
    eq(s.state.set_calls, before + 1, "old session write fenced");
    x = w; patch_field(&x, IDCELL_TLV_GRANT_EPOCH, c.grant_epoch - 1, 8);
    node_test_handle_frame(s.dev, &x);
    eq(s.state.set_calls, before + 1, "old grant epoch write fenced");
    x = w; patch_field(&x, IDCELL_TLV_OWNER, c.owner_token ^ 1, 4);
    node_test_handle_frame(s.dev, &x);
    eq(s.state.set_calls, before + 1, "old owner token write fenced");
    x = w; patch_field(&x, IDCELL_TLV_SCHEMA_REF, 0xFFFF, 2);
    node_test_handle_frame(s.dev, &x);
    eq(s.state.set_calls, before + 1, "tampered schema_ref rejected");
    x = w;
    idcell_tlv_put(x.payload, sizeof(x.payload), &x.payload_len, 0, 0, 0x80, "x", 1);
    node_test_handle_frame(s.dev, &x);
    eq(s.state.set_calls, before + 1, "unknown critical TLV rejected");

    opt.command_id = 30; opt.valid_for_ms = 100;
    eq(idcell_node_write_ex(s.host, 0x0200, 0, 25, c.owner_token, "ex", &opt),
       IDCELL_OK, "extended write API sends valid command");
    scene_step(&s); scene_step(&s);
    eq(s.state.set_calls, before + 2, "extended write executes through real transport");
    scene_free(&s);

    scene_init(&s, 0);
    ok(scene_bind(&s), "bind read-only scene");
    idcell_node_get_contract(s.host, &s.dev_did, &c);
    eq(idcell_node_write(s.host, 0x0100, 0, 2, c.owner_token, "read-only"), IDCELL_E_PERM,
       "in-contract read-only point distinguished as permission error");
    scene_free(&s);
}

static void make_receipt(scene_t *s, idcell_frame_t *f, uint8_t type,
                         uint64_t session_delta, uint64_t command_delta)
{
    idcell_peer_t *p = &s->host->peers[0];
    uint16_t pos = 0;
    memset(f, 0, sizeof(*f)); f->ver = IDCELL_PROTO_VER_BYTE; f->type = type;
    f->src = s->dev_did; f->dst = s->host_did; f->txn = p->write_txn;
    if (type == IDCELL_FT_ERROR) {
        const char *code = "E_LEASE";
        const char *object = "WRITE";
        idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0,
                       IDCELL_TLV_ERR_BODY, code, 7);
        idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0,
                       IDCELL_EF_OBJECT, object, 5);
    } else {
        const char *result = "OK";
        idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0,
                       IDCELL_TLV_RESULT, result, 2);
    }
    put64(f->payload, &pos, IDCELL_TLV_COMMAND_ID, p->write_command_id + command_delta);
    put32(f->payload, &pos, IDCELL_TLV_BIND_ID, p->write_binding);
    put64(f->payload, &pos, IDCELL_TLV_SESSION_ID, p->write_session + session_delta);
    put64(f->payload, &pos, IDCELL_TLV_GRANT_EPOCH, p->write_grant);
    put64(f->payload, &pos, IDCELL_TLV_AUTHORITY_ID, p->write_authority);
    put64(f->payload, &pos, IDCELL_TLV_AUTHORITY_EPOCH, p->write_authority_epoch);
    put64(f->payload, &pos, IDCELL_TLV_MEMBER_EPOCH, p->write_member_epoch);
    f->payload_len = pos;
}

static int deliver_write_result(scene_t *s, idcell_frame_t *f, uint16_t index,
                                uint8_t sub, double value, uint64_t command)
{
    idcell_peer_t *p = &s->host->peers[0];
    int before = s->write_results;
    p->write_pending = 1; p->write_txn = f->txn;
    p->write_index = index; p->write_sub = sub; p->write_value = value;
    p->write_command_id = command;
    p->write_binding = p->contract.binding_id;
    p->write_session = p->contract.session_id;
    p->write_grant = p->contract.grant_epoch;
    p->write_authority = p->contract.authority_id;
    p->write_authority_epoch = p->contract.authority_epoch;
    p->write_member_epoch = p->contract.member_epoch;
    node_test_handle_frame(s->dev, f);
    idcell_node_poll(s->host, s->now);
    return s->write_results > before ? s->last_write_err : -1;
}

static void test_receipt_correlation(void)
{
    scene_t s;
    idcell_contract_t c;
    idcell_write_options_t opt;
    idcell_frame_t f;
    printf("[DONE/ERROR correlation]\n");
    scene_init(&s, 1); ok(scene_bind(&s), "bind receipt scene");
    idcell_node_get_contract(s.host, &s.dev_did, &c);
    opt.command_id = 60; opt.valid_for_ms = 100;
    idcell_node_write_ex(s.host, 0x0200, 0, 22, c.owner_token, "receipt", &opt);
    make_receipt(&s, &f, IDCELL_FT_DONE, 1, 0);
    node_test_handle_frame(s.host, &f);
    eq(s.write_results, 0, "old-session DONE ignored");
    ok(s.host->peers[0].write_pending, "old-session DONE leaves pending write intact");
    make_receipt(&s, &f, IDCELL_FT_DONE, 0, 1);
    node_test_handle_frame(s.host, &f);
    eq(s.write_results, 0, "command-mismatched DONE ignored");
    make_receipt(&s, &f, IDCELL_FT_DONE, 0, 0);
    node_test_handle_frame(s.host, &f);
    eq(s.write_results, 1, "fully matched DONE delivered");
    eq(s.last_write_err, IDCELL_OK, "matched DONE reports success");

    opt.command_id = 60;
    idcell_node_write_ex(s.host, 0x0200, 0, 22, c.owner_token, "current-B", &opt);
    make_receipt(&s, &f, IDCELL_FT_ERROR, (uint64_t)-1, 0);
    node_test_handle_frame(s.host, &f);
    eq(s.write_results, 1, "late A ERROR not delivered to current B with reused txn/command");
    ok(s.host->peers[0].write_pending, "late A ERROR does not clear B pending write");
    make_receipt(&s, &f, IDCELL_FT_DONE, 0, 0);
    node_test_handle_frame(s.host, &f);
    eq(s.write_results, 2, "current B still accepts its own DONE after late A ERROR");

    opt.command_id = 61;
    s.host->peers[0].txn = 0xFFFE;
    idcell_node_write_ex(s.host, 0x0200, 0, 23, c.owner_token, "wrap", &opt);
    eq(s.host->peers[0].write_txn, 0xFFFF, "write txn wraps at uint16 boundary");
    make_receipt(&s, &f, IDCELL_FT_ERROR, 0, 0);
    node_test_handle_frame(s.host, &f);
    eq(s.write_results, 3, "matched ERROR delivered at wrapped txn");
    eq(s.last_write_err, IDCELL_E_LEASE, "matched ERROR preserves concrete code");
    scene_free(&s);
}

static void test_publish_permissions(void)
{
    scene_t s;
    unsigned hx[256], dx[256];
    int i, reads, datas;
    printf("[publish direction and permission]\n");
    scene_init(&s, 1);
    s.dev->caps[0].kind = IDCELL_KIND_COMMAND;
    s.dev->caps[0].dir = IDCELL_DIR_W;
    s.host->reqs[0].kind = IDCELL_KIND_COMMAND;
    ok(scene_bind(&s), "write-only command point reaches contract without read grant");
    reads = s.state.read_calls; datas = s.data_calls;
    for (i = 0; i < 30; i++) scene_step(&s);
    idwp_count_all(&s.dev_wire.tx, dx);
    eq(s.state.read_calls, reads, "write-only periodic publish never calls value_fn");
    eq(s.data_calls, datas, "write-only periodic publish never calls data_fn");
    eq(dx[IDWP_T_EVENT], 0, "write-only periodic publish emits no EVENT");
    scene_free(&s);

    scene_init(&s, 1); ok(scene_bind(&s), "bind before permission tightening");
    for (i = 0; i < 20; i++) scene_step(&s);
    s.dev->caps[0].perm = IDCELL_PERM_P3;
    s.host->peers[0].caps[0].perm = IDCELL_PERM_P3;
    reads = s.state.read_calls; datas = s.data_calls;
    idwp_count_all(&s.dev_wire.tx, dx);
    for (i = 0; i < 30; i++) scene_step(&s);
    idwp_count_all(&s.dev_wire.tx, hx);
    eq(s.state.read_calls, reads, "permission-short publish stops before value_fn");
    eq(s.data_calls, datas, "permission-short consumer drops values before data_fn");
    eq(hx[IDWP_T_EVENT], 0, "permission-short publish emits no new EVENT");
    scene_free(&s);
}

static void test_pending_instance_frames(void)
{
    scene_t s;
    idcell_contract_t oldc, c;
    idcell_frame_t delayed, delayed_provider, reneg;
    idwp_frame_t wire;
    int i, prepared;
    uint32_t binding_b;
    uint64_t session_b;
    printf("[delayed ABORT and RENEGOTIATE]\n");
    scene_init(&s, 1);
    prepared = 0;
    for (i = 0; i < 500 && !prepared; i++) {
        idcell_node_poll(s.dev, s.now);
        if (s.dev->peers[0].bind_phase == IDCELL_BIND_PREPARED) prepared = 1;
        else { idcell_node_poll(s.host, s.now); s.now += 10; }
    }
    oldc = s.dev->peers[0].pending_contract;
    memset(&delayed, 0, sizeof(delayed));
    delayed.ver = IDCELL_PROTO_VER_BYTE; delayed.type = IDCELL_FT_BIND;
    delayed.src = s.dev_did; delayed.dst = s.host_did;
    {
        uint16_t pos = 0;
        put8(delayed.payload, &pos, IDCELL_TLV_BIND_PHASE, IDCELL_BIND_PHASE_ABORT);
        put32(delayed.payload, &pos, IDCELL_TLV_BIND_ID, oldc.binding_id);
        put64(delayed.payload, &pos, IDCELL_TLV_SESSION_ID, oldc.session_id);
        put64(delayed.payload, &pos, IDCELL_TLV_GRANT_EPOCH, oldc.grant_epoch);
        delayed.payload_len = pos;
    }
    delayed_provider = delayed;
    delayed_provider.src = s.host_did; delayed_provider.dst = s.dev_did;
    idcell_node_bind_abort(s.dev, &s.host_did);
    for (i = 0; i < 5; i++) scene_step(&s);
    prepared = 0;
    for (i = 0; i < 500 && !prepared; i++) {
        scene_step(&s);
        if (s.dev->peers[0].bind_phase == IDCELL_BIND_PREPARED &&
            s.host->peers[0].bind_phase == IDCELL_BIND_COMMIT_SENT &&
            s.host->peers[0].pending_contract.binding_id &&
            s.host->peers[0].pending_contract.binding_id ==
                s.dev->peers[0].pending_contract.binding_id &&
            s.host->peers[0].pending_contract.session_id ==
                s.dev->peers[0].pending_contract.session_id) prepared = 1;
    }
    ok(prepared, "prepare B pending really exists on both endpoints");
    binding_b = s.dev->peers[0].pending_contract.binding_id;
    session_b = s.dev->peers[0].pending_contract.session_id;
    node_test_handle_frame(s.dev, &delayed_provider);
    node_test_handle_frame(s.host, &delayed);
    ok(s.dev->peers[0].pending_contract.binding_id == binding_b &&
       s.dev->peers[0].pending_contract.session_id == session_b &&
       s.host->peers[0].pending_contract.binding_id == binding_b &&
       s.host->peers[0].pending_contract.session_id == session_b,
       "direction-correct delayed abort A cannot clear either prepare B");
    ok(scene_bind(&s), "prepare B still commits after delayed abort A");
    scene_free(&s);

    scene_init(&s, 1); ok(scene_bind(&s), "bind before online renegotiation");
    idcell_node_get_contract(s.host, &s.dev_did, &oldc);
    eq(idcell_node_renegotiate(s.host, &s.dev_did), IDCELL_OK, "send FT_RENEGOTIATE");
    ok(idwp_find_frame(&s.host_wire.tx, IDWP_T_RENEG, &wire), "wire contains FT_RENEGOTIATE");
    prepared = 0;
    for (i = 0; i < 500 && !prepared; i++) {
        idcell_node_poll(s.dev, s.now);
        if (s.dev->peers[0].bind_phase == IDCELL_BIND_PREPARED) prepared = 1;
        else { idcell_node_poll(s.host, s.now); s.now += 10; }
    }
    ok(prepared && s.dev->peers[0].has_contract, "new prepare linked while old active remains");
    memset(&reneg, 0, sizeof(reneg)); reneg.ver = IDCELL_PROTO_VER_BYTE;
    reneg.type = IDCELL_FT_RENEGOTIATE; reneg.src = s.host_did; reneg.dst = s.dev_did;
    {
        uint16_t pos = 0;
        put32(reneg.payload, &pos, IDCELL_TLV_OLD_BINDING, oldc.binding_id);
        put64(reneg.payload, &pos, IDCELL_TLV_OLD_SESSION, oldc.session_id);
        put64(reneg.payload, &pos, IDCELL_TLV_OLD_GRANT, oldc.grant_epoch);
        reneg.payload_len = pos;
    }
    binding_b = s.dev->peers[0].pending_contract.binding_id;
    node_test_handle_frame(s.dev, &reneg);
    eq(s.dev->peers[0].pending_contract.binding_id, binding_b,
       "duplicate old RENEGOTIATE does not clear new pending");
    idcell_node_bind_abort(s.dev, &s.host_did);
    for (i = 0; i < 5; i++) scene_step(&s);
    idcell_node_get_contract(s.host, &s.dev_did, &c);
    ok(c.binding_id == oldc.binding_id && c.session_id == oldc.session_id,
       "old contract survives aborted renegotiation");
    scene_free(&s);
}

static void test_relative_time_and_wrap(void)
{
    scene_t s;
    idcell_contract_t c;
    idcell_write_options_t opt;
    int base;
    printf("[relative validity and u32 wrap]\n");
    scene_init(&s, 1); s.now = UINT32_MAX - 80;
    ok(scene_bind(&s), "binding remains valid across u32 clock wrap");
    idcell_node_get_contract(s.host, &s.dev_did, &c);
    s.host->now_ms = 123;
    s.dev->now_ms = UINT32_MAX - 2;
    opt.command_id = 70; opt.valid_for_ms = 4;
    base = s.state.set_calls;
    eq(idcell_node_write_ex(s.host, 0x0200, 0, 24, c.owner_token, "relative", &opt),
       IDCELL_OK, "relative valid_for accepted with independent clock origins");
    idcell_node_poll(s.dev, 1);
    eq(s.state.set_calls, base + 1, "receiver maps relative validity across wrap");
    opt.command_id = 71; opt.valid_for_ms = 0;
    eq(idcell_node_write_ex(s.host, 0x0200, 0, 24, c.owner_token, "zero", &opt),
       IDCELL_E_LEASE, "zero relative validity rejected");
    opt.valid_for_ms = IDCELL_MAX_VALID_FOR_MS + 1;
    eq(idcell_node_write_ex(s.host, 0x0200, 0, 24, c.owner_token, "too-long", &opt),
       IDCELL_E_LEASE, "relative validity upper bound enforced");
    {
        idcell_frame_t first, second;
        make_write(&s, &first, 0x0200, 0, 24, 72, 20);
        make_write(&s, &second, 0x0200, 0, 25, 73, 20);
        base = s.state.set_calls;
        node_test_receive_frame(s.dev, &first);
        node_test_receive_frame(s.dev, &second);
        eq(s.dev->write_queue_count, 2, "positive-TTL commands enter bounded production queue");
        idcell_node_poll(s.dev, s.dev->now_ms);
        eq(s.state.set_calls, base + 1, "first queued command executes before its deadline");
        idcell_node_poll(s.dev, s.dev->now_ms + 21);
        eq(s.state.set_calls, base + 1, "second queued command expires without setter side effect");
    }
    scene_free(&s);
}

static void test_command_cache_closed(void)
{
    scene_t s;
    idcell_frame_t first, w;
    int i, expected = 0;
    printf("[bounded completion cache]\n");
    scene_init(&s, 1); ok(scene_bind(&s), "bind cache scene");
    for (i = 0; i < IDCELL_COMMAND_CACHE + 1; i++) {
        make_write(&s, &w, 0x0200, 0, 20 + i, (uint64_t)(i + 1), 100);
        if (i == 0) first = w;
        node_test_handle_frame(s.dev, &w);
        if (i < IDCELL_COMMAND_CACHE) expected++;
        eq(s.state.set_calls, expected, i < IDCELL_COMMAND_CACHE ?
           "command accepted while completion cache has space" :
           "new command rejected when completion cache is full");
    }
    node_test_handle_frame(s.dev, &first);
    eq(s.state.set_calls, expected, "oldest replay stays idempotent after cache overflow");
    scene_free(&s);
}

static void recreate_dev_with_snapshot(scene_t *s, const idcell_snapshot_t *snap)
{
    idcell_node_cfg_t cfg = s->dev->cfg;
    idcell_transport_t tr = s->dev->tr;
    idcell_capability_t caps[2];
    caps[0] = s->dev->caps[0]; caps[1] = s->dev->caps[1];
    idcell_node_free(s->dev);
    s->dev = idcell_node_new(&cfg);
    idcell_node_set_transport(s->dev, &tr);
    idcell_node_register_capability(s->dev, &caps[0]);
    idcell_node_register_capability(s->dev, &caps[1]);
    idcell_node_set_value_source(s->dev, value_fn, &s->state);
    idcell_node_set_setter(s->dev, set_fn, &s->state);
    s->now = 0;
    idcell_node_restore(s->dev, snap);
}

static void test_renegotiate_and_restart(void)
{
    scene_t s;
    idcell_contract_t oldc, newc;
    idcell_snapshot_t snap;
    idcell_frame_t w;
    int i, before;
    printf("[renegotiation and restart]\n");
    scene_init(&s, 1);
    ok(scene_bind(&s), "initial binding for restart");
    idcell_node_get_contract(s.host, &s.dev_did, &oldc);
    eq(idcell_node_renegotiate(s.host, &s.dev_did), IDCELL_OK, "start explicit renegotiation");
    for (i = 0; i < 500 && s.dev->peers[0].bind_phase != IDCELL_BIND_PREPARED; i++) {
        idcell_node_poll(s.dev, s.now);
        if (s.dev->peers[0].bind_phase != IDCELL_BIND_PREPARED) {
            idcell_node_poll(s.host, s.now); s.now += 10;
        }
    }
    ok(s.dev->peers[0].has_contract, "old provider contract remains active during prepare");
    before = s.state.set_calls;
    make_write(&s, &w, 0x0200, 0, 25, 89, s.now + 100);
    node_test_handle_frame(s.dev, &w);
    eq(s.state.set_calls, before + 1, "old contract still serves writes before recommit");
    eq(idcell_node_bind_abort(s.dev, &s.host_did), IDCELL_OK, "abort renegotiation");
    for (i = 0; i < 6; i++) scene_step(&s);
    idcell_node_get_contract(s.host, &s.dev_did, &newc);
    ok(newc.binding_id == oldc.binding_id && newc.session_id == oldc.session_id,
       "abort preserves old active contract");

    eq(idcell_node_snapshot(s.dev, &snap), IDCELL_OK, "snapshot highest epochs");
    ok(snap.grant_epoch_floor >= oldc.grant_epoch && snap.authority_epoch >= oldc.authority_epoch &&
       snap.member_epoch >= oldc.member_epoch, "snapshot persists only epoch floors/fingerprint");
    make_write(&s, &w, 0x0200, 0, 26, 90, s.now + 100);
    recreate_dev_with_snapshot(&s, &snap);
    ok(s.dev->now_ms == 0 && s.dev->grant_epoch_counter == snap.grant_epoch_floor,
       "new empty node restores only snapshot floors and resets clock");
    before = s.state.set_calls;
    node_test_handle_frame(s.dev, &w);
    eq(s.state.set_calls, before, "restart invalidates old lease/token/session");
    eq(idcell_node_renegotiate(s.host, &s.dev_did), IDCELL_OK, "renegotiate after restart");
    ok(scene_bind(&s), "new epoch binding reactivates after restart");
    idcell_node_get_contract(s.host, &s.dev_did, &newc);
    ok(newc.grant_epoch > oldc.grant_epoch && newc.session_id != oldc.session_id,
       "reactivation requires higher epoch and new session");
    before = s.state.set_calls;
    node_test_handle_frame(s.dev, &w);
    eq(s.state.set_calls, before, "old epoch write still rejected after reactivation");
    make_write(&s, &w, 0x0200, 0, 27, 91, s.now + 100);
    node_test_handle_frame(s.dev, &w);
    eq(s.state.set_calls, before + 1, "new epoch write executes");
    scene_free(&s);
}

typedef struct {
    idcell_did_t did[3];
    uint8_t buf[3][16384];
    size_t len[3];
    idcell_link_profile_t profile;
} test_bus_t;

typedef struct {
    test_bus_t *bus;
    int port;
} bus_endpoint_t;

static int bus_send2(void *ctx, const uint8_t *buf, size_t len)
{
    bus_endpoint_t *ep = (bus_endpoint_t *)ctx;
    test_bus_t *b = ep->bus;
    int i;
    for (i = 0; i < 3; i++) {
        int broadcast = 1, k;
        for (k = 0; k < 8; k++) if (buf[20 + k] != 0xFF) broadcast = 0;
        if (i == ep->port || (!broadcast && memcmp(buf + 20, b->did[i].b, 8) != 0)) continue;
        if (b->len[i] + len > sizeof(b->buf[i])) return -1;
        memcpy(b->buf[i] + b->len[i], buf, len); b->len[i] += len;
    }
    return 0;
}

static int bus_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t timeout)
{
    bus_endpoint_t *ep = (bus_endpoint_t *)ctx;
    test_bus_t *b = ep->bus;
    size_t n;
    (void)timeout;
    if (!b->len[ep->port]) return 0;
    n = b->len[ep->port] < cap ? b->len[ep->port] : cap;
    memcpy(buf, b->buf[ep->port], n);
    b->len[ep->port] -= n;
    if (b->len[ep->port]) memmove(b->buf[ep->port], b->buf[ep->port] + n, b->len[ep->port]);
    return (int)n;
}

typedef struct {
    test_bus_t bus;
    bus_endpoint_t ep[3];
    idcell_node_t *dev, *a, *b;
    device_state_t state;
    idcell_did_t a_did, b_did;
    uint32_t now;
} dual_scene_t;

static idcell_node_t *dual_host(dual_scene_t *s, int port, uint64_t seed)
{
    idcell_node_cfg_t cfg;
    idcell_requirement_t req;
    idcell_node_t *n;
    memset(&cfg, 0, sizeof(cfg)); idcell_did_generate(seed, &cfg.did);
    memset(cfg.cred, 0x42, sizeof(cfg.cred)); cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 100; cfg.lease_ttl_ms = 10000;
    n = idcell_node_new(&cfg);
    s->ep[port].bus = &s->bus; s->ep[port].port = port;
    {
        idcell_transport_t tr;
        tr.send = bus_send2; tr.recv = bus_recv; tr.profile = &s->bus.profile; tr.ctx = &s->ep[port];
        idcell_node_set_transport(n, &tr);
    }
    memset(&req, 0, sizeof(req)); req.index = 0xFFFF; req.kind = IDCELL_KIND_STATE;
    req.qty = IDCELL_QTY_TEMPERATURE; snprintf(req.unit, sizeof(req.unit), "Cel");
    req.accept_count = 1; snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "Cel");
    req.perm = IDCELL_PERM_P2; req.want_ms = 20; req.stale_ms = 1000;
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_node_register_requirement(n, &req);
    s->bus.did[port] = cfg.did;
    return n;
}

static void dual_init(dual_scene_t *s)
{
    idcell_node_cfg_t cfg;
    idcell_capability_t cap;
    memset(s, 0, sizeof(*s));
    s->bus.profile.media = IDCELL_MEDIA_LOOPBACK; s->bus.profile.topology = IDCELL_TOPO_MULTI_DROP;
    memset(&cfg, 0, sizeof(cfg)); idcell_did_generate(0xD100, &cfg.did);
    memset(cfg.cred, 0x42, sizeof(cfg.cred)); cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 100; cfg.lease_ttl_ms = 10000;
    s->dev = idcell_node_new(&cfg); s->bus.did[0] = cfg.did;
    s->ep[0].bus = &s->bus; s->ep[0].port = 0;
    {
        idcell_transport_t tr;
        tr.send = bus_send2; tr.recv = bus_recv; tr.profile = &s->bus.profile; tr.ctx = &s->ep[0];
        idcell_node_set_transport(s->dev, &tr);
    }
    fill_cap(&cap, 0x0200, IDCELL_QTY_TEMPERATURE, "Cel", IDCELL_DIR_RW,
             IDCELL_PERM_P2, -40, 85);
    idcell_node_register_capability(s->dev, &cap);
    idcell_node_set_value_source(s->dev, value_fn, &s->state);
    idcell_node_set_setter(s->dev, set_fn, &s->state);
    s->a = dual_host(s, 1, 0xD101); s->a_did = idcell_node_did(s->a);
}

static void dual_free(dual_scene_t *s)
{
    if (s->dev) idcell_node_free(s->dev); if (s->a) idcell_node_free(s->a);
    if (s->b) idcell_node_free(s->b);
}

static void dual_step(dual_scene_t *s, int include_a)
{
    idcell_node_poll(s->dev, s->now);
    if (include_a) idcell_node_poll(s->a, s->now);
    if (s->b) idcell_node_poll(s->b, s->now);
    s->now += 10;
}

static int dual_bound(dual_scene_t *s, idcell_node_t *host, const idcell_did_t *peer)
{
    idcell_contract_t c;
    (void)s;
    return idcell_node_get_contract(host, peer, &c) == IDCELL_OK;
}

static void dual_write(dual_scene_t *s, const idcell_contract_t *c,
                       const idcell_did_t *src, double value, uint64_t command)
{
    idcell_frame_t f;
    uint16_t pos = 0;
    uint8_t b[8];
    memset(&f, 0, sizeof(f)); f.ver = IDCELL_PROTO_VER_BYTE; f.type = IDCELL_FT_WRITE;
    f.src = *src; f.dst = s->bus.did[0]; f.txn = (uint16_t)command;
    idcell_put_f64(b, value);
    idcell_tlv_put(f.payload, sizeof(f.payload), &pos, 0x0200, 0, IDCELL_TLV_VALUE, b, 8);
    put16(f.payload, &pos, IDCELL_TLV_SCHEMA_REF, c->pt[0].schema_ref);
    put32(f.payload, &pos, IDCELL_TLV_BIND_ID, c->binding_id);
    put64(f.payload, &pos, IDCELL_TLV_SESSION_ID, c->session_id);
    put64(f.payload, &pos, IDCELL_TLV_GRANT_EPOCH, c->grant_epoch);
    put64(f.payload, &pos, IDCELL_TLV_AUTHORITY_ID, c->authority_id);
    put64(f.payload, &pos, IDCELL_TLV_AUTHORITY_EPOCH, c->authority_epoch);
    put64(f.payload, &pos, IDCELL_TLV_MEMBER_EPOCH, c->member_epoch);
    put64(f.payload, &pos, IDCELL_TLV_COMMAND_ID, command);
    put32(f.payload, &pos, IDCELL_TLV_VALID_FOR, 100);
    put32(f.payload, &pos, IDCELL_TLV_OWNER, c->owner_token);
    idcell_tlv_put(f.payload, sizeof(f.payload), &pos, 0, 0, IDCELL_TLV_INTENT, "dual", 4);
    f.payload_len = pos;
    node_test_handle_frame(s->dev, &f);
}

static void test_executor_handover(int release)
{
    dual_scene_t s;
    idcell_contract_t ac, bc;
    int i, base;
    printf(release ? "[executor release handover]\n" : "[executor TTL handover]\n");
    dual_init(&s);
    for (i = 0; i < 500 && !dual_bound(&s, s.a, &s.bus.did[0]); i++) dual_step(&s, 1);
    ok(dual_bound(&s, s.a, &s.bus.did[0]), "controller A binds writable point");
    idcell_node_get_contract(s.a, &s.bus.did[0], &ac);
    dual_write(&s, &ac, &s.a_did, 21, 1);
    eq(s.state.set_calls, 1, "controller A initial write executes");
    s.b = dual_host(&s, 2, 0xD102); s.b_did = idcell_node_did(s.b);
    for (i = 0; i < 500 && !s.dev->peers[1].commit_waiting; i++) dual_step(&s, 1);
    ok(s.dev->peers[1].commit_waiting, "controller B waits for old owner");
    ok(!dual_bound(&s, s.b, &s.bus.did[0]), "B not active before release/TTL");
    dual_write(&s, &ac, &s.a_did, 22, 2);
    eq(s.state.set_calls, 2, "old owner continues while B waits");
    if (release) {
        eq(idcell_node_release(s.a, &s.bus.did[0]), IDCELL_OK, "A confirms release");
        for (i = 0; i < 20 && !dual_bound(&s, s.b, &s.bus.did[0]); i++) dual_step(&s, 1);
    } else {
        for (i = 0; i < 1100 && !dual_bound(&s, s.b, &s.bus.did[0]); i++) dual_step(&s, 0);
    }
    ok(dual_bound(&s, s.b, &s.bus.did[0]), "B activates only after release/TTL");
    idcell_node_get_contract(s.b, &s.bus.did[0], &bc);
    ok(bc.grant_epoch > ac.grant_epoch, "B receives higher grant epoch");
    base = s.state.set_calls;
    dual_write(&s, &ac, &s.a_did, 23, 3);
    dual_write(&s, &bc, &s.b_did, 24, 4);
    dual_write(&s, &ac, &s.a_did, 25, 5);
    dual_write(&s, &bc, &s.b_did, 26, 6);
    eq(s.state.set_calls, base + 2, "interleaved A/B writes only execute current executor grant");
    dual_free(&s);
}

static void run_tests(void)
{
    test_schema();
    test_executor_handover(1);
    test_executor_handover(0);
    test_bind_lifecycle();
    test_publish_permissions();
    test_pending_instance_frames();
    test_receipt_correlation();
    test_contract_and_write();
    test_relative_time_and_wrap();
    test_command_cache_closed();
    test_renegotiate_and_restart();
    printf("SUMMARY pass=%d fail=%d\n", g_pass, g_fail);
}

static int vector(const char *name)
{
    if (strcmp(name, "schema") == 0) {
        idcell_schema_def_t a, b;
        idcell_schema_standard(IDCELL_DTYPE_F64, 0, "Cel", &a);
        idcell_schema_standard(IDCELL_DTYPE_I16, 2, "Cel", &b);
        printf("f64_id=%llu i16_id=%llu f64_ns=%llu ",
               (unsigned long long)a.schema_id, (unsigned long long)b.schema_id,
               (unsigned long long)(a.schema_id >> 40));
        printf("need=%d allowed=%d ", idcell_schema_check_change(&a, &b, 0),
               idcell_schema_check_change(&a, &b, 1));
        b = a; snprintf(b.fields[0].value_type, sizeof(b.fields[0].value_type), "i16");
        printf("same_id=%d ", idcell_schema_check_change(&a, &b, 1));
        b = a; snprintf(b.fields[0].name, sizeof(b.fields[0].name), "unknown");
        printf("unknown=%d\n", idcell_schema_check_change(&a, &b, 1));
        return 1;
    }
    if (strcmp(name, "bind") == 0) {
        scene_t s; idcell_contract_t c; int i, prepared = 0;
        scene_init(&s, 1);
        for (i = 0; i < 500 && !prepared; i++) {
            idcell_node_poll(s.dev, s.now);
            if (s.dev->peers[0].bind_phase == IDCELL_BIND_PREPARED) prepared = 1;
            else { idcell_node_poll(s.host, s.now); s.now += 10; }
        }
        printf("prepared_visible=%d ", idcell_node_get_contract(s.dev, &s.host_did, &c) == IDCELL_OK);
        idcell_node_bind_abort(s.dev, &s.host_did);
        for (i = 0; i < 5; i++) scene_step(&s);
        printf("abort_visible=%d ", idcell_node_get_contract(s.host, &s.dev_did, &c) == IDCELL_OK);
        scene_bind(&s);
        printf("commit_visible=%d ", idcell_node_get_contract(s.host, &s.dev_did, &c) == IDCELL_OK);
        idcell_node_get_contract(s.host, &s.dev_did, &c);
        printf("outside_rejected=%d\n",
               idcell_node_write(s.host, 0x0100, 0, 2, c.owner_token, "outside") != IDCELL_OK);
        scene_free(&s); return 1;
    }
    if (strcmp(name, "mailbox") == 0) {
        scene_t s; idcell_frame_t w, x;
        scene_init(&s, 1); scene_bind(&s);
        make_write(&s, &w, 0x0200, 0, 24, 1, 100);
        printf("valid=%d ", deliver_write_result(&s, &w, 0x0200, 0, 24, 1));
        printf("duplicate=%d ", deliver_write_result(&s, &w, 0x0200, 0, 24, 1));
        x = w; idcell_put_f64(x.payload + 6, 25.0);
        printf("conflict=%d ", deliver_write_result(&s, &x, 0x0200, 0, 25, 1));
        make_write(&s, &w, 0x0200, 0, 24, 2, 0);
        printf("expired=%d ", deliver_write_result(&s, &w, 0x0200, 0, 24, 2));
        make_write(&s, &w, 0x0200, 0, 24, 3, 100);
        x = w; patch_field(&x, IDCELL_TLV_SESSION_ID, 0xFFFF, 8);
        printf("old_session=%d ", deliver_write_result(&s, &x, 0x0200, 0, 24, 3));
        x = w; patch_field(&x, IDCELL_TLV_GRANT_EPOCH, 0, 8);
        printf("old_epoch=%d\n", deliver_write_result(&s, &x, 0x0200, 0, 24, 3));
        scene_free(&s); return 1;
    }
    if (strcmp(name, "restart") == 0) {
        scene_t s; idcell_contract_t oldc, newc; idcell_snapshot_t snap;
        idcell_frame_t w;
        scene_init(&s, 1); scene_bind(&s);
        idcell_node_get_contract(s.host, &s.dev_did, &oldc);
        idcell_node_snapshot(s.dev, &snap);
        make_write(&s, &w, 0x0200, 0, 26, 90, s.now + 100);
        recreate_dev_with_snapshot(&s, &snap);
        printf("old_rejected=%d ", deliver_write_result(&s, &w, 0x0200, 0, 26, 90));
        idcell_node_renegotiate(s.host, &s.dev_did); scene_bind(&s);
        idcell_node_get_contract(s.host, &s.dev_did, &newc);
        printf("higher=%d ", newc.grant_epoch > oldc.grant_epoch);
        printf("old_epoch_rejected=%d ", deliver_write_result(&s, &w, 0x0200, 0, 26, 90));
        make_write(&s, &w, 0x0200, 0, 27, 91, 100);
        printf("new_executed=%d\n", deliver_write_result(&s, &w, 0x0200, 0, 27, 91));
        scene_free(&s); return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    (void)&idwp_get_f64;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 3 && strcmp(argv[1], "--vector") == 0) {
        if (!vector(argv[2])) return 2;
        return 0;
    }
    run_tests();
    return g_fail ? 1 : 0;
}
