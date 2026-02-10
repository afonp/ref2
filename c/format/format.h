#ifndef REF2_FORMAT_H
#define REF2_FORMAT_H

#include <stdint.h>
#include <stddef.h>
#include "token.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Field taxonomy ─────────────────────────────────────────────────────────── */

typedef enum {
    FIELD_MAGIC,            /* constant magic bytes, entropy ≈ 0 */
    FIELD_CONSTANT,         /* fixed value, not magic */
    FIELD_ENUM,             /* 2–16 distinct values */
    FIELD_SEQUENCE_NUMBER,  /* monotonically increasing within session */
    FIELD_LENGTH,           /* correlates with payload length */
    FIELD_PAYLOAD,          /* high-entropy, variable-length, usually last */
    FIELD_NONCE,            /* high-entropy, fixed-length, no repetition */
    FIELD_STRING,           /* >80% printable ASCII */
    FIELD_OPAQUE,           /* unclassified */
} field_type_t;

/* ── Schema types ───────────────────────────────────────────────────────────── */

typedef struct {
    size_t       offset;
    size_t       length;         /* 0 = variable */
    field_type_t type;
    char         name[64];       /* e.g. "field_00_magic" */
    double       entropy;        /* Shannon entropy in bits */
    uint32_t     enum_values[16];
    size_t       enum_count;
} field_t;

typedef struct {
    uint32_t  type_id;
    field_t  *fields;
    size_t    field_count;
    char      name[64];          /* e.g. "msg_type_00" */
} message_schema_t;

typedef struct {
    message_schema_t *schemas;
    size_t            schema_count;
} protocol_schema_t;

/* ── Format inference API ───────────────────────────────────────────────────── */

protocol_schema_t *infer_format(token_stream_t **streams, size_t stream_count,
                                const framing_info_t *framing);

/* Lower-level steps exposed for testing */
uint32_t    *cluster_messages    (token_stream_t **streams, size_t stream_count,
                                  size_t *total_msgs_out, int *k_out);
double      *align_cluster       (token_t **msgs, size_t msg_count,
                                  size_t *consensus_len_out);
field_t     *segment_fields      (const double *conservation, size_t len,
                                  const framing_info_t *framing,
                                  size_t *field_count_out);
field_type_t classify_field      (token_t **msgs, size_t msg_count,
                                  size_t offset, size_t length);

double field_entropy (token_t **msgs, size_t msg_count,
                      size_t offset, size_t length);

const char  *field_type_name     (field_type_t t);

/* ── Memory management ──────────────────────────────────────────────────────── */

void protocol_schema_free  (protocol_schema_t *schema);
void message_schema_free   (message_schema_t  *schema);

#ifdef __cplusplus
}
#endif

#endif /* REF2_FORMAT_H */
