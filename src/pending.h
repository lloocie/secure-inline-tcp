#ifndef PENDING_H
#define PENDING_H
#include "packet.h"
#include <stdint.h>
#define PENDING_SLOTS 256
#define PENDING_TTL 10

struct pending_record { int used; uint64_t created; unsigned char bytes[44]; };
struct pending_frame { int used; uint64_t created; size_t length; unsigned char bytes[FRAME_MAX], hash[32]; };
struct pending_stats { unsigned long replay, unmatched, expired_records, bad_tag, full; };
struct pending {
    struct pending_record records[PENDING_SLOTS];
    struct pending_frame frames[PENDING_SLOTS];
    unsigned char consumed[PENDING_SLOTS][32];
    size_t consumed_count, consumed_next;
    struct pending_stats stats;
};
/* Records arrive through authenticated, ordered TLS. The caller separately
 * validates their session prefix and strictly increasing nonce counters.
 */
int pending_record(struct pending *pending, const unsigned char record[44], uint64_t now);
int pending_frame(struct pending *pending, const unsigned char *frame, size_t length, uint64_t now);
void pending_expire(struct pending *pending, uint64_t now);
/* Return one authenticated plaintext frame, or 0 if nothing can be delivered.
 * Caller repeatedly drains successful results and forwards only those frames.
 */
int pending_take(struct pending *pending, const unsigned char key[32], unsigned char out[FRAME_MAX], size_t *length);
#endif
