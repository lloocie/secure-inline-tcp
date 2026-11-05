#include "pending.h"
#include <string.h>

static int consumed(const struct pending *pending, const unsigned char hash[32]) {
    for (size_t index=0;index<pending->consumed_count;index++)
        if (!memcmp(pending->consumed[index],hash,32)) return 1;
    return 0;
}

int pending_record(struct pending *pending, const unsigned char record[44], uint64_t now) {
    for (size_t index=0;index<PENDING_SLOTS;index++) if (!pending->records[index].used) {
        struct pending_record *slot=&pending->records[index];
        memcpy(slot->bytes,record,44); slot->created=now; slot->used=1; return 1;
    }
    pending->stats.full++; return 0;
}

int pending_frame(struct pending *pending, const unsigned char *frame, size_t length, uint64_t now) {
    unsigned char hash[32];
    if (length>FRAME_MAX || !fingerprint(frame,length,hash)) return 0;
    /* An exact accepted duplicate is dropped immediately. Older duplicates
     * evicted from this bounded cache still lack a usable nonce association:
     * consumed records cannot be reannounced over strictly ordered TLS.
     */
    if (consumed(pending,hash)) { pending->stats.replay++; return 0; }
    for (size_t index=0;index<PENDING_SLOTS;index++) if (!pending->frames[index].used) {
        struct pending_frame *slot=&pending->frames[index];
        memcpy(slot->bytes,frame,length); memcpy(slot->hash,hash,32);
        slot->length=length; slot->created=now; slot->used=1; return 1;
    }
    pending->stats.full++; return 0;
}

void pending_expire(struct pending *pending, uint64_t now) {
    for (size_t index=0;index<PENDING_SLOTS;index++) {
        struct pending_record *record=&pending->records[index];
        struct pending_frame *frame=&pending->frames[index];
        if (record->used && now-record->created>=PENDING_TTL) {
            record->used=0; pending->stats.expired_records++;
        }
        /* A tampered frame no longer matches its authenticated fingerprint.
         * It is dropped here without guessing a nonce or emitting plaintext.
         * Other unmatched frames may simply have lost/delayed control records.
         */
        if (frame->used && now-frame->created>=PENDING_TTL) {
            frame->used=0; pending->stats.unmatched++;
        }
    }
}

int pending_take(struct pending *pending, const unsigned char key[32], unsigned char out[FRAME_MAX], size_t *length) {
    for (size_t frame_index=0;frame_index<PENDING_SLOTS;frame_index++) {
        struct pending_frame *frame=&pending->frames[frame_index];
        if (!frame->used) continue;
        /* This second replay check catches duplicates queued before the first
         * copy was accepted, not only duplicates arriving afterwards.
         */
        if (consumed(pending,frame->hash)) {
            frame->used=0; pending->stats.replay++; continue;
        }
        for (size_t record_index=0;record_index<PENDING_SLOTS;record_index++) {
            struct pending_record *record=&pending->records[record_index];
            if (!record->used || memcmp(frame->hash,record->bytes+12,32)) continue;
            memcpy(out,frame->bytes,frame->length); *length=frame->length;
            frame->used=0; record->used=0;
            if (!transform(out,length,key,record->bytes,0)) {
                pending->stats.bad_tag++; break;
            }
            memcpy(pending->consumed[pending->consumed_next],frame->hash,32);
            pending->consumed_next=(pending->consumed_next+1)%PENDING_SLOTS;
            if (pending->consumed_count<PENDING_SLOTS) pending->consumed_count++;
            return 1;
        }
    }
    return 0;
}
