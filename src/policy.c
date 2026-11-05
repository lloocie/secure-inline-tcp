#include "policy.h"
#include <string.h>

/* Reject empty, signed, zero, nondecimal and out-of-range ports rather than
 * silently truncating a number with atoi()/a cast.
 */
int policy_port(const char *text, uint16_t *port) {
    unsigned value=0;
    if (!text || !*text) return 0;
    for (const char *digit=text; *digit; digit++) {
        if (*digit<'0' || *digit>'9') return 0;
        value=value*10u+(unsigned)(*digit-'0');
        if (value>65535) return 0;
    }
    if (!value) return 0;
    *port=(uint16_t)value; return 1;
}

int policy_match(const struct policy *policy, const unsigned char *frame,
                 size_t length, int from_host) {
    struct packet packet;
    if (!parse_packet(frame,length,&packet)) return 0;
    const unsigned char *source=from_host?policy->local:policy->remote;
    const unsigned char *destination=from_host?policy->remote:policy->local;
    if (memcmp(frame+26,source,4) || memcmp(frame+30,destination,4)) return 0;
    unsigned source_port=(unsigned)frame[packet.tcp]*256+frame[packet.tcp+1];
    unsigned destination_port=(unsigned)frame[packet.tcp+2]*256+frame[packet.tcp+3];
    /* Match the service port on either end, allowing requests and replies.
     * Empty SYN/ACK/FIN/RST segments use this same policy and receive tags.
     */
    return source_port==policy->port || destination_port==policy->port;
}
