#ifndef POLICY_H
#define POLICY_H
#include "packet.h"

/* Select one explicit host pair and one TCP service port in both directions.
 * Addresses are four bytes in network order, not host-endian integers.
 */
struct policy { unsigned char local[4], remote[4]; uint16_t port; };
int policy_port(const char *text, uint16_t *port);
int policy_match(const struct policy *policy, const unsigned char *frame,
                 size_t length, int from_host);
#endif
