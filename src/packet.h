/* Shared interface between raw forwarding, packet processing, and unit tests.
 * The include guard prevents duplicate declarations on repeated inclusion.
 */
#ifndef PACKET_H
#define PACKET_H
#include <stddef.h>
#include <stdint.h>
/* Fixed lab buffer capacity, including the Ethernet header and GCM tag. */
#define FRAME_MAX 2048
/* Full 128-bit GCM authentication tag; never truncate it on the data path. */
#define TAG_SIZE 16
/* Byte offsets into the full Ethernet frame; end is one past the IP packet.
 * Keeping offsets rather than C wire structs avoids alignment/padding issues.
 */
struct packet { size_t ip, tcp, payload, end; };
/* Return 1 for a structurally supported frame, otherwise 0. */
int parse_packet(const unsigned char *frame, size_t length, struct packet *packet);
/* Caller supplies valid parsed offsets and the current exclusive packet end. */
void checksums(unsigned char *frame, const struct packet *packet);
/* In-place payload transform. length is updated on success; 0 means discard.
 * Callers must provide FRAME_MAX bytes of writable storage for encryption.
 */
int transform(unsigned char *frame, size_t *length, const unsigned char key[32],
              const unsigned char nonce[12], int encrypt);
/* Produce the 32-byte canonical protected-packet lookup digest. */
int fingerprint(const unsigned char *frame, size_t length, unsigned char hash[32]);
#endif
