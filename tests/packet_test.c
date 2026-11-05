/* Unit tests for byte-level behavior; no namespaces, raw sockets, or root.
 * These checks do not exercise the DH handshake or full Linux forwarding.
 */
#include "packet.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
/* Build deterministic Ethernet/IPv4/TCP bytes. The optional four TCP NOP
 * bytes exercise data-offset handling without changing the application data.
 */
static void sample(unsigned char *frame, size_t payload, int options) {
    /* EtherType 0x0800, IPv4 version/IHL 0x45, TTL 64, TCP protocol 6. */
    memset(frame,0,FRAME_MAX); frame[12]=8; frame[14]=0x45; frame[22]=64; frame[23]=6;
    frame[26]=10; frame[29]=1; frame[30]=10; frame[33]=2;
    /* TCP source port 50000, destination 8080; ACK+PSH flags below. */
    frame[34]=0xc3; frame[35]=0x50; frame[36]=0x1f; frame[37]=0x90;
    frame[46]=options?0x60:0x50; frame[47]=0x18;
    /* IPv4 total length includes headers and payload, but not Ethernet. */
    size_t total=40+payload+(options?4:0); frame[16]=(unsigned char)(total>>8); frame[17]=(unsigned char)total;
    if (options) { frame[54]=1; frame[55]=1; frame[56]=1; frame[57]=1; }
    for (size_t index=0;index<payload;index++) frame[54+(options?4:0)+index]=(unsigned char)index;
    /* Populate valid original checksums for exact round-trip comparison. */
    struct packet packet; assert(parse_packet(frame,total+14,&packet)); checksums(frame,&packet);
}
/* Fixed key/nonce are test fixtures ONLY. Reusing them here checks independent
 * transforms; live encryption must allocate a fresh nonce for every packet.
 */
int main(void) {
    unsigned char key[32]={1},nonce[12]={2},frame[FRAME_MAX],original[FRAME_MAX],protected_frame[FRAME_MAX];
    /* Exercise empty payloads and sizes through 1440 bytes, with/without
     * TCP options. Every success must append exactly 16 tag bytes.
     */
    for (int options=0;options<2;options++) for (size_t payload=0;payload<=1440;payload+=5) {
        sample(frame,payload,options); size_t length=54+payload+(options?4:0), initial=length;
        memcpy(original,frame,length); assert(transform(frame,&length,key,nonce,1)); assert(length==initial+16);
        memcpy(protected_frame,frame,length); size_t protected_length=length;
        /* Corrupt the tag: authenticated decryption must reject the packet. */
        frame[length-1]^=1; assert(!transform(frame,&length,key,nonce,0));
        memcpy(frame,protected_frame,protected_length); length=protected_length;
        /* Corrupt TCP sequence metadata bound by AAD: rejection is required. */
        frame[38]^=1; assert(!transform(frame,&length,key,nonce,0));
        memcpy(frame,protected_frame,protected_length); length=protected_length;
        /* Restore the untouched protected copy and require byte-for-byte
         * recovery of headers, payload, lengths, and original checksums.
         */
        assert(transform(frame,&length,key,nonce,0)); assert(length==initial); assert(!memcmp(frame,original,initial));
    }
    /* Reject a truncated header and an IPv4 MF fragment before slicing TCP. */
    sample(frame,5,0); struct packet packet;
    assert(!parse_packet(frame,53,&packet)); frame[20]=0x20; assert(!parse_packet(frame,59,&packet));
    puts("Packet round trips, empty payloads, TCP options, tamper rejection and parser checks passed");
}
