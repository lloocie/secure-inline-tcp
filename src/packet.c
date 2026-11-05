/* Byte-oriented packet operations, independent of Linux raw sockets.
 * Frame offsets assume Ethernet II without VLAN tags; all multi-byte wire
 * fields are read explicitly to avoid alignment and host-endianness issues.
 */
#include "packet.h"
#include <string.h>
#include <openssl/evp.h>

/* Read a network-order (big-endian) unsigned 16-bit field. */
static unsigned get16(const unsigned char *bytes) { return (unsigned)bytes[0]*256+bytes[1]; }
/* Write the high byte first, regardless of the CPU's native byte order. */
static void put16(unsigned char *bytes, unsigned value) { bytes[0]=(unsigned char)(value>>8); bytes[1]=(unsigned char)value; }
/* Internet checksum accumulation: add 16-bit words. A final odd byte is
 * the high half of a word whose low byte is zero. Leave carry folding to finish.
 */
static unsigned sum_bytes(const unsigned char *bytes, size_t length, unsigned sum) {
    while (length>1) { sum+=get16(bytes); bytes+=2; length-=2; }
    if (length) sum+=(unsigned)bytes[0]<<8;
    return sum;
}
/* Fold end-around carries, then complement to form the stored checksum. */
static unsigned finish(unsigned sum) {
    while (sum>>16) sum=(sum&65535)+(sum>>16);
    return (~sum)&65535;
}
/* Steps 3/9: validate enough structure to locate the TCP payload safely.
 * Offsets: EtherType 12, IPv4 start 14, IPv4 protocol 23, total length 16.
 * This is structural validation, not validation of incoming IP/TCP checksums.
 */
int parse_packet(const unsigned char *frame, size_t length, struct packet *packet) {
    /* Minimum sizes: Ethernet 14 + IPv4 20 + TCP 20. Protocol 6 is TCP. */
    if (length<54 || get16(frame+12)!=0x0800 || frame[14]>>4!=4 || frame[23]!=6) return 0;
    /* IPv4 IHL and TCP data offset measure 32-bit words, not bytes.
     * IPv4 total length excludes Ethernet headers and Ethernet padding.
     */
    size_t ip_length=(frame[14]&15)*4u;
    size_t total=get16(frame+16);
    /* 0xbfff rejects the reserved flag, MF, and any fragment offset; DF is
     * allowed. A complete TCP segment is required: no IP reassembly here.
     */
    if (ip_length<20 || total<ip_length+20 || total+14>length || (get16(frame+20)&0xbfff)) return 0;
    size_t tcp=14+ip_length;
    size_t tcp_length=(frame[tcp+12]>>4)*4u;
    if (tcp_length<20 || ip_length+tcp_length>total) return 0;
    /* end is exclusive: frame[payload..end) contains the TCP payload.
     * On the protected side that range includes ciphertext AND the tag.
     */
    packet->ip=14; packet->tcp=tcp; packet->payload=tcp+tcp_length; packet->end=14+total;
    return 1;
}
/* Steps 7/10: recompute both checksums after changing the payload/length.
 * The IPv4 checksum covers only its header. The TCP checksum also covers a
 * pseudo-header containing source/destination IPs, protocol and TCP length.
 */
void checksums(unsigned char *frame, const struct packet *packet) {
    /* An existing checksum must be zero while calculating its replacement. */
    frame[24]=frame[25]=0;
    put16(frame+24,finish(sum_bytes(frame+14,packet->tcp-14,0)));
    frame[packet->tcp+16]=frame[packet->tcp+17]=0;
    unsigned tcp_length=(unsigned)(packet->end-packet->tcp);
    /* IPv4 addresses occupy eight bytes at Ethernet-frame offset 26.
     * Protocol 6 and TCP segment length complete the pseudo-header sum.
     */
    unsigned sum=sum_bytes(frame+26,8,6+tcp_length);
    put16(frame+packet->tcp+16,finish(sum_bytes(frame+packet->tcp,tcp_length,sum)));
}
/* Additional authenticated data remains visible but is bound to the GCM tag.
 * Copy both headers, including options, then normalize TTL and both checksums.
 * Ethernet is excluded because its addresses change on every local link.
 * Both encryption/decryption use the PROTECTED IPv4 length in this AAD.
 */
static size_t aad(const unsigned char *frame, const struct packet *packet, unsigned char out[120]) {
    size_t length=packet->payload-14;
    memcpy(out,frame+14,length);
    /* These offsets are relative to the copied IPv4 header, not the frame. */
    out[8]=out[10]=out[11]=0;
    out[packet->tcp-14+16]=out[packet->tcp-14+17]=0;
    return length;
}
/* Control lookup key = SHA-256(canonical IP/TCP headers || ciphertext || tag).
 * It identifies the pending nonce record but is not itself authentication.
 * GCM verification must succeed before any recovered payload is forwarded.
 */
int fingerprint(const unsigned char *frame, size_t length, unsigned char hash[32]) {
    struct packet packet;
    unsigned char header[120]; unsigned result_length=0;
    if (!parse_packet(frame,length,&packet)) return 0;
    /* Use OpenSSL's digest API rather than implementing SHA-256 locally.
     * Short-circuit checks stop on failure and free the allocated context.
     */
    EVP_MD_CTX *context=EVP_MD_CTX_new();
    int ok=context && EVP_DigestInit_ex(context,EVP_sha256(),NULL)==1 &&
        EVP_DigestUpdate(context,header,aad(frame,&packet,header))==1 &&
        EVP_DigestUpdate(context,frame+packet.payload,packet.end-packet.payload)==1 &&
        EVP_DigestFinal_ex(context,hash,&result_length)==1 && result_length==32;
    EVP_MD_CTX_free(context); return ok;
}
/* Steps 6/10: encrypt=1 protects; encrypt=0 verifies and restores.
 * key is 32 bytes (AES-256); nonce is 12 bytes (96 bits); tag is 16 bytes.
 * Decrypted bytes stay in work until CipherFinal confirms authenticity.
 * On failure callers must discard the frame: encryption may already have
 * adjusted its IPv4 length, even though no complete result was produced.
 */
int transform(unsigned char *frame, size_t *length, const unsigned char key[32], const unsigned char nonce[12], int encrypt) {
    struct packet packet;
    unsigned char work[FRAME_MAX], header[120]; int count=0, tail=0;
    if (!parse_packet(frame,*length,&packet)) return 0;
    size_t payload_length=packet.end-packet.payload;
    /* Reject buffer overflow and protected packets too short to hold a tag.
     * A zero-byte original payload is valid and produces a tag-only payload.
     */
    if ((encrypt && packet.end+TAG_SIZE>FRAME_MAX) || (!encrypt && payload_length<TAG_SIZE)) return 0;
    /* Set protected length before building AAD. On decryption the received
     * header already has that length; restore original length only on success.
     */
    if (encrypt) { packet.end+=TAG_SIZE; put16(frame+16,(unsigned)(packet.end-14)); }
    else payload_length-=TAG_SIZE;
    size_t header_length=aad(frame,&packet,header);
    /* Initialize GCM, set nonce size, then provide key and nonce. Feed AAD
     * separately with a NULL output pointer: it is authenticated, not encrypted.
     * Only bytes at the parsed payload offset enter the cipher as plaintext.
     */
    EVP_CIPHER_CTX *context=EVP_CIPHER_CTX_new();
    int ok=context && EVP_CipherInit_ex(context,EVP_aes_256_gcm(),NULL,NULL,NULL,encrypt)==1 &&
        EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_GCM_SET_IVLEN,12,NULL)==1 &&
        EVP_CipherInit_ex(context,NULL,NULL,key,nonce,encrypt)==1 &&
        EVP_CipherUpdate(context,NULL,&count,header,(int)header_length)==1 &&
        EVP_CipherUpdate(context,work,&count,frame+packet.payload,(int)payload_length)==1;
    /* Decrypt: install the received trailing tag before final verification. */
    if (ok && !encrypt) ok=EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_GCM_SET_TAG,TAG_SIZE,frame+packet.payload+payload_length)==1;
    /* GCM finalization is the authentication decision on the receive side.
     * A wrong key, nonce, header, ciphertext, or tag causes failure here.
     */
    if (ok) ok=EVP_CipherFinal_ex(context,work+count,&tail)==1;
    /* Encrypt: fetch the full tag and append it after equal-length ciphertext. */
    if (ok && encrypt) ok=EVP_CIPHER_CTX_ctrl(context,EVP_CTRL_GCM_GET_TAG,TAG_SIZE,work+payload_length)==1;
    EVP_CIPHER_CTX_free(context);
    if (!ok) return 0;
    /* Commit only a complete result. No tentative decrypted bytes escape. */
    memcpy(frame+packet.payload,work,payload_length+(encrypt?TAG_SIZE:0));
    if (!encrypt) { packet.end-=TAG_SIZE; put16(frame+16,(unsigned)(packet.end-14)); }
    /* Rebuild checksums for the protected/restored form and return its exact
     * frame length, dropping any original Ethernet padding from this length.
     */
    checksums(frame,&packet); *length=packet.end; return 1;
}
