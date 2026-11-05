/* Linux device process: capture -> encrypt -> send, or receive -> verify -> restore.
 * OpenSSL handles the authenticated DH control session; AF_PACKET handles host
 * packets directly. These are separate paths: TLS never tunnels host packets.
 */
#define _DEFAULT_SOURCE
#include "packet.h"
#include "policy.h"
#include "pending.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

/* Portable association/replay code is also exercised by unprivileged tests. */
static struct pending pending;
static unsigned long encrypted, decrypted, policy_drops;
static volatile sig_atomic_t running=1, report_requested=0;

static void signal_handler(int number) {
    if (number==SIGUSR1) report_requested=1;
    else running=0;
}

/* Monotonic time prevents VM wall-clock corrections changing queue lifetimes. */
static uint64_t seconds_now(void) {
    struct timespec current;
    if (clock_gettime(CLOCK_MONOTONIC,&current)!=0) {
        perror("clock_gettime"); exit(EXIT_FAILURE);
    }
    return (uint64_t)current.tv_sec;
}

/* SIGUSR1 prints machine-readable diagnostics without exposing keys/nonces. */
static void report(void) {
    fprintf(stderr,"stats enc=%lu dec=%lu policy=%lu replay=%lu unmatched=%lu expired_records=%lu bad_tag=%lu full=%lu\n",
        encrypted,decrypted,policy_drops,pending.stats.replay,pending.stats.unmatched,
        pending.stats.expired_records,pending.stats.bad_tag,pending.stats.full);
    fflush(stderr);
}
/* Fatal errors stop forwarding. The lab leaves kernel forwarding disabled,
 * so exiting does not silently switch selected traffic back to plaintext.
 * perror reports OS errors; the OpenSSL error queue adds crypto diagnostics.
 */
static void fail(const char *message) { perror(message); ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }
/* Keep all required setup/I/O checks explicit: false means terminate. */
static void require(int condition, const char *message) { if (!condition) fail(message); }
/* Steps 3 and 9: receive complete Ethernet frames from one named interface.
 * AF_PACKET/SOCK_RAW requires root or CAP_NET_RAW. ETH_P_ALL observes all
 * Ethernet protocols, but the later parser selects only untagged IPv4/TCP.
 * Capturing a frame does not consume the kernel's own copy.
 */
static int raw_socket(const char *name, unsigned char mac[6]) {
    int descriptor=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    require(descriptor>=0,"AF_PACKET (run as root)");
    /* Read the interface's actual MAC for use as the egress source address. */
    struct ifreq request={0};
    require(strlen(name)<IFNAMSIZ,"interface name"); strcpy(request.ifr_name,name);
    require(ioctl(descriptor,SIOCGIFHWADDR,&request)==0,"interface MAC"); memcpy(mac,request.ifr_hwaddr.sa_data,6);
    /* Bind by interface index, restricting this socket to the requested link. */
    struct sockaddr_ll address={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),.sll_ifindex=(int)if_nametoindex(name)};
    require(address.sll_ifindex && bind(descriptor,(struct sockaddr *)&address,sizeof(address))==0,"raw bind");
    return descriptor;
}
/* Convert a configured next-hop MAC from text into six Ethernet bytes.
 * The extra %c detects unwanted trailing characters; each octet must fit.
 */
static void parse_mac(const char *text, unsigned char mac[6]) {
    unsigned values[6]; char extra;
    require(sscanf(text,"%x:%x:%x:%x:%x:%x%c",&values[0],&values[1],&values[2],&values[3],&values[4],&values[5],&extra)==6,"MAC syntax");
    for (int index=0;index<6;index++) { require(values[index]<256,"MAC range"); mac[index]=(unsigned char)values[index]; }
}
/* Step 4: create the independently authenticated device control channel.
 * Device2 listens; Device1 connects. Both present certificates and verify the
 * other device's trusted CA and DNS identity. TLS 1.3 authenticates the complete
 * handshake and confirms possession of keys before this function returns.
 */
static SSL *session(int server, const char *address, const char *certificate, const char *key, const char *ca, const char *peer_name, SSL_CTX **owner) {
    SSL_CTX *context=SSL_CTX_new(TLS_method()); require(context!=NULL,"TLS context"); *owner=context;
    require(SSL_CTX_set_min_proto_version(context,TLS1_3_VERSION)==1 && SSL_CTX_set_max_proto_version(context,TLS1_3_VERSION)==1,"TLS version");
    /* Force finite-field ephemeral Diffie-Hellman, rather than an EC group.
     * OpenSSL supplies standardized p/g parameters and public-value validation.
     */
    require(SSL_CTX_set1_groups_list(context,"ffdhe2048")==1,"finite-field DH group");
    /* This TLS suite uses HKDF-SHA-384. Host payload encryption later uses
     * exported AES-256 keys; it does not reuse TLS record encryption keys.
     */
    require(SSL_CTX_set_ciphersuites(context,"TLS_AES_256_GCM_SHA384")==1,"TLS cipher");
    require(SSL_CTX_use_certificate_chain_file(context,certificate)==1 && SSL_CTX_use_PrivateKey_file(context,key,SSL_FILETYPE_PEM)==1 && SSL_CTX_check_private_key(context)==1,"identity");
    require(SSL_CTX_load_verify_locations(context,ca,NULL)==1,"CA");
    /* Requiring a client certificate makes authentication mutual. Disable
     * session caching/tickets so a new run establishes a fresh DH session.
     */
    SSL_CTX_set_verify(context,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);
    SSL_CTX_set_session_cache_mode(context,SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(context,0);
    int descriptor=socket(AF_INET,SOCK_STREAM,0); require(descriptor>=0,"control socket");
    struct sockaddr_in remote={.sin_family=AF_INET,.sin_port=htons(9443)};
    require(inet_pton(AF_INET,address,&remote.sin_addr)==1,"control IP");
    /* The server's CONTROL_IP is its local bind address; the client's is
     * the remote server address. TCP port 9443 is reserved for control only.
     */
    if (server) {
        int enabled=1; setsockopt(descriptor,SOL_SOCKET,SO_REUSEADDR,&enabled,sizeof(enabled));
        require(bind(descriptor,(struct sockaddr *)&remote,sizeof(remote))==0 && listen(descriptor,1)==0,"control listen");
        int accepted=accept(descriptor,NULL,NULL); require(accepted>=0,"control accept"); close(descriptor); descriptor=accepted;
    } else require(connect(descriptor,(struct sockaddr *)&remote,sizeof(remote))==0,"control connect (start server first)");
    /* Bound blocking handshake/control reads and writes. These are socket
     * I/O timeouts, not a background heartbeat or automatic reconnect policy.
     */
    struct timeval timeout={.tv_sec=10};
    setsockopt(descriptor,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(descriptor,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    SSL *tls=SSL_new(context); require(tls!=NULL,"TLS allocation");
    /* CA trust alone is insufficient: also require the expected peer name
     * (dev1/dev2), which is included in the generated certificate's DNS SAN.
     */
    require(SSL_set1_host(tls,peer_name)==1 && SSL_set_fd(tls,descriptor)==1,"peer identity");
    require((server?SSL_accept(tls):SSL_connect(tls))==1 && SSL_get_verify_result(tls)==X509_V_OK,"authenticated DH handshake");
    fprintf(stderr,"Authenticated DH session ready: %s\n",peer_name); return tls;
}
/* Steps 8 and 11: change only the link-local Ethernet addresses here.
 * IP addresses remain the original hosts' addresses. The socket is already
 * bound to the egress interface; send emits a frame with no extra wrapping.
 */
static void send_frame(int descriptor, unsigned char *frame, size_t length, const unsigned char source[6], const unsigned char destination[6]) {
    memcpy(frame,destination,6); memcpy(frame+6,source,6);
    require(send(descriptor,frame,length,0)==(ssize_t)length,"frame send");
}
/* Release only fully authenticated packets. Keep matching and duplicate
 * handling in pending.c so tests exercise the actual device receive path.
 */
static void deliver(int host, const unsigned char key[32], const unsigned char source[6], const unsigned char destination[6]) {
    unsigned char frame[FRAME_MAX]; size_t length;
    while (pending_take(&pending,key,frame,&length)) {
        send_frame(host,frame,length,source,destination); decrypted++;
    }
}
/* Both device roles use this one executable; arguments select direction,
 * local interfaces, expected peer identity, and destination MAC addresses.
 */
int main(int argc, char **argv) {
    if (argc!=14) {
        fprintf(stderr,"Usage: %s server|client HOST_IF PEER_IF CONTROL_IP CERT KEY CA PEER_NAME HOST_MAC PEER_MAC LOCAL_HOST_IP REMOTE_HOST_IP SERVICE_PORT\n",argv[0]); return 2;
    }
    int server=!strcmp(argv[1],"server"); require(server || !strcmp(argv[1],"client"),"role");
    /* Let a failed TLS socket write return an error instead of terminating
     * asynchronously with SIGPIPE; require() then reports the failure.
     */
    signal(SIGPIPE,SIG_IGN);
    signal(SIGUSR1,signal_handler);
    signal(SIGTERM,signal_handler);
    signal(SIGINT,signal_handler);
    unsigned char host_source[6],peer_source[6],host_destination[6],peer_destination[6];
    parse_mac(argv[9],host_destination); parse_mac(argv[10],peer_destination);
    struct policy policy;
    require(inet_pton(AF_INET,argv[11],policy.local)==1 &&
            inet_pton(AF_INET,argv[12],policy.remote)==1 &&
            memcmp(policy.local,policy.remote,4)!=0,"distinct local/remote host IPs");
    require(policy_port(argv[13],&policy.port),"TCP service port (1..65535)");
    fprintf(stderr,"policy local=%s remote=%s service_port=%u; other transit is dropped\n",
            argv[11],argv[12],(unsigned)policy.port);
    /* Bind capture interfaces first, then block on authenticated session
     * establishment. No selected frame is transmitted before session() returns.
     */
    int host=raw_socket(argv[2],host_source), peer=raw_socket(argv[3],peer_source);
    SSL_CTX *context=NULL; SSL *tls=session(server,argv[4],argv[5],argv[6],argv[7],argv[8],&context);
    /* Exporter layout, identical at both ends:
     * [0..31] client->server key, [32..63] server->client key,
     * [64..67] client nonce prefix, [68..71] server nonce prefix.
     * The protocol label separates this material from other TLS exporter uses.
     */
    unsigned char material[72]; const char *label="EXPORTER-inline-tcp-payload-v1";
    require(SSL_export_keying_material(tls,material,sizeof(material),label,strlen(label),NULL,0,0)==1,"session key derivation");
    /* Swap send/receive views by role so each sender uses its peer's receive
     * key. Independent direction keys prevent cross-direction nonce overlap
     * from reusing the same AES key/nonce pair.
     */
    const unsigned char *send_key=material+(server?32:0), *receive_key=material+(server?0:32);
    const unsigned char *prefix=material+64+(server?4:0), *receive_prefix=material+64+(server?0:4);
    uint64_t counter=0, received_counter=0;
    /* TLS is a byte stream: one read need not contain one complete record.
     * Accumulate exactly 44 bytes before interpreting a nonce announcement.
     */
    unsigned char incoming[44]; size_t received=0;
    /* One event loop owns TLS and both raw sockets, avoiding concurrent use
     * of one SSL object. poll waits up to one second; SSL_pending also checks
     * application bytes already decrypted inside OpenSSL's internal buffers.
     */
    struct pollfd descriptors[3]={{SSL_get_fd(tls),POLLIN,0},{host,POLLIN,0},{peer,POLLIN,0}};
    while (running) {
        if (report_requested) { report(); report_requested=0; }
        int ready=poll(descriptors,3,SSL_pending(tls)?0:1000);
        if (ready<0 && errno==EINTR) continue;
        require(ready>=0,"poll"); pending_expire(&pending,seconds_now());
        for (int index=0;index<3;index++) require(!(descriptors[index].revents&(POLLERR|POLLHUP|POLLNVAL)),"connection closed");
        if ((descriptors[0].revents&POLLIN) || SSL_pending(tls)) {
            int count=SSL_read(tls,incoming+received,(int)(sizeof(incoming)-received)); require(count>0,"control receive"); received+=(size_t)count;
            if (received==sizeof(incoming)) {
                /* TLS preserves control ordering. Demand increasing counters
                 * and the expected session prefix before accepting a record.
                 * Data-frame order is independent of this counter check.
                 */
                uint64_t value=0; for (int index=4;index<12;index++) value=(value<<8)|incoming[index];
                require(!memcmp(incoming,receive_prefix,4) && value>received_counter,"control nonce monotonicity"); received_counter=value;
                pending_record(&pending,incoming,seconds_now());
                received=0;
            }
        }
        for (int index=1;index<3;index++) if (descriptors[index].revents&POLLIN) {
            unsigned char frame[FRAME_MAX]; struct sockaddr_ll origin; socklen_t address_length=sizeof(origin);
            /* MSG_TRUNC reports the actual frame length even if it exceeds
             * our buffer. Drop oversized frames and outgoing capture copies
             * before parsing, preventing truncation reads and forwarding loops.
             */
            ssize_t count=recvfrom(descriptors[index].fd,frame,sizeof(frame),MSG_TRUNC,(struct sockaddr *)&origin,&address_length);
            require(count>=0,"frame receive"); if (count>FRAME_MAX || origin.sll_pkttype==PACKET_OUTGOING) continue;
            size_t length=(size_t)count; struct packet packet;
            if (!parse_packet(frame,length,&packet)) continue;
            /* Require BOTH host addresses in the correct ingress direction,
             * and the configured service port on one end of the TCP flow.
             * Unselected transit is dropped rather than forwarded in clear.
             */
            if (!policy_match(&policy,frame,length,index==1)) { policy_drops++; continue; }
            if (index==1) {
                /* Step 7: reserve tag space inside the 1500-byte middle MTU.
                 * Host MTU 1484 in lab.sh normally enforces this upstream.
                 */
                if (packet.end-14+TAG_SIZE>1500) { fprintf(stderr,"Dropped: middle-link MTU\n"); continue; }
                /* Step 5: consume a fresh counter for EVERY encryption,
                 * including a host retransmission with the same TCP SEQ.
                 * Never wrap the counter under a key; restart both devices.
                 */
                require(counter!=UINT64_MAX,"nonce exhausted: restart both devices"); counter++;
                /* Serialize nonce = four session-prefix bytes + eight
                 * big-endian counter bytes. It is sent only over TLS control.
                 */
                unsigned char record[44]; memcpy(record,prefix,4);
                for (int offset=0;offset<8;offset++) record[11-offset]=(unsigned char)(counter>>(offset*8));
                /* Step 6: encrypt payload and append tag, then identify the
                 * resulting protected representation with a SHA-256 digest.
                 */
                require(transform(frame,&length,send_key,record,1) && fingerprint(frame,length,record+12),"encryption");
                /* Announce before raw transmission. There is no per-record
                 * acknowledgement: receiver buffering handles either arrival
                 * order, and expiration/saturation can still drop the packet.
                 */
                size_t written=0; require(SSL_write_ex(tls,record,sizeof(record),&written)==1 && written==sizeof(record),"control send");
                send_frame(peer,frame,length,peer_source,peer_destination);
                encrypted++;
            } else {
                /* Peer-side raw input is buffered, never sent directly to
                 * the host or interpreted as plaintext on a lookup failure.
                 */
                pending_frame(&pending,frame,length,seconds_now());
            }
        }
        /* Match newly arrived frames/records and release only verified data. */
        deliver(host,receive_key,host_source,host_destination);
    }
    report();
    OPENSSL_cleanse(material,sizeof(material));
    close(SSL_get_fd(tls)); SSL_free(tls); SSL_CTX_free(context);
    close(host); close(peer); return 0;
}
