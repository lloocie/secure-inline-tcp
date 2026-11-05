/* Exercise the real policy and receive-association code without root/Linux. */
#include "policy.h"
#include "pending.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct pending receiver;
static const unsigned char key[32]={1};

static size_t sample(unsigned char frame[FRAME_MAX], uint16_t port) {
    memset(frame,0,FRAME_MAX);
    frame[12]=8; frame[14]=0x45; frame[17]=45; frame[22]=64; frame[23]=6;
    frame[26]=10; frame[28]=1; frame[29]=1;
    frame[30]=10; frame[32]=3; frame[33]=2;
    frame[34]=0xc3; frame[35]=0x50;
    frame[36]=(unsigned char)(port>>8); frame[37]=(unsigned char)port;
    frame[46]=0x50; frame[47]=0x18; memcpy(frame+54,"Hello",5);
    struct packet packet; assert(parse_packet(frame,59,&packet)); checksums(frame,&packet);
    return 59;
}

static size_t protect(unsigned char frame[FRAME_MAX], unsigned char record[44], unsigned counter) {
    size_t length=sample(frame,8080);
    memset(record,0,44); record[11]=(unsigned char)counter;
    assert(transform(frame,&length,key,record,1));
    assert(fingerprint(frame,length,record+12)); return length;
}

static void filter_tests(void) {
    struct policy policy={{10,0,1,1},{10,0,3,2},8080};
    unsigned char frame[FRAME_MAX]; size_t length=sample(frame,8080);
    assert(policy_match(&policy,frame,length,1));
    assert(!policy_match(&policy,frame,length,0));
    frame[29]=9; assert(!policy_match(&policy,frame,length,1)); frame[29]=1;
    frame[33]=9; assert(!policy_match(&policy,frame,length,1)); frame[33]=2;
    length=sample(frame,8081); assert(!policy_match(&policy,frame,length,1));
    /* Reply: swap both addresses and ports; only peer ingress may accept it. */
    length=sample(frame,8080);
    unsigned char temporary[4]; memcpy(temporary,frame+26,4);
    memcpy(frame+26,frame+30,4); memcpy(frame+30,temporary,4);
    memcpy(temporary,frame+34,2); memcpy(frame+34,frame+36,2); memcpy(frame+36,temporary,2);
    assert(policy_match(&policy,frame,length,0)); assert(!policy_match(&policy,frame,length,1));
    /* Pure ACK: selection must not depend on nonempty application data. */
    frame[17]=40; assert(policy_match(&policy,frame,54,0));
    frame[20]=0x20; assert(!policy_match(&policy,frame,54,0));
    uint16_t port=0;
    assert(policy_port("8080",&port) && port==8080);
    assert(policy_port("65535",&port) && port==65535);
    const char *invalid[]={"","0","65536","-1","+80","80x"," 80","99999999999999999999"};
    for (size_t index=0;index<sizeof(invalid)/sizeof(invalid[0]);index++)
        assert(!policy_port(invalid[index],&port));
}

static void receive_tests(void) {
    unsigned char frame[FRAME_MAX], second[FRAME_MAX], out[FRAME_MAX], record[44], next[44]; size_t output=0;
    size_t length=protect(frame,record,1);
    /* Duplicate already queued before the nonce record arrives. */
    memset(&receiver,0,sizeof(receiver));
    assert(pending_frame(&receiver,frame,length,100));
    assert(pending_frame(&receiver,frame,length,100));
    assert(!pending_take(&receiver,key,out,&output));
    assert(pending_record(&receiver,record,100));
    assert(pending_take(&receiver,key,out,&output)); assert(output==59 && !memcmp(out+54,"Hello",5));
    assert(!pending_take(&receiver,key,out,&output)); assert(receiver.stats.replay==1);
    /* Replay after acceptance is rejected immediately, with no second output. */
    assert(!pending_frame(&receiver,frame,length,101)); assert(receiver.stats.replay==2);
    assert(!pending_take(&receiver,key,out,&output));

    /* Corrupt ciphertext, tag and authenticated header separately. A changed
     * fingerprint cannot use the authentic record and must expire unmatched.
     */
    const size_t offsets[]={54,74,38};
    for (size_t index=0;index<3;index++) {
        memset(&receiver,0,sizeof(receiver)); length=protect(frame,record,2);
        frame[offsets[index]]^=1;
        assert(pending_record(&receiver,record,100)); assert(pending_frame(&receiver,frame,length,100));
        assert(!pending_take(&receiver,key,out,&output)); pending_expire(&receiver,110);
        assert(receiver.stats.unmatched==1 && receiver.stats.expired_records==1);
    }
    /* Even a matching index does not bypass GCM: wrong nonce must fail. */
    memset(&receiver,0,sizeof(receiver)); length=protect(frame,record,3); record[11]^=1;
    assert(pending_record(&receiver,record,100)); assert(pending_frame(&receiver,frame,length,100));
    assert(!pending_take(&receiver,key,out,&output)); assert(receiver.stats.bad_tag==1);

    /* Lose packet 4, deliver 6 before 5, then expire the missing association.
     * Counters come from individual records, not a guessed receive sequence.
     */
    memset(&receiver,0,sizeof(receiver)); protect(frame,record,4); assert(pending_record(&receiver,record,100));
    length=protect(frame,record,5); assert(pending_record(&receiver,record,100));
    size_t second_length=protect(second,next,6); assert(pending_record(&receiver,next,100));
    assert(pending_frame(&receiver,second,second_length,101)); assert(pending_take(&receiver,key,out,&output));
    assert(pending_frame(&receiver,frame,length,102)); assert(pending_take(&receiver,key,out,&output));
    pending_expire(&receiver,110); assert(receiver.stats.expired_records==1);
    assert(!pending_take(&receiver,key,out,&output));

    /* Missing control records, saturation and late frames must fail closed. */
    memset(&receiver,0,sizeof(receiver)); length=protect(frame,record,7);
    for (size_t index=0;index<PENDING_SLOTS;index++) assert(pending_frame(&receiver,frame,length,100));
    assert(!pending_frame(&receiver,frame,length,100)); assert(receiver.stats.full==1);
    pending_expire(&receiver,110); assert(receiver.stats.unmatched==PENDING_SLOTS);
    assert(pending_record(&receiver,record,111)); assert(!pending_take(&receiver,key,out,&output));

    /* Evict an old fingerprint from the bounded fast-replay cache. It must
     * still never be delivered again: its one-use record is already gone.
     */
    memset(&receiver,0,sizeof(receiver));
    length=protect(frame,record,8);
    assert(pending_record(&receiver,record,100)); assert(pending_frame(&receiver,frame,length,100));
    assert(pending_take(&receiver,key,out,&output));
    for (unsigned index=0;index<PENDING_SLOTS;index++) {
        /* Prefix bytes vary too, keeping every test nonce distinct. */
        memset(next,0,44); next[0]=1; next[10]=(unsigned char)(index>>8); next[11]=(unsigned char)index;
        second_length=sample(second,8080);
        assert(transform(second,&second_length,key,next,1)); assert(fingerprint(second,second_length,next+12));
        assert(pending_record(&receiver,next,101)); assert(pending_frame(&receiver,second,second_length,101));
        assert(pending_take(&receiver,key,out,&output));
    }
    assert(pending_frame(&receiver,frame,length,102));
    assert(!pending_take(&receiver,key,out,&output)); pending_expire(&receiver,112);
    assert(receiver.stats.unmatched==1);
}

int main(void) {
    filter_tests(); receive_tests();
    puts("PASS: host-pair/port policy, replay, tampering, GCM rejection, loss/reordering, expiration and capacity");
    return 0;
}
