//#include <net/inet_sock.h>
//#include <net/sock.h>
#include <linux/ptrace.h>
#include <linux/version.h>
//#include <linux/bpf.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/perf_event.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include "include/bpf_helpers.h"
#include "include/bpf_endian.h"

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

#define IP_TCP 6
#define ETH_HLEN 14

#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#define BPF_PACKET_HEADER __attribute__((packed)) __attribute__((deprecated("packet")))

struct ethernet_t {
  unsigned long long  dst:48;
  unsigned long long  src:48;
  unsigned int        type:16;
} BPF_PACKET_HEADER;

struct ip_t {
  unsigned char   ver:4;           // byte 0
  unsigned char   hlen:4;
  unsigned char   tos;
  unsigned short  tlen;
  unsigned short  identification; // byte 4
  unsigned short  ffo_unused:1;
  unsigned short  df:1;
  unsigned short  mf:1;
  unsigned short  foffset:13;
  unsigned char   ttl;             // byte 8
  unsigned char   nextp;
  unsigned short  hchecksum;
  unsigned int    src;            // byte 12
  unsigned int    dst;            // byte 16
} BPF_PACKET_HEADER;

struct tcp_t {
  unsigned short  src_port;   // byte 0
  unsigned short  dst_port;
  unsigned int    seq_num;    // byte 4
  unsigned int    ack_num;    // byte 8
  unsigned char   offset:4;    // byte 12
  unsigned char   reserved:4;
  unsigned char   flag_cwr:1;
  unsigned char   flag_ece:1;
  unsigned char   flag_urg:1;
  unsigned char   flag_ack:1;
  unsigned char   flag_psh:1;
  unsigned char   flag_rst:1;
  unsigned char   flag_syn:1;
  unsigned char   flag_fin:1;
  unsigned short  rcv_wnd;
  unsigned short  cksum;      // byte 16
  unsigned short  urg_ptr;
} BPF_PACKET_HEADER;

struct Key {
	u32 src_ip;               //source ip
	u32 dst_ip;               //destination ip
	unsigned short src_port;  //source port
	unsigned short dst_port;  //destination port
};

struct Key_Actual {
  u64 init_ts;              //init package receive time
	u32 src_ip;               //source ip
	u32 dst_ip;               //destination ip
	unsigned short src_port;  //source port
	unsigned short dst_port;  //destination port
};

struct Leaf {
  u64 init_ts;
  u64 timestamp;            //timestamp in ns
	u32 payload_length;
  u32 ifindex;
  u32 ingress_ifindex;
  u32 is_http;
  u64 is_request;
  char buf[3];
};

struct bpf_map_def SEC("maps") sessions = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct Key),
    .value_size = sizeof(struct Leaf),
    .max_entries = 5000000,
};

struct bpf_map_def SEC("maps") state = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct Key_Actual),
    .value_size = sizeof(struct Leaf),
    .max_entries = 20000000,
};

unsigned long long load_byte(void *skb,
  unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
  unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
  unsigned long long off) asm("llvm.bpf.load.word");
u64 load_dword(void *skb, u64 off) {
  return ((u64)load_word(skb, off) << 32) | load_word(skb, off + 4);
}

#define MASK(_n) ((_n) < 64 ? (1ull << (_n)) - 1 : ((u64)-1LL))
#define MASK128(_n) ((_n) < 128 ? ((unsigned __int128)1 << (_n)) - 1 : ((unsigned __int128)-1))

u64 bpf_dext_pkt(void *pkt, u64 off, u64 bofs, u64 bsz) {
  if (bofs == 0 && bsz == 8) {
    return load_byte(pkt, off);
  } else if (bofs + bsz <= 8) {
    return load_byte(pkt, off) >> (8 - (bofs + bsz)) & MASK(bsz);
  } else if (bofs == 0 && bsz == 16) {
    return load_half(pkt, off);
  } else if (bofs + bsz <= 16) {
    return load_half(pkt, off) >> (16 - (bofs + bsz)) & MASK(bsz);
  } else if (bofs == 0 && bsz == 32) {
    return load_word(pkt, off);
  } else if (bofs + bsz <= 32) {
    return load_word(pkt, off) >> (32 - (bofs + bsz)) & MASK(bsz);
  } else if (bofs == 0 && bsz == 64) {
    return load_dword(pkt, off);
  } else if (bofs + bsz <= 64) {
    return load_dword(pkt, off) >> (64 - (bofs + bsz)) & MASK(bsz);
  }
  return 0;
}

void * bpf_map_lookup_elem_(uintptr_t map, void *key) {
  return bpf_map_lookup_elem((void *)map, key);
}

u64 bpf_pseudo_fd(u64, u64) asm("llvm.bpf.pseudo");

// packet parsing state machine helpers
#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

//注意该宏不能超过三个参数（含fmt）
#define bpf_printk_debugf(fmt, ...)                        \
    do {                                               \
        char s[] = fmt;                                \
        bpf_trace_printk(s, sizeof(s), ##__VA_ARGS__); \
    } while (0)

SEC("socket/sock_filter")
int sock_filter(struct __sk_buff *skb)
{
  // u32 pid = bpf_get_current_pid_tgid();
  // struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  // filter IP packets (ethernet type = 0x0800)
  // bpf_printk_debugf("new packet received:%d\n", ethernet->type);
  //    if (!(ethernet->type == 0x0800)) {
  //	goto DROP;
  //    }
  if (!(bpf_dext_pkt(skb, (u64)ethernet + 12, 0, 16) == 0x0800)) {
    goto DROP_WITHOUT_INSERT;
  }

  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  // filter TCP packets (ip next protocol = 0x06)
  //    if (ip->nextp != IP_TCP) {
  //	goto DROP;
  //    }
  if (bpf_dext_pkt(skb, (u64)ip + 9, 0, 8) != IP_TCP)
  {
    goto DROP_WITHOUT_INSERT;
  }

  u32 tcp_header_length = 0;
  u32 ip_header_length = 0;
  u32 payload_offset = 0;
  u32 payload_length = 0;
  u64 ts = bpf_ktime_get_ns();
  u64 current_ts = 0;
  struct Leaf *lookup_leaf;
  struct Key key;
  struct Key_Actual keySub = {};
  struct Leaf zero = {0, 0, 0, 0, 0, 0, 0};
  zero.ifindex = skb->ifindex;
  zero.ingress_ifindex = skb->ingress_ifindex;
  zero.init_ts = ts;
  zero.timestamp = ts;
  zero.buf[0] = '0';
  keySub.init_ts = ts;

  // calculate ip header length
  // value to multiply * 4
  // e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
  //  ip_header_length = ip->hlen << 2;
  ip_header_length = bpf_dext_pkt(skb, (u64)ip + 0, 4, 4) << 2; // SHL 2 -> *4 multiply

  // check ip header length against minimum
  if (ip_header_length < sizeof(*ip))
  {
    goto DROP_WITHOUT_INSERT;
  }

  // shift cursor forward for dynamic ip header size
  void *_ = cursor_advance(cursor, (ip_header_length - sizeof(*ip)));

  struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

  // retrieve ip src/dest and port src/dest of current packet
  // and save it into struct Key
  // key.dst_ip = ip->dst;
  // key.src_ip = ip->src;
  // key.dst_port = tcp->dst_port;
  // key.src_port = tcp->src_port;
  key.dst_ip = bpf_dext_pkt(skb, (u64)ip + 16, 0, 32);
  key.src_ip = bpf_dext_pkt(skb, (u64)ip + 12, 0, 32);
  key.dst_port = bpf_dext_pkt(skb, (u64)tcp + 2, 0, 16);
  key.src_port = bpf_dext_pkt(skb, (u64)tcp + 0, 0, 16);
  keySub.src_ip = key.src_ip;
  keySub.dst_ip = key.dst_ip;
  keySub.src_port = key.src_port;
  keySub.dst_port = key.dst_port;
  u64 ack_flag =  bpf_dext_pkt(skb, (u64)tcp+13, 3, 1);
  u64 sync_flag = bpf_dext_pkt(skb, (u64)tcp+13, 6, 1);
  if (ack_flag == 1 && sync_flag == 1) {
    zero.is_request = 2;
  } else if (ack_flag == 0 && sync_flag == 1) {
    zero.is_request = 1;
  }
  //bpf_printk_debugf("sync: %lld, ack:%lld\n",  sync_flag, ack_flag);
  // calculate tcp header length
  // value to multiply *4
  // e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
  // tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply
  tcp_header_length = bpf_dext_pkt(skb, (u64)tcp + 12, 0, 4) << 2;

  // calculate payload offset and length
  payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
  // payload_length = ip->tlen - ip_header_length - tcp_header_length;
  payload_length = bpf_dext_pkt(skb, (u64)ip + 2, 0, 16) - ip_header_length - tcp_header_length;
  zero.payload_length = payload_length;

  // http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
  // minimum length of http request is always geater than 7 bytes
  // avoid invalid access memory
  // include empty payload
  if (payload_length < 7)
  {
    goto DROP;
  }

  // load first 7 byte of payload into p (payload_array)
  // direct access to skb not allowed
  unsigned long p[7];
  int i = 0;
  for (i = 0; i < 7; i++)
  {
    p[i] = load_byte(skb, payload_offset + i);
  }

  // find a match with an HTTP message
  // HTTP
  if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P'))
  {
    bpf_printk_debugf("HTTP Received\n");
    unsigned long q[12];
    if (payload_length >= 12) {
      for (i = 7; i < 12; i++) {
        q[i] = load_byte(skb, payload_offset + i);
      }
      if (p[5] == '1') {
        zero.buf[0] = q[9];
        zero.buf[1] = q[10];
        zero.buf[2] = q[11];
      } else if (p[5] == '2') {
        zero.buf[0] = q[7];
        zero.buf[1] = q[8];
        zero.buf[2] = q[9];
      }
    }
    goto HTTP_MATCH;
  }
  // GET
  if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T'))
  {
    bpf_printk_debugf("GET Received\n");
    goto HTTP_MATCH;
  }
  // POST
  if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T'))
  {
    bpf_printk_debugf("POST Received\n");
    goto HTTP_MATCH;
  }
  // PUT
  if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T'))
  {
    bpf_printk_debugf("PUT Received\n");
    goto HTTP_MATCH;
  }
  // DELETE
  if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E'))
  {
    bpf_printk_debugf("DELETE Received\n");
    goto HTTP_MATCH;
  }
  // HEAD
  if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D'))
  {
    bpf_printk_debugf("HEAD Received\n");
    goto HTTP_MATCH;
  }

  // no HTTP match
  // check if packet belong to an HTTP session
  lookup_leaf = bpf_map_lookup_elem(&sessions, &key);
  // struct Leaf * lookup_leaf = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -1), &key);
  if (lookup_leaf)
  {
    // send packet to userspace
    current_ts = lookup_leaf->init_ts;
    zero.init_ts = current_ts;
    if (zero.is_request == 0) {
      zero.payload_length = payload_length + lookup_leaf->payload_length;
      zero.is_request = lookup_leaf->is_request;
    }
    zero.is_http = lookup_leaf->is_http;
    if (zero.is_http == 1 && zero.is_request == 0) {
      bpf_printk_debugf("current ts is: %lld, is request is: %lld\n", ts, lookup_leaf->is_request);
      bpf_printk_debugf("received updated:%lld\n", zero.payload_length);
    }
    if (lookup_leaf->buf[0] != '0' && zero.buf[0] == '0') {
      zero.buf[0] = lookup_leaf->buf[0];
      zero.buf[1] = lookup_leaf->buf[1];
      zero.buf[2] = lookup_leaf->buf[2];
    }
    zero.ifindex = lookup_leaf->ifindex;
    zero.ingress_ifindex = lookup_leaf->ingress_ifindex;
    keySub.init_ts = current_ts;
    bpf_map_update_elem(&state, &keySub, &zero, BPF_ANY);
    bpf_map_update_elem(&sessions, &key, &zero, BPF_ANY);
    if (zero.is_http == 1) {
      goto KEEP;
    }
    goto DROP_WITHOUT_INSERT;
  }
  goto DROP;

// keep the packet and send it to userspace returning -1
  HTTP_MATCH:
  // if not already present, insert into map <Key, Leaf>
  lookup_leaf = bpf_map_lookup_elem(&sessions, &key);
  if (lookup_leaf)
  {
    current_ts = lookup_leaf->init_ts;
    zero.init_ts = current_ts;
    if (zero.is_request == 0) {
      zero.payload_length = payload_length + lookup_leaf->payload_length;
      zero.is_request = lookup_leaf->is_request;
    }
    if (lookup_leaf->buf[0] != '0' && zero.buf[0] == '0') {
      zero.buf[0] = lookup_leaf->buf[0];
      zero.buf[1] = lookup_leaf->buf[1];
      zero.buf[2] = lookup_leaf->buf[2];
    }
    zero.ifindex = lookup_leaf->ifindex;
    zero.ingress_ifindex = lookup_leaf->ingress_ifindex;
    keySub.init_ts = current_ts;
  }
  zero.is_http = 1;
  bpf_map_update_elem(&state, &keySub, &zero, BPF_ANY);
  bpf_map_update_elem(&sessions, &key, &zero, BPF_ANY);
  bpf_printk_debugf("match http:%d, is_http_request:%lld\n", zero.payload_length, zero.is_request);
//({typeof(Leaf) *leaf = bpf_map_lookup_elem_(bpf_pseudo_fd(1, -1), &key); if (!leaf) { bpf_map_update_elem_(bpf_pseudo_fd(1, -1), &key, &zero, BPF_NOEXIST); leaf = bpf_map_lookup_elem_(bpf_pseudo_fd(1, -1), &key); if (!leaf) return 0;}leaf;});
// bpf_printk_debugf("new packet received\n");
  KEEP:
  return -1;

// drop the packet returning 0
  DROP:
  lookup_leaf = bpf_map_lookup_elem(&sessions, &key);
  if (lookup_leaf)
  {
    if (zero.is_request == 0) {
      zero.payload_length = payload_length + lookup_leaf->payload_length;
      zero.is_request = lookup_leaf->is_request;
    }
    if (lookup_leaf->buf[0] != '0' && zero.buf[0] == '0') {
      zero.buf[0] = lookup_leaf->buf[0];
      zero.buf[1] = lookup_leaf->buf[1];
      zero.buf[2] = lookup_leaf->buf[2];
    }
    current_ts = lookup_leaf->init_ts;
    zero.init_ts = current_ts;
    zero.is_http = lookup_leaf->is_http;
    zero.ifindex = lookup_leaf->ifindex;
    zero.ingress_ifindex = lookup_leaf->ingress_ifindex;
    keySub.init_ts = current_ts;
  }
  bpf_map_update_elem(&state, &keySub, &zero, BPF_ANY);
  bpf_map_update_elem(&sessions, &key, &zero, BPF_ANY);
  return 0;
  DROP_WITHOUT_INSERT:
  return 0;
};
char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
