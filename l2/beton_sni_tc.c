/* beton_sni_tc — PROTOTYPE L2 для VM. На хосте не собирать и не цеплять.
 *
 * TC egress: смотрит TCP->BETON_PORT, извлекает SNI из ClientHello и сравнивает
 * по границам домена (точное имя или поддомен; notfoo.com не матчится).
 * Совпало -> SHOT, иначе OK.
 * Переименование бинаря не помогает: давится соединение, а не процесс.
 *
 * Ограничения (честно):
 * - ECH шифрует настоящее SNI: видим только outer-имя. ECH-цель ловится
 *   DNS/IP-слоями, а не этим фильтром.
 * - Фрагментация/сегментация: ClientHello обычно в первом сегменте; разрезанный
 *   hello может проскочить — принят как известный зазор, чинится NFQUEUE-фолбэком.
 * - Верифаер: все циклы ограничены константами (BETON_NPATS/MAX_PAT_LEN/SCAN).
 *
 * Сборка и цепление — только в VM (см. build.sh, README.md).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>

#include "patterns.h"

#ifndef BETON_PORT
#define BETON_PORT 443
#endif

#define SCAN_BYTES 1024

/* Безопасное чтение байта/u16 с проверкой границ. */
static __always_inline int pkt_u8(struct __sk_buff *skb, __u32 off, __u8 *out)
{
	__u8 v = 0;
	if (bpf_skb_load_bytes(skb, off, &v, 1) < 0)
		return -1;
	*out = v;
	return 0;
}

static __always_inline int pkt_u16(struct __sk_buff *skb, __u32 off, __u16 *out)
{
	__u8 hi = 0, lo = 0;
	if (pkt_u8(skb, off, &hi) < 0 || pkt_u8(skb, off + 1, &lo) < 0)
		return -1;
	*out = ((__u16)hi << 8) | lo;
	return 0;
}

#define BETON_MAX_HOST 64
#define BETON_MAX_EXTS 32

/* Извлечь первое host_name из SNI в out (lowercase). Вернуть длину или -1.
 * Границы: только [base, end). ECH: вернёт outer-имя (честный зазор).
 */
static __always_inline int parse_sni(struct __sk_buff *skb, __u32 base,
				     __u32 end, __u8 *out)
{
	__u32 o, ext_end, i;
	__u16 v16;
	__u8 b;

	/* record header: 0x16 + len; handshake header: 0x01 */
	if (pkt_u8(skb, base, &b) < 0 || b != 0x16)
		return -1;
	if (pkt_u8(skb, base + 5, &b) < 0 || b != 0x01)
		return -1;
	o = base + 5 + 4;
	o += 2 + 32; /* version + random */
	if (o + 1 > end)
		return -1;
	if (pkt_u8(skb, o, &b) < 0)
		return -1;
	o += 1 + b; /* session id */
	if (o + 2 > end || pkt_u16(skb, o, &v16) < 0)
		return -1;
	o += 2 + v16; /* cipher suites */
	if (o + 1 > end || pkt_u8(skb, o, &b) < 0)
		return -1;
	o += 1 + b; /* compression */
	if (o + 2 > end || pkt_u16(skb, o, &v16) < 0)
		return -1;
	o += 2;
	ext_end = o + v16;
	if (ext_end < o)
		return -1;
	/* ext_end может уходить за окно: итерируем до min(ext_end, end) */
	for (i = 0; i < BETON_MAX_EXTS; i++) {
		__u16 etype, elen;
		__u32 eo, win_end;
		win_end = ext_end < end ? ext_end : end;
		if (o + 4 > win_end)
			break;
		if (pkt_u16(skb, o, &etype) < 0 || pkt_u16(skb, o + 2, &elen) < 0)
			return -1;
		o += 4;
		eo = o + elen;
		if (eo < o || eo > ext_end)
			return -1;
		if (eo > end) {
			/* Расширение разрезано окном: SNI в нём — честный проскок,
			 * чужое — просто выходим. */
			if (etype == 0x0000)
				return -1;
			break;
		}
		if (etype != 0x0000) {
			o = eo;
			continue;
		}
		/* server_name: list_len + entries(type,len,name) */
		{
			__u16 llen, nlen;
			__u32 p, list_end, j;
			__u8 ntype;
			if (pkt_u16(skb, o, &llen) < 0)
				return -1;
			p = o + 2;
			list_end = p + llen;
			if (list_end > o + elen)
				return -1;
			eo = o + elen;
			while (p + 3 <= list_end) {
				if (pkt_u8(skb, p, &ntype) < 0 || pkt_u16(skb, p + 1, &nlen) < 0)
					return -1;
				p += 3;
				if (p + nlen > list_end)
					return -1;
				if (ntype == 0) {
					__u32 cp = nlen > BETON_MAX_HOST ? BETON_MAX_HOST : nlen;
					for (j = 0; j < BETON_MAX_HOST; j++) {
						__u8 c = 0;
						if (j >= cp)
							break;
						if (pkt_u8(skb, p + j, &c) < 0)
							return -1;
						if (c >= 'A' && c <= 'Z')
							c += 32;
						out[j] = c;
					}
					(void)eo;
					return (int)cp;
				}
				p += nlen;
			}
			return -1;
		}
	}
	return -1;
}

/* Точное совпадение или поддомен (.base). notfoo.com НЕ матчится. */
static __always_inline int host_matches(const __u8 *host, int hlen,
					const struct beton_pat *pat)
{
	int i;
	__u32 start;

	if (hlen <= 0 || hlen > BETON_MAX_HOST)
		return 0;
	if (hlen == pat->len) {
		for (i = 0; i < BETON_MAX_PAT_LEN; i++) {
			if (i >= hlen)
				break;
			if (host[i] != pat->data[i])
				return 0;
		}
		return 1;
	}
	if (hlen < pat->len + 2)
		return 0;
	start = (__u32)hlen - pat->len;
	if (host[start - 1] != '.')
		return 0;
	for (i = 0; i < BETON_MAX_PAT_LEN; i++) {
		if (i >= pat->len)
			break;
		if (host[start + i] != pat->data[i])
			return 0;
	}
	return 1;
}

SEC("tc/egress")
int beton_sni(struct __sk_buff *skb)
{
	__u8 proto = 0, ip_proto = 0;
	__u32 ip_off, tcp_off, pay_off, tail;
	__u16 dport = 0;
	__u8 ihl, doff;

	if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), (void *)&dport, 2) < 0)
		return TC_ACT_OK;
	if (dport != __constant_htons(ETH_P_IP))
		return TC_ACT_OK;

	ip_off = sizeof(struct ethhdr);
	if (pkt_u8(skb, ip_off + 9, &ip_proto) < 0)
		return TC_ACT_OK;
	if (ip_proto != IPPROTO_TCP)
		return TC_ACT_OK;
	if (pkt_u8(skb, ip_off, &ihl) < 0)
		return TC_ACT_OK;
	ihl &= 0x0F;
	tcp_off = ip_off + (__u32)ihl * 4;
	if (tcp_off > ip_off + 60)
		return TC_ACT_OK;

	/* dport: байты tcp_off+2..3 */
	{
		__u8 hi = 0, lo = 0;
		if (pkt_u8(skb, tcp_off + 2, &hi) < 0 || pkt_u8(skb, tcp_off + 3, &lo) < 0)
			return TC_ACT_OK;
		dport = ((__u16)hi << 8) | lo;
	}
	if (dport != BETON_PORT)
		return TC_ACT_OK;

	if (pkt_u8(skb, tcp_off + 12, &doff) < 0)
		return TC_ACT_OK;
	doff = (doff >> 4) & 0x0F;
	pay_off = tcp_off + (__u32)doff * 4;
	tail = pay_off + SCAN_BYTES;
	if (tail > (sizeof(struct ethhdr) + 1500))
		tail = sizeof(struct ethhdr) + 1500;

	/* Извлекаем SNI и сравниваем по границам домена. */
	{
		__u8 host[BETON_MAX_HOST] = {0};
		int hlen = parse_sni(skb, pay_off, tail, host);
		int k2;
		if (hlen < 0)
			return TC_ACT_OK;
#pragma unroll
		for (k2 = 0; k2 < BETON_NPATS; k2++) {
			if (host_matches(host, hlen, &beton_pats[k2]))
				return TC_ACT_SHOT;
		}
	}
	(void)proto;
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
