#include <linux/skbuff.h>
#include <net/sock.h>

/* Request tracking */

/* http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
 * minimum length of http request is always greater than 7 bytes.
 */
#define HTTP_REQUEST_MIN_LEN 7

/* Table from (Task group id|Task id) to (Number of received http requests).
 * We need to gather requests per task and not only per task group (i.e. userspace pid)
 * so that entries can be cleared up independently when a task exits.
 * This implies that userspace needs to do the per-process aggregation.
 */
BPF_HASH(received_http_requests, u64, u64);

/* skb_copy_datagram_iter() (Kernels >= 3.19) is in charge of copying socket
 * buffers from kernel to userspace.
 *
 * skb_copy_datagram_iter() has an associated tracepoint
 * (trace_skb_copy_datagram_iovec), which would be more stable than a kprobe but
 * it lacks the offset argument.
 */
int kprobe__skb_copy_datagram_iter(struct pt_regs *ctx, const struct sk_buff *skb, int offset, void *unused_iovec, int len)
{
	/* Inspect the beginning of socket buffers copied to user-space to determine if they correspond to http requests.
	 *
	 * Caveats:
	 *
	 * Requests may not appear at the beginning of a packet due to:
	 * - Persistent connections.
	 * - Packet fragmentation.
	 *
	 * We could inspect the full packet but:
	 * - It's very inefficient.
	 * - Examining the non-linear (paginated) area of a socket buffer would be
	 *   really tricky from ebpf.
	 */

	/* Verify it's a TCP socket
	 * TODO: is it worth caching it in a socket table?
	 */
	struct sock *sk = skb->sk;
	unsigned short skc_family = sk->__sk_common.skc_family;
	switch (skc_family) {
	case PF_INET:
	case PF_INET6:
	case PF_UNIX:
		break;
	default:
		return 0;
	}
	/* The socket type and protocol are not directly addressable since they are
	 * bitfields. We access them by assuming sk_write_queue is immediately before
	 * them (admittedly pretty hacky).
	 */
	unsigned int flags = 0;
	size_t flags_offset = offsetof(typeof(struct sock), sk_write_queue) + sizeof(sk->sk_write_queue);
	bpf_probe_read(&flags, sizeof(flags), ((u8*)sk) + flags_offset);
	u16 sk_type = flags >> 16;
	if (sk_type != SOCK_STREAM) {
		return 0;
	}
	u8 sk_protocol = flags >> 8 & 0xFF;
	/* The protocol is unset (IPPROTO_IP) in Unix sockets. */
	if ((sk_protocol != IPPROTO_TCP) && ((skc_family == PF_UNIX) && (sk_protocol != IPPROTO_IP))) {
		return 0;
	}

	/* Inline implementation of skb_headlen(). */
	unsigned int head_len = skb->len - skb->data_len;
	unsigned int available_data = head_len - offset;
	if (available_data < HTTP_REQUEST_MIN_LEN) {
		return 0;
	}

	/* Check if buffer begins with a method name followed by a space.
	 *
	 * To avoid false positives it would be good to do a deeper inspection
	 * (i.e. fully ensure a 'Method SP Request-URI SP HTTP-Version CRLF'
	 * structure) but loops are not allowed in ebpf, making variable-size-data
	 * parsers infeasible.
	 */
	u8 data[8] = {};
	void* dst = skb->data + offset;
	if (available_data > HTTP_REQUEST_MIN_LEN) {
		/* We have confirmed having access to 7 bytes, but need 8 bytes to check the
		 * space after OPTIONS. bpf_probe_read() requires its second argument to be
		 * an immediate, so we obtain the data in this unsexy way.
		 */
		bpf_probe_read(&data, 8, dst);
	} else {
		bpf_probe_read(&data, 7, dst);
	}

	switch (data[0]) {
	/* DELETE */
	case 'D':
		if ((data[1] != 'E') || (data[2] != 'L') || (data[3] != 'E') || (data[4] != 'T') || (data[5] != 'E') || (data[6] != ' ')) {
			return 0;
		}
		break;

	/* GET */
	case 'G':
		if ((data[1] != 'E') || (data[2] != 'T') || (data[3] != ' ')) {
			return 0;
		}
		break;

	/* HEAD */
	case 'H':
		if ((data[1] != 'E') || (data[2] != 'A') || (data[3] != 'D') || (data[4] != ' ')) {
			return 0;
		}
		break;

	/* OPTIONS */
	case 'O':
		if (available_data < 8 || (data[1] != 'P') || (data[2] != 'T') || (data[3] != 'I') || (data[4] != 'O') || (data[5] != 'N') || (data[6] != 'S') || (data[7] != ' ')) {
			return 0;
		}
		break;

	/* PATCH/POST/PUT */
	case 'P':
		switch (data[1]) {
		case 'A':
			if ((data[2] != 'T') || (data[3] != 'C') || (data[4] != 'H') || (data[5] != ' ')) {
				return 0;
			}
			break;
		case 'O':
			if ((data[2] != 'S') || (data[3] != 'T') || (data[4] != ' ')) {
				return 0;
			}
			break;
		case 'U':
			if ((data[2] != 'T') || (data[3] != ' ')) {
				return 0;
			}
			break;
		}
		break;

	default:
		return 0;
	}

	/* Finally, bump the request counter for current task. */
	u64 pid_tgid = bpf_get_current_pid_tgid();
	received_http_requests.increment(pid_tgid);

	return 0;
}

/* Responses tracking. */
enum http_codes {
	_100 = 0,		/* Continue */

	_200,			/* OK */
	_201,			/* Created */
	_202,			/* Accepted */
	_204,			/* No Content */

	_308,			/* Permanent Redirect Redirect */

	_400,			/* Bad Request */
	_401,			/* Unauthorized */
	_403,			/* Forbidden */
	_404,			/* Not Found */
	_408,			/* Request Timeout */
	_451,			/* Unavailable For Legal Reasons */

	_500,			/* Internal Server Error */
	_501,			/* Not Implemented */
	_502,			/* Bad Gateway */
	_503,			/* Service Unavailable */

	HTTP_CODE_OTHER,	/* Catch all */
	LAST_HTTP_CODE,
};

struct http_response_codes_t {
	u32 codes[LAST_HTTP_CODE];
};

/* HTTP responses look like "HTTP/1.1 XXX". We only need to read the first 12 characters */
#define HTTP_CODE_MSG_LEN 12

/* Keep copy_from_iter context between kprobe and the kretprobe. */
struct copy_from_iter_args_t {
	void *data;
	size_t bytes;
};

/* Hash map from (Task group id|Task id) to (Number of sent http responses' codes).
 * We need to gather responses per task and not only per task group (i.e. userspace pid)
 * so that entries can be cleared up independently when a task exits.
 * This implies that userspace needs to do the per-process aggregation.
 */
BPF_HASH(sent_http_responses, u64, struct http_response_codes_t);

/* Hash map from (Task group id|Task id) to (Pointer to data to send).
 * We need to save the pointer to where the data are written by copy_from_iter()
 */
BPF_HASH(copy_from_iter_args_table, u64, struct copy_from_iter_args_t);

/* Hash map from (Task group id|Task id) to (Flag if copy is pending).
 * We need to save the data to the copy_from_iter_args_table hash map only when copy_from_iter() is called
 * by tcp_sendmsg() and only the first time is called.
 * We only check if an element is present in the hash map, the value is ignored.
 */
BPF_HASH(tcp_sendmsg_copy_pending, u64, int);

/* Parse HTTP code from string to int */
static int http_code_atoi(char hundreds, char tens, char units)
{
	if (hundreds < '0' || hundreds > '9') {
		return -1;
	} else {
		hundreds -= '0';
	}
	if (tens < '0' || tens > '9') {
		return -1;
	} else {
		tens -= '0';
	}
	 if (units < '0' || units > '9') {
		return -1;
	} else {
		units -= '0';
	}

	return (hundreds * 100 + tens * 10 + units);
}

/* Update HTTP codes in the BPF hash table. */
static int update_sent_http_responses_codes(u64 pid_tgid, int http_code)
{
	struct http_response_codes_t new_codes_counts = {0, };

	struct http_response_codes_t *current_codes_counts = sent_http_responses.lookup_or_init(&pid_tgid, &new_codes_counts);
	new_codes_counts = *current_codes_counts;

	switch (http_code) {
	case 100:
		new_codes_counts.codes[_100]++;
		break;

	case 200:
		new_codes_counts.codes[_200]++;
		break;
	case 201:
		new_codes_counts.codes[_201]++;
		break;
	case 202:
		new_codes_counts.codes[_202]++;
		break;
	case 204:
		new_codes_counts.codes[_204]++;
		break;

	case 308:
		new_codes_counts.codes[_308]++;
		break;

	case 400:
		new_codes_counts.codes[_400]++;
		break;
	case 401:
		new_codes_counts.codes[_401]++;
		break;
	case 403:
		new_codes_counts.codes[_403]++;
		break;
	case 404:
		new_codes_counts.codes[_404]++;
		break;
	case 408:
		new_codes_counts.codes[_408]++;
		break;
	case 451:
		new_codes_counts.codes[_451]++;
		break;

	case 500:
		new_codes_counts.codes[_500]++;
		break;
	case 501:
		new_codes_counts.codes[_501]++;
		break;
	case 502:
	new_codes_counts.codes[_502]++;
		break;
	case 503:
		new_codes_counts.codes[_503]++;
		break;

	default:
		/* HTTP response code not tracked, use the catch all */
		new_codes_counts.codes[HTTP_CODE_OTHER]++;
	}
	sent_http_responses.update(&pid_tgid, &new_codes_counts);
	return 0;
}

/* When tcp_sendmsg is invoked, we use tcp_sendmsg_copy_pending to signal that
 * {kprobe,kretprobe}__copy_from_iter will have to analyze the copied data
 */
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
	struct sock *skp = 0;
	bpf_probe_read(&skp, sizeof(struct sock *), &sk);
	unsigned short skc_family = 0;
	bpf_probe_read(&skc_family, sizeof(unsigned short), &skp->__sk_common.skc_family);

	/* We ensure to track only inet sockets */
	if (skc_family != PF_INET && skc_family != PF_INET6)
		return 0;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	int val = 0;
	tcp_sendmsg_copy_pending.update(&pid_tgid, &val);
	return 0;
}

/* Cleanup when the tcp_sendmsg() returns. */
int kretprobe__tcp_sendmsg(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	/* Extra safety delete in case that copy_from_iter() is not called (e.g. iovec is empty) */
	tcp_sendmsg_copy_pending.delete(&pid_tgid);
	return 0;
}

/* copy_from_iter() is called within tcp_sendmsg() but it could also be called from elsewhere,
 * so we check whether we are from withing tcp_sendmsg.
 *
 * Look to http://lxr.free-electrons.com/source/include/net/sock.h#L1771 for more functions to track.
 * We cannot hook skb_do_copy_data_nocache() because is inline, so we need to hook the functions called by it.
 * We track only copy_from_iter(), this seems sufficient in the container context because network cards are virtual.
 */
int kprobe__copy_from_iter(struct pt_regs *ctx, void *addr, size_t bytes, struct iov_iter *i)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	int *copy_pending = (int *)tcp_sendmsg_copy_pending.lookup(&pid_tgid);

	/* Check if we have some pending copy.
	 * copy_from_iter() may be called by functions other than tcp_sendmsg(), but we care only for data from it.
	 */
	if (copy_pending == NULL) {
		return 0;
	}

	/* We are in the tcp_sendmsg function, save the buffer pointer
	 * No risk of overwriting because of copy_pending != NULL
	 */
	struct copy_from_iter_args_t cfia = {0,};
	bpf_probe_read(&cfia.data, sizeof(void *), &addr);
	bpf_probe_read(&cfia.bytes, sizeof(size_t), &bytes);
	copy_from_iter_args_table.update(&pid_tgid, &cfia);
	return 0;
}

int kretprobe__copy_from_iter(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct copy_from_iter_args_t *cfia_p = (struct copy_from_iter_args_t *)copy_from_iter_args_table.lookup(&pid_tgid);
	if (cfia_p == NULL) {
		return 0;
	}

	/* Remove the hash table entry before processing the pending copy */
	tcp_sendmsg_copy_pending.delete(&pid_tgid);
	/* Remove the hash table entry before reading the buffer */
	copy_from_iter_args_table.delete(&pid_tgid);

	struct copy_from_iter_args_t cfia = {0,};
	bpf_probe_read(&cfia, sizeof(struct copy_from_iter_args_t), cfia_p);


	unsigned char data[HTTP_CODE_MSG_LEN] = {0,};
	bpf_probe_read(&data, HTTP_CODE_MSG_LEN, cfia.data);

	/* eBPF does not have strncmp() yet, see https://github.com/iovisor/bcc/issues/691
	 * Compare the buffer to "HTTP/1.1".
	 */
	if (data[0] != 'H' || data[1] != 'T' || data[2] != 'T' || data[3] != 'P' ||
		data[4] != '/' || data[5] != '1' || data[6] != '.' || data[7] != '1' || data[8] != ' ') {
		return 0;
	}

	int http_code = http_code_atoi(data[9], data[10], data[11]);
	update_sent_http_responses_codes(pid_tgid, http_code);

	return 0;
}

/* Clear out response count entries of tasks on exit */
int kprobe__do_exit(struct pt_regs *ctx) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	received_http_requests.delete(&pid_tgid);
	sent_http_responses.delete(&pid_tgid);
	return 0;
}
