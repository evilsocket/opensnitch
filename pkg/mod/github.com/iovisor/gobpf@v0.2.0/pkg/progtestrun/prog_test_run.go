package progtestrun

import (
	"fmt"
	"unsafe"
)

/*
#include <linux/version.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static __u64 ptr_to_u64(void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

int bpf_prog_test_run(int fd, int repeat, char *data, int data_size,
		      char *data_out, int *data_out_size, int *retval,
		      int *duration)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	union bpf_attr attr;
	int ret;

	memset(&attr, 0, sizeof(attr));

	attr.test.prog_fd = fd;
	attr.test.data_in = ptr_to_u64((void *) data);
	attr.test.data_out = ptr_to_u64((void *) data_out);
	attr.test.data_size_in = data_size;
	attr.test.repeat = repeat;

	ret = syscall(__NR_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
	if (data_out_size)
		*data_out_size = attr.test.data_size_out;
	if (retval)
		*retval = attr.test.retval;
	if (duration)
		*duration = attr.test.duration;
	return ret;
#else
	errno = ENOSYS;
	return -1;
#endif
}
*/
import "C"

// Run exposes BPF_PROG_TEST_RUN to test xdp and skp programs.
// `data` will be passed to your program as `__sk_buff *ptr`.
// `dataOut` (optional) will hold `skb->data` after run, if large enough.
func Run(progFd, repeat int, data []byte, dataOut []byte) (int, int, int, error) {
	if data == nil {
		// http://elixir.free-electrons.com/linux/v4.12/source/net/bpf/test_run.c#L78
		// http://elixir.free-electrons.com/linux/v4.12/source/include/uapi/linux/if_ether.h#L32
		return -1, 0, 0, fmt.Errorf("data must be at least 14 bytes (corresponding to ETH_HLEN)")
	}
	var (
		dataOutPtr  *C.char
		dataOutLen  C.int
		returnValue C.int
		duration    C.int

		dataPtr = (*C.char)(unsafe.Pointer(&data[0]))
		dataLen = C.int(len(data))
	)
	if dataOut != nil {
		dataOutPtr = (*C.char)(unsafe.Pointer(&dataOut[0]))
	}
	ret, err := C.bpf_prog_test_run(C.int(progFd), C.int(repeat), dataPtr, dataLen, dataOutPtr, &dataOutLen, &returnValue, &duration)
	if ret != 0 {
		return -1, 0, 0, fmt.Errorf("bpf_prog_test_run failed: %v (%d)", err, ret)
	}
	return int(returnValue), int(duration), int(dataOutLen), nil
}
