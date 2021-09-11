Since v1.4.0 the default process monitor method is eBPF.


What is eBPF?
---
https://ebpf.io/
> eBPF is a revolutionary technology with origins in the Linux kernel that can run sandboxed programs in an operating system kernel. It is used to safely and efficiently extend the capabilities of the kernel without requiring to change kernel source code or load kernel modules.

How does it work?
---

When this method is used, we load an eBPF module (similar to a kernel module) that hooks some kernel functions in order to read and get the parameters (source IP, destination, IP, etc).

https://github.com/evilsocket/opensnitch/tree/master/ebpf_prog

Why is it better to use this process monitor method?
---
This technology allow us to intercept processes faster and in a more secure way. ProcFS is easier to fool:

https://github.com/gianlucaborello/libprocesshider


We can also intercept connections initiated from kernel space, like those initiated by rootkits or VPNs:

![image](https://user-images.githubusercontent.com/2742953/131679603-44f6c0be-dc21-41a7-8bbb-c0b7ed84ec43.png)

WireGuard connection:

![image](https://user-images.githubusercontent.com/2742953/132577647-d4451f79-d4e5-400b-9f7a-937ff8100a2e.png)



Read more:

- https://www.brendangregg.com/blog/2019-01-01/learn-ebpf-tracing.html
- https://blog.cloudflare.com/cloudflare-architecture-and-how-bpf-eats-the-world/
- https://thenewstack.io/how-ebpf-turns-linux-into-a-programmable-kernel/
- https://netflixtechblog.com/how-netflix-uses-ebpf-flow-logs-at-scale-for-network-insight-e3ea997dca96?gi=89c7bb8b4054
- https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/
