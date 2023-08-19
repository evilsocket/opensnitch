# Object pinning

BPF has a persistent view of maps and programs under its own filesystem
`/sys/fs/bpf`. Users are able to make each object visible under the bpffs.
We call it `object pinning`. This is done by calling syscall `bpf(2)` with
a command `BPF_OBJ_PIN`. After doing that, users are able to use the object
with commands such as `BPF_OBJ_GET`, or remove the object with an ordinary
VFS syscall `unlink(2)`.

Doing that, we can make maps and programs stay alive across process
terminations. This mechanism provides a much more consistent way of sharing
objects with other processes, compared to other solutions such as `tc`,
where objects are shared via Unix domain sockets.

## Different pinning options

`C.bpf_map_def.pinning` (defined in
[bpf.h](https://github.com/iovisor/gobpf/blob/446e57e0e24e/elf/include/bpf.h#L616))
can be set to one the following pinning options.

* `PIN_NONE` : object is not pinned
* `PIN_OBJECT_NS` : pinning that is local to an object (to-be-implemented)
* `PIN_GLOBAL_NS` : pinning with a global namespace under e.g. `/sys/fs/bpf/ns1/globals`
* `PIN_CUSTOM_NS` : pinning with a custom path given as section parameter

### Pinning with `PIN_CUSTOM_NS`

When loading a module with `C.bpf_map_def.pinning` set to `PIN_CUSTOM_NS`,
an additional path must be set in the `elf.SectionParams.PinPath` parameter
to `Load()`. For example:

(C source file for an ELF object)
```
struct bpf_map_def SEC("maps/dummy_array_custom") dummy_array_custom = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 1024,
	.pinning = PIN_CUSTOM_NS,
};
```

(Go source file that actually uses the ELF object)
```
b := elf.NewModule(customELFFileName)
var secParams = map[string]elf.SectionParams{
    "maps/dummy_array_custom": elf.SectionParams{
        PinPath: "ns1/test1",
    },
}
if err := b.Load(secParams); err != nil {
    fmt.Println(err)
}
```

Then you can check if the object is pinned like below:

```
$ ls -l /sys/fs/bpf/ns1/test1
```

### Unpinning with `PIN_CUSTOM_NS`

To unpin a custom pinned map, we need an additional path
`elf.CloseOptions.PinPath` as parameter to `CloseExt()`. For example:

```
var closeOptions = map[string]elf.CloseOptions{
    "maps/dummy_array_custom": elf.CloseOptions{
        Unpin:   true,
        PinPath: "ns1/test1",
    },
}
if err := b.CloseExt(closeOptions); err != nil {
    fmt.Println(err)
}
```

Or you can also remove the file just like below:

```
os.Remove("/sys/fs/bpf/ns1/test1")
```
