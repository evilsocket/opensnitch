// +build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"

	"github.com/vishvananda/netlink"
)

type command struct {
	Function    func([]string)
	Description string
	ArgCount    int
}

var (
	commands = map[string]command{
		"protocol": {cmdProtocol, "prints the protocol version", 0},
		"create":   {cmdCreate, "creates a new ipset", 2},
		"destroy":  {cmdDestroy, "creates a new ipset", 1},
		"list":     {cmdList, "list specific ipset", 1},
		"listall":  {cmdListAll, "list all ipsets", 0},
		"add":      {cmdAddDel(netlink.IpsetAdd), "add entry", 2},
		"del":      {cmdAddDel(netlink.IpsetDel), "delete entry", 2},
	}

	timeoutVal   *uint32
	timeout      = flag.Int("timeout", -1, "timeout, negative means omit the argument")
	comment      = flag.String("comment", "", "comment")
	withComments = flag.Bool("with-comments", false, "create set with comment support")
	withCounters = flag.Bool("with-counters", false, "create set with counters support")
	withSkbinfo  = flag.Bool("with-skbinfo", false, "create set with skbinfo support")
	replace      = flag.Bool("replace", false, "replace existing set/entry")
)

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	if *timeout >= 0 {
		v := uint32(*timeout)
		timeoutVal = &v
	}

	log.SetFlags(log.Lshortfile)

	cmdName := args[0]
	args = args[1:]

	cmd, exist := commands[cmdName]
	if !exist {
		fmt.Printf("Unknown command '%s'\n\n", cmdName)
		printUsage()
		os.Exit(1)
	}

	if cmd.ArgCount != len(args) {
		fmt.Printf("Invalid number of arguments. expected=%d given=%d\n", cmd.ArgCount, len(args))
		os.Exit(1)
	}

	cmd.Function(args)
}

func printUsage() {
	fmt.Printf("Usage: %s COMMAND [args] [-flags]\n\n", os.Args[0])
	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Println("Available commands:")
	for _, name := range names {
		fmt.Printf("  %-15v %s\n", name, commands[name].Description)
	}
	fmt.Println("\nAvailable flags:")
	flag.PrintDefaults()
}

func cmdProtocol(_ []string) {
	protocol, minProto, err := netlink.IpsetProtocol()
	check(err)
	log.Println("Protocol:", protocol, "min:", minProto)
}

func cmdCreate(args []string) {
	err := netlink.IpsetCreate(args[0], args[1], netlink.IpsetCreateOptions{
		Replace:  *replace,
		Timeout:  timeoutVal,
		Comments: *withComments,
		Counters: *withCounters,
		Skbinfo:  *withSkbinfo,
	})
	check(err)
}

func cmdDestroy(args []string) {
	check(netlink.IpsetDestroy(args[0]))
}

func cmdList(args []string) {
	result, err := netlink.IpsetList(args[0])
	check(err)
	log.Printf("%+v", result)
}

func cmdListAll(args []string) {
	result, err := netlink.IpsetListAll()
	check(err)
	for _, ipset := range result {
		log.Printf("%+v", ipset)
	}
}

func cmdAddDel(f func(string, *netlink.IPSetEntry) error) func([]string) {
	return func(args []string) {
		setName := args[0]
		element := args[1]

		mac, _ := net.ParseMAC(element)
		entry := netlink.IPSetEntry{
			Timeout: timeoutVal,
			MAC:     mac,
			Comment: *comment,
			Replace: *replace,
		}

		check(f(setName, &entry))
	}
}

// panic on error
func check(err error) {
	if err != nil {
		panic(err)
	}
}
