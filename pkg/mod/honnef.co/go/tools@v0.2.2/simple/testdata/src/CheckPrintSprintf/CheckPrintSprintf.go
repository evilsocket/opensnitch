package pkg

import "fmt"

func fn() {
	fmt.Print(fmt.Sprintf("%d", 1))         // want `should use fmt\.Printf`
	fmt.Println(fmt.Sprintf("%d", 1))       // want `don't forget the newline`
	fmt.Fprint(nil, fmt.Sprintf("%d", 1))   // want `should use fmt\.Fprintf`
	fmt.Fprintln(nil, fmt.Sprintf("%d", 1)) // want `don't forget the newline`
	fmt.Sprint(fmt.Sprintf("%d", 1))        // want `should use fmt\.Sprintf`
	fmt.Sprintln(fmt.Sprintf("%d", 1))      // want `don't forget the newline`

	arg := "%d"
	fmt.Println(fmt.Sprintf(arg, 1))
}
