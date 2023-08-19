package pkg

func done() bool { return false }

var a, b int
var x bool

func fn() {
	for {
		if done() { // want `could lift into loop condition`
			break
		}
	}

	for {
		if !done() { // want `could lift into loop condition`
			break
		}
	}

	for {
		if a > b || b > a { // want `could lift into loop condition`
			break
		}
	}

	for {
		if x && (a == b) { // want `could lift into loop condition`
			break
		}
	}

	for {
		if done() { // want `could lift into loop condition`
			break
		}
		println()
	}

	for {
		println()
		if done() {
			break
		}
	}

	for {
		if done() {
			println()
			break
		}
	}
}
