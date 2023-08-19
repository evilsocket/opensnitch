package pkg

func a() { // unused
	b()
}

func b() { // unused
	a()
}
