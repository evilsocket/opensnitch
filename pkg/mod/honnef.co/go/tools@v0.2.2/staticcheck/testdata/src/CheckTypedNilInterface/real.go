package pkg

import "log"

type iface interface{ m() }

type t1 struct{ int }

func (t *t1) m() { log.Println(t.int) }

type internalMessage struct{ v *t1 }

func f(msg chan internalMessage, input int) {
	k := &t1{input}

	if input > 2 {
		k = nil
	}
	msg <- internalMessage{k}

}

func SyncPublicMethod(input int) iface {
	ch := make(chan internalMessage)
	go f(ch, input)
	answer := <-ch
	// Problem: if answer.v == nil then this will created typed nil iface return value
	return answer.v
}

func main() {
	for i := 0; i < 10; i++ {
		k := SyncPublicMethod(i)
		if k == nil { // want `this comparison is never true`
			log.Println("never printed")
			return
		}

		// Will panic.
		k.m()
	}
}
