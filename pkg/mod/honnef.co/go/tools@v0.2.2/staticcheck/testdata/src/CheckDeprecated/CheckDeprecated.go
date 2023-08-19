package pkg

import _ "CheckDeprecatedassist"          // want `Alas, it is deprecated\.`
import _ "AnotherCheckDeprecatedassist"   // want `Alas, it is deprecated\.`
import foo "AnotherCheckDeprecatedassist" // want `Alas, it is deprecated\.`
import "AnotherCheckDeprecatedassist"     // want `Alas, it is deprecated\.`

func init() {
	foo.Fn()
	AnotherCheckDeprecatedassist.Fn()
}
