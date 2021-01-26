package main

import (
	"gitlab.com/confiks/ctcl/holder"
	"gitlab.com/confiks/ctcl/issuer"
)

func main() {
	issuer.LoadKeys()
	holder.Start()
}
