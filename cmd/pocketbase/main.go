package main

import (
	"github.com/pocketbase/pocketbase"

	_ "github.com/pluto-org-co/pocketbase-sdk/migrations"
)

func main() {
	app := pocketbase.New()

	if err := app.Start(); err != nil {
		panic(err)
	}
}
