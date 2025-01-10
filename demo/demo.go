package main

import (
	"log"
	"net/http"
)

func main() {
	http.Handle("/", http.FileServer(http.Dir("./demo")))
	log.Println("Listening :3000")
	http.ListenAndServe(":3000", nil)
}
