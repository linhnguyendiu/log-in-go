package main

import (
	"fmt"
	"log-in-go/db"
	routers "log-in-go/routes"

	"github.com/gin-gonic/gin"
)

func init() {
	db.InitialMigration()
}

func main() {
	fmt.Println("Hello auth")
	r := gin.Default()
	routers.GetRoute(r)

	r.Run()
}
