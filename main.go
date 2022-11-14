package main

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	openidconnect "github.com/gmctechsols/luau/openid_connect"
)

func main() {
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"*"},
		AllowHeaders: []string{"*"},
		MaxAge:       12 * time.Hour,
	}))
	r.LoadHTMLGlob("templates/*")

	r.GET("/openidconnect/authorize", openidconnect.AuthorizeHandler)
	r.POST("/openidconnect/signin", openidconnect.SiginHandler)
	r.POST("/openidconnect/token", openidconnect.TokenHandler)

	r.Run()
}
