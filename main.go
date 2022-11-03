package main

import (
	"net/http"
  "github.com/google/uuid"

	"github.com/gin-gonic/gin"
	"github.com/gmctechsols/luau/types"
)

func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
    c.JSON(http.StatusOK, types.Tinent{Id: uuid.New()})
	})
	r.Run()
}
