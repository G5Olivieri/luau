package adapters

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	docs "github.com/G5Olivieri/luau/clients/docs"
	"github.com/G5Olivieri/luau/clients/internal"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type restClient struct {
	ID           uuid.UUID         `json:"id" format:"uuid"`
	Name         map[string]string `json:"name" example:"default:client,pt_BR:cliente"`
	RedirectURIs []string          `json:"redirect_uris" swaggertype:"array,string" format:"uri" example:"https://client-app.com/oauth/callback"`
}

type restCreateOrUpdateClientRequest struct {
	Name         map[string]string `json:"name" example:"default:client,pt_BR:client"`
	RedirectURIs []string          `json:"redirect_uris" swaggertype:"array,string" format:"uri" example:"https://client-app.com/oauth/callback"`
}

func fromClient(client *internal.Client) *restClient {
	return &restClient{
		ID:           client.ID,
		Name:         client.Name,
		RedirectURIs: urisURLToStrings(client.RedirectURIs),
	}
}

type restAdapter struct {
	impl internal.ClientsService
}

type limitOffset struct {
	Limit  *int `form:"limit"`
	Offset *int `form:"offset"`
}

// listClients godoc
// @Summary list clients
// @Schemes
// @Description list clients
// @Tags clients
// @Accept json
// @Produce json
// @Param limit query int false "limit items (max: 1024)" default(256)
// @Param offset query int false "offset items" default(0)
// @Success 200 {array} []restClient
// @Success 400
// @Router / [get]
func (a restAdapter) listClients(ctx *gin.Context) {
	var query limitOffset
	if err := ctx.ShouldBindQuery(&query); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if query.Limit == nil {
		*query.Limit = 256
	}

	if query.Offset == nil {
		*query.Offset = 0
	}

	clients, err := a.impl.List(ctx.Request.Context(), *query.Limit, *query.Offset)

	if err != nil {
		log.Println(err.Error())
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	response := make([]*restClient, 0, len(clients))
	for _, v := range clients {
		response = append(response, fromClient(v))
	}
	ctx.JSON(http.StatusOK, response)
}

// createClient godoc
// @Summary create a client
// @Schemes
// @Description create a client
// @Tags clients
// @Accept json
// @Produce json
// @Param request body restCreateOrUpdateClientRequest true "create client"
// @Success 201 {object} restClient
// @Success 400
// @Router / [post]
func (a restAdapter) createClient(ctx *gin.Context) {
	var createRequest restCreateOrUpdateClientRequest
	if err := ctx.BindJSON(&createRequest); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	urls, err := urisStringToURLs(createRequest.RedirectURIs)
	if err != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	clientCreated, err := a.impl.Create(ctx.Request.Context(), &internal.CreateClientRequest{
		Name:         createRequest.Name,
		RedirectURIs: urls,
	})
	if err != nil {
		log.Printf("internal server error: %v", err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	ctx.Header("Location", fmt.Sprintf("/%s", clientCreated.ID.String()))
	ctx.JSON(http.StatusCreated, fromClient(clientCreated))

}

// getClientByID godoc
// @Summary get client by id
// @Schemes
// @Description get a client by id
// @Tags clients
// @Accept json
// @Produce json
// @Param id path string true "client id" Format(uuid)
// @Success 200 {object} restClient
// @Failure 404
// @Router /{id} [get]
func (a restAdapter) getClientByID(ctx *gin.Context) {
	providedID := ctx.Param("id")
	id, err := uuid.Parse(providedID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client, err := a.impl.GetByID(ctx.Request.Context(), &id)
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			ctx.Writer.WriteHeader(http.StatusNotFound)
		} else {
			log.Printf("Internal server error: %v", err)
			ctx.Writer.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	ctx.JSON(http.StatusOK, fromClient(client))

}

// deleteClientByID godoc
// @Summary delete client by id
// @Schemes
// @Description delete a client by id
// @Tags clients
// @Accept json
// @Produce json
// @Param id path string true "client id" Format(uuid)
// @Success 204
// @Failure 404
// @Router /{id} [delete]
func (a restAdapter) deleteClientByID(ctx *gin.Context) {
	providedID := ctx.Param("id")
	id, err := uuid.Parse(providedID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err = a.impl.DeleteByID(ctx.Request.Context(), &id); err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			ctx.Writer.WriteHeader(http.StatusNotFound)
		} else {
			log.Printf("Internal server error: %v", err)
			ctx.Writer.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	ctx.Writer.WriteHeader(http.StatusNoContent)

}

// updateClient godoc
// @Summary update client
// @Schemes
// @Description update a client
// @Tags clients
// @Accept json
// @Produce json
// @Param id path string true "client id" Format(uuid)
// @Param request body restCreateOrUpdateClientRequest true "update client"
// @Success 200 {object} restClient
// @Failure 404
// @Router /{id} [put]
func (a restAdapter) updateClient(ctx *gin.Context) {
	providedID := ctx.Param("id")
	id, err := uuid.Parse(providedID)

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var updateRequest restCreateOrUpdateClientRequest
	if err := ctx.BindJSON(&updateRequest); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	urls, err := urisStringToURLs(updateRequest.RedirectURIs)
	if err != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	clientUpdate, err := a.impl.Update(ctx.Request.Context(), &internal.Client{
		ID:           id,
		Name:         updateRequest.Name,
		RedirectURIs: urls,
	})
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			ctx.Writer.WriteHeader(http.StatusNotFound)
			return
		}
		log.Printf("internal server error: %v", err)
		ctx.Writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	ctx.JSON(http.StatusOK, fromClient(clientUpdate))
}

func NewRestHTTPHandler(impl internal.ClientsService) http.Handler {
	router := gin.Default()

	adapter := restAdapter{
		impl: impl,
	}

	router.POST("/", adapter.createClient)
	router.GET("/", adapter.listClients)
	router.GET("/:id", adapter.getClientByID)
	router.DELETE("/:id", adapter.deleteClientByID)
	router.PUT("/:id", adapter.updateClient)

	docs.SwaggerInfo.Title = "Client API"
	docs.SwaggerInfo.Description = "This is a client API"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = ""
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Schemes = []string{"http", "https"}

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	return router
}
