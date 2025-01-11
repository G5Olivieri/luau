package adapters

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	docs "github.com/G5Olivieri/luau/clients/docs"
	"github.com/G5Olivieri/luau/clients/internal"
	"github.com/G5Olivieri/luau/jose/jwt"
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
	Name         map[string]string `json:"name" example:"default:client,pt_BR:cliente"`
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
// @Security OAuth2Application[openid]
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

	clients, err := a.impl.List(ctx, *query.Limit, *query.Offset)

	if err != nil {
		log.Println(err.Error())
		ctx.Status(http.StatusInternalServerError)
		return
	}
	response := make([]*restClient, 0, len(clients))
	for _, v := range clients {
		response = append(response, fromClient(v))
	}
	ctx.JSON(http.StatusOK, response)
}

// createClient godoc
// @Security OAuth2Application[openid]
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

	clientCreated, err := a.impl.Create(ctx, &internal.CreateClientRequest{
		Name:         createRequest.Name,
		RedirectURIs: urls,
	})
	if err != nil {
		log.Printf("internal server error: %v", err)
		ctx.Status(http.StatusInternalServerError)
		return
	}

	ctx.Header("Location", fmt.Sprintf("/%s", clientCreated.ID.String()))
	ctx.JSON(http.StatusCreated, fromClient(clientCreated))

}

// getClientByID godoc
// @Security OAuth2Application[openid]
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

	client, err := a.impl.GetByID(ctx, &id)
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			ctx.Status(http.StatusNotFound)
		} else {
			log.Printf("Internal server error: %v", err)
			ctx.Status(http.StatusInternalServerError)
		}
		return
	}

	ctx.JSON(http.StatusOK, fromClient(client))
}

// deleteClientByID godoc
// @Security OAuth2Application[openid]
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
	if err = a.impl.DeleteByID(ctx, &id); err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			ctx.Status(http.StatusNotFound)
		} else {
			log.Printf("Internal server error: %v", err)
			ctx.Status(http.StatusInternalServerError)
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}

// updateClient godoc
// @Security OAuth2Application[openid]
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

	clientUpdate, err := a.impl.Update(ctx, &internal.Client{
		ID:           id,
		Name:         updateRequest.Name,
		RedirectURIs: urls,
	})
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			ctx.Status(http.StatusNotFound)
			return
		}
		log.Printf("internal server error: %v", err)
		ctx.Status(http.StatusInternalServerError)
		return
	}
	ctx.JSON(http.StatusOK, fromClient(clientUpdate))
}

func authMiddleware(ctx *gin.Context) {
	authorization := ctx.GetHeader("authorization")
	if authorization == "" {
		log.Println("authorization is empty")
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	splited := strings.Split(authorization, " ")
	if len(splited) != 2 {
		log.Println("invalid authorization")
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if splited[0] != "Bearer" {
		log.Println("scheme is not Bearer")
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	token := splited[1]

	// TODO: decode JWT, Get Public Key at JWKS, Validate signature, issuer, aud, exp
	if token == "" {
		log.Println("token is empty")
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// TODO: get from env
	verifier, err := NewJWKSVerifierFromUri(ctx, "http://luau:8080/oidc/.well-known/jwks.json")
	if err != nil {
		log.Println(err)
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	valid, err := jwt.VerifySignatureCompact(ctx, verifier, token)

	if err != nil {
		log.Println(err)
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if !valid {
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}
}

// @securitydefinitions.oauth2.accessCode OAuth2Application
// @authorizationUrl http://localhost:8080/oidc/auth
// @tokenUrl http://localhost:8080/oidc/token
// @scope.openid "OpenID Connect scope"
func NewRestHTTPHandler(impl internal.ClientsService) http.Handler {
	router := gin.Default()

	adapter := restAdapter{
		impl: impl,
	}

	router.Use()

	apiRouter := router.Group("/api", authMiddleware)

	apiRouter.POST("/", adapter.createClient)
	apiRouter.GET("/", adapter.listClients)
	apiRouter.GET("/:id", adapter.getClientByID)
	apiRouter.DELETE("/:id", adapter.deleteClientByID)
	apiRouter.PUT("/:id", adapter.updateClient)

	docs.SwaggerInfo.Title = "Client API"
	docs.SwaggerInfo.Description = "This is a client API"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = ""
	docs.SwaggerInfo.BasePath = "/api"
	docs.SwaggerInfo.Schemes = []string{"http", "https"}

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	return router
}
