package adapters

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/G5Olivieri/luau/jose/jwt"
	docs "github.com/G5Olivieri/luau/users/docs"
	"github.com/G5Olivieri/luau/users/internal"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type restUsernamePassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type restUser struct {
	ID        uuid.UUID  `json:"id" format:"uuid"`
	Username  string     `json:"username"`
	Password  string     `json:"password"`
	LastLogin *time.Time `json:"last_login,omitempty" format:"date-time"`
}

type restCreateOrUpdateUserRequest struct {
	Username  string     `json:"username"`
	Password  string     `json:"password"`
	LastLogin *time.Time `json:"last_login,omitempty" format:"date-time"`
}

func fromUser(user *internal.User) *restUser {
	return &restUser{
		ID:        user.ID,
		Username:  user.Username,
		Password:  user.Password,
		LastLogin: user.LastLogin,
	}
}

type restAdapter struct {
	impl     internal.UsersService
	authHost string
}

type limitOffset struct {
	Limit  *int `form:"limit"`
	Offset *int `form:"offset"`
}

// listUsers godoc
// @Security OAuth2Application[openid]
// @Summary list users
// @Schemes
// @Description list users
// @Tags users
// @Accept json
// @Produce json
// @Param limit query int false "limit items (max: 1024)" default(256)
// @Param offset query int false "offset items" default(0)
// @Success 200 {array} []restUser
// @Success 400
// @Router / [get]
func (a restAdapter) listUsers(ctx *gin.Context) {
	var query limitOffset
	if err := ctx.ShouldBindQuery(&query); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if query.Limit == nil {
		query.Limit = new(int)
		*query.Limit = 256
	}

	if query.Offset == nil {
		query.Offset = new(int)
		*query.Offset = 0
	}

	users, err := a.impl.List(ctx, *query.Limit, *query.Offset)

	if err != nil {
		log.Println(err.Error())
		ctx.Status(http.StatusInternalServerError)
		return
	}
	response := make([]*restUser, 0, len(users))
	for _, v := range users {
		response = append(response, fromUser(v))
	}
	ctx.JSON(http.StatusOK, response)
}

// createUser godoc
// @Security OAuth2Application[openid]
// @Summary create an user
// @Schemes
// @Description create an user
// @Tags users
// @Accept json
// @Produce json
// @Param request body restCreateOrUpdateUserRequest true "create user"
// @Success 201 {object} restUser
// @Success 400
// @Router / [post]
func (a restAdapter) createUser(ctx *gin.Context) {
	var createRequest restCreateOrUpdateUserRequest
	if err := ctx.BindJSON(&createRequest); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userCreated, err := a.impl.Create(ctx, &internal.CreateUserRequest{
		Username:  createRequest.Username,
		Password:  createRequest.Password,
		LastLogin: createRequest.LastLogin,
	})
	if err != nil {
		log.Printf("internal server error: %v", err)
		ctx.Status(http.StatusInternalServerError)
		return
	}

	ctx.Header("Location", fmt.Sprintf("/%s", userCreated.ID.String()))
	ctx.JSON(http.StatusCreated, fromUser(userCreated))

}

// getUserByID godoc
// @Security OAuth2Application[openid]
// @Summary get user by id
// @Schemes
// @Description get an user by id
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "user id" Format(uuid)
// @Success 200 {object} restUser
// @Failure 404
// @Router /{id} [get]
func (a restAdapter) getUserByID(ctx *gin.Context) {
	providedID := ctx.Param("id")
	id, err := uuid.Parse(providedID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := a.impl.GetByID(ctx, &id)
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			ctx.Status(http.StatusNotFound)
		} else {
			log.Printf("Internal server error: %v", err)
			ctx.Status(http.StatusInternalServerError)
		}
		return
	}

	ctx.JSON(http.StatusOK, fromUser(user))
}

// getUserByUsername godoc
// @Security OAuth2Application[openid]
// @Summary get user by username
// @Schemes
// @Description get an user by username
// @Tags users
// @Accept json
// @Produce json
// @Param username path string true "user username"
// @Success 200 {object} restUser
// @Failure 404
// @Router /username/{username} [get]
func (a restAdapter) getUserByUsername(ctx *gin.Context) {
	username := ctx.Param("username")

	user, err := a.impl.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			ctx.Status(http.StatusNotFound)
		} else {
			log.Printf("Internal server error: %v", err)
			ctx.Status(http.StatusInternalServerError)
		}
		return
	}

	ctx.JSON(http.StatusOK, fromUser(user))
}

// getUserByUsernamePassword godoc
// @Security OAuth2Application[openid]
// @Summary get user by username and password
// @Schemes
// @Description get an user by username and password
// @Tags users
// @Accept json
// @Produce json
// @Param request body restUsernamePassword true "username and password"
// @Success 200 {object} restUser
// @Failure 404
// @Router /username-password [post]
func (a restAdapter) getUserByUsernamePassword(ctx *gin.Context) {
	var usernamePassword restUsernamePassword
	if err := ctx.BindJSON(&usernamePassword); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := a.impl.GetByUsernamePassword(ctx, usernamePassword.Username, usernamePassword.Password)
	if err != nil {
		if errors.Is(err, internal.ErrNotFound) {
			ctx.Status(http.StatusNotFound)
		} else {
			log.Printf("Internal server error: %v", err)
			ctx.Status(http.StatusInternalServerError)
		}
		return
	}

	ctx.JSON(http.StatusOK, fromUser(user))
}

// deleteUserByID godoc
// @Security OAuth2Application[openid]
// @Summary delete user by id
// @Schemes
// @Description delete an user by id
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "user id" Format(uuid)
// @Success 204
// @Failure 404
// @Router /{id} [delete]
func (a restAdapter) deleteUserByID(ctx *gin.Context) {
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

// updateUser godoc
// @Security OAuth2Application[openid]
// @Summary update user
// @Schemes
// @Description update an user
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "user id" Format(uuid)
// @Param request body restCreateOrUpdateUserRequest true "update user"
// @Success 200 {object} restUser
// @Failure 404
// @Router /{id} [put]
func (a restAdapter) updateUser(ctx *gin.Context) {
	providedID := ctx.Param("id")
	id, err := uuid.Parse(providedID)

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var updateRequest restCreateOrUpdateUserRequest
	if err := ctx.BindJSON(&updateRequest); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userUpdate, err := a.impl.Update(ctx, &internal.User{
		ID:        id,
		Username:  updateRequest.Username,
		Password:  updateRequest.Password,
		LastLogin: updateRequest.LastLogin,
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
	ctx.JSON(http.StatusOK, fromUser(userUpdate))
}

func (a restAdapter) authMiddleware(ctx *gin.Context) {
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
	verifier, err := NewJWKSVerifierFromUri(ctx, fmt.Sprintf("%s/oidc/.well-known/jwks.json", a.authHost))
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
func NewRestHTTPHandler(impl internal.UsersService, authHost string) http.Handler {
	router := gin.Default()

	adapter := restAdapter{
		impl:     impl,
		authHost: authHost,
	}

	router.Use()

	apiRouter := router.Group("/api", adapter.authMiddleware)

	apiRouter.POST("/", adapter.createUser)
	apiRouter.GET("/", adapter.listUsers)
	apiRouter.GET("/:id", adapter.getUserByID)
	apiRouter.DELETE("/:id", adapter.deleteUserByID)
	apiRouter.PUT("/:id", adapter.updateUser)

	apiRouter.GET("/username/:username", adapter.getUserByUsername)
	apiRouter.POST("/username-password", adapter.getUserByUsernamePassword)

	docs.SwaggerInfo.Title = "User API"
	docs.SwaggerInfo.Description = "This is an user API"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = ""
	docs.SwaggerInfo.BasePath = "/api"
	docs.SwaggerInfo.Schemes = []string{"http", "https"}

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	return router
}
