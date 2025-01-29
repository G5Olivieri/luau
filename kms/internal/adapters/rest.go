package adapters

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/G5Olivieri/luau/jose/jwk"
	"github.com/G5Olivieri/luau/jose/jwt"
	"github.com/G5Olivieri/luau/kms"
	docs "github.com/G5Olivieri/luau/kms/docs"
	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type restJwk struct {
	Kty     jwk.KeyType  `json:"kty"`
	Use     *jwk.KeyUse  `json:"use,omitempty"`
	KeyOps  []jwk.KeyOps `json:"key_ops"`
	Alg     *jwk.KeyAlg  `json:"alg,omitempty"`
	Kid     *string      `json:"kid,omitempty"`
	X5u     string       `json:"x5u,omitempty" format:"uri"`
	X5c     []string     `json:"x5c,omitempty"`
	X5t     *string      `json:"x5t,omitempty"`
	X5tS256 *string      `json:"x5t#S256,omitempty"`

	// oct
	K *string `json:"k,omitempty"`

	// RSA Public Key
	E *string `json:"e,omitempty"`
	N *string `json:"n,omitempty"`

	// RSA Private Key
	Dp *string `json:"dp,omitempty"`
	Dq *string `json:"dq,omitempty"`
	Qi *string `json:"qi,omitempty"`

	// EC Public Key
	Curve *string `json:"crv,omitempty"`
	X     *string `json:"x,omitempty"`
	Y     *string `json:"y,omitempty"`

	// EC and RSA Private Key
	D *string `json:"d,omitempty"`
}

func fromJwk(k *jwk.JWK) *restJwk {
	var x5u string
	if k.X5u != nil {
		x5u = k.X5u.String()
	}
	return &restJwk{
		Kty:     k.Kty,
		Use:     k.Use,
		KeyOps:  k.KeyOps,
		Alg:     k.Alg,
		Kid:     k.Kid,
		X5u:     x5u,
		X5c:     k.X5c,
		X5t:     k.X5t,
		X5tS256: k.X5tS256,
		K:       k.K,
		E:       k.E,
		N:       k.N,
		Dp:      k.Dp,
		Dq:      k.Dq,
		Qi:      k.Qi,
		Curve:   k.Curve,
		X:       k.X,
		Y:       k.Y,
		D:       k.D,
	}
}

type restCreateOrUpdateKeyRequest struct {
	Alg    jwk.KeyAlg   `json:"alg" validate:"required,oneof=HS256 HS384 HS512 RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512"`
	Type   jwk.KeyType  `json:"typ" validate:"required,oneof=RSA EC OCT"`
	KeyOps []jwk.KeyOps `json:"key_ops" validate:"required,dive,oneof=sign verify encrypt decrypt wrapkey unwrapkey derivekey derivebits"`
	Use    jwk.KeyUse   `json:"use" validate:"required,oneof=sig enc"`
}

type signRequest struct {
	Message string `json:"message" validate:"required" format:"base64"`
}

type signResponse struct {
	Signature string `json:"signature" validate:"required" format:"base64"`
}

type verifyRequest struct {
	Message   string `json:"message" validate:"required" format:"base64"`
	Signature string `json:"signature" validate:"required" format:"base64"`
}

type verifyResponse struct {
	Valid bool `json:"valid"`
}

type restAdapter struct {
	impl     kms.KMS
	authHost string
}

type limitOffset struct {
	Limit  *int `form:"limit"`
	Offset *int `form:"offset"`
}

type restJwks struct {
	Jwks []*restJwk `json:"jwks"`
}

// listKeys godoc
// @Security OAuth2Application[openid]
// @Summary list keys
// @Schemes
// @Description list keys
// @Tags keys
// @Accept json
// @Produce json
// @Param limit query int false "limit items (max: 1024)" default(256)
// @Param offset query int false "offset items" default(0)
// @Success 200 {array} restJwks
// @Success 400
// @Router / [get]
func (a restAdapter) listKeys(ctx *gin.Context) {
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

	keys, err := a.impl.List(ctx, *query.Limit, *query.Offset)

	if err != nil {
		log.Println(err.Error())
		ctx.Status(http.StatusInternalServerError)
		return
	}

	response := make([]*restJwk, 0, len(keys))
	for _, v := range keys {
		jwk, err := v.JWK()
		if err != nil {
			ctx.Status(http.StatusInternalServerError)
			return
		}
		response = append(response, fromJwk(jwk))
	}
	ctx.JSON(http.StatusOK, restJwks{Jwks: response})
}

// listPublicKeys godoc
// @Security OAuth2Application[openid]
// @Summary list public keys
// @Schemes
// @Description list public keys
// @Tags keys
// @Accept json
// @Produce json
// @Param limit query int false "limit items (max: 1024)" default(256)
// @Param offset query int false "offset items" default(0)
// @Success 200 {array} restJwks
// @Success 400
// @Router /public-keys [get]
func (a restAdapter) listPublicKeys(ctx *gin.Context) {
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

	keys, err := a.impl.GetPublicKeys(ctx, *query.Limit, *query.Offset)

	if err != nil {
		log.Println(err.Error())
		ctx.Status(http.StatusInternalServerError)
		return
	}

	response := make([]*restJwk, 0, len(keys))
	for _, v := range keys {
		jwk, err := v.JWK()
		if err != nil {
			ctx.Status(http.StatusInternalServerError)
			return
		}
		response = append(response, fromJwk(jwk))
	}
	ctx.JSON(http.StatusOK, restJwks{Jwks: response})
}

// createKey godoc
// @Security OAuth2Application[openid]
// @Summary create a key
// @Schemes
// @Description create a key
// @Tags keys
// @Accept json
// @Produce json
// @Param request body restCreateOrUpdateKeyRequest true "create key"
// @Success 201 {object} restJwk
// @Success 400
// @Router / [post]
func (a restAdapter) createKey(ctx *gin.Context) {
	var createRequest restCreateOrUpdateKeyRequest
	if err := ctx.BindJSON(&createRequest); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	created, err := a.impl.GenerateKey(ctx, kms.KeySpec{
		Alg:    createRequest.Alg,
		Type:   createRequest.Type,
		KeyOps: createRequest.KeyOps,
		Use:    createRequest.Use,
	})

	if err != nil {
		log.Printf("internal server error: %v", err)
		ctx.Status(http.StatusInternalServerError)
		return
	}
	jwk, err := created.JWK()

	if err != nil {
		log.Printf("internal server error: %v", err)
		ctx.Status(http.StatusInternalServerError)
		return
	}

	ctx.Header("Location", fmt.Sprintf("/%s", created.GetID()))
	ctx.JSON(http.StatusCreated, fromJwk(jwk))
}

// getKeyByID godoc
// @Security OAuth2Application[openid]
// @Summary get key by id
// @Schemes
// @Description get a key by id
// @Tags keys
// @Accept json
// @Produce json
// @Param id path string true "key id" Format(uuid)
// @Success 200 {object} restJwk
// @Failure 404
// @Router /{id} [get]
func (a restAdapter) getKeyByID(ctx *gin.Context) {
	providedID := ctx.Param("id")

	key, err := a.impl.Get(ctx, providedID)
	if err != nil {
		if errors.Is(err, kms.ErrKeyNotFound) {
			ctx.Status(http.StatusNotFound)
		} else {
			log.Printf("Internal server error: %v", err)
			ctx.Status(http.StatusInternalServerError)
		}
		return
	}

	jwk, err := key.JWK()
	if err != nil {
		log.Printf("Internal server error: %v", err)
		ctx.Status(http.StatusInternalServerError)
		return
	}
	ctx.JSON(http.StatusOK, fromJwk(jwk))
}

// getPublicKeyByID godoc
// @Security OAuth2Application[openid]
// @Summary get public key by id
// @Schemes
// @Description get a public key by id
// @Tags keys
// @Accept json
// @Produce json
// @Param id path string true "key id" Format(uuid)
// @Success 200 {object} restJwk
// @Failure 404
// @Router /{id}/public-key [get]
func (a restAdapter) getPublicKeyByID(ctx *gin.Context) {
	providedID := ctx.Param("id")

	key, err := a.impl.GetPublicKey(ctx, providedID)
	if err != nil {
		if errors.Is(err, kms.ErrKeyNotFound) {
			ctx.Status(http.StatusNotFound)
		} else if errors.Is(err, kms.ErrInvalidKeyOperation) {
			ctx.Status(http.StatusBadRequest)
		} else {
			log.Printf("Internal server error: %v", err)
			ctx.Status(http.StatusInternalServerError)
		}
		return
	}

	jwk, err := key.JWK()
	if err != nil {
		log.Printf("Internal server error: %v", err)
		ctx.Status(http.StatusInternalServerError)
		return
	}
	ctx.JSON(http.StatusOK, fromJwk(jwk))
}

// sign godoc
// @Security OAuth2Application[openid]
// @Summary sign
// @Schemes
// @Description sign
// @Tags keys
// @Accept json
// @Produce json
// @Param request body signRequest true "sign message"
// @Param id path string true "key id" Format(uuid)
// @Success 200 {object} signResponse
// @Failure 404
// @Router /{id}/sign [post]
func (a restAdapter) sign(ctx *gin.Context) {
	providedID := ctx.Param("id")

	var signReq signRequest
	if err := ctx.BindJSON(&signReq); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	message, err := base64.StdEncoding.DecodeString(signReq.Message)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "message must be base64"})
		return
	}

	signature, err := a.impl.Sign(ctx, providedID, message)
	if err != nil {
		if errors.Is(err, kms.ErrKeyNotFound) {
			ctx.Status(http.StatusNotFound)
		} else if errors.Is(err, kms.ErrInvalidKeyOperation) {
			ctx.Status(http.StatusBadRequest)
		} else {
			log.Printf("Internal server error: %v", err)
			ctx.Status(http.StatusInternalServerError)
		}
		return
	}

	ctx.JSON(http.StatusOK, signResponse{
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
}

// veiryf godoc
// @Security OAuth2Application[openid]
// @Summary verify
// @Schemes
// @Description verify
// @Tags keys
// @Accept json
// @Produce json
// @Param id path string true "key id" Format(uuid)
// @Param request body verifyRequest true "verify message"
// @Success 200 {object} verifyResponse
// @Failure 404
// @Router /{id}/verify [post]
func (a restAdapter) verify(ctx *gin.Context) {
	providedID := ctx.Param("id")

	var verifyReq verifyRequest
	if err := ctx.BindJSON(&verifyReq); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	message, err := base64.StdEncoding.DecodeString(verifyReq.Message)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "message must be base64"})
		return
	}

	signature, err := base64.StdEncoding.DecodeString(verifyReq.Signature)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "signature must be base64"})
		return
	}

	valid, err := a.impl.Verify(ctx, providedID, message, signature)

	if err != nil {
		if errors.Is(err, kms.ErrKeyNotFound) {
			ctx.Status(http.StatusNotFound)
		} else if errors.Is(err, kms.ErrInvalidKeyOperation) {
			ctx.Status(http.StatusBadRequest)
		} else {
			log.Printf("Internal server error: %v", err)
			ctx.Status(http.StatusInternalServerError)
		}
		return
	}

	ctx.JSON(http.StatusOK, verifyResponse{
		Valid: valid,
	})
}

func (r restAdapter) authMiddleware(ctx *gin.Context) {
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
	verifier, err := jwt.NewJWKSVerifierFromUri(ctx, fmt.Sprintf("%s/oidc/.well-known/jwks.json", r.authHost))
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
func NewRestHTTPHandler(impl kms.KMS, authHost string) http.Handler {
	router := gin.Default()

	adapter := restAdapter{
		impl:     impl,
		authHost: authHost,
	}

	// apiRouter := router.Group("/api", adapter.authMiddleware)
	apiRouter := router.Group("/api")

	apiRouter.POST("", adapter.createKey)
	apiRouter.GET("", adapter.listKeys)
	apiRouter.GET("/public-keys", adapter.listPublicKeys)
	apiRouter.GET("/:id", adapter.getKeyByID)
	apiRouter.GET("/:id/public-key", adapter.getPublicKeyByID)
	apiRouter.POST("/:id/sign", adapter.sign)
	apiRouter.POST("/:id/verify", adapter.verify)

	docs.SwaggerInfo.Title = "KMS API"
	docs.SwaggerInfo.Description = "This is a kms API"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = ""
	docs.SwaggerInfo.BasePath = "/api"
	docs.SwaggerInfo.Schemes = []string{"http", "https"}

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	return router
}
