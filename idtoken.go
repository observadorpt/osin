package osin

import (
	"crypto/sha256"
	"encoding/base64"
	jwt "github.com/dgrijalva/jwt-go"
	"io"
	"strings"
	"time"
)

// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
func (s *Server) generateIDToken(userData interface{}, client Client, scopesString string, nonce string, accessToken string) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims["iss"] = s.Config.Issuer
	token.Claims["sub"] = userData.(User).GetSub()
	token.Claims["aud"] = client.GetId()
	token.Claims["iat"] = time.Now().Unix()
	token.Claims["nonce"] = nonce
	token.Claims["exp"] = time.Now().Add(time.Duration(s.Config.IDTokenExpiration) * time.Second).Unix()
	if accessToken != "" {
		hasher := sha256.New()
		io.WriteString(hasher, accessToken)
		sum := hasher.Sum(nil)
		accessTokenHash := base64.URLEncoding.EncodeToString(sum[0 : len(sum)/2])
		token.Claims["at_hash"] = accessTokenHash
	}
	scopes := strings.Split(scopesString, " ")
	for _, scope := range scopes {
		claims := s.ClaimManager.GetClaims(scope, userData)
		for k, v := range claims {
			token.Claims[k] = v
		}
	}
	key, _ := jwt.ParseRSAPrivateKeyFromPEM(s.Config.JWTKey)
	a, err := token.SignedString(key)
	return a, err
}
