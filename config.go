package osin

// AllowedAuthorizeType is a collection of allowed auth request types
type AllowedAuthorizeType []AuthorizeRequestType

// Exists returns true if the auth type exists in the list
func (t AllowedAuthorizeType) Exists(rt AuthorizeRequestTypes) bool {
	ret := make(map[string]bool)
	for _, k := range rt {
		ret[k] = false
		for _, z := range t {
			if z == AuthorizeRequestType(k) {
				ret[k] = true
			}
		}
	}
	for _, v := range ret {
		if v == false {
			return false
		}
	}
	return true
}

// AllowedAccessType is a collection of allowed access request types
type AllowedAccessType []AccessRequestType

// Exists returns true if the access type exists in the list
func (t AllowedAccessType) Exists(rt AccessRequestType) bool {
	for _, k := range t {
		if k == rt {
			return true
		}
	}
	return false
}

// ServerConfig contains server configuration information
type ServerConfig struct {
	// Authorization token expiration in seconds (default 5 minutes)
	AuthorizationExpiration int32

	// Access token expiration in seconds (default 1 hour)
	AccessExpiration int32

	// Token type to return
	TokenType string

	// List of allowed authorize types (only CODE by default)
	AllowedAuthorizeTypes AllowedAuthorizeType

	// List of allowed access types (only AUTHORIZATION_CODE by default)
	AllowedAccessTypes AllowedAccessType

	// HTTP status code to return for errors - default 200
	// Only used if response was created from server
	ErrorStatusCode int

	// If true allows client secret also in params, else only in
	// Authorization header - default false
	AllowClientSecretInParams bool

	// If true allows access request using GET, else only POST - default false
	AllowGetAccessRequest bool

	// Separator to support multiple URIs in Client.GetRedirectUri().
	// If blank (the default), don't allow multiple URIs.
	RedirectUriSeparator string

	// OpenID connect config
	// Issuer for ID token http://openid.net/specs/openid-connect-core-1_0.html#IDToken
	Issuer string

	// ID token expire time in second, default 1 hour
	IDTokenExpiration int32

	// JSON Web Token key
	JWTKey []byte
}

// NewServerConfig returns a new ServerConfig with default configuration
func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		AuthorizationExpiration:   250,
		AccessExpiration:          3600,
		IDTokenExpiration:         3600,
		TokenType:                 "bearer",
		AllowedAuthorizeTypes:     AllowedAuthorizeType{CODE},
		AllowedAccessTypes:        AllowedAccessType{AUTHORIZATION_CODE},
		ErrorStatusCode:           200,
		AllowClientSecretInParams: false,
		AllowGetAccessRequest:     false,
	}
}
