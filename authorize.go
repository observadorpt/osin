package osin

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuthorizeRequestType is the type for OAuth param `response_type`
type AuthorizeRequestType string
type AuthorizeRequestTypes []string

const (
	CODE     AuthorizeRequestType = "code"
	TOKEN                         = "token"
	ID_TOKEN                      = "id_token"
)

// Authorize request information
type AuthorizeRequest struct {
	Type        AuthorizeRequestTypes
	Client      Client
	Scope       string
	RedirectUri string
	State       string
	Nonce       string

	// Set if request is authorized
	Authorized bool

	// Token expiration in seconds. Change if different from default.
	TokenExpiration   int32
	IdTokenExpiration int32
	CodeExpiration    int32

	// Data to be passed to storage. Not used by the library.
	UserData interface{}

	// HttpRequest *http.Request for special use
	HttpRequest *http.Request
}

// Authorization data
type AuthorizeData struct {
	// Client information
	Client Client

	// Authorization code
	Code string

	// Token expiration in seconds
	ExpiresIn int32

	// Requested scope
	Scope string

	// Redirect Uri from request
	RedirectUri string

	// State data from request
	State string

	// Date created
	CreatedAt time.Time

	// Data to be passed to storage. Not used by the library.
	UserData interface{}
}

func (rt AuthorizeRequestTypes) HasType(t AuthorizeRequestType) bool {
	for _, k := range rt {
		if AuthorizeRequestType(k) == t {
			return true
		}
	}
	return false
}

// IsExpired is true if authorization expired
func (d *AuthorizeData) IsExpired() bool {
	return d.IsExpiredAt(time.Now())
}

// IsExpired is true if authorization expires at time 't'
func (d *AuthorizeData) IsExpiredAt(t time.Time) bool {
	return d.ExpireAt().Before(t)
}

// ExpireAt returns the expiration date
func (d *AuthorizeData) ExpireAt() time.Time {
	return d.CreatedAt.Add(time.Duration(d.ExpiresIn) * time.Second)
}

// AuthorizeTokenGen is the token generator interface
type AuthorizeTokenGen interface {
	GenerateAuthorizeToken(data *AuthorizeData) (string, error)
}

// HandleAuthorizeRequest is the main http.HandlerFunc for handling
// authorization requests
func (s *Server) HandleAuthorizeRequest(w *Response, r *http.Request) *AuthorizeRequest {
	r.ParseForm()

	// create the authorization request
	unescapedUri, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
	if err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", "")
		w.InternalError = err
		return nil
	}

	ret := &AuthorizeRequest{
		State:       r.Form.Get("state"),
		Scope:       r.Form.Get("scope"),
		Nonce:       r.Form.Get("nonce"),
		RedirectUri: unescapedUri,
		Authorized:  false,
		HttpRequest: r,
	}

	// must have a valid Client
	ret.Client, err = w.Storage.GetClient(r.Form.Get("client_id"))
	if err != nil {
		w.SetErrorState(E_SERVER_ERROR, "", ret.State)
		w.InternalError = err
		return nil
	}
	if ret.Client == nil {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}
	if ret.Client.GetRedirectUri() == "" {
		w.SetErrorState(E_UNAUTHORIZED_CLIENT, "", ret.State)
		return nil
	}

	// check redirect uri, if there are multiple client redirect uri's
	// don't set the uri
	if ret.RedirectUri == "" && FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator) == ret.Client.GetRedirectUri() {
		ret.RedirectUri = FirstUri(ret.Client.GetRedirectUri(), s.Config.RedirectUriSeparator)
	}

	if err = ValidateUriList(ret.Client.GetRedirectUri(), ret.RedirectUri, s.Config.RedirectUriSeparator); err != nil {
		w.SetErrorState(E_INVALID_REQUEST, "", ret.State)
		w.InternalError = err
		return nil
	}

	w.SetRedirect(ret.RedirectUri)

	// missing Types: id_token, code token, code id_token, id_token token, code id_token TOKEN
	requestType := AuthorizeRequestTypes(strings.Fields(r.Form.Get("response_type")))
	if s.Config.AllowedAuthorizeTypes.Exists(requestType) {
		ret.Type = requestType
		if requestType.HasType(CODE) {
			ret.CodeExpiration = s.Config.AuthorizationExpiration
		}
		if requestType.HasType(TOKEN) {
			ret.TokenExpiration = s.Config.AccessExpiration
		}
		if requestType.HasType(ID_TOKEN) {
			ret.IdTokenExpiration = s.Config.IDTokenExpiration
		}
		return ret
	}

	w.SetErrorState(E_UNSUPPORTED_RESPONSE_TYPE, "", ret.State)
	return nil
}

func (s *Server) FinishAuthorizeRequest(w *Response, r *http.Request, ar *AuthorizeRequest) {
	// don't process if is already an error
	if w.IsError {
		return
	}

	// force redirect response
	w.SetRedirect(ar.RedirectUri)

	if ar.Authorized {
		if ar.Type.HasType(TOKEN) {
			w.SetRedirectFragment(true)

			// generate token directly
			ret := &AccessRequest{
				Type:            IMPLICIT,
				Code:            "",
				Client:          ar.Client,
				RedirectUri:     ar.RedirectUri,
				Scope:           ar.Scope,
				Nonce:           ar.Nonce,
				GenerateRefresh: false, // per the RFC, should NOT generate a refresh token in this case
				Authorized:      true,
				Expiration:      ar.TokenExpiration,
				UserData:        ar.UserData,
				ARType:          ar.Type,
			}

			s.FinishAccessRequest(w, r, ret)
			if ar.State != "" && w.InternalError == nil {
				w.Output["state"] = ar.State
			}
		}
		if ar.Type.HasType(CODE) {
			// generate authorization token
			ret := &AuthorizeData{
				Client:      ar.Client,
				CreatedAt:   s.Now(),
				ExpiresIn:   ar.CodeExpiration,
				RedirectUri: ar.RedirectUri,
				State:       ar.State,
				Scope:       ar.Scope,
				UserData:    ar.UserData,
			}

			// generate token code
			code, err := s.AuthorizeTokenGen.GenerateAuthorizeToken(ret)
			if err != nil {
				w.SetErrorState(E_SERVER_ERROR, "", ar.State)
				w.InternalError = err
				return
			}
			ret.Code = code

			// save authorization token
			if err = w.Storage.SaveAuthorize(ret); err != nil {
				w.SetErrorState(E_SERVER_ERROR, "", ar.State)
				w.InternalError = err
				return
			}

			// redirect with code
			w.Output["code"] = ret.Code
			w.Output["state"] = ret.State

			if ar.Type.HasType(ID_TOKEN) {
				IDToken, err := s.generateIDToken(ar.UserData, ar.Client, ar.Scope, ar.Nonce, "")
				if err != nil {
					w.SetError(E_SERVER_ERROR, "")
					w.InternalError = err
					return
				}
				w.Output["id_token"] = IDToken
			}
		}
	} else {
		// redirect with error
		w.SetErrorState(E_ACCESS_DENIED, "", ar.State)
	}
}
