package osin

type User interface {
	GetSub() string
}

type UserStorage interface {
	Auth(username, password string) (User, error)
	GetUser(sub string) (User, error)
}

type DefaultUser struct {
	Sub string
}

func (d *DefaultUser) GetSub() string {
	return d.Sub
}

/*type User struct {
	// required field for openid connect
	ID                  string    `json:"-"`
	Sub                 string    `json:"sub,omitempty"`
	Name                string    `json:"name,omitempty"`
	GivenName           string    `json:"given_name,omitempty"`
	FamilyName          string    `json:"family_name,omitempty"`
	MiddleName          string    `json:"middle_name,omitempty"`
	Profile             string    `json:"profile,omitempty"`
	Picture             string    `json:"picture,omitempty"`
	Email               string    `json:"email,omitempty"`
	EmailVerified       bool      `json:"email_verified,omitempty"`
	Gender              string    `json:"gender,omitempty"`
	Birthdate           string    `json:"birthdate,omitempty"`
	PhoneNumber         string    `json:"phone_number,omitempty"`
	PhoneNumberVerified bool      `json:"phone_number_verified,omitempty"`
	Address             Address   `json:"address,omitempty"`
	UpdateAt            time.Time `json:"updated_at,omitempty"`
}
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}*/
