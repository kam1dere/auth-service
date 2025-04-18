package jwt

type GetDataFromTokenParams struct {
	Token string
}

type GetDataFromTokenResponse struct {
	UserId int64
}
type CreateTokenParams struct {
	UserId int64
}

type CreateTokenResponse struct {
	AccessToken  string
	RefreshToken string
}

type ValidateTokenParams struct {
	Token string
}
