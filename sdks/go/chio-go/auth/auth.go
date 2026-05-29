package auth

type StaticBearer struct {
	AuthToken string
}

func StaticBearerToken(authToken string) StaticBearer {
	return StaticBearer{AuthToken: authToken}
}
