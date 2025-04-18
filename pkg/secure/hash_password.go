package secure

import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 8)
	return string(bytes), err
}

func CheckPassword(password, toBeVerified string) error {
	return bcrypt.CompareHashAndPassword([]byte(password), []byte(toBeVerified))
}
