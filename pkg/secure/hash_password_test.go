package secure

import (
	"strings"
	"testing"
)

func TestHashAndCheckPassword(t *testing.T) {
	plainPassword := "SuperSecret123!"

	// Хешируем пароль
	hashed, err := HashPassword(plainPassword)
	if err != nil {
		t.Fatalf("Error hashing password: %v", err)
	}

	// Убедимся, что хеш не равен исходному паролю
	if hashed == plainPassword {
		t.Fatalf("Hashed password should not equal the plain password")
	}

	// Проверяем, что хеш начинается с ожидаемого префикса bcrypt
	if !strings.HasPrefix(hashed, "$2a$") && !strings.HasPrefix(hashed, "$2b$") && !strings.HasPrefix(hashed, "$2y$") {
		t.Errorf("Hashed password has unexpected prefix: %s", hashed[:4])
	}

	// Проверяем, что функция CheckPassword возвращает nil для корректного пароля
	if err := CheckPassword(hashed, plainPassword); err != nil {
		t.Errorf("CheckPassword failed for correct password: %v", err)
	}

	// Проверяем, что для неверного пароля возвращается ошибка
	if err := CheckPassword(hashed, "WrongPassword"); err == nil {
		t.Errorf("CheckPassword succeeded for wrong password")
	}
}

func TestCheckPassword_InvalidHash(t *testing.T) {
	// Передаем некорректный хеш
	invalidHash := "not_a_valid_hash"
	err := CheckPassword(invalidHash, "anything")
	if err == nil {
		t.Errorf("Expected error when comparing with an invalid hash")
	}
}
