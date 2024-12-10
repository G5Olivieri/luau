package user

type PasswordEncoder[T Password] interface {
	EncodeToString(password T) (string, error)
	DecodeFromString(password string) (T, error)
}
