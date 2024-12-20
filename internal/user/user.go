package user

import "github.com/google/uuid"

type User struct {
	ID        string
	Username  string
	Password  Password
	LastLogin int64
}

func (u User) CheckPassword(password []byte) bool {
	return u.Password.Verify(password)
}

var emptyUser *User

func EmptyUser() User {
	if emptyUser == nil {
		emptyUser = &User{
			ID:       uuid.Nil.String(),
			Username: "",
			Password: NewDummyPassword(),
		}
	}
	return *emptyUser
}
