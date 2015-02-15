package server

import (
	"errors"

	ss "github.com/fym201/shadowsocks-go/shadowsocks"
)

type Config struct {
	Name     string `json:"name"`     //The server name,if empty set it to [address]
	Ip       string `json:"ip"`       //The server ip address to listen
	Port     string `json:"port"`     //The server port to listen
	Password string `json:"password"` //The Cipher password
	Method   string `json:"method"`   //The Cipher method
}

//Full address [Ip + : + Port]
func (c *Config) Address() string {
	return c.Ip + ":" + c.Port
}

func CheckConfig(config *Config) (err error) {
	if config == nil {
		err = errors.New("config is nil")
		return
	}

	if config.Port == "" {
		err = errors.New("the port can not empty")
		return
	}

	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}

	if config.Name == "" {
		config.Name = config.Address()
	}

	if err = ss.CheckCipherMethod(config.Method); err != nil {
		return
	}
	return
}
