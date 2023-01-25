package models

type Config struct {
	IsLocal bool `json:"isLocal"`
	Listen  struct {
		Port string `json:"port"`
		IP   string `json:"ip"`
	} `json:"listen"`
	Services []Service `json:"services"`
}
