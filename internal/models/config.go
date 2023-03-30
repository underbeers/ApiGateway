package models

type Config struct {
	Listen struct {
		Port string `json:"port"`
		IP   string `json:"ip"`
	} `json:"listen"`
	Services []Service `json:"services"`
}
