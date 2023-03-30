package config

import (
	"ApiGateway/internal/models"
	"fmt"
	"log"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
)

const (
	cantReadFile        = "can't read file "
	defaultServicesList = "default_services"
	servicesList        = "services"
)

func GetConfig() *models.Config {
	instance := &models.Config{}
	instance.Listen.IP = getEnv("GATEWAY_IP", "")
	instance.Listen.Port = getEnv("GATEWAY_PORT", "")

	return instance
}

func getEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return defaultVal
}

func ReadServicesList() *models.ServiceList {
	instance := &models.ServiceList{}
	err := cleanenv.ReadConfig(fmt.Sprintf("%s.json", servicesList), instance)
	if err != nil {
		log.Fatalf(cantReadFile+servicesList+" %s", err.Error())
	}

	// if services.json is empty, we fill ServiceList with default services info
	if len(instance.ServiceList) == 0 {
		err := cleanenv.ReadConfig(fmt.Sprintf("%s.json", defaultServicesList), instance)
		if err != nil {
			log.Fatalf(cantReadFile+defaultServicesList+" %s", err.Error())
		}
	}

	return instance
}
