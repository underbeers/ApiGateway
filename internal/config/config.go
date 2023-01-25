package config

import (
	"ApiGateway/internal/models"
	"fmt"
	"go.uber.org/zap"
	"log"

	"github.com/ilyakaznacheev/cleanenv"
)

const (
	cantReadFile        = "can't read file "
	defaultServicesList = "default_services"
	servicesList        = "services"
)

func GetConfig(isLocal bool) *models.Config {
	logger, _ := zap.NewProduction()
	logger.Info("Read application config")
	instance := &models.Config{IsLocal: isLocal}
	configType := getConfigType(instance.IsLocal)
	if err := cleanenv.ReadConfig(fmt.Sprintf("./conf/%s.json", configType), instance); err != nil {
		help, _ := cleanenv.GetDescription(instance, nil)
		logger.Info(help)
		logger.Fatal(cantReadFile+"./conf/%s.json"+configType, zap.Error(err))
	}

	return instance
}

func getConfigType(isLocal bool) string {
	if isLocal {
		return "local"
	}

	return "config"
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
