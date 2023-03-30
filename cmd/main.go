package main

import (
	"ApiGateway/internal/api"
	"ApiGateway/internal/config"
	"go.uber.org/zap"
)

func main() {
	cfg := config.GetConfig()
	gateWay := api.NewGateWay(cfg)
	err := gateWay.Start()
	if err != nil {
		gateWay.Logger.Fatal("Can't start gateway api", zap.Error(err))
	}
}
