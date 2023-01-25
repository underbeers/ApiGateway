package main

import (
	"ApiGateway/internal/api"
	"ApiGateway/internal/config"
	"flag"
	"go.uber.org/zap"
)

func main() {
	isLocalFlag := flag.Bool("use_local_config", false, "use for starting locally in debug mode")
	flag.Parse()
	cfg := config.GetConfig(*isLocalFlag)
	gateWay := api.NewGateWay(cfg)
	err := gateWay.Start()
	if err != nil {
		gateWay.Logger.Fatal("Can't start gateway api", zap.Error(err))
	}
}
