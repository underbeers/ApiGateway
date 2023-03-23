build_image:
	docker build -t rodmul/pl_api_gateway:v2 .
run:
	docker run -d -p 6002:6002 --name=pl_api_gateway --mount type=bind,source="$(shell pwd)"/logs,target=/root/logs --mount type=bind,source="$(shell pwd)"/conf,target=/root/conf -e GATEWAY_PORT='6002' -e GATEWAY_IP='127.0.0.1' rodmul/pl_api_gateway:v2
local:
	go build -o . cmd/main.go
	./main --use_local_config
