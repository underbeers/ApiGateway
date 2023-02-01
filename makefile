build_image:
	docker build -t rodmul/pl_api_gateway:v1 .
run:
	docker run -d -p 6000:6000 --name=pl_gateway --mount type=bind,source="$(shell pwd)"/logs,target=/root/logs --mount type=bind,source="$(shell pwd)"/conf,target=/root/conf rodmul/pl_api_gateway:v1
local:
	go build -o . cmd/main.go
	./main --use_local_config
