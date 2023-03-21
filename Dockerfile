FROM golang:1.18-alpine AS build

WORKDIR /build

COPY . .

RUN go mod download
RUN go build -o /build/api_gateway /build/cmd/main.go

FROM alpine:latest

WORKDIR /app

COPY ./conf ./conf
COPY ./services.json ./services.json
COPY ./default_services.json ./default_services.json
COPY --from=build /build/api_gateway .

ENV GATEWAY_IP=$GATEWAY_IP
ENV GATEWAY_PORT=$GATEWAY_PORT

EXPOSE $GATEWAY_PORT

CMD [ "./api_gateway" ]
