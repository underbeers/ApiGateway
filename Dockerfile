FROM golang:1.18-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . ./

RUN go build -o ./api_gateway ./cmd/main.go

EXPOSE 6000

ENV GATEWAY_IP=$GATEWAY_IP
ENV GATEWAY_PORT=$GATEWAY_PORT

CMD [ "./api_gateway" ]