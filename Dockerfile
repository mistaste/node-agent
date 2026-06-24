FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOFLAGS="" go build -ldflags="-checklinkname=0" -o node-agent .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates docker-cli docker-cli-compose git
COPY --from=builder /app/node-agent /usr/local/bin/node-agent
EXPOSE 8099
CMD ["node-agent"]
