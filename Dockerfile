# Build Stage
FROM golang:1.25-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /app-http ./cmd/server/main.go

# Runtime Stage
FROM alpine:3.19
RUN apk add --no-cache bash openssl
WORKDIR /app
COPY ./web ./web
COPY scripts/gen-keys.sh ./scripts/gen-keys.sh
RUN chmod +x ./scripts/gen-keys.sh
COPY --from=builder /app-http .
RUN chmod +x ./app-http

ENTRYPOINT [ "/bin/sh", "-c", "./scripts/gen-keys.sh && ./app-http" ]