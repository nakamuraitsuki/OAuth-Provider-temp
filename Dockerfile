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
WORKDIR /app
COPY --from=builder /app/web ./web
COPY --from=builder /app-http .
RUN chmod +x ./app-http

ENTRYPOINT [ "./app-http" ]