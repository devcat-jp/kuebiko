# --- Build stage -----------------------------------------------------------
FROM golang:1.26-alpine AS build

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /kuebiko .

# --- Runtime stage ---------------------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 1000 kuebiko

COPY --from=build /kuebiko /usr/local/bin/kuebiko

USER kuebiko

ENV APP_HOST=0.0.0.0 \
    APP_PORT=8080 \
    APP_DATA_DIR=/data

EXPOSE 8080

ENTRYPOINT ["kuebiko"]
