# syntax=docker/dockerfile:1
FROM golang:alpine AS builder

RUN apk add --no-cache git

ARG TARGETPLATFORM

ENV CGO_ENABLED=0

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN go build -ldflags="-s -w" -o auth-server .

FROM alpine

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/auth-server .

ENTRYPOINT ["/app/auth-server"]
