FROM golang:1.25.7-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -buildid=" \
    -o /out/password-verifier \
    ./cmd/password-verifier

FROM alpine:3.23.3

WORKDIR /app

ENV GO_ENV=production
ENV VERIFIER_ADDR=0.0.0.0:7499

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/password-verifier /app/password-verifier

EXPOSE 7499

RUN adduser -D -u 1000 appuser && chown -R 1000:1000 /app
USER 1000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:7499/healthz >/dev/null || exit 1

CMD ["./password-verifier"]
