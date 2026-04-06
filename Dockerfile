FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -o /app/bin/app ./cmd/cli

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/bin/app .
COPY --from=builder /app/workflows ./workflows
COPY --from=builder /app/runtime ./runtime

CMD ["./app"]
