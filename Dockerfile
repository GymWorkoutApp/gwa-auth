# Build Multstage
# Builder
FROM golang:alpine as builder
WORKDIR /go/src/github.com/GymWorkoutApp/gwa_auth
ADD . /go/src/github.com/GymWorkoutApp/gwa_auth
RUN apk add --update --no-cache \
    tzdata \
    git \
    glide \
    ca-certificates && \
    update-ca-certificates && \
    cp /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime && \
    echo "America/Sao_Paulo" > /etc/timezone && \
    glide install && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o gwa_auth .

# Final image
FROM alpine:3.8
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /go/src/github.com/GymWorkoutApp/gwa_auth .
ENTRYPOINT ["sh", "app.sh", "./gwa_auth"]