FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/zandu-forwarder ./cmd/zandu-forwarder \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/zandu-forwarder /usr/local/bin/zandu-forwarder
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV ZANDU_CONFIG=/data/forwarder.json \
    ZANDU_LISTEN=:8080 \
    ZANDU_ADMIN_LISTEN=:8081
VOLUME /data
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/zandu-forwarder"]
