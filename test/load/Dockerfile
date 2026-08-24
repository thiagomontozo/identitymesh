FROM golang:1.26.6-alpine3.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY test/load ./test/load
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/identitymesh-load ./test/load
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/identitymesh-load /identitymesh-load
USER nonroot:nonroot
ENTRYPOINT ["/identitymesh-load"]
