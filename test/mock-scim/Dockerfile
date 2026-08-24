FROM golang:1.26.6-alpine3.23 AS build
WORKDIR /src
COPY test/mock-scim/go.mod ./
COPY test/mock-scim/main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mock-scim .
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mock-scim /mock-scim
EXPOSE 8090
USER nonroot:nonroot
ENTRYPOINT ["/mock-scim"]
