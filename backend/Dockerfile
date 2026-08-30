FROM golang:1.27.0-alpine3.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY backend ./backend
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/identitymesh ./backend/cmd/server
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/identitymesh-healthcheck ./backend/cmd/healthcheck
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/identitymesh /app/identitymesh
COPY --from=build /out/identitymesh-healthcheck /app/identitymesh-healthcheck
COPY migrations /app/migrations
ENV IDENTITYMESH_MIGRATIONS_DIR=/app/migrations
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/identitymesh"]
