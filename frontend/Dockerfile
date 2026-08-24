FROM node:26.3.0-alpine3.22 AS build
WORKDIR /app
COPY frontend/package*.json ./
RUN --mount=type=secret,id=identitymesh_ca,required=false if [ -f /run/secrets/identitymesh_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/identitymesh_ca; fi; npm ci
COPY frontend .
ARG VITE_API_ORIGIN=
ENV VITE_API_ORIGIN=$VITE_API_ORIGIN
RUN npm run build
FROM build AS verify
RUN npm run lint && npm run typecheck && npm test -- --run
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
USER 101
