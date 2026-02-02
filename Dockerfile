FROM docker.io/falcosecurity/falco:0.43.0 AS falco
COPY --from=docker.io/falcosecurity/falcoctl:0.12.2 /bin/falcoctl /usr/bin/falcoctl

FROM docker.io/library/golang:1.25-alpine AS builder
RUN apk add --no-cache git just
WORKDIR /app
COPY . .
RUN just build && mv -v build/falco-validator* /app/falco-validator

FROM falco
COPY --from=builder /app/falco-validator* /usr/bin/falco-validator
ENTRYPOINT ["falco-validator"]
