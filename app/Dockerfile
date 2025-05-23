# Build
FROM --platform=$BUILDPLATFORM golang:1.24.2 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

# Create the user not root (UID/GID 1000)
RUN echo "nonroot:x:1000:1000:nonroot:/:" > /etc/passwd && \
    echo "nonroot:x:1000:" > /etc/group && \
    chmod 644 /etc/passwd /etc/group

# Build the multi-arch binary
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-s -w" -trimpath -o main .

# Runtime
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /app/main .
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

USER nonroot:nonroot

EXPOSE 50051

ENTRYPOINT ["./main"]