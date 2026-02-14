FROM nginx@sha256:5878d06ae4c83d73285438255f705bb3f9a736f41cd24876ed25bb33faf76c7d

# Generate self-signed TLS cert at build time (swap for real cert in production)
RUN apk add --no-cache openssl && \
    mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/sentinel.key \
    -out /etc/nginx/ssl/sentinel.crt \
    -subj "/CN=sentinel/O=Sentinel"

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY static/ /usr/share/nginx/html/
EXPOSE 8080 8443
