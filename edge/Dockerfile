FROM nginx:1.30.6-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY html /usr/share/nginx/html
HEALTHCHECK --interval=20s --timeout=5s CMD wget -q -O /dev/null http://127.0.0.1/_health || exit 1
