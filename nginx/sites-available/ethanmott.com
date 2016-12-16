server {
    server_name             ethanmott.com www.ethanmott.com;

    listen                  [::]:80;
    listen                  80;

    include                 boilerplate/disable/logging.conf;

    return                  301 https://ethanmott.com$request_uri;
}

server {
    server_name             www.ethanmott.com

    listen                  [::]:443 ssl http2;
    listen                  443 ssl http2;

    include                 boilerplate/enable/ssl.conf;

    return                  301 https://ethanmott.com$request_uri;
}

server {
    server_name             ethanmott.com 127.0.0.1 localhost;

    listen                  [::]:443 ssl http2;
    listen                  443 ssl http2;

    include                 boilerplate/enable/ssl.conf;
    #ssl_certificate         /etc/nginx/certs/fullchain.pem;
    #ssl_certificate_key     /etc/nginx/certs/privkey.pem;

    root                    /var/www/ethanmott.com/;

    include                 boilerplate/enable/uploads.conf;
    include                 boilerplate/enable/gzip.conf;

    include                 boilerplate/limits/methods.conf;
    include                 boilerplate/limits/requests.conf;

    access_log              /var/log/nginx/ethanmott.com.bots.log main if=$is_bot; #buffer=10k flush=1m;
    access_log              /var/log/nginx/ethanmott.com.access.log main if=!$is_bot; #buffer=10k flush=1m;
    error_log               /var/log/nginx/ethanmott.com.error.log error;

    include                 boilerplate/locations/letsencrypt.conf;
    include                 boilerplate/locations/system.conf;
    include                 boilerplate/locations/errors.conf;
    include                 boilerplate/locations/static.conf;

    add_header              Content-Security-Policy "default-src 'self' https://maxcdn.bootstrapcdn.com";
}