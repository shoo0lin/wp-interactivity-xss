#!/usr/bin/env bash
# Provision a throwaway WordPress 7.1.2 lab for this PoC.
#
# LAB ONLY. Creates two containers on 127.0.0.1:18080 with known lab passwords.
# Do not expose this port to the internet.
#
#   ./docker/provision.sh
#
# Override any value with an environment variable before running.
set -euo pipefail

WP_PORT="${WP_PORT:-18080}"
WP_ADMIN_USER="${WP_ADMIN_USER:-bindadmin}"
WP_ADMIN_PASS="${WP_ADMIN_PASS:-labadminpass}"
WP_ADMIN_EMAIL="${WP_ADMIN_EMAIL:-bindadmin@example.lab}"
WP_AUTHOR_USER="${WP_AUTHOR_USER:-author}"
WP_AUTHOR_PASS="${WP_AUTHOR_PASS:-labauthorpass}"
WP_AUTHOR_EMAIL="${WP_AUTHOR_EMAIL:-author@example.lab}"
WP_DB_PASS="${WP_DB_PASS:-wppw}"
WP_DB_ROOT_PASS="${WP_DB_ROOT_PASS:-rootpw}"

echo "[*] network"
docker network create wplab 2>/dev/null || echo "    network exists"

echo "[*] database"
if ! docker inspect wpdb >/dev/null 2>&1; then
  docker run -d --name wpdb --network wplab \
    -e MARIADB_ROOT_PASSWORD="$WP_DB_ROOT_PASS" \
    -e MARIADB_DATABASE=wp \
    -e MARIADB_USER=wpuser \
    -e MARIADB_PASSWORD="$WP_DB_PASS" \
    mariadb:11 >/dev/null
  echo "    waiting for mariadb"
  for _ in $(seq 1 30); do
    if docker exec wpdb bash -c "mariadb -uroot -p'$WP_DB_ROOT_PASS' -e 'SELECT 1;'" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
else
  echo "    wpdb exists"
fi

echo "[*] wordpress container"
if ! docker inspect wpsite >/dev/null 2>&1; then
  docker run -d --name wpsite --network wplab -p "127.0.0.1:${WP_PORT}:8080" \
    -e WORDPRESS_DB_HOST=wpdb -e WORDPRESS_DB_NAME=wp \
    -e WORDPRESS_DB_USER=wpuser -e WORDPRESS_DB_PASSWORD="$WP_DB_PASS" \
    wordpress:cli-php8.3 sleep infinity >/dev/null
else
  echo "    wpsite exists"
fi

echo "[*] install WordPress 7.1.2 + theme"
docker exec -u 0 wpsite bash -c "
  set -e
  cd /var/www/html
  if ! wp core is-installed --allow-root >/dev/null 2>&1; then
    wp core download --version=7.1.2 --force --allow-root
    wp core install \
      --url=http://127.0.0.1:${WP_PORT} \
      --title=BindLab \
      --admin_user='${WP_ADMIN_USER}' \
      --admin_password='${WP_ADMIN_PASS}' \
      --admin_email='${WP_ADMIN_EMAIL}' \
      --skip-email --allow-root
  fi
  wp theme install twentytwentyfive --activate --allow-root
  if ! wp user get '${WP_AUTHOR_USER}' --allow-root >/dev/null 2>&1; then
    wp user create '${WP_AUTHOR_USER}' '${WP_AUTHOR_EMAIL}' \
      --role=author --user_pass='${WP_AUTHOR_PASS}' --allow-root
  fi
"

echo "[*] start the built-in server"
docker exec -u 0 -d wpsite bash -c \
  'cd /var/www/html && wp server --host=0.0.0.0 --port=8080 --allow-root' >/dev/null || true
sleep 2

echo "[*] verify"
curl -s -o /dev/null -w "    http://127.0.0.1:${WP_PORT}/ -> %{http_code}\n" \
  "http://127.0.0.1:${WP_PORT}/"
docker exec -u 0 wpsite bash -c \
  'sha256sum /var/www/html/wp-includes/js/dist/script-modules/interactivity/index.min.js'

echo
echo "Ready. Run:"
echo "  cd poc && python3 validate_xss.py"
