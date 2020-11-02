#!/usr/bin/env bash

echo "Remove Development Tools"
dnf groupremove "Development Tools" -y

echo "Remove HTPPD"
dnf remove @httpd -y

echo "Remove mariadb"
dnf remove @mariadb -y

echo "Remove Dependencies"
dnf remove gcc zip \
        httpd \
        mod_ssl \
        redis \
        mariadb \
        mariadb-server \
        python3-devel python3-pip python3-virtualenv \
        python3-policycoreutils \
        policycoreutils-python-utils \
        libxslt-devel zlib-devel -y

echo "Remove Php & Dependencies"					 
dnf remove php php-fpm php-devel php-pear \
        php-mysqlnd \
        php-ssdeep \
        php-intl \
        php-mbstring \
        php-xml \
        php-bcmath \
        php-opcache \
        php-pecl-redis5 \
        php-json \
        php-zip \
        php-gd -y

echo "Delete local direcotory"
userdel misp
rm -rf /var/lib/mariadb
rm -rf /var/lib/mysql/
rm -rf /etc/my.cnf.d/
rm -rf /home/misp
rm -rf /usr/share/mariadb
rm -rf /etc/httpd
rm -rf /etc/php-fpm.d
rm -rf /etc/php.d
rm -rf /var/log/httpd/
rm -rf /var/log/php-fpm/
rm -rf /var/log/mariadb/

ldconfig

echo "Reboot"
reboot
