#!/usr/bin/env bash

echo "Remove Development Tools"
sleep 2
dnf groupremove "Development Tools" -y

echo "Remove HTPPD"
sleep 2
dnf remove @httpd -y

echo "Remove mariadb"
sleep 2
dnf remove @mariadb -y

echo "Remove Dependencies"
sleep 2
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
sleep 2			 
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
sleep 2
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

# if you need to clean - remove all directory /var/www/MISP, but need to to build everything again, long time to waiting build LIEF
# rm -rf /var/www/MISP
sleep 2
ldconfig

echo "Reboot"
sleep 2
reboot
