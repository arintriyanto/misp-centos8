#!/bin/bash
#export RUN_PYTHON='/usr/bin/scl enable rh-python36 '
#export RUN_MYSQL='/usr/bin/scl enable rh-mariadb101 '
export RUN_PHP='/usr/bin/php '
export PHP_INI="/etc/php.ini"
export max_execution_time='300'
export memory_limit='2048M'
export upload_max_filesize='50M'
export post_max_size='50M'
export MISP_USER='misp'
export MISP_PASSWORD="$(openssl rand -hex 32)"
export PATH_TO_MISP='/var/www/MISP'
export CAKE="$PATH_TO_MISP/app/Console/cake"
export HOSTNAME='misp.local'
export FQDN='misp.local'
export MISP_BASEURL='http://10.25.15.154'
export MISP_LIVE='1'
export DBHOST='localhost'
export DBNAME='misp'
export DBUSER_ADMIN='root'
export DBPASSWORD_ADMIN="$(openssl rand -hex 32)"
export DBUSER_MISP='misp'
export DBPASSWORD_MISP="$(openssl rand -hex 32)"
export OPENSSL_CN='Common Name'
export OPENSSL_C='LU'
export OPENSSL_ST='State'
export OPENSSL_L='Location'
export OPENSSL_O='Organization'
export OPENSSL_OU='Organizational Unit'
export OPENSSL_EMAILADDRESS='info@localhost'
export GPG_REAL_NAME='Autogenerated Key'
export GPG_COMMENT='WARNING: MISP AutoGenerated Key consider this Key VOID!'
export GPG_EMAIL_ADDRESS='admin@admin.test'
export GPG_KEY_LENGTH='2048'
export GPG_PASSPHRASE='Password1234'
export OPENSSL_CN=${FQDN}
export OPENSSL_C='LU'
export OPENSSL_ST='State'
export OPENSSL_L='Location'
export OPENSSL_O='Organization'
export OPENSSL_OU='Organizational Unit'
export OPENSSL_EMAILADDRESS="info@${FQDN}"
export WWW_USER="apache"
export SUDO_WWW="sudo -H -u $WWW_USER"
export SUDO_CMD="sudo -H -u ${MISP_USER}"
echo "Admin (root) DB Password: $DBPASSWORD_ADMIN"
echo "User  (misp) DB Password: $DBPASSWORD_MISP"