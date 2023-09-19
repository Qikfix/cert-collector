#!/bin/bash

#
# Disclaimer .: This script doesn't intend to be supported or responsability of Red Hat, this is an
#               independent initiative that will help for sure any Satellite case related to certs/ssl
# date .......: 09/18/2023
# Developer ..: Waldirio M Pinheiro <waldirio@redhat.com>/<waldirio@gmail.com>
# License ....: GPLv3
#


if [ "$1" == "" ]; then
  echo "Please, execute '$0 --server', '$0 --capsule' or '$0 --content_host'"
  echo "exiting ..."
  exit 0
fi


LOG_DIR="/var/tmp/certs_log"


create_log_dir()
{
  if [ ! -d $LOG_DIR ]; then
    echo "Creating the dir $LOG_DIR"
    mkdir -pv $LOG_DIR
  else
    echo "dir $LOG_DIR already around"
  fi
}


#create_log_dir

server_func()
{
  LOG_SRV_FILE="/var/tmp/certs_full_server_info.log"
  > $LOG_SRV_FILE

  SRV_PORT_SSH="22"
  SRV_PORT_DB="5432"
  SRV_PORT_SMART_PROXY="9009"
  SRV_PORT_REDIS="6379"
  SRV_PORT_HTTP="80"
  SRV_PORT_HTTPS="443"
  SRV_PORT_CP="23443"
  SRV_SERVER_SSL_CA="/etc/pki/katello/certs/katello-default-ca.crt"
  SRV_SERVER_SSL_CERT="/etc/pki/katello/certs/katello-apache.crt"
  SRV_SERVER_ANCHORS_DIR="/etc/pki/ca-trust/source/anchors/"

  echo "# Server" | tee -a $LOG_SRV_FILE


  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the connection to cdn.redhat.com using the redhat-uep cert" | tee -a $LOG_SRV_FILE
  echo "# echo | openssl s_client -connect cdn.redhat.com:443 -CAfile /etc/rhsm/ca/redhat-uep.pem -showcerts" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  echo | openssl s_client -connect cdn.redhat.com:443 -CAfile /etc/rhsm/ca/redhat-uep.pem -showcerts &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the connection to subscription.rhsm.redhat.com using the redhat-uep cert" | tee -a $LOG_SRV_FILE
  echo "# openssl s_client -connect subscription.rhsm.redhat.com:443 -CAfile /etc/rhsm/ca/redhat-uep.pem -showcerts" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  echo | openssl s_client -connect subscription.rhsm.redhat.com:443 -CAfile /etc/rhsm/ca/redhat-uep.pem -showcerts &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the connection to subscription.rhsm.redhat.com using the redhat-uep cert enabling debug" | tee -a $LOG_SRV_FILE
  echo "# openssl s_client -connect subscription.rhsm.redhat.com:443 -CAfile /etc/rhsm/ca/redhat-uep.pem -showcerts -debug" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  echo | openssl s_client -connect subscription.rhsm.redhat.com:443 -CAfile /etc/rhsm/ca/redhat-uep.pem -showcerts -debug &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the subscription.rhsm.redhat.com head using curl" | tee -a $LOG_SRV_FILE
  echo "# curl -vvv --head --cacert /etc/rhsm/ca/redhat-uep.pem https://subscription.rhsm.redhat.com" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  curl -vvv --head --cacert /etc/rhsm/ca/redhat-uep.pem https://subscription.rhsm.redhat.com &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the cdn.redhat.com head using curl" | tee -a $LOG_SRV_FILE
  echo "# curl -vvv --head --cacert /etc/rhsm/ca/redhat-uep.pem https://cdn.redhat.com" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  curl -vvv --head --cacert /etc/rhsm/ca/redhat-uep.pem https://cdn.redhat.com &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE

  #echo | tee -a $LOG_SRV_FILE
  #echo "# Checking XXX" | tee -a $LOG_SRV_FILE
  #echo "# COMMAND_HERE" | tee -a $LOG_SRV_FILE
  #echo "=====" >> $LOG_SRV_FILE
  #COMMAND_HERE &>> $LOG_SRV_FILE
  ##nmap --script  ssl-enum-ciphers -p 443 subscription.rhsm.redhat.com
  #echo "=====" >> $LOG_SRV_FILE


  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the Apache Cert" | tee -a $LOG_SRV_FILE
  echo "# echo | openssl s_client -connect $(hostname):$SRV_PORT_HTTPS" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  echo | openssl s_client -connect $(hostname):$SRV_PORT_HTTPS &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the Apache response using - $SRV_SERVER_SSL_CA" | tee -a $LOG_SRV_FILE
  echo "# curl -vvv --cacert $SRV_SERVER_SSL_CA https://$(hostname):$SRV_PORT_HTTPS" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  curl -vvv --cacert $SRV_SERVER_SSL_CA https://$(hostname):$SRV_PORT_HTTPS &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the Apache response using - $SRV_SERVER_SSL_CERT" | tee -a $LOG_SRV_FILE
  echo "# curl -vvv --cacert $SRV_SERVER_SSL_CERT https://$(hostname):$SRV_PORT_HTTPS" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  curl -vvv --cacert $SRV_SERVER_SSL_CERT https://$(hostname):$SRV_PORT_HTTPS &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the Candlepin Cert" | tee -a $LOG_SRV_FILE
  echo "# echo | openssl s_client -connect localhost:$SRV_PORT_CP" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  echo | openssl s_client -connect localhost:$SRV_PORT_CP &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  
  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the Candlepin endpoint" | tee -a $LOG_SRV_FILE
  echo "# curl -s https://localhost:$SRV_PORT_CP/candlepin/status | python3 -m json.tool" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  curl -s https://localhost:$SRV_PORT_CP/candlepin/status | python3 -m json.tool &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the anchors dir" | tee -a $LOG_SRV_FILE
  echo "# ls -l /etc/pki/ca-trust/source/anchors/" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  ls -l /etc/pki/ca-trust/source/anchors/ &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  
  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the certs content under anchors dir" | tee -a $LOG_SRV_FILE
  echo "# for b in \$(ls -1 $SRV_SERVER_ANCHORS_DIR); do echo - \$b;openssl x509 -in $SRV_SERVER_ANCHORS_DIR/\$b -text -noout; done" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  for b in $(ls -1 $SRV_SERVER_ANCHORS_DIR); do echo - $b;openssl x509 -in $SRV_SERVER_ANCHORS_DIR/$b -text -noout; done &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the certs set in answer file" | tee -a $LOG_SRV_FILE
  echo "# grep cert /etc/foreman-installer/scenarios.d/satellite-answers.yaml" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  grep cert /etc/foreman-installer/scenarios.d/satellite-answers.yaml &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the bundle certs" | tee -a $LOG_SRV_FILE
  echo "# awk -v cmd='openssl x509 -noout -subject -issuer -dates' ' /BEGIN/{close(cmd)};{print | cmd}' <  /etc/pki/tls/certs/ca-bundle.crt" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  awk -v cmd='openssl x509 -noout -subject -issuer -dates' ' /BEGIN/{close(cmd)};{print | cmd}' <  /etc/pki/tls/certs/ca-bundle.crt &>> $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE



  #curl -s -v --header "Content-Type:application/json" --request GET --cacert /etc/pki/katello/certs/katello-server-ca.crt https://$(hostname)/katello/api/status | python3 -m json.tool
  echo
  echo "Please, check the file $LOG_SRV_FILE for the complete information"
}

capsule_func()
{
  echo "capsule"
}

ch_func()
{
  echo "content host"
}

case $1 in
  "--server")
    server_func
    ;;
  "--capsule")
    capsule_func
    ;;
  "--content_host")
    ch_func
    ;;
  *) echo -e "Option not available\nexiting ..."
    ;;
esac
