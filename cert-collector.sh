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
TAR_FILE="/var/tmp/certs_log.tar"


create_log_dir()
{
  if [ ! -d $LOG_DIR ]; then
    echo "Creating the dir $LOG_DIR"
    mkdir -pv $LOG_DIR
  else
    echo "dir $LOG_DIR already around, cleaning up"
    rm -vf $LOG_DIR/*
  fi
}


create_log_dir

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
  echo | openssl s_client -connect cdn.redhat.com:443 -CAfile /etc/rhsm/ca/redhat-uep.pem -showcerts &>> $LOG_DIR/openssl_cdn_redhat_com_showcerts.log
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the connection to subscription.rhsm.redhat.com using the redhat-uep cert" | tee -a $LOG_SRV_FILE
  echo "# openssl s_client -connect subscription.rhsm.redhat.com:443 -CAfile /etc/rhsm/ca/redhat-uep.pem -showcerts" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  echo | openssl s_client -connect subscription.rhsm.redhat.com:443 -CAfile /etc/rhsm/ca/redhat-uep.pem -showcerts &>> $LOG_DIR/openssl_subscription_rhsm_redhat_com_showcerts.log
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the connection to subscription.rhsm.redhat.com using the redhat-uep cert enabling debug" | tee -a $LOG_SRV_FILE
  echo "# openssl s_client -connect subscription.rhsm.redhat.com:443 -CAfile /etc/rhsm/ca/redhat-uep.pem -showcerts -debug" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  echo | openssl s_client -connect subscription.rhsm.redhat.com:443 -CAfile /etc/rhsm/ca/redhat-uep.pem -showcerts -debug &>> $LOG_DIR/openssl_subscription_rhsm_redhat_com_showcerts_debug.log
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the subscription.rhsm.redhat.com head using curl" | tee -a $LOG_SRV_FILE
  echo "# curl -vvv --head --cacert /etc/rhsm/ca/redhat-uep.pem https://subscription.rhsm.redhat.com" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  curl -vvv --head --cacert /etc/rhsm/ca/redhat-uep.pem https://subscription.rhsm.redhat.com &>> $LOG_DIR/curl_subscription_rhsm_redhat_com_verbose_head.log
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the cdn.redhat.com head using curl" | tee -a $LOG_SRV_FILE
  echo "# curl -vvv --head --cacert /etc/rhsm/ca/redhat-uep.pem https://cdn.redhat.com" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  curl -vvv --head --cacert /etc/rhsm/ca/redhat-uep.pem https://cdn.redhat.com &>> $LOG_DIR/curl_cdn_redhat_com_verbose_head.log
  echo "=====" >> $LOG_SRV_FILE

  #echo | tee -a $LOG_SRV_FILE
  #echo "# Checking XXX" | tee -a $LOG_SRV_FILE
  #echo "# COMMAND_HERE" | tee -a $LOG_SRV_FILE
  #echo "=====" >> $LOG_SRV_FILE
  #COMMAND_HERE &>> $LOG_SRV_FILE
  ##nmap --script  ssl-enum-ciphers -p 443 subscription.rhsm.redhat.com
  #echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the CP Cert" | tee -a $LOG_SRV_FILE
  echo "# echo | openssl s_client -connect localhost:$SRV_PORT_CP" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  echo | openssl s_client -connect localhost:$SRV_PORT_CP &>> $LOG_DIR/openssl_localhost_$SRV_PORT_cp.log
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the CP response" | tee -a $LOG_SRV_FILE
  echo "# curl -vvv https://localhost:$SRV_PORT_CP" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  curl -vvv https://localhost:$SRV_PORT_CP &>> $LOG_DIR/curl_localhost_${SRV_PORT_CP}.log
  echo "=====" >> $LOG_SRV_FILE



  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the Apache Cert" | tee -a $LOG_SRV_FILE
  echo "# echo | openssl s_client -connect $(hostname -f):$SRV_PORT_HTTPS" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  echo | openssl s_client -connect $(hostname -f):$SRV_PORT_HTTPS &>> $LOG_DIR/openssl_$(hostname -f)_$SRV_PORT_HTTPS.log
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the Apache response using - $SRV_SERVER_SSL_CA" | tee -a $LOG_SRV_FILE
  echo "# curl -vvv --cacert $SRV_SERVER_SSL_CA https://$(hostname -f):$SRV_PORT_HTTPS" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  curl -vvv --cacert $SRV_SERVER_SSL_CA https://$(hostname -f):$SRV_PORT_HTTPS &>> $LOG_DIR/curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_ca.log
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the Apache response using - $SRV_SERVER_SSL_CERT" | tee -a $LOG_SRV_FILE
  echo "# curl -vvv --cacert $SRV_SERVER_SSL_CERT https://$(hostname):$SRV_PORT_HTTPS" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  curl -vvv --cacert $SRV_SERVER_SSL_CERT https://$(hostname):$SRV_PORT_HTTPS &>> $LOG_DIR/curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_server.log
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the Candlepin Cert" | tee -a $LOG_SRV_FILE
  echo "# echo | openssl s_client -connect localhost:$SRV_PORT_CP" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  echo | openssl s_client -connect localhost:$SRV_PORT_CP &>> $LOG_DIR/openssl_localhost_${SRV_PORT_CP}.log
  echo "=====" >> $LOG_SRV_FILE
  
  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the Candlepin endpoint" | tee -a $LOG_SRV_FILE
  echo "# curl -s https://localhost:$SRV_PORT_CP/candlepin/status | python3 -m json.tool" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  curl -s https://localhost:$SRV_PORT_CP/candlepin/status | python3 -m json.tool &>> $LOG_DIR/curl_localhost_${SRV_PORT_CP}_candlepin_status.log
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the anchors dir" | tee -a $LOG_SRV_FILE
  echo "# ls -l /etc/pki/ca-trust/source/anchors/" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  ls -l /etc/pki/ca-trust/source/anchors/ &>> $LOG_DIR/list_of_files_under_anchors.log
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
  grep cert /etc/foreman-installer/scenarios.d/satellite-answers.yaml &>> $LOG_DIR/cert_entries_satellite-answers_yaml.log
  echo "=====" >> $LOG_SRV_FILE

  echo | tee -a $LOG_SRV_FILE
  echo "# Checking the bundle certs" | tee -a $LOG_SRV_FILE
  echo "# awk -v cmd='openssl x509 -noout -subject -issuer -dates' ' /BEGIN/{close(cmd)};{print | cmd}' <  /etc/pki/tls/certs/ca-bundle.crt" | tee -a $LOG_SRV_FILE
  echo "=====" >> $LOG_SRV_FILE
  awk -v cmd='openssl x509 -noout -subject -issuer -dates' ' /BEGIN/{close(cmd)};{print | cmd}' <  /etc/pki/tls/certs/ca-bundle.crt &>> $LOG_DIR/info_ca-bundle_crt.log
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

report()
{
  type=$1
  if [ "$1" == "server" ]; then


      ## SUBSCRIPTION_RHSM_REDHAT_COM
      # =============================
      # Checking the openssl_subscription_rhsm_redhat_com_showcerts.log file
      # ---
      check_verification=$(grep "^Verification: OK" $LOG_DIR/openssl_subscription_rhsm_redhat_com_showcerts.log | wc -l)
      check_verification_return_code=$(grep "^    Verify return code: 0 (ok)" $LOG_DIR/openssl_subscription_rhsm_redhat_com_showcerts.log | wc -l)

      if [ "$check_verification" -eq 1 ] && [ "$check_verification_return_code" -eq 1 ]; then
        check_response__openssl_subscription_rhsm_redhat_com_showcerts="OK"
      else
        check_response__openssl_subscription_rhsm_redhat_com_showcerts="FAIL"
      fi
      # ---

      # Checking the curl_subscription_rhsm_redhat_com_verbose_head.log file
      # ---
      check_set_cert_ver_loc=$(grep "^* successfully set certificate verify locations:" $LOG_DIR/curl_subscription_rhsm_redhat_com_verbose_head.log | wc -l)
      check_set_cert_path=$(grep "^*   CAfile: /etc/rhsm/ca/redhat-uep.pem" $LOG_DIR/curl_subscription_rhsm_redhat_com_verbose_head.log | wc -l)
      check_san_matches=$(grep "^*  subjectAltName: host \"subscription.rhsm.redhat.com\" matched cert's \"subscription.rhsm.redhat.com\"" $LOG_DIR/curl_subscription_rhsm_redhat_com_verbose_head.log | wc -l)
      check_ssl_cert_ver=$(grep "^*  SSL certificate verify ok." $LOG_DIR/curl_subscription_rhsm_redhat_com_verbose_head.log | wc -l)

      if [ "$check_set_cert_ver_loc" -eq 1 ] && [ "$check_set_cert_path" -eq 1 ] && [ "$check_san_matches" -eq 1 ] && [ "$check_ssl_cert_ver" -eq 1 ]; then
        check_response__curl_subscription_rhsm_redhat_com_verbose_head="OK"
      else
        check_response__curl_subscription_rhsm_redhat_com_verbose_head="FAIL"
      fi
      # ---
      # =============================


      ## CDN_REDHAT_COM
      # =============================
      # Checking the openssl_cdn_redhat_com_showcerts.log file
      # ---
      check_verification=$(grep "^Verification: OK" $LOG_DIR/openssl_cdn_redhat_com_showcerts.log | wc -l)
      check_verification_return_code=$(grep "^Verify return code: 0 (ok)" $LOG_DIR/openssl_cdn_redhat_com_showcerts.log | wc -l)

      if [ "$check_verification" -eq 1 ] && [ "$check_verification_return_code" -eq 1 ]; then
        check_response__openssl_cdn_redhat_com_showcerts="OK"
      else
        check_response__openssl_cdn_redhat_com_showcerts="FAIL"
      fi
      # ---

      # Checking the curl_cdn_redhat_com_verbose_head.log file
      # ---
      check_set_cert_ver_loc=$(grep "^* successfully set certificate verify locations:" $LOG_DIR/curl_cdn_redhat_com_verbose_head.log | wc -l)
      check_set_cert_path=$(grep "^*   CAfile: /etc/rhsm/ca/redhat-uep.pem" $LOG_DIR/curl_cdn_redhat_com_verbose_head.log | wc -l)
      check_san_matches=$(grep "^*  subjectAltName: host \"cdn.redhat.com\" matched cert's \"cdn.redhat.com\"" $LOG_DIR/curl_cdn_redhat_com_verbose_head.log | wc -l)
      check_ssl_cert_ver=$(grep "^*  SSL certificate verify ok." $LOG_DIR/curl_cdn_redhat_com_verbose_head.log | wc -l)

      if [ "$check_set_cert_ver_loc" -eq 1 ] && [ "$check_set_cert_path" -eq 1 ] && [ "$check_san_matches" -eq 1 ] && [ "$check_ssl_cert_ver" -eq 1 ]; then
        check_response__curl_cdn_redhat_com_verbose_head="OK"
      else
        check_response__curl_cdn_redhat_com_verbose_head="FAIL"
      fi
      # ---
      # =============================


      ## CANDLEPIN
      # =============================
      # Checking the CP openssl_localhost_23443.log file
      # ---
      check_verification=$(grep "^Verification: OK" $LOG_DIR/openssl_localhost_23443.log | wc -l)
      check_verification_return_code=$(grep "^    Verify return code: 0 (ok)" $LOG_DIR/openssl_localhost_23443.log | wc -l)

      if [ "$check_verification" -eq 1 ] && [ "$check_verification_return_code" -eq 1 ]; then
        check_response__openssl_localhost_23443="OK"
      else
        check_response__openssl_localhost_23443="FAIL"
      fi
      # ---


      # Checking the curl_localhost_23443.log file
      # ---
      check_set_cert_ver_loc=$(grep "^* successfully set certificate verify locations:" $LOG_DIR/curl_localhost_23443.log | wc -l)
      check_set_cert_path=$(grep "^*   CAfile: /etc/pki/tls/certs/ca-bundle.crt" $LOG_DIR/curl_localhost_23443.log | wc -l)
      check_san_matches=$(grep "^*  subjectAltName: host \"localhost\" matched cert's \"localhost\"" $LOG_DIR/curl_localhost_23443.log | wc -l)
      check_ssl_cert_ver=$(grep "^*  SSL certificate verify ok." $LOG_DIR/curl_localhost_23443.log | wc -l)
      check_cp_mode=$(grep "^    \"mode\": \"NORMAL\"," $LOG_DIR/curl_localhost_23443_candlepin_status.log | wc -l)

      if [ "$check_set_cert_ver_loc" -eq 1 ] && [ "$check_set_cert_path" -eq 1 ] && [ "$check_san_matches" -eq 1 ] && [ "$check_ssl_cert_ver" -eq 1 ] && [ "$check_cp_mode" -eq 1 ]; then
        check_response__curl_localhost_23443="OK"
      else
        check_response__curl_localhost_23443="FAIL"
      fi
      # ---
      # =============================

      ## Satellite server - Apache 443 using server_ssl_ca
      # =============================
      # Checking the apache - openssl_$(hostname -f)_${SRV_PORT_HTTPS}.log file
      # ---
      check_verification=$(grep "^Verification: OK" $LOG_DIR/openssl_$(hostname -f)_${SRV_PORT_HTTPS}.log | wc -l)
      check_verification_return_code=$(grep "^Verify return code: 0 (ok)" $LOG_DIR/openssl_$(hostname -f)_${SRV_PORT_HTTPS}.log | wc -l)

      if [ "$check_verification" -eq 1 ] && [ "$check_verification_return_code" -eq 1 ]; then
        check_response__openssl_satserver_443="OK"
      else
        check_response__openssl_satserver_443="FAIL"
      fi
      # ---


      # Checking the curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_ca.log file
      # ---
      check_set_cert_ver_loc=$(grep "^* successfully set certificate verify locations:" $LOG_DIR/curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_ca.log | wc -l)
      check_set_cert_path=$(grep "^*   CAfile: /etc/pki/katello/certs/katello-default-ca.crt" $LOG_DIR/curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_ca.log | wc -l)
      check_san_matches=$(grep "^*  subjectAltName: host \"$(hostname -f)\" matched cert's \"$(hostname -f)\"" $LOG_DIR/curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_ca.log | wc -l)
      check_ssl_cert_ver=$(grep "^*  SSL certificate verify ok." $LOG_DIR/curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_ca.log | wc -l)

      if [ "$check_set_cert_ver_loc" -eq 1 ] && [ "$check_set_cert_path" -eq 1 ] && [ "$check_san_matches" -eq 1 ] && [ "$check_ssl_cert_ver" -eq 1 ]; then
        check_response__curl_satserver_443_using_server_ssl_ca="OK"
      else
        check_response__curl_satserver_443_using_server_ssl_ca="FAIL"
      fi
      # ---
      # =============================


      ## Satellite server - Apache 443 using server_ssl_server
      # =============================
      # TODO: Check if this should change as well from self signed to custom cert
      # Checking the apache - openssl_$(hostname -f)_${SRV_PORT_HTTPS}.log file
      # ---
      check_verification=$(grep "^Verification: OK" $LOG_DIR/openssl_$(hostname -f)_${SRV_PORT_HTTPS}.log | wc -l)
      check_verification_return_code=$(grep "^Verify return code: 0 (ok)" $LOG_DIR/openssl_$(hostname -f)_${SRV_PORT_HTTPS}.log | wc -l)

      if [ "$check_verification" -eq 1 ] && [ "$check_verification_return_code" -eq 1 ]; then
        check_response__openssl_satserver_443="OK"
      else
        check_response__openssl_satserver_443="FAIL"
      fi
      # ---


      # Checking the curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_server.log file
      # ---
      check_set_cert_ver_loc=$(grep "^* successfully set certificate verify locations:" $LOG_DIR/curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_server.log | wc -l)
      check_set_cert_path=$(grep "^*   CAfile: /etc/pki/katello/certs/katello-apache.crt" $LOG_DIR/curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_server.log | wc -l)
      check_san_matches=$(grep "^*  subjectAltName: host \"$(hostname -f)\" matched cert's \"$(hostname -f)\"" $LOG_DIR/curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_server.log | wc -l)
      check_ssl_cert_ver=$(grep "^*  SSL certificate verify ok." $LOG_DIR/curl_$(hostname -f)_${SRV_PORT_HTTPS}_using_server_ssl_server.log | wc -l)

      if [ "$check_set_cert_ver_loc" -eq 1 ] && [ "$check_set_cert_path" -eq 1 ] && [ "$check_san_matches" -eq 1 ] && [ "$check_ssl_cert_ver" -eq 1 ]; then
        check_response__curl_satserver_443_using_server_ssl_server="OK"
      else
        check_response__curl_satserver_443_using_server_ssl_server="FAIL"
      fi
      # ---
      # =============================

      ## Check the directory /root/ssl-build
      # =============================
      if [ -d /root/ssl-build ]; then
        check_dir_ssl_build="OK"
      else
        check_dir_ssl_build="FAIL"
      fi
      # =============================


    echo  "server"
    echo "####################################################"
    echo "# Communication with subscription.rhsm.redhat.com"
    echo "#   via openssl (2 checks) ................: ${check_response__openssl_subscription_rhsm_redhat_com_showcerts}"
    echo "#   via curl (4 checks) ...................: ${check_response__curl_subscription_rhsm_redhat_com_verbose_head}"
    echo "#"
    echo "# Communication with cdn.redhat.com"
    echo "#   via openssl (2 checks) ................: ${check_response__openssl_cdn_redhat_com_showcerts}"
    echo "#   via curl (4 checks) ...................: ${check_response__curl_cdn_redhat_com_verbose_head}"
    echo "#"
    echo "# Is /root/ssl-build present? .............: ${check_dir_ssl_build}"
    echo "#"
    echo "# Communication with Satellite - Candlepin"
    echo "#   via openssl (2 checks) ................: ${check_response__openssl_localhost_23443}"
    echo "#   via curl (5 checks) ...................: ${check_response__curl_localhost_23443}"
    echo "#"
    echo "# Communication with Satellite - Apache 443 using server_ssl_ca"
    echo "#   via openssl (2 checks) ................: ${check_response__openssl_satserver_443}"
    echo "#   via curl (4 checks) ...................: ${check_response__curl_satserver_443_using_server_ssl_ca}"
    echo "#"
    echo "# Communication with Satellite - Apache 443 using server_ssl_server"
    echo "#   via openssl (2 checks) ................: ${check_response__openssl_satserver_443}"
    echo "#   via curl (4 checks) ...................: ${check_response__curl_satserver_443_using_server_ssl_server}"
    echo "#"
    echo "#"
    echo "####################################################"
  fi
}

tar_file()
{
  echo "Compacting the files"
  echo "running .... 'tar cpf ${TAR_FILE} ${LOG_DIR}'"
  tar cpf $TAR_FILE $LOG_DIR &>/dev/null
  echo "Please, upload the file $TAR_FILE to the case" 
}

case $1 in
  "--server")
    server_func
    report server
    tar_file
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
