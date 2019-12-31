#!/bin/bash
set -o pipefail  # exit if pipe command fails
[ -z "$DEBUG" ] || set -x
PROGRAM=$(basename "${BASH_SOURCE[0]}")

# Docs
# https://gist.github.com/curipha/a815596770c1454eb373c123aa24f622
# https://www.zeitgeist.se/2013/11/22/strongswan-howto-create-your-own-vpn/


# Defined in the Dockerfile but
# if undefined, populate environment variables with sane defaults
SWANCTL_DIR="$DATADIR"
SWANCTL_ETC="/etc/swanctl"
SWANCTL_CONF="/etc/swanctl/swanctl.conf"
STRONGSWAN_DIR="/etc/strongswan.d"
TEMPLATES="${TEMPLATES:-${STRONGSWAN_DIR}/templates}"

export CONFD="${CONFD:-${SWANCTL_DIR}/conf.d}"
export SECRETSD="${SECRETSD:-${CONFD}/secrets}"
export POOLSD="${POOLSD:-${CONFD}/pools}"
export CONNECTIONSD="${CONNECTIONSD:-${CONFD}/connections}"

export IPSEC_CA_KEY="${SWANCTL_DIR}/private/ca.pem"
export IPSEC_CA_CRT="${SWANCTL_DIR}/x509ca/ca.pem"
export IPSEC_SERVER_KEY="${SWANCTL_DIR}/private/server.pem"
export IPSEC_SERVER_CRT="${SWANCTL_DIR}/x509/server.pem"
export IPSEC_SERVER_CRL="${SWANCTL_DIR}/x509crl/server.crl"

export IPSEC_CLIENT_KEY_PATH="${SWANCTL_DIR}/private"
export IPSEC_CLIENT_CERTS_PATH="${SWANCTL_DIR}/x509"
export IPSEC_CLIENT_PATH="${SWANCTL_DIR}/clients"
export IPSEC_CLIENT_CLRS_PATH="${SWANCTL_DIR}/x509crl"

###

export BASE_DN="${BASE_DN:-C=Home, O=Lar}"
export SERVER_NAME="${SERVER_NAME:-raspi.lar}"
export CLIENT_LIFETIME_DAYS=${CLIENT_LIFETIME_DAYS:-5000}

export CA_GENERATE_DN="${CA_GENERATE_DN:-$BASE_DN, CN=VPN Root CA}"
export CA_LIFETIME_DAYS=${CA_LIFETIME_DAYS:-5000}
export CRT_SERVER_GENERATE_SAN="${CRT_SERVER_GENERATE_SAN:-$SERVER_NAME}"
export CRT_SERVER_GENERATE_DN="${CRT_SERVER_GENERATE_DN:-$BASE_DN, CN=$SERVER_NAME}"
export CRT_SERVER_LIFETIME_DAYS=${CRT_SERVER_LIFETIME_DAYS:-365}

export CHARON_PLUGINS_DISABLE="${CHARON_PLUGINS_DISABLE:-attr-sql stroke eap-sim-file eap-sim eap-radius}"
export CHARON_PLUGINS_ENABLE="${CHARON_PLUGINS_ENABLE:-}"

export CONNECTION_NAME=${CONNECTION_NAME:-public}
export CONNECTION_DEVICE=${CONNECTION_DEVICE:-eth0}
export CONNECTION_POOL_ADDRS="${CONNECTION_POOL_ADDRS:-10.10.10.0/24}"
export CONNECTION_POOL_DNS="${CONNECTION_POOL_DNS:-1.1.1.1,8.8.4.4}"

###

# Generate a configuration type from template (if provided)
generate_swanctl_conf() {
    local kind="$1"
    local confname="$2"
    local template="$3"

    local conf

    mkdir -p "${SECRETSD}"
    mkdir -p "${POOLSD}"
    mkdir -p "${CONNECTIONSD}"
    cat <<-EOF > "${SWANCTL_CONF}"
	# https://wiki.strongswan.org/projects/strongswan/wiki/Strongswanconf#Referencing-other-Sections
	connections {
	    include ${CONNECTIONSD}/*.conf
	}
	pools {
	    include ${POOLSD}/*.conf
	}
	secrets {
	    include ${SECRETSD}/*.conf
	}
	EOF
    case "${kind}" in
        connection)
            conf="${CONNECTIONSD}/${confname}.conf"
            ;;
        pool)
            conf="${POOLSD}/${confname}.conf"
            ;;
        secret)
            conf="${SECRETSD}/${confname}.conf"
            ;;
        *)
            echo "! Error, template type not found"
            return 1
        ;;
    esac
    if [ -z "${template}" ]
    then
        template="${TEMPLATES}/${kind}.template"
    else
        if [ ! -r "${template}" ]
        then
            template="${TEMPLATES}/${template}.template"
            if [ ! -r "${template}" ]
            then
                echo "! Error, template ${template} not found"
                return 1
            fi
        fi
    fi
    if [ -r "${conf}" ]
    then
        echo "* ${conf} exists, skipping generation ... "
    else
        echo "* Generating ${conf} from ${template} ... "
        envsubst < "${template}" > "${conf}"
    fi
}

# Generate CA certificates
generate_ca_certs() {
    local dn="$1"
    local days="$2"

    echo "* Generating CA certificate: ${dn} ... "
    pki --gen --outform pem > "${IPSEC_CA_KEY}"
    chmod 600 "${IPSEC_CA_KEY}"
    pki --self --ca \
              --in "${IPSEC_CA_KEY}" \
              --dn "${dn}" \
              --lifetime "${days}" \
              --outform pem > "${IPSEC_CA_CRT}"
}

# Generate server certificates using CA certificates
generate_server_certs() {
    local dn="$1"
    local host="$2"
    local days="$3"
  
    echo "* Generating VPN server certificate (${host}): ${dn} ... "
    pki --gen --outform pem > "${IPSEC_SERVER_KEY}"
    chmod 600 "${IPSEC_SERVER_KEY}"
    pki --pub --in "${IPSEC_SERVER_KEY}" | pki --issue \
              --cacert "${IPSEC_CA_CRT}" \
              --cakey "${IPSEC_CA_KEY}" \
              --dn "${dn}" \
              --san "${host}" \
              --lifetime "${days}" \
              --flag serverAuth \
              --flag ikeIntermediate \
              --outform pem > "${IPSEC_SERVER_CRT}"
    # An empty CRL that is signed by the CA
    pki --signcrl \
        --cacert "${IPSEC_CA_CRT}" \
        --cakey "${IPSEC_CA_KEY}" \
        --lifetime 30 > "${IPSEC_SERVER_CRL}"
}

# Revoke client certificates and remove secrets
revoke_user_certs() {
    local user="$1"
    local reason="${2:-key-compromise}"

    if [ -r "${SECRETSD}/${user}.conf" ]
    then
        echo "* Revoking VPN user certificate: ${user} ..."
        pki --signcrl --reason "${reason}" \
                --cacert "${IPSEC_CA_CRT}" \
                --cakey "${IPSEC_CA_KEY}" \
                --cert "${IPSEC_CLIENT_CERTS_PATH}/${user}.pem" \
                --lifetime 30 \
                --lastcrl "${IPSEC_SERVER_CRL}" \
                --outform pem > "${IPSEC_SERVER_CRL}"
        echo "* Removing secrets and pkcs12 files ..."
        mv "${SECRETSD}/${user}.conf" "${SECRETSD}/${user}.revoked"
        rm -f "${IPSEC_CLIENT_PATH}/${user}.p12"
    else
        echo "! Error, user not found!"
        return 1
    fi
}

# Generate client certificates
generate_user_certs() {
    local user="$1"
    local password="$2"
    local dn="$3"
    local san="$4"
    local days="$5"
  
    mkdir -p "${IPSEC_CLIENT_KEY_PATH}"
    mkdir -p "${IPSEC_CLIENT_CERTS_PATH}"
    mkdir -p "${IPSEC_CLIENT_PATH}"

    echo "* Creating VPN user certificate: ${user} ..."
    # Assign random password if not set
    if [ -z "${password}" ]
    then
        # Generate a random password
        P1=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
        P2=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
        P3=`cat /dev/urandom | tr -cd abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789 | head -c 3`
        password="$P1$P2$P3"
        echo "* No VPN_PASSWORD set, generated a random one: $password"
    fi
    echo "* Create key and certificate for user: ${user} ..."
    pki --gen --outform pem > "${IPSEC_CLIENT_KEY_PATH}/${user}.pem"
    pki --pub --in "${IPSEC_CLIENT_KEY_PATH}/${user}.pem" | pki --issue \
              --cacert "${IPSEC_CA_CRT}" \
              --cakey "${IPSEC_CA_KEY}" \
              --dn "${dn}" \
              --san "${san}" \
              --lifetime "${days}" \
              --outform pem > "${IPSEC_CLIENT_CERTS_PATH}/${user}.pem"
    chmod 600 "${IPSEC_CLIENT_KEY_PATH}/${user}.pem"
    echo "* Create encrypted PKCS#12 file for user devices: ${user} ..."
    openssl pkcs12 -export -password "pass:${password}" \
                   -inkey "${IPSEC_CLIENT_KEY_PATH}/${user}.pem" \
                   -in "${IPSEC_CLIENT_CERTS_PATH}/${user}.pem" \
                   -name "${user}" \
                   -certfile "${IPSEC_CA_CRT}" \
                   -caname "HomeVPN Root CA" \
                   -out "${IPSEC_CLIENT_PATH}/${user}.p12"
    echo "* Create secret: ${SECRETSD}/${user}.conf"
    mkdir -p "${SECRETSD}"
    cat <<-EOF > "${SECRETSD}/${user}.conf"
	eap-${user} {
	    id = ${user}
	    secret = "${password}" 
	}
	private-${user} {
	    file = ${IPSEC_CLIENT_KEY_PATH}/${user}.pem
	}
	EOF
    # Create password file for user
    echo "${password}" > "${IPSEC_CLIENT_PATH}/${user}-P12-XAUTH-Password.txt"
    return 1
}

# Enable iptables and ip forwarding
enable_networking() {
    local net="$1"
    local device="$2"

    # sysctl not needed, can be defined via docker compose!
    echo "* Defining sysctl parameters ...."
    sysctl -q -w net.ipv4.ip_forward=1
    if ! iptables --table nat --check POSTROUTING -s "${net}" -o "${device}" --jump MASQUERADE  2>/dev/null
    then
        echo "* Defining iptables masquerading ..."
        iptables --table nat --append POSTROUTING -s "${net}" -o "${device}" -m policy --dir out --pol ipsec --jump ACCEPT
        iptables --table nat --append POSTROUTING -s "${net}" -o "${device}" --jump MASQUERADE
    fi
}

# Remove iptables masquerading
disable_networking() {
    local net="$1"
    local device="$2"

    if iptables --table nat --check POSTROUTING -s "${net}" -o "${device}" --jump MASQUERADE  2>/dev/null
    then
        echo "* Disabling iptables masquerading ..."
        iptables --table nat -D POSTROUTING -s "${net}" -o "${device}" --jump MASQUERADE
        iptables --table nat -D POSTROUTING -s "${net}" -o "${device}" -m policy --dir out --pol ipsec --jump ACCEPT
    fi
}

# Enable or disable a plugin
strongswan_charon_plugin() {
    local plugin="$1"
    local state="$2"

    local pluginfile="${STRONGSWAN_DIR}/charon/${plugin}.conf"
    if [ ! -r "${pluginfile}" ]
    then
        echo "! Error, plugin ${plugin} not found"
        return 1
    else
        case "${state}" in
            yes|Yes|YES|y|Y|On|on|ON|1)
                echo "* Enabling plugin ${plugin} ..."
                sed -i '/[[:blank:]]\+load[[:blank:]]\+=[[:blank:]]\+.*$/s/=.*$/= yes/' "${pluginfile}"
                ;;
            no|No|NO|n|N|Off|off|OFF|0)
                echo "* Disabling plugin ${plugin} ..."
                sed -i '/[[:blank:]]\+load[[:blank:]]\+=[[:blank:]]\+.*$/s/=.*$/= no/' "${pluginfile}"
                ;;
            *)
                echo "! Error, state '${state}' not correct (yes,on,1 or no,off,0)"
                return 1
                ;;
        esac
    fi
}

# exec charon in bg
run_charon_responder() {
    local charon="/usr/lib/strongswan/charon"
    (
        {
            exec ${charon} $@
        }
    ) &
    pid=$!
    echo "* Launching pid=${pid}: ${charon} $@"
    sleep 10
    if [ "$(pgrep ${charon})" != "${pid}" ]
    then
        echo "! Error launching '${charon} $@'."
        rvalue=1
    else
        echo "* Pid=${pid} running"
        rvalue=0
    fi
    return ${rvalue}
}

# Generate configuration and run server
run_server() {
    local maintemplate="$1"

    local rc

    for p in ${CHARON_PLUGINS_DISABLE}
    do
        strongswan_charon_plugin ${p} off || true
    done
    for p in ${CHARON_PLUGINS_ENABLE}
    do
        strongswan_charon_plugin ${p} on || true
    done
    generate_swanctl_conf connection "${CONNECTION_NAME}" "${maintemplate}"
    generate_swanctl_conf pool "${CONNECTION_NAME}"
    generate_swanctl_conf secret "${CONNECTION_NAME}"
    run_charon_responder
    rc=$?
    if [ ${rc} -eq 0 ]
    then
        trap exit_server SIGINT SIGTERM
        swanctl --load-all --noprompt                                       && \
        enable_networking "${CONNECTION_POOL_ADDRS}" "${CONNECTION_DEVICE}" && \
        wait
    fi
    return ${rc}
}

# Catch exit, disable iptables and kill all services
exit_server() {
    echo "* Caught SIGTERM/SIGINT signal!" 
    trap - SIGINT SIGTERM # clear the trap
    for pid in /run/*.pid
    do
        echo "* Killing ${pid}: $(<${pid})"
        # Sends SIGTERM to /run/*.pid
        kill $(<${pid})
    done
    disable_networking "${CONNECTION_POOL_ADDRS}" "${CONNECTION_DEVICE}"
}

usage() {
    cat <<EOF
Usage:
    $PROGRAM [ run-server | add-client | revoke-client | public-ip | render-template | swanctl | help ] [options]

Strongswan VPN manager. It generates certificates and configuration parameters to setup a
VPN server with Stronswan and manage client certificates and secrets. Default configuration
is generated from templates, you can provide your own templates in <datadir>/templates
($CONFD) and use environment variables to fill the values.
If the configuration is already provided in $CONFD,
it will not be overwritten, so you can define your own complex configuration there.

Subcommands:

    help            Shows usage help

    run-server [<maintemplate>]
        Renders connection <maintemplate> -if provided- in $CONFD, generates certs
        if they are not found and finally starts strongswan charon responder.
        Variables depend on the template, but the default/base template uses:
        - SERVER_NAME=<server-ip-or-dns>
        - BASE_DN=<C=ES, O=Lar>
        - CONNECTION_DEVICE=<server-net-device>
        - CONNECTION_POOL_ADDRS=<client-ip-pool>
        - CONNECTION_POOL_DNS=<client-dns>

    add-client <user> [<password>]
        Generates client certificates ready to be imported in 
        "${IPSEC_CLIENT_PATH}/${user}.p12" and defines "${SECRETSD}/<user>.conf"
        for server. Variables used:
        - BASE_DN=<C=ES, O=Lar>

    revoke-client <user>
        Revokes client in "${IPSEC_SERVER_CRL}", deletes "${IPSEC_CLIENT_PATH}/<user>.p12"
        and renames "${SECRETSD}/<user>.conf".

    public-ip       Shows public IPv4 and IPv6

    render-template <template> <name> [<kind>]
        Renders the template (it can be a file or a name matching a file <template>.template)
        and outputs the generated file in $CONFD/<kind>/<name>.conf. By default kind is
        "connection", but it can be: connection, pool, secret.
        Variables depend on the template, so you are free to use as many as you
        want. You can define your own template files in <datadir>/templates.

    swanctl [args]
        Invoke swanctl with the arguments passed.
EOF
}

##################################################################################
# Main program

# Make sure folders are there
for p in ecdsa pkcs12 pkcs8 private pubkey rsa x509 x509aa x509ac x509ca x509crl x509ocsp
do
    [ -d "${SWANCTL_DIR}/${p}" ] && rm -rf ${SWANCTL_ETC}/${p} || mv ${SWANCTL_ETC}/${p} ${SWANCTL_DIR}/${p}
    ln -sf ${SWANCTL_DIR}/${p} ${SWANCTL_ETC}/${p}
done
[ -d "${SWANCTL_DIR}/templates" ] && {
    cp ${SWANCTL_DIR}/templates/* ${TEMPLATES}/ 2>/dev/null || true
}

# Generate CA and server certs
[ -r "${IPSEC_CA_CRT}" ] || generate_ca_certs "${CA_GENERATE_DN}" "${CA_LIFETIME_DAYS}"
[ -r "${IPSEC_SERVER_CRT}" ] || generate_server_certs "${CRT_SERVER_GENERATE_DN}" "${CRT_SERVER_GENERATE_SAN}" "${CRT_SERVER_LIFETIME_DAYS}"

case "$1" in
  run-server)
    template="$2"
    run_server "${template}"
    ;;
  add-client|revoke-client)
    user="$2"
    pass="$3"
    if [ -z "${user}" ]
    then
        echo "  Please provide a username!"
        exit 1
    else
        case "$1" in
        add-client)
            generate_user_certs "${user}" "${pass}" "${BASE_DN}, CN=${san}" "${user}" "${CLIENT_LIFETIME_DAYS}"
            ;;
        revoke-client)
            revoke_user_certs "${user}"
            ;;
        esac
        echo "* Reloading credentials ..."
        swanctl --load-creds
    fi
    ;;
  public-ip)
    # https://ipecho.net/plain
    echo "* Public IPv4 is $(curl -s https://api.ipify.org)"
    echo "* Public IPv6 is $(curl -s https://api6.ipify.org)"
    ;;
  render-template)
    template="$2"
    name="$3"
    kind="${4:-connection}"
    if [ -z "${template}" ] || [ -z "${name}" ]
    then
        echo "  Please provide a template and a name!"
        exit 1
    else
        generate_swanctl_conf "${kind}" "${name}" "${template}"
    fi
    ;;
  swanctl)
    shift
    swanctl "$@"
    ;;
  help|--help)
    usage
    ;;
  *)
    # for debug
    exec "$@"
    ;;
esac
