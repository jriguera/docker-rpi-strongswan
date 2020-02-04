# StrongSwan Docker

# docker build . -t strongswan
# docker run -ti --name vpnserver --privileged -v $(pwd)/strongswan:/data -p 500:500/udp -p 4500:4500/udp strongswan
# docker run --name vpnserver --cap-add net_admin -v $(pwd)/strongswan:/data -p 500:500/udp -p 4500:4500/udp strongswan
# Create client
# docker exec -ti vpnserver add-client <username> <password>

#ARG ARCH=arm32v6
ARG ARCH=amd64
FROM "${ARCH}/alpine:3.11"

ARG VERSION=5.8
ARG MYVERSION=jose1
ARG DATADIR=/data
ARG PORT_IKE=500
ARG PORT_IPSECNAT=4500
ARG UID=1000
ARG GUID=1000
ARG TZ=Europe/Amsterdam
ARG ARCH

LABEL org.label-schema.description="strongSwan Docker image based on Alpine for the Raspberry Pi."
LABEL org.label-schema.name="strongswan"
LABEL org.label-schema.version="${VERSION}-${MYVERSION}"
LABEL org.label-schema.usage="https://hub.docker.com/r/jriguera/rpi-strongswan/README.md"
LABEL org.label-schema.url="https://hub.docker.com/r/jriguera/rpi-strongswan"
LABEL org.label-schema.vcs-url="https://github.com/jriguera/docker-rpi-strongswan"
LABEL maintainer="Jose Riguera <jriguera@gmail.com>"
LABEL architecture="${ARCH}"

ENV LANG=en_US.utf8
ENV LC_ALL=C.UTF-8
ENV DATADIR="${DATADIR}"
ENV PORT_IKE="${PORT_IKE}"
ENV PORT_IPSECNAT="${PORT_IPSECNAT}"
ENV TEMPLATES="/etc/strongswan.d/templates"

RUN set -xe                                                                 && \
    apk -U upgrade                                                          && \
    # User/group
    addgroup -g "${GUID}" -S ipsec                                          && \
    adduser -h "${DATADIR}" -D -G ipsec -s /sbin/nologin -u "${UID}" ipsec  && \
    # Installing Alpine packages
    apk add --no-cache \
        ca-certificates \
        pwgen \
        su-exec \
        tzdata \
        socat \
        net-tools \
        curl \
        bash \
        openssl \
        gettext \
        strongswan~${VERSION} \
                                                                            && \
    # Timezone
    cp "/usr/share/zoneinfo/${TZ}" /etc/localtime                           && \
    echo "${TZ}" > /etc/timezone                                            && \
    # clean up
    rm -rf /tmp/* /var/tmp/* /var/cache/apk/* /var/cache/distfiles/*        && \
    rm -rf /etc/init.d /etc/udhcpd.conf

COPY templates/*.template "${TEMPLATES}"/
# COPY sysctl.conf /etc/sysctl.d/10-strongswan.conf
COPY vpn.sh /usr/local/bin/
RUN set -xe                                                                 && \
    chmod a+x /usr/local/bin/*                                              && \
    ln -s /usr/local/bin/vpn.sh /usr/local/bin/docker-entrypoint.sh         && \
    ln -s /usr/local/bin/vpn.sh /docker-entrypoint.sh                       && \
    ln -s /usr/local/bin/vpn.sh /run.sh                                     && \
    # Remove old ipsec folders
    rm -rf /etc/ipsec.conf /etc/ipsec.d /etc/ipsec.secrets

VOLUME ["${DATADIR}"]
EXPOSE "${PORT_IKE}/udp" "${PORT_IPSECNAT}/udp"

# Define default command
ENTRYPOINT ["/run.sh"]
CMD ["run-server"]
