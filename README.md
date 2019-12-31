# Strongswan VPN Server Docker Image

Run Strongswan 5.8 in docker. This docker image uses the new swanctl configuration
instead of the old ipsec. This image is created for Raspberry Pi but it can be build
and run in X86 arch.

This project was initially based on https://github.com/netzfisch/rpi-vpn-server


## Features

* It generates certificates and configuration parameters to setup a VPN server with Strongswan.
  Configuration is splitted in a conf.d folder.

* Default configuration is generated from templates, you can provide your own templates and
  use environment variables to fill the values.

* Manage client certificates and secrets: add or revoke using CRL.


# Usage

```
docker run --privileged --name vpnserver --cap-add net_admin -v $(pwd)/strongswan:/data -p 500:500/udp -p 4500:4500/udp strongswan help

Usage:
    run.sh [ run-server | add-client | revoke-client | public-ip | render-template | swanctl | help ] [options]

Strongswan VPN manager. It generates certificates and configuration parameters to setup a
VPN server with Stronswan and manage client certificates and secrets. Default configuration
is generated from templates, you can provide your own templates in <datadir>/templates
(/data/conf.d) and use environment variables to fill the values.
If the configuration is already provided in /data/conf.d,
it will not be overwritten, so you can define your own complex configuration there.

Subcommands:

    help            Shows usage help

    run-server [<maintemplate>]
        Renders connection <maintemplate> -if provided- in /data/conf.d, generates certs
        if they are not found and finally starts strongswan charon responder.
        Variables depend on the template, but the default/base template uses:
        - SERVER_NAME=<server-ip-or-dns>
        - BASE_DN=<C=ES, O=Lar>
        - CONNECTION_DEVICE=<server-net-device>
        - CONNECTION_POOL_ADDRS=<client-ip-pool>
        - CONNECTION_POOL_DNS=<client-dns>

    add-client <user> [<password>]
        Generates client certificates ready to be imported in 
        "/data/pkcs12/.p12" and defines "/data/conf.d/secrets/<user>.conf"
        for server. Variables used:
        - BASE_DN=<C=ES, O=Lar>

    revoke-client <user>
        Revokes client in "/data/x509crl/server.crl", deletes "/data/pkcs12/<user>.p12"
        and renames "/data/conf.d/secrets/<user>.conf".

    public-ip       Shows public IPv4 and IPv6

    render-template <template> <name> [<kind>]
        Renders the template (it can be a file or a name matching a file <template>.template)
        and outputs the generated file in /data/conf.d/<kind>/<name>.conf. By default kind is
        "connection", but it can be: connection, pool, secret.
        Variables depend on the template, so you are free to use as many as you
        want. You can define your own template files in <datadir>/templates.

    swanctl [args]
        Invoke swanctl with the arguments passed.
```

By default, if no parameters are provided, it will run strongswan server (responder).
The best way to run this project is with docker-compose with a configuration like:

```
version: "3.3"
services:
  vpnserver:
    image: strongswan:latest
    container_name: vpnserver
    sysctls:
    - net.core.somaxconn=1024
    - net.ipv4.ip_forward=1
    - net.ipv4.tcp_syncookies=0
    environment:
    - SERVER_NAME=192.168.1.105
    - BASE_DN=C=ES, O=Lar
    - CONNECTION_DEVICE=wlp61s0
    - CONNECTION_POOL_ADDRS=10.1.1.0/24
    - CONNECTION_POOL_DNS=1.1.1.1,8.8.4.4
    cap_add:
    - NET_ADMIN
    network_mode: "host"
    privileged: true
    ports:
    - "500:500/udp"
    - "4500:4500/udp"
    volumes:
    - ./strongswan:/data
    restart: unless-stopped
```

First time, certificates and configuration is automatically created based
on the environment variables defined in the `docker-compose.yml` file
or using the defaults in `docker/vpn.sh`, if not defined. when docker-compose
is up (`docker-compose up`) you can create clients by attaching a session
to the container and run `add-client <user> [<password>]`:

```
docker exec -ti vpnserver /run.sh add-client pepe password
```

In the directory `/data/clients` you will find the encrypted PKCS#12 file
`pepe.p12` and the `pepe-P12-XAUTH-Password.txt` file.  Import `<user>.p12`
(unlocked by `<user-P12-XAUTH-Password.txt>`) into your
remote system, e.g. use:

* **Android** - Install [strongSwan](https://play.google.com/store/apps/details?id=org.strongswan.android)
* **Linux** - Install  [network-manager](https://wiki.strongswan.org/projects/strongswan/wiki/NetworkManagerhttps://wiki.strongswan.org/projects/strongswan/wiki/NetworkManager).
* **macOS X** - Open Keychain App and import the PKCS#12 file into the system-keychain (not login) and mark as "always trusted". Than go to [Network Settings] > [Add Interface] > [VPN (IKEv2)] and enter the credentials:
  * ServerAdress = HOSTNAME
  * RemoteID = HOSTNAME
  * LocalID = VPN_USER
  * AuthenticationSettings = Certificate of VPN_USER

> The **user-P12-XAUTH-Password.txt** will be also used as key for **XAUTH scenarios**!


# References

* https://wiki.strongswan.org/projects/strongswan/wiki/IKEv2Examples
* https://sysadmins.co.za/setup-a-site-to-site-ipsec-vpn-with-strongswan-on-ubuntu/
* https://serverfault.com/questions/977099/how-to-configure-ipsec-strongswan-interface-so-that-only-assigned-interface-g
* https://github.com/jawj/IKEv2-setup#vpn-clients
* https://www.cl.cam.ac.uk/~mas90/resources/strongswan/
* https://proprivacy.com/guides/vpn-encryption-the-complete-guide


# Develop

Run `./docker-build.sh` to build the docker image based on the current architecture.

## Create final release and publish to Docker Hub and Github

Run `./create-publish-release.sh` after defining the `GITHUB_TOKEN` and `docker login`


# Author and License

(c) 2020 Jose Riguera, jriguera@gmail.com

> Licensed under the Apache License, Version 2.0 (the "License");
> you may not use this file except in compliance with the License.
> You may obtain a copy of the License at
> 
>     http://www.apache.org/licenses/LICENSE-2.0
> 
> Unless required by applicable law or agreed to in writing, software
> distributed under the License is distributed on an "AS IS" BASIS,
> WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
> See the License for the specific language governing permissions and
> limitations under the License.

