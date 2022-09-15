FROM python:3.8-slim as CSP

RUN apt-get update && \
    rm -rf /usr/local/bin/python3 && \
    apt-get install -y --no-install-recommends git ansible python3-pip build-essential libxml2-dev libxslt-dev python3-dev && \
    git clone https://github.com/ansible-middleware/redhat-csp-download.git && \
    mkdir /redhat-packages
WORKDIR /redhat-csp-download
RUN /usr/bin/python3 -m pip install -r requirements.txt && \
    ansible-galaxy collection install middleware_automation.redhat_csp_download
ADD /redhat/csp-download.sh /redhat-csp-download/
ARG REDHAT_EMAIL
ARG REDHAT_TOKEN
RUN ./csp-download.sh ${REDHAT_EMAIL} ${REDHAT_TOKEN}

FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ARG GRPC_PYTHON_BUILD_SYSTEM_OPENSSL=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential git libgmp3-dev curl procps less libffi-dev wget unzip jq libssl-dev libxml2-dev libxslt-dev python3.8-dev cargo software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa && \
    apt-get install -y --no-install-recommends python3.8 python3-pip python3-setuptools python3.8-distutils && \
    cd /usr/bin/ && rm -rf python3 && ln -s python3.8 python3
RUN apt-get install -y openssh-server && \
    mkdir /var/run/sshd

RUN mkdir /git
WORKDIR /git

RUN python3 -m pip install --upgrade pip==21.2.4 && \
    pip3 install --upgrade setuptools==57.5.0 && \
    pip3 install --upgrade distlib && \
    pip3 install wheel

RUN pip3 install flask==1.1.2 flask_restx flask_sqlalchemy flask_jwt_extended pymongo==3.12.2 asn1==2.2.0 cython ibm-cos-sdk flask-mail==0.9.1 flask_cors certifi requests pyyaml supervisor dnspython pyaes ecdsa qrcode aiorpcx aiohttp aiohttp_socks bitstring jsonrpcclient==3.3.5 jsonrpcserver==4.2.0 jinja2==3.0.3 werkzeug==2.0.3
RUN pip3 install cryptography==3.3.2 pycryptodome argon2 pycryptodomex pyopenssl
RUN pip3 install grpcio-tools
RUN pip3 install lxml
RUN pip3 uninstall -y itsdangerous && \
    pip3 install itsdangerous==2.0.0

ADD flask-oidc.patch /
RUN git clone https://github.com/puiterwijk/flask-oidc.git && \
    cd flask-oidc && \
    patch -p1 < /flask-oidc.patch && \
    git submodule init && \
    git submodule update && \
    pip3 install -e .

WORKDIR /
RUN mkdir /redhat-packages
ADD redhat /redhat

##### Red Hat Single Sign-On #####
ADD /redhat/install-java.sh /
RUN ./install-java.sh
ENV PATH /opt/jdk-11.0.12+7-jre/bin:$PATH

COPY --from=CSP /redhat-packages/rh-sso-7.4.0.zip /redhat-packages/

RUN unzip /redhat-packages/rh-sso-7.4.0.zip && \
    mv rh-sso-7.4 rhsso-7.4 && \
    cd /rhsso-7.4/bin && \
    cp /redhat/standalone.xml /rhsso-7.4/bin/standalone.xml.org && \
    cp /redhat/keycloak.jks /rhsso-7.4/standalone/configuration/ && \
    cp /redhat/run-rhsso.sh /rhsso-7.4/bin/ && \
    cp /redhat/initialize-rhsso.sh /rhsso-7.4/bin/ && \
    cp /redhat/realm-export.json.org /rhsso-7.4/bin/

##### Red Hat Process Automation Manager  #####
WORKDIR /

COPY --from=CSP /redhat-packages/jboss-eap-7.3.0.zip /redhat-packages/
COPY --from=CSP /redhat-packages/rh-sso-7.4.0-eap7-adapter.zip /redhat-packages/
COPY --from=CSP /redhat-packages/rhpam-7.11.0-business-central-eap7-deployable.zip /redhat-packages/
COPY --from=CSP /redhat-packages/rhpam-7.11.0-kie-server-ee8.zip /redhat-packages/

RUN unzip /redhat-packages/jboss-eap-7.3.0.zip && \
    unzip -o -d /jboss-eap-7.3 /redhat-packages/rh-sso-7.4.0-eap7-adapter.zip && \
    unzip -o /redhat-packages/rhpam-7.11.0-business-central-eap7-deployable.zip && \
    unzip /redhat-packages/rhpam-7.11.0-kie-server-ee8.zip

RUN mv kie-server.war /jboss-eap-7.3/standalone/deployments/ && \
    cp -r SecurityPolicy/* /jboss-eap-7.3/bin/ && \
    rm -rf SecurityPolicy && \
    touch /jboss-eap-7.3/standalone/deployments/kie-server.war.dodeploy && \
    cp /redhat/standalone-full.xml /jboss-eap-7.3/bin/standalone-full.xml.org && \
    cp /redhat/run-rhpam.sh /jboss-eap-7.3/bin/ && \
    cp /redhat/get-kie-secrets.py /jboss-eap-7.3/bin/ && \
    cp /redhat/import-rule.sh /jboss-eap-7.3/bin/
ADD Authorization_Policy.git /git/Authorization_Policy.git
RUN mkdir -p /git/Authorization_Policy.git/refs && \
    mkdir -p /git/Authorization_Policy.git/refs/heads && \
    mkdir -p /git/Authorization_Policy.git/refs/tags

RUN rm -rf /redhat && \
    rm -rf /redhat-packages

### Add contents without git clone to ease development
WORKDIR /git
RUN mkdir -p dap-blueprint
ADD src dap-blueprint/src
ADD entrypoints dap-blueprint/entrypoints
ADD DigitalAssets-Electrum dap-blueprint/DigitalAssets-Electrum
RUN cd dap-blueprint/src/dap_client && \
    pip3 install -e . && \
    cd ../dap_util && \
    pip3 install -e . && \
    cd ../../DigitalAssets-Electrum && \
    pip3 install -e .

WORKDIR /git/dap-blueprint
ARG DBAAS_CA
ENV DBAAS_CA=${DBAAS_CA} \
    DBAAS_CA_FILE=/git/dap-blueprint/dbaas-cert.pem
RUN echo -----BEGIN CERTIFICATE----- > dbaas-cert.pem && \
    echo "${DBAAS_CA}" >> dbaas-cert.pem && \
    echo -----END CERTIFICATE----- >> dbaas-cert.pem

ARG ELECTRUM_USER=electrum
ARG ELECTRUM_PASSWORD=passw0rd
ARG ELECTRUM_DATA=/data
ENV ELECTRUM_USER=${ELECTRUM_USER} \
    ELECTRUM_PASSWORD=${ELECTRUM_PASSWORD} \
    ELECTRUM_DATA=${ELECTRUM_DATA}

ARG BUILD=1

### In production, a private key must not be displayed. ###
ARG DAP_ROOT_DIR=/git/dap-blueprint
ARG BUILD_TIME_SECRET
ARG OLD_BUILD_TIME_SECRET
ENV DAP_ROOT_DIR=${DAP_ROOT_DIR} \
    BUILD_TIME_SECRET=${BUILD_TIME_SECRET} \
    OLD_BUILD_TIME_SECRET=${OLD_BUILD_TIME_SECRET}
RUN mkdir -p secrets && \
    mkdir -p build-time-keys && \
    echo ${BUILD_TIME_SECRET} > secrets/build-time-secret.txt && \
    ./src/dap_util/dap_crypto.py gen_rsa_keypair ./build-time-keys && \
    echo "DAP service public key (pem format)" && \
    cat ./build-time-keys/public.pem && \
    echo "" && \
    cat ./build-time-keys/private.pem && \
    echo ""

WORKDIR /git/dap-blueprint/entrypoints
ENTRYPOINT ["./entrypoint.sh"]
