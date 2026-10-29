ARG BUILD_FROM
FROM $BUILD_FROM
# Base image is pinned to Python 3.12 on Alpine 3.20 (build.yaml). Packages come from Alpine's signed repositories;
# nothing is downloaded and run from the internet. ssh tools are optional: if they can't be installed, the app still
# builds and printing still works.
RUN apk add --no-cache openssh-client-default openssh-keygen || echo "WARNING: ssh packages unavailable; ssh tool disabled"
COPY gateway.py haapi.py tools.py receipt.py docs.py pairing.py ed25519.py caps.py hacfg.py routers.py inventory.py health.py checkup.py phone.py doorbell.py investigate.py /app/
# Offline maker list: the public IEEE MA-L table, about 370 KB (maintainers rebuild it with maintenance/oui_refresh.py,
# which is not copied into the image)
COPY oui.txt.gz /app/
WORKDIR /app
ENV S6_KEEP_ENV=1
CMD [ "/usr/bin/with-contenv", "python3", "-u", "/app/gateway.py" ]
