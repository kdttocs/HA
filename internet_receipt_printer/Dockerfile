ARG BUILD_FROM
FROM $BUILD_FROM
# Python standard library only; nothing is downloaded at build or run time.
COPY pairing.py receipt_printer.py /app/
WORKDIR /app
ENV S6_KEEP_ENV=1
CMD [ "/usr/bin/with-contenv", "python3", "-u", "/app/receipt_printer.py" ]
