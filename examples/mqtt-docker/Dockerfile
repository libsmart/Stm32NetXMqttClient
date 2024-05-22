# Use the official Eclipse Mosquitto image with OpenSSL support
FROM eclipse-mosquitto:openssl

# Set the working directory to /mosquitto
WORKDIR /mosquitto

# Copy the mosquitto.conf file from the local config directory into the image
COPY --chmod=600 config/mosquitto.conf config/mosquitto.conf
COPY --chmod=600 config/dhparam.pem config/dhparam.pem
COPY --chmod=600 config/password_file.txt config/password_file.txt
COPY --chmod=600 config/ca.crt config/ca.crt
COPY --chmod=600 config/server.crt config/server.crt
COPY --chmod=600 config/server.key config/server.key


# Expose the default Mosquitto ports
EXPOSE 1883 8883 9001

