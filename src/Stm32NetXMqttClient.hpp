/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32NETXMQTTCLIENT_STM32NETXMQTTCLIENT_HPP
#define LIBSMART_STM32NETXMQTTCLIENT_STM32NETXMQTTCLIENT_HPP

#include <libsmart_config.hpp>
#include <main.h>

#include "nx_api.h"
#include "tx_api.h"
#include "nxd_mqtt_client.h"
#include "Stm32ItmLogger.hpp"
#include "Stm32NetX.hpp"
#include "WaitOption.hpp"

#ifdef LIBSMART_ENABLE_STD_FUNCTION
#include <cstdint>
#include <functional>
#include <iomanip>
#include <utility>
#endif

#ifdef NX_SECURE_ENABLE

#include "Secure/X509.hpp"
#include "nx_secure_tls.h"

/* TLS buffers and certificate containers. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

#endif

#define CRYPTO_METADATA_CLIENT_SIZE 11600
#define TLS_PACKET_BUFFER_SIZE      4000


namespace Stm32NetXMqttClient {
#ifdef NX_SECURE_ENABLE
    /* calculated with nx_secure_tls_metadata_size_calculate */
    static CHAR crypto_metadata_client[CRYPTO_METADATA_CLIENT_SIZE] __attribute__((section(".ccmram")));
    /* Define the TLS packet reassembly buffer. */
    static UCHAR tls_packet_buffer[TLS_PACKET_BUFFER_SIZE] __attribute__((section(".ccmram")));
#endif

    class MqttClient;
    inline MqttClient *mqttClient = {};

    template<class T, class Method, Method m, class... Params>
    static auto bounce(NXD_MQTT_CLIENT *mqtt_client_ptr, Params... params) ->
        decltype(((*reinterpret_cast<T *>(mqttClient)).*m)(params...)) {
        UNUSED(mqtt_client_ptr);
        // BREAKPOINT;
        return ((*reinterpret_cast<T *>(mqttClient)).*m)(params...);
    }


    class MqttClient : public Stm32ItmLogger::Loggable,
                       public Stm32Common::Nameable,
                       public Stm32ThreadX::Thread,
                       protected NXD_MQTT_CLIENT {
        /** EventFlags used by MqttClient */
        using Flags = enum {
            NONE = 0,
            IS_CREATED = 1 << 0,
            IS_CONNECTED = 1 << 1,
            IS_READY_FOR_CONNECT = 1 << 2,
            THE_END = 1 << 31
        };

    public:
        ~MqttClient() override {
            deleteClient();
        }

        explicit MqttClient(Stm32NetX::NetX *nx)
            : MqttClient(nx, &Stm32ItmLogger::emptyLogger) { ; }

        MqttClient(Stm32NetX::NetX *nx, Stm32ItmLogger::LoggerInterface *logger)
            : Loggable(logger),
              Nameable("clientid"),
              Thread(Stm32ThreadX::BOUNCE(MqttClient, mqttThread), reinterpret_cast<ULONG>(this), priority(),
                     "Stm32NetXMqttClient::MqttClient::mqttThread()"), NXD_MQTT_CLIENT(), NX(nx) {
        }

        [[noreturn]] void mqttThread();

        /**
         * @brief Get the client ID of the MQTT client.
         *
         * @return const char* - The client ID.
         *
         * This method returns the client ID of the MQTT client. The client ID is obtained from the `Nameable` class.
         *
         * @see Nameable::getName()
         */
        const char *getClientId();


        /**
         * @brief Set the client ID of the MQTT client.
         *
         * @param clientid - The client ID to set.
         *
         * This method sets the client ID of the MQTT client. The client ID is used to identify the client when connecting to an MQTT broker. It is obtained from the `Nameable` class.
         *
         * @see Nameable::setName()
         */
        void setClientId(const char *clientid);


        /**
         * @brief Check if the MQTT client is ready for connection.
         *
         * @return bool - `true` if the client is ready for connection, `false` otherwise.
         *
         * This method checks if the MQTT client is ready for connection by checking the value of the `IS_READY_FOR_CONNECT` flag.
         */
        bool isReadyForConnect() { return flags.isSet(IS_READY_FOR_CONNECT); }


        /**
         * @brief Check if the MQTT client is connected.
         *
         * @return bool - `true` if the client is connected, `false` otherwise.
         *
         * This method checks if the MQTT client is connected by returning the value of the `IS_CONNECTED` flag in the `flags` variable.
         * The method returns `true` if the client is connected and `false` otherwise.
         */
        bool isConnected() { return flags.isSet(IS_CONNECTED); }


        /**
         * @brief Publishes a message to a topic on the MQTT client.
         *
         * @param topic_name The name of the topic to publish the message to.
         * @param message The message to be published.
         * @param retain Indicates whether the message should be retained by the broker.
         * @param QoS The quality of service for message delivery.
         * @param waitOption The wait option for the publish operation.
         *
         * This method publishes a message to the specified topic on the MQTT client. It logs the publishing operation,
         * and returns the status of the publish operation.
         *
         * @return The status of the publish operation. Returns NXD_MQTT_SUCCESS if successful, otherwise an error code.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_publish
         */
        UINT publish(const CHAR *topic_name,
                     const CHAR *message,
                     UINT retain,
                     UINT QoS,
                     Stm32ThreadX::WaitOption waitOption);


        /**
         * @brief Subscribes to a specified MQTT topic with the given Quality of Service level.
         *
         * @param topic_name The name of the topic to subscribe to.
         * @param QoS The Quality of Service level for the subscription.
         * @return The return value from the `nxd_mqtt_client_subscribe` function.
         *
         * This method subscribes to the specified MQTT topic with the provided Quality of Service level.
         * It logs the subscription information and calls the `nxd_mqtt_client_subscribe` function to perform the subscription.
         * If the subscription fails, an error log is generated.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_subscribe
         */
        UINT subscribe(const CHAR *topic_name, UINT QoS);


        /**
         * @brief Unsubscribe from an MQTT topic.
         *
         * @param topic_name The name of the topic to unsubscribe from.
         * @return The result of the unsubscribe operation.
         *
         * This method unsubscribes the MQTT client from the specified topic. It logs the unsubscribe operation and checks the return value
         * of the nxd_mqtt_client_unsubscribe() function for errors. If an error occurs, an error log is generated.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_unsubscribe
         */
        UINT unsubscribe(const CHAR *topic_name);


        /**
         * @brief Get a message from the MQTT client.
         *
         * @param topic_buffer The buffer to store the topic of the message.
         * @param topic_buffer_size The size of the topic buffer.
         * @param actual_topic_length A pointer to store the actual length of the topic.
         * @param message_buffer The buffer to store the message payload.
         * @param message_buffer_size The size of the message buffer.
         * @param actual_message_length A pointer to store the actual length of the message payload.
         *
         * This method retrieves a message from the MQTT client. It populates the provided topic buffer
         * with the topic of the message and the message buffer with the message payload. The maximum
         * sizes of the topic and message buffers are specified by topic_buffer_size and message_buffer_size,
         * respectively.
         *
         * @return The status code indicating the success or failure of the operation.
         *
         * If the message retrieval is successful, the return value will be NXD_MQTT_SUCCESS. If there is no
         * message available, the return value will be NXD_MQTT_NO_MESSAGE. Any other return value indicates
         * an error.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_message_get
         */
        UINT messageGet(UCHAR *topic_buffer,
                        UINT topic_buffer_size,
                        UINT *actual_topic_length,
                        UCHAR *message_buffer,
                        UINT message_buffer_size,
                        UINT *actual_message_length);


        /**
         * @brief Checks if there is a pending MQTT message.
         *
         * This method checks if there is a pending MQTT message available. It calls the `nxd_mqtt_client_message_get`
         * function to check the presence of a message.
         *
         * @return `true` if there is a pending MQTT message, `false` otherwise.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_message_get
         */
        bool hasMessage();


        /**
         * @brief Create the MQTT client instance.
         *
         * @return The result code of the MQTT client creation.
         *
         * This method is used to create the MQTT client instance. It allocates memory for the client and initializes it
         * using the nxd_mqtt_client_create() function from the NetX Duo MQTT library. The client ID is obtained using
         * the getClientId() method. The created client instance will be associated with the current IP instance and packet pool.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_create
         */
        UINT create();


        /**
         * @brief Connect to an MQTT server.
         *
         * @param server_ip Pointer to a NXD_ADDRESS struct representing the IP address of the server.
         * @param server_port The port number of the server.
         * @param keepalive The keepalive interval in seconds.
         * @param clean_session Whether to start with a clean session or not.
         * @param waitOption An instance of the WaitOption class representing the wait option to use.
         *
         * This method establishes a connection to an MQTT server. It takes the IP address and port number
         * of the server, the keepalive interval, the clean session flag, and a wait option. The wait option
         * determines the behavior of the connect method when waiting for the connection to be established.
         *
         * @return The result of the nxd_mqtt_client_connect function. If the connection is successful, the
         *         return value is NXD_MQTT_SUCCESS. Otherwise, an error code is returned.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_connect
         */
        UINT connect(NXD_ADDRESS *server_ip, UINT server_port, UINT keepalive, UINT clean_session,
                     Stm32ThreadX::WaitOption waitOption);


        /**
         * @brief Establish a secure connection with an MQTT server.
         *
         * @param server_ip Pointer to an NXD_ADDRESS struct representing the IP address of the MQTT server.
         * @param server_port The port number of the MQTT server.
         * @param keepalive The keep-alive interval in seconds.
         * @param clean_session Set to NX_TRUE to indicate a clean session, NX_FALSE otherwise.
         * @param waitOption A WaitOption object defining the wait option for the connection.
         * @return The return code of the secure connection operation.
         *
         * This method establishes a secure connection with an MQTT server using the specified server IP address, port number,
         * keep-alive interval, clean session flag, and wait option. It internally calls the `nxd_mqtt_client_secure_connect`
         * function to perform the secure connection. The client ID of the MQTT client is obtained using the `getClientId`
         * method and is included in the log message.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_secure_connect
         */
        UINT secureConnect(NXD_ADDRESS *server_ip, UINT server_port, UINT keepalive, UINT clean_session,
                           Stm32ThreadX::WaitOption waitOption);


        /**
         * @brief Disconnects the MQTT client from the broker.
         *
         * @return The status code of the disconnection operation.
         *
         * This method disconnects the MQTT client from the broker. It first logs the disconnect operation with the
         * client ID using the logger. Then, it calls the `nxd_mqtt_client_disconnect()` function to disconnect from the
         * broker. If the disconnection is successful, the method clears the `IS_CONNECTED` flag and sets the
         * `IS_READY_FOR_CONNECT` flag. Finally, it returns the status code of the disconnection operation.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_disconnect
         */
        UINT disconnect();


        /**
         * @brief Deletes the MQTT client instance and releases all associated resources.
         *
         * @return The return code. Returns NXD_MQTT_SUCCESS if successful, else an error code.
         *
         * This method deletes the MQTT client instance and releases all the resources associated with it.
         * It first clears the "IS_READY_FOR_CONNECT" flag and then calls the nxd_mqtt_client_delete() function
         * to delete the client.
         *
         * If the delete operation fails, an error message is logged and the error code is returned.
         * Otherwise, the "IS_CONNECTED" and "IS_CREATED" flags are cleared and the return code is
         * returned.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_delete
         */
        UINT deleteClient();


        /**
         * @brief Sets the login credentials for the MQTT client.
         *
         * This method sets the login credentials (username and password) for the MQTT client.
         *
         * @param username The username for the MQTT client.
         * @param password The password for the MQTT client.
         * @return The status code indicating the success or failure of the operation.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_set_login
         */
        UINT loginSet(const char *username, const char *password);


        /**
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_disconnect_notify_set
         */
        UINT disconnectNotifySet(VOID (*disconnect_notify)(NXD_MQTT_CLIENT *client_ptr));

        /**
         * @TODO Finish
         * @param client_ptr
         */
        static VOID disconnectNotify(NXD_MQTT_CLIENT *client_ptr) {
            auto self = reinterpret_cast<MqttClient *>(client_ptr);
            Stm32ItmLogger::logger.printf("disconnectNotify client_ptr=0x%08x\r\n", client_ptr);
            Stm32ItmLogger::logger.printf("disconnectNotify self=0x%08x\r\n", self);
        }

        /**
         * @TODO Finish
         */
        VOID disconnectCallback() {
            log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
                    ->printf("Stm32NetXMqttClient::MqttClient[%s]::disconnectCallback()\r\n", getClientId());
            // Stm32ItmLogger::logger.setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            // ->println("Stm32NetXMqttClient::MqttClient::disconnectCallback()");
            // Stm32ItmLogger::logger.printf("disconnectNotify this=0x%08x\r\n", this);
            flags.clear(IS_CONNECTED);
        }


        void begin();

#ifdef NX_SECURE_ENABLE
        /**
         * @brief TLS setup callback function.
         *
         * This function is called during the setup of a TLS session. It initializes the TLS module,
         * creates a TLS session, sets up packet buffers, allocates space for the certificate,
         * initializes the certificate to verify incoming server certificates, and adds a CA certificate
         * to the trusted store.
         *
         * @param TLS_session_ptr          Pointer to the TLS session.
         * @param certificate_ptr          Pointer to the certificate from the broker.
         * @param trusted_certificate_ptr  Pointer to the trusted certificate.
         * @return                         The result code.
         *
         * The function returns NX_SUCCESS on success. If any of the operations fail, an error code is returned.
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_disconnect_notify_set
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter1.md#secure-mqtt-connection
         */
        UINT tlsSetupCallback(
            NX_SECURE_TLS_SESSION *TLS_session_ptr,
            NX_SECURE_X509_CERT *certificate_ptr,
            NX_SECURE_X509_CERT *trusted_certificate_ptr) {
            // const auto logger = &Stm32ItmLogger::logger;
            const auto logger = log();
            logger->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
                    ->printf("Stm32NetXMqttClient::MqttClient[%s]::tlsSetupCallback()\r\n", getClientId());

            UINT ret = NX_SUCCESS;


            // Initialize TLS module
            // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_initialize
            nx_secure_tls_initialize();


            // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_metadata_size_calculate
            ULONG metadata_size;
            ret = nx_secure_tls_metadata_size_calculate(&nx_crypto_tls_ciphers, &metadata_size);
            if (ret != NX_SUCCESS) {
                logger->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                        ->printf("TLS session failed. nx_secure_tls_metadata_size_calculate() = 0x%02x\r\n",
                                 ret);
                return ret;
            }
            logger->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::NOTICE)
                    ->printf("metadata_size = %lu\r\n", metadata_size);


            // Create a TLS session
            // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_session_create
            ret = nx_secure_tls_session_create(TLS_session_ptr, &nx_crypto_tls_ciphers,
                                               crypto_metadata_client, sizeof(crypto_metadata_client));
            if (ret != NX_SUCCESS) {
                logger->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                        ->printf("TLS session create failed. nx_secure_tls_session_create() = 0x%02x\r\n",
                                 ret);
                return ret;
            }


            // Need to allocate space for the certificate coming in from the broker
            memset((certificate_ptr), 0, sizeof(NX_SECURE_X509_CERT));


            // Allocate space for packet reassembly
            ret = nx_secure_tls_session_packet_buffer_set(TLS_session_ptr, tls_packet_buffer,
                                                          sizeof(tls_packet_buffer));
            if (ret != NX_SUCCESS) {
                logger->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                        ->printf(
                            "TLS session packet buffet set failed. nx_secure_tls_session_packet_buffer_set() = 0x%02x\r\n",
                            ret);
                return ret;
            }


            // allocate space for the certificate coming in from the remote host
            ret = nx_secure_tls_remote_certificate_allocate(TLS_session_ptr, certificate_ptr,
                                                            tls_packet_buffer, sizeof(tls_packet_buffer));
            if (ret != NX_SUCCESS) {
                logger->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                        ->printf(
                            "TLS remote certificate allocations failed. nx_secure_tls_remote_certificate_allocate() = 0x%02x\r\n",
                            ret);
                return ret;
            }


            // initialize Certificate to verify incoming server certificates
            Stm32NetX::Secure::X509 x509TrustedCert(trusted_certificate_ptr, logger);

            ret = fnGetTrustedCertificate(x509TrustedCert);
            if (ret != NX_SUCCESS) {
                logger->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                        ->printf(
                            "TLS trusted certificate get failed. fnGetTrustedCertificate() = 0x%02x\r\n",
                            ret);
                return ret;
            }


            // Add a CA Certificate to our trusted store
            // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-secure-tls/chapter4.md#nx_secure_tls_trusted_certificate_add
            ret = nx_secure_tls_trusted_certificate_add(TLS_session_ptr, x509TrustedCert.getCert());
            if (ret != NX_SUCCESS) {
                logger->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                        ->printf(
                            "TLS trusted certificate add failed. nx_secure_tls_trusted_certificate_add() = 0x%02x\r\n",
                            ret);
                return ret;
            }

            return ret;
        }


#endif

#ifdef LIBSMART_ENABLE_STD_FUNCTION

    public:
        using fnGetTrustedCertificate_t = std::function<UINT(Stm32NetX::Secure::X509 &x509TrustedCert)>;

        void setGetTrustedCertificateFunction(const fnGetTrustedCertificate_t &fn) {
            fnGetTrustedCertificate = fn;
        }

    private:
        fnGetTrustedCertificate_t fnGetTrustedCertificate = [](Stm32NetX::Secure::X509 &x509TrustedCert) {
            return static_cast<UINT>(NX_NOT_ENABLED);
        };

#endif

    protected:
        void createNetworkThread();

    private:
        Stm32NetX::NetX *NX;
        UCHAR *clientStackMemory = {};
        Stm32ThreadX::EventFlags flags{"Stm32NetXMqttClient::MqttClient::flags", getLogger()};

    public:
        static UINT setup(TX_BYTE_POOL *byte_pool) {
            Stm32ItmLogger::logger.setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
                    ->println("Stm32NetXMqttClient::MqttClient::setup()");

            mqttClient = new MqttClient(Stm32NetX::NX, &Stm32ItmLogger::logger);
            mqttClient->createNetworkThread();

            return TX_SUCCESS;
        }
    };
}

#endif //LIBSMART_STM32NETXMQTTCLIENT_STM32NETXMQTTCLIENT_HPP
