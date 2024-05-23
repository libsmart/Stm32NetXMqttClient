/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32NETXMQTTCLIENT_STM32NETXMQTTCLIENT_HPP
#define LIBSMART_STM32NETXMQTTCLIENT_STM32NETXMQTTCLIENT_HPP

#include <libsmart_config.hpp>

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
#endif

#define CRYPTO_METADATA_CLIENT_SIZE 11600
#define TLS_PACKET_BUFFER_SIZE      4000

/* TLS buffers and certificate containers. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;


namespace Stm32NetXMqttClient {
    /* calculated with nx_secure_tls_metadata_size_calculate */
    static CHAR crypto_metadata_client[CRYPTO_METADATA_CLIENT_SIZE] __attribute__((section(".ccmram")));
    /* Define the TLS packet reassembly buffer. */
    static UCHAR tls_packet_buffer[TLS_PACKET_BUFFER_SIZE] __attribute__((section(".ccmram")));


    template<class T, class Method, Method m, class... Params>
    static auto bounce(NXD_MQTT_CLIENT *mqtt_client_ptr, Params... params) ->
        decltype(((*reinterpret_cast<T *>(mqtt_client_ptr->nxd_mqtt_thread.tx_thread_entry_parameter)).*m)(params...)) {
        return ((*reinterpret_cast<T *>(mqtt_client_ptr->nxd_mqtt_thread.tx_thread_entry_parameter)).*m)(params...);
    }


    class MqttClient;
    inline MqttClient *mqttClient = {};

    class MqttClient : public Stm32ItmLogger::Loggable, public Stm32Common::Nameable, public Stm32ThreadX::Thread,
                       public NXD_MQTT_CLIENT {
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

        const char *getClientId();


        bool isReadyForConnect() { return flags.isSet(IS_READY_FOR_CONNECT); }
        bool isConnected() { return flags.isSet(IS_CONNECTED); }

        /**
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_publish
         */
        UINT publish(const CHAR *topic_name,
                     const CHAR *message,
                     UINT retain,
                     UINT QoS,
                     Stm32ThreadX::WaitOption waitOption);

        /**
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_subscribe
         */
        UINT subscribe(const CHAR *topic_name, UINT QoS);

        /**
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_unsubscribe
         */
        UINT unsubscribe(const CHAR *topic_name);

        /**
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
         * @note This method assumes that the MQTT client instance has been created and is connected to the broker.
         */
        bool hasMessage();


        /**
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_create
         */
        UINT create();

        /**
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_connect
         */
        UINT connect(NXD_ADDRESS *server_ip, UINT server_port, UINT keepalive, UINT clean_session,
                     Stm32ThreadX::WaitOption waitOption);

        /**
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_secure_connect
         */
        UINT secureConnect(NXD_ADDRESS *server_ip, UINT server_port, UINT keepalive, UINT clean_session,
                           Stm32ThreadX::WaitOption waitOption);

        /**
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_disconnect
         */
        UINT disconnect();

        /**
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


        static VOID disconnectNotify(NXD_MQTT_CLIENT *client_ptr) {
            auto self = reinterpret_cast<MqttClient *>(client_ptr);
            Stm32ItmLogger::logger.printf("disconnectNotify client_ptr=0x%08x\r\n", client_ptr);
            Stm32ItmLogger::logger.printf("disconnectNotify self=0x%08x\r\n", self);
        }

        VOID disconnectCallback() {
            log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
                    ->printf("Stm32NetXMqttClient::MqttClient[%s]::disconnectCallback()\r\n", getClientId());
            // Stm32ItmLogger::logger.setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            // ->println("Stm32NetXMqttClient::MqttClient::disconnectCallback()");
            // Stm32ItmLogger::logger.printf("disconnectNotify this=0x%08x\r\n", this);
            flags.clear(IS_CONNECTED);
        }

#ifdef NX_SECURE_ENABLE
        UINT tlsSetupCallback(
            NX_SECURE_TLS_SESSION *TLS_session_ptr,
            NX_SECURE_X509_CERT *certificate_ptr,
            NX_SECURE_X509_CERT *trusted_certificate_ptr) {
            const auto logger = &Stm32ItmLogger::logger;
            logger->setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
                    ->printf("Stm32NetXMqttClient::MqttClient[%s]::tlsSetupCallback()\r\n", getClientId());

            UINT ret = NX_SUCCESS;

            // Initialize TLS module
            nx_secure_tls_initialize();


            // Create a TLS session
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
            // ret = fnGetTrustedCertificate(x509TrustedCert);
            ret = x509TrustedCert.certificateInitialize(rootca, rootca_length);
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


        void setRootCa(const uint8_t *data, const USHORT data_length) {
            rootca = const_cast<uint8_t *>(data);
            rootca_length = data_length;
        }


        static UINT tls_setup_callback(NXD_MQTT_CLIENT *,
                                       NX_SECURE_TLS_SESSION *,
                                       NX_SECURE_X509_CERT *,
                                       NX_SECURE_X509_CERT *) {
            return NX_NOT_ENABLED;
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
        static uint8_t *rootca;
        static USHORT rootca_length;

    public:
        static UINT setup(TX_BYTE_POOL *byte_pool) {
            Stm32ItmLogger::logger.setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
                    ->println("Stm32NetXMqttClient::MqttClient::setup()");

            mqttClient = new MqttClient(Stm32NetX::NX, &Stm32ItmLogger::logger);
            mqttClient->createNetworkThread();

            return TX_SUCCESS;
        }
    };

    inline uint8_t *MqttClient::rootca = nullptr;
    inline USHORT MqttClient::rootca_length = 0;
}

#endif //LIBSMART_STM32NETXMQTTCLIENT_STM32NETXMQTTCLIENT_HPP
