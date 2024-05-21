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


namespace Stm32NetXMqttClient {
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
            flags.create();
        }

        [[noreturn]] void mqttThread();

        const char *getClientId();

        /**
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_create
         */
        UINT create();

        /**
         *
         * @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_connect
         */
        UINT connect(NXD_ADDRESS *server_ip, UINT server_port, UINT keepalive, UINT clean_session,
                     Stm32ThreadX::WaitOption waitOption) {
            log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
                    ->printf("Stm32NetXMqttClient::MqttClient[%s]::connect()\r\n", getClientId());

            const auto ret = nxd_mqtt_client_connect(this,
                                                     server_ip,
                                                     server_port,
                                                     keepalive,
                                                     clean_session,
                                                     waitOption());
            if (ret != NXD_MQTT_SUCCESS) {
                log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                        ->printf("MQTT client '%s' connect failed. nxd_mqtt_client_connect() = 0x%02x\r\n",
                                 getClientId(), ret);
                return ret;
            }
            flags.set(IS_CONNECTED);
            return ret;
        }

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

            // mqttClient.createNetworkThread();


            mqttClient = new MqttClient(Stm32NetX::NX, &Stm32ItmLogger::logger);
            mqttClient->createNetworkThread();

            return TX_SUCCESS;
        }
    };

    // inline MqttClient mqttClient(Stm32NetX::NX, &Stm32ItmLogger::logger);
}

#endif //LIBSMART_STM32NETXMQTTCLIENT_STM32NETXMQTTCLIENT_HPP
