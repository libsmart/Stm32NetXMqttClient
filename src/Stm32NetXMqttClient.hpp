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


namespace Stm32NetXMqttClient {
    class MqttClient;
    inline MqttClient *mqttClient = {};

    class MqttClient : public Stm32ItmLogger::Loggable, public Stm32ThreadX::Thread, public NXD_MQTT_CLIENT {
    public:
        explicit MqttClient(Stm32NetX::NetX *nx)
            : MqttClient(nx, &Stm32ItmLogger::emptyLogger) { ; }

        MqttClient(Stm32NetX::NetX *nx, Stm32ItmLogger::LoggerInterface *logger)
            : Loggable(logger),
              Thread(Stm32ThreadX::BOUNCE(MqttClient, mqttThread), reinterpret_cast<ULONG>(this), priority(),
                     "Stm32NetXMqttClient::MqttClient"),
              NXD_MQTT_CLIENT(), NX(nx) {
        }

        [[noreturn]] void mqttThread();

        const char *getClientId();

    protected:
        void createNetworkThread();

    private:
        Stm32NetX::NetX *NX;

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
