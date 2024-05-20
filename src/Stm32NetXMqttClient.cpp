/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "Stm32NetXMqttClient.hpp"

using namespace Stm32NetXMqttClient;

void MqttClient::createNetworkThread() {
    setStack(NX->getBytePool()->allocate(LIBSMART_STM32NETX_MQTT_CLIENT_THREAD_STACK_SIZE),
             LIBSMART_STM32NETX_MQTT_CLIENT_THREAD_STACK_SIZE);

    // Start thread
    createThread();
    resume();
}

void MqttClient::mqttThread() {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXMqttClient::MqttClient::mqttThread()");

    UINT ret = 1;

    log(Stm32ItmLogger::LoggerInterface::Severity::DEBUGGING)
            ->println("NX->waitForIpInstance()");
    NX->waitForIpInstance();
    log(Stm32ItmLogger::LoggerInterface::Severity::DEBUGGING)
            ->println("NX->waitForPacketPool()");
    NX->waitForPacketPool();

    for (;;) {
        log(Stm32ItmLogger::LoggerInterface::Severity::DEBUGGING)
                ->println("NX->waitForIp()");
        NX->waitForIp();

        // Create MQTT client instance
        static char client_name[] = "Stm32NetXMqttClient::MqttClient";
        log(Stm32ItmLogger::LoggerInterface::Severity::DEBUGGING)
                ->println("nxd_mqtt_client_create()");
        ret = nxd_mqtt_client_create(this,
                                     client_name,
                                     const_cast<CHAR *>(getClientId()), strlen(getClientId()),
                                     NX->getIpInstance(),
                                     NX->getPacketPool(),
                                     NX->getBytePool()->allocate(LIBSMART_STM32NETX_MQTT_CLIENT_STACK_SIZE),
                                     LIBSMART_STM32NETX_MQTT_CLIENT_STACK_SIZE,
                                     LIBSMART_STM32NETX_MQTT_CLIENT_THREAD_PRIORITY,
                                     NX_NULL, 0);
        if (ret != NXD_MQTT_SUCCESS) {
            log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                    ->printf("MQTT client create failed. nxd_mqtt_client_create() = 0x%02x\r\n", ret);
            assert_param(ret == NXD_MQTT_SUCCESS);
        }


        // Run as long as ip address is valid
        for (;;) {
            if (!NX->isIpSet()) break;
            tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
        }


        // Disconnect from the broker.
        log(Stm32ItmLogger::LoggerInterface::Severity::DEBUGGING)
                ->println("nxd_mqtt_client_disconnect()");
        ret = nxd_mqtt_client_disconnect(this);
        if (ret != NXD_MQTT_SUCCESS) {
            log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                    ->printf("MQTT client disconnect failed. nxd_mqtt_client_disconnect() = 0x%02x\r\n", ret);
            assert_param(ret == NXD_MQTT_SUCCESS);
        }


        // Delete the client instance, release all the resources.
        log(Stm32ItmLogger::LoggerInterface::Severity::DEBUGGING)
                ->println("nxd_mqtt_client_delete()");
        ret = nxd_mqtt_client_delete(this);
        if (ret != NXD_MQTT_SUCCESS) {
            log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                    ->printf("MQTT client delete failed. nxd_mqtt_client_delete() = 0x%02x\r\n", ret);
            assert_param(ret == NXD_MQTT_SUCCESS);
        }
    }
}

const char *MqttClient::getClientId() {
    return "clientid";
}
