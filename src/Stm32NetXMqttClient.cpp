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

    // ret = NX->waitForIpInstance();
    // ret = NX->waitForPacketPool();

    // Create MQTT client instance
    static char client_name[] = "Stm32NetXMqttClient::MqttClient";
    /*
    ret = nxd_mqtt_client_create(this,
                                 client_name,
                                 const_cast<CHAR *>(getClientId()), strlen(getClientId()),
                                 NX->getIpInstance(),
                                 NX->getPacketPool(),
                                 NX->getBytePool()->allocate(LIBSMART_STM32NETX_MQTT_CLIENT_STACK_SIZE),
                                 LIBSMART_STM32NETX_MQTT_CLIENT_STACK_SIZE,
                                 LIBSMART_STM32NETX_MQTT_CLIENT_THREAD_PRIORITY,
                                 NX_NULL, 0);
    */
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("MQTT client create failed. nxd_mqtt_client_create() = 0x%02x\r\n", ret);
        assert_param(ret == NXD_MQTT_SUCCESS);
    }


    for (;;) {
        tx_thread_sleep(1);
    }
}

const char *MqttClient::getClientId() {
    return "clientid";
}
