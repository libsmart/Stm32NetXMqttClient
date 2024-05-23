/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "Stm32NetXMqttClient.hpp"

#include "Address.hpp"
#ifdef NX_SECURE_ENABLE
#include "nx_secure_tls.h"
#include "nx_secure_x509.h"
#endif

using namespace Stm32NetXMqttClient;

void MqttClient::createNetworkThread() {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXMqttClient::MqttClient::createNetworkThread()");

    // Set the stack for the thread
    setStack(NX->getBytePool()->allocate(LIBSMART_STM32NETX_MQTT_CLIENT_THREAD_STACK_SIZE),
             LIBSMART_STM32NETX_MQTT_CLIENT_THREAD_STACK_SIZE);

    // Start thread
    createThread();
    resume();
}

void MqttClient::mqttThread() {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXMqttClient::MqttClient::mqttThread()");

    /*
    Stm32NetX::Address address;
    address.nxd_ip_version = 4;
    address.nxd_ip_address.v4 = IP_ADDRESS(10, 82, 2, 198);;
    */

    UINT ret = 1;

    NX->waitForIpInstance();
    NX->waitForPacketPool();

    for (;;) {
        NX->waitForIp();

        for (;;) {
            // Create MQTT client instance
            ret = create();
            if (ret != NXD_MQTT_SUCCESS) {
                break;
            }

            // disconnectNotifySet(
            // bounce<MqttClient, decltype(&MqttClient::disconnectCallback), &MqttClient::disconnectCallback>);

            /*
            ret = loginSet("testuser", "eZ.1234");
            if (ret != NXD_MQTT_SUCCESS) {
                break;
            }
            */

            /*
            ret = connect(&address, NXD_MQTT_PORT, 30, NX_TRUE,
                          Stm32ThreadX::WaitOption{TX_TIMER_TICKS_PER_SECOND * 10});
            if (ret != NXD_MQTT_SUCCESS) {
                break;
            }
            */

            flags.await(IS_CONNECTED);

            // Run as long as ip address is valid
            while (NX->isIpSet() && flags.isSet(IS_CONNECTED)) {
                tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND);
            }
            break;
        }

        // Disconnect from the broker.
        disconnect();

        // Delete the client instance, release all the resources.
        deleteClient();

        // Wait 5 seconds
        tx_thread_sleep(TX_TIMER_TICKS_PER_SECOND * 5);
    }
}

const char *MqttClient::getClientId() {
    return Nameable::getName();
}

UINT MqttClient::create() {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::create()\r\n", getClientId());


    // Allocate memory for the mqtt client
    if (clientStackMemory == nullptr) {
        clientStackMemory = NX->getBytePool()->allocate(LIBSMART_STM32NETX_MQTT_CLIENT_STACK_SIZE);
    }

    const auto ret = nxd_mqtt_client_create(this,
                                            const_cast<CHAR *>("mqtt_client"),
                                            const_cast<CHAR *>(getClientId()), strlen(getClientId()),
                                            NX->getIpInstance(),
                                            NX->getPacketPool(),
                                            clientStackMemory,
                                            LIBSMART_STM32NETX_MQTT_CLIENT_STACK_SIZE,
                                            LIBSMART_STM32NETX_MQTT_CLIENT_THREAD_PRIORITY,
                                            NX_NULL, 0);
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("MQTT client '%s' create failed. nxd_mqtt_client_create() = 0x%02x\r\n",
                         getClientId(), ret);
        return ret;
    }
    flags.set(IS_CREATED);
    flags.set(IS_READY_FOR_CONNECT);

    return ret;
}

UINT MqttClient::connect(NXD_ADDRESS *server_ip, UINT server_port, UINT keepalive, UINT clean_session,
                         Stm32ThreadX::WaitOption waitOption) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::connect()\r\n", getClientId());

    flags.clear(IS_READY_FOR_CONNECT);

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

UINT MqttClient::secureConnect(NXD_ADDRESS *server_ip, UINT server_port, UINT keepalive, UINT clean_session,
                               Stm32ThreadX::WaitOption waitOption) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::secureConnect()\r\n", getClientId());

#ifdef NX_SECURE_ENABLE
    flags.clear(IS_READY_FOR_CONNECT);

    const auto ret = nxd_mqtt_client_secure_connect(this,
                                                    server_ip,
                                                    server_port,
                                                    bounce<
                                                        MqttClient,
                                                        decltype(&MqttClient::tlsSetupCallback),
                                                        &MqttClient::tlsSetupCallback,
                                                        NX_SECURE_TLS_SESSION *,
                                                        NX_SECURE_X509_CERT *,
                                                        NX_SECURE_X509_CERT *>,
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
#else
    log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
            ->println("NOT ENABLED");
    return NX_NOT_ENABLED;
#endif
}

UINT MqttClient::disconnect() {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::disconnect()\r\n", getClientId());

    const auto ret = nxd_mqtt_client_disconnect(this);
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("MQTT client '%s' disconnect failed. nxd_mqtt_client_disconnect() = 0x%02x\r\n",
                         getClientId(), ret);
        return ret;
    }
    flags.clear(IS_CONNECTED);
    flags.set(IS_READY_FOR_CONNECT);
    return ret;
}

UINT MqttClient::deleteClient() {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::deleteClient()\r\n", getClientId());

    flags.clear(IS_READY_FOR_CONNECT);

    const auto ret = nxd_mqtt_client_delete(this);
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("MQTT client '%s' delete failed. nxd_mqtt_client_delete() = 0x%02x\r\n",
                         getClientId(), ret);
        return ret;
    }
    flags.clear(IS_CONNECTED);
    flags.clear(IS_CREATED);
    return ret;
}

UINT MqttClient::loginSet(const char *username, const char *password) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::loginSet(%s, ...)\r\n", getClientId(), username);

    const auto ret = nxd_mqtt_client_login_set(this,
                                               const_cast<CHAR *>(username), strlen(username),
                                               const_cast<CHAR *>(password), strlen(password));
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("MQTT client '%s' login set failed. nxd_mqtt_client_login_set() = 0x%02x\r\n",
                         getClientId(), ret);
    }
    return ret;
}

UINT MqttClient::disconnectNotifySet(void (*disconnect_notify)(NXD_MQTT_CLIENT *client_ptr)) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::disconnectNotifySet()\r\n", getClientId());

    const auto ret = nxd_mqtt_client_disconnect_notify_set(this, disconnect_notify);
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "MQTT client '%s' disconnect notify set failed. nxd_mqtt_client_disconnect_notify_set() = 0x%02x\r\n",
                    getClientId(), ret);
    }
    return ret;
}
