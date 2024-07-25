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

    // Create thread
    createThread();
    // resume();
}

void MqttClient::mqttThread() {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("Stm32NetXMqttClient::MqttClient::mqttThread()");

    /*
    Stm32NetX::Address address;
    address.nxd_ip_version = 4;
    address.nxd_ip_address.v4 = IP_ADDRESS(10, 82, 2, 198);;
    */

    UCHAR topic_buffer[128];
    UINT actual_topic_length;
    UCHAR message_buffer[32];
    UINT actual_message_length;

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
                if (hasMessage()) {
                    memset(topic_buffer, 0, sizeof(topic_buffer));
                    memset(message_buffer, 0, sizeof(message_buffer));

                    ret = messageGet(
                        topic_buffer, sizeof(topic_buffer) - 1, &actual_topic_length,
                        message_buffer, sizeof(message_buffer) - 1, &actual_message_length
                    );
                    if (ret == NXD_MQTT_SUCCESS) {
                        auto subscription = findSubscriptionByTopic(reinterpret_cast<char *>(topic_buffer));
                        if (subscription != nullptr) {
                            subscription->runOnMsgCallback(
                                reinterpret_cast<char *>(topic_buffer),
                                reinterpret_cast<char *>(message_buffer));
                        }

                        log(Stm32ItmLogger::LoggerInterface::Severity::NOTICE)
                                ->printf("MQTT '%s' = '%s'\r\n",
                                         topic_buffer,
                                         message_buffer
                                );
                    }
                }
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

void MqttClient::setClientId(const char *clientid) {
    Nameable::setName(clientid);
}

UINT MqttClient::willMessageSet(const CHAR *will_topic, const CHAR *will_message, UINT will_retain_flag,
                                UINT will_QoS) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::willMessageSet('%s', '%s')\r\n", getClientId(), will_topic,
                     will_message);

    // https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_will_message_set
    const auto ret = nxd_mqtt_client_will_message_set(this,
                                                      reinterpret_cast<const UCHAR *>(will_topic),
                                                      strlen(will_topic),
                                                      (UCHAR *) will_message,
                                                      strlen(will_message),
                                                      will_retain_flag,
                                                      will_QoS
    );
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("MQTT client '%s' will message set failed. nxd_mqtt_client_will_message_set() = 0x%02x\r\n",
                         getClientId(), ret);
    }
    return ret;
}

UINT MqttClient::willMessageSet(Topic *topic, const CHAR *will_message, UINT will_retain_flag, UINT will_QoS) {
    return willMessageSet(topic->getTopic(), will_message, will_retain_flag, will_QoS);
}

UINT MqttClient::publish(const CHAR *topic_name, const CHAR *message, const UINT retain, const UINT QoS,
                         const Stm32ThreadX::WaitOption waitOption) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::publish('%s', '%s')\r\n", getClientId(), topic_name,
                     message);

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_publish
    const auto ret = nxd_mqtt_client_publish(this,
                                             const_cast<CHAR *>(topic_name),
                                             strlen(topic_name),
                                             const_cast<CHAR *>(message),
                                             strlen(message),
                                             retain,
                                             QoS,
                                             waitOption());
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXMqttClient::MqttClient[%s]: nxd_mqtt_client_publish('%s', '%s') = 0x%02x\r\n",
                         getClientId(), topic_name, message, ret);
    }
    if (ret == NXD_MQTT_NOT_CONNECTED) {
        flags.clear(IS_CONNECTED);
    }
    return ret;
}

UINT MqttClient::publish(const CHAR *topic_name, const CHAR *message, UINT retain, UINT QoS) {
    return publish(topic_name, message, retain, QoS, Stm32ThreadX::WaitOption{
                       Stm32ThreadX::WaitOption::NO_WAIT
                   });
}

UINT MqttClient::publish(Topic *topic, const CHAR *message, UINT retain, UINT QoS,
                         Stm32ThreadX::WaitOption waitOption) {
    return publish(topic->getTopic(), message, retain, QoS, waitOption);
}

UINT MqttClient::publish(Topic *topic, const CHAR *message, UINT retain, UINT QoS) {
    return publish(topic, message, retain, QoS, Stm32ThreadX::WaitOption{
                       Stm32ThreadX::WaitOption::NO_WAIT
                   });
}

UINT MqttClient::subscribe(const CHAR *topic_name, UINT QoS) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::subscribe('%s')\r\n", getClientId(), topic_name);

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_subscribe
    const auto ret = nxd_mqtt_client_subscribe(this,
                                               const_cast<CHAR *>(topic_name),
                                               strlen(topic_name),
                                               QoS
    );
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("Stm32NetXMqttClient::MqttClient[%s]: nxd_mqtt_client_subscribe('%s') = 0x%02x\r\n",
                         getClientId(), topic_name, ret);
    }
    if (ret == NXD_MQTT_NOT_CONNECTED) {
        flags.clear(IS_CONNECTED);
    }
    return ret;
}

UINT MqttClient::subscribe(Subscription *subscription) {
    auto ret = subscribe(subscription->getTopic(), subscription->getQoS());
    if (ret == NXD_MQTT_SUCCESS) {
        registerSubscription(subscription);
    }
    return ret;
}


UINT MqttClient::unsubscribe(const CHAR *topic_name) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::unsubscribe('%s')\r\n", getClientId(), topic_name);

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_unsubscribe
    const auto ret = nxd_mqtt_client_unsubscribe(this,
                                                 const_cast<CHAR *>(topic_name),
                                                 strlen(topic_name)
    );
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("MQTT client '%s' unsubscribe failed. nxd_mqtt_client_unsubscribe() = 0x%02x\r\n",
                         getClientId(), ret);
    }
    if (ret == NXD_MQTT_NOT_CONNECTED) {
        flags.clear(IS_CONNECTED);
    }
    return ret;
}

UINT MqttClient::unsubscribe(Subscription *subscription) {
    unregisterSubscription(subscription);
    return unsubscribe(subscription->getTopic());
}

UINT MqttClient::messageGet(UCHAR *topic_buffer, UINT topic_buffer_size, UINT *actual_topic_length,
                            UCHAR *message_buffer, UINT message_buffer_size, UINT *actual_message_length) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::messageGet()\r\n", getClientId());

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_message_get
    const auto ret = nxd_mqtt_client_message_get(this,
                                                 topic_buffer,
                                                 topic_buffer_size,
                                                 actual_topic_length,
                                                 message_buffer,
                                                 message_buffer_size,
                                                 actual_message_length
    );
    if (ret != NXD_MQTT_SUCCESS && ret != NXD_MQTT_NO_MESSAGE) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("MQTT client '%s' message get failed. nxd_mqtt_client_message_get() = 0x%02x\r\n",
                         getClientId(), ret);
    }
    return ret;
}

bool MqttClient::hasMessage() {
    UINT actual_topic_length, actual_message_length;
    UCHAR topic_buffer, message_buffer;

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_message_get
    const auto ret = nxd_mqtt_client_message_get(this,
                                                 &topic_buffer,
                                                 0,
                                                 &actual_topic_length,
                                                 &message_buffer,
                                                 0,
                                                 &actual_message_length
    );
    return ret == NXD_MQTT_INSUFFICIENT_BUFFER_SPACE;
}

UINT MqttClient::create() {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::create()\r\n", getClientId());


    // Allocate memory for the mqtt client
    if (clientStackMemory == nullptr) {
        clientStackMemory = NX->getBytePool()->allocate(LIBSMART_STM32NETX_MQTT_CLIENT_STACK_SIZE);
    }

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_create
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

        flags.clear(IS_CREATED | IS_READY_FOR_CONNECT);
        return ret;
    }

    flags.set(IS_CREATED | IS_READY_FOR_CONNECT);
    return ret;
}

UINT MqttClient::connect(NXD_ADDRESS *server_ip, UINT server_port, UINT keepalive, UINT clean_session,
                         Stm32ThreadX::WaitOption waitOption) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::connect()\r\n", getClientId());

    flags.clear(IS_READY_FOR_CONNECT);

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_connect
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

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_secure_connect
    const auto ret = nxd_mqtt_client_secure_connect(this,
                                                    server_ip,
                                                    server_port,
                                                    // tls_setup_callback,

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

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_disconnect
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

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_delete
    const auto ret = nxd_mqtt_client_delete(this);
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf("MQTT client '%s' delete failed. nxd_mqtt_client_delete() = 0x%02x\r\n",
                         getClientId(), ret);
        return ret;
    }
    flags.clear(IS_CONNECTED | IS_CREATED);
    return ret;
}

UINT MqttClient::loginSet(const char *username, const char *password) {
    log(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->printf("Stm32NetXMqttClient::MqttClient[%s]::loginSet(%s, ...)\r\n", getClientId(), username);

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_set_login
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

    // @see https://github.com/eclipse-threadx/rtos-docs/blob/main/rtos-docs/netx-duo/netx-duo-mqtt/chapter3.md#nxd_mqtt_client_disconnect_notify_set
    const auto ret = nxd_mqtt_client_disconnect_notify_set(this, disconnect_notify);
    if (ret != NXD_MQTT_SUCCESS) {
        log(Stm32ItmLogger::LoggerInterface::Severity::ERROR)
                ->printf(
                    "MQTT client '%s' disconnect notify set failed. nxd_mqtt_client_disconnect_notify_set() = 0x%02x\r\n",
                    getClientId(), ret);
    }
    return ret;
}

void MqttClient::begin() {
    resume();
}


bool MqttClient::registerSubscription(Subscription *subscription) {
    for (auto &i: subscriptions) {
        if (i == nullptr) {
            i = subscription;
            return true;
        }
    }
    return false;
}

bool MqttClient::unregisterSubscription(Subscription *subscription) {
    for (auto &i: subscriptions) {
        if (i == subscription) {
            i = nullptr;
            return true;
        }
    }
    return false;
}

Subscription *MqttClient::findSubscriptionByTopic(const char *topic) {
    for (auto &i: subscriptions) {
        if (i != nullptr && i->topicMatches(topic)) {
            return i;
        }
    }
    return nullptr;
}

