/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "Stm32NetXMqttClientCPPWrapper.hpp"
#include <Stm32NetXMqttClient.hpp>

UINT Stm32NetXMqttClient_setup(TX_BYTE_POOL *byte_pool) {
    return Stm32NetXMqttClient::MqttClient::setup(byte_pool);
}
