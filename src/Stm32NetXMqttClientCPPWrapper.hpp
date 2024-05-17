/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32NETXMQTTCLIENT_STM32NETXCPPWRAPPER_HPP
#define LIBSMART_STM32NETXMQTTCLIENT_STM32NETXCPPWRAPPER_HPP

#include "tx_api.h"

#ifdef __cplusplus
extern "C" {
#endif

extern UINT Stm32NetXMqttClient_setup(TX_BYTE_POOL *byte_pool);

#ifdef __cplusplus
}
#endif


#endif //LIBSMART_STM32NETXMQTTCLIENT_STM32NETXCPPWRAPPER_HPP
