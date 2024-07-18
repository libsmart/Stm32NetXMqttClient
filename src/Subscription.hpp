/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef LIBSMART_STM32NETXMQTTCLIENT_SUBSCRIPTION_HPP
#define LIBSMART_STM32NETXMQTTCLIENT_SUBSCRIPTION_HPP

#include <functional>
#include "Topic.hpp"

namespace Stm32NetXMqttClient {
    class Subscription : public Topic {
    public:
        using fn_onMsg_t = std::function<void(const char *message)>;


        virtual void runOnMsgCallback(const char *message) {
            fn_onMsg(message);
        }

        virtual void setOnMsgCallback(const fn_onMsg_t &cb) { fn_onMsg = cb; }

        [[nodiscard]] virtual UINT getQoS() const {
            return QoS;
        }

        virtual void setQoS(const UINT QoS) {
            this->QoS = QoS;
        }

    private:
        fn_onMsg_t fn_onMsg = [](const char *message) { ; };
        UINT QoS = 0;
    };
}

#endif
