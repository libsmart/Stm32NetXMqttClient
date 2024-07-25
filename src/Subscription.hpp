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
        using fn_onMsg_t = std::function<void(const char *topic, const char *message)>;


        virtual void runOnMsgCallback(const char *topic, const char *message) {
            fn_onMsg(topic, message);
        }

        virtual void setOnMsgCallback(const fn_onMsg_t &cb) { fn_onMsg = cb; }

        [[nodiscard]] virtual UINT getQoS() const {
            return QoS;
        }

        virtual void setQoS(const UINT QoS) {
            this->QoS = QoS;
        }


        virtual bool topicMatches(const char *topic) {
            if (strcmp(this->getTopic(), topic) == 0) return true;
            return matches(topic, this->getTopic());
        }

    private:
        fn_onMsg_t fn_onMsg = [](const char *topic, const char *message) { ; };
        UINT QoS = 0;


        // Split a topic string into its components
        void split(const char *str, char delimiter, char tokens[][32], int &count) {
            count = 0;
            const char *start = str;
            const char *end = strchr(start, delimiter);

            while (end != nullptr) {
                strncpy(tokens[count], start, end - start);
                tokens[count][end - start] = '\0';
                ++count;
                start = end + 1;
                end = strchr(start, delimiter);
            }
            strcpy(tokens[count], start);
            ++count;
        }

        // Check if a topic matches a subscription pattern
        bool matches(const char *topic, const char *pattern) {
            char topicTokens[10][32]; // Assume max 10 levels, each max 32 chars
            char patternTokens[10][32];
            int topicCount = 0;
            int patternCount = 0;

            split(topic, '/', topicTokens, topicCount);
            split(pattern, '/', patternTokens, patternCount);

            int i = 0, j = 0;
            while (i < topicCount && j < patternCount) {
                if (strcmp(patternTokens[j], "#") == 0) {
                    return true;
                }
                if (strcmp(patternTokens[j], "+") != 0 && strcmp(patternTokens[j], topicTokens[i]) != 0) {
                    return false;
                }
                ++i;
                ++j;
            }

            return (i == topicCount && j == patternCount);
        }
    };
}

#endif
