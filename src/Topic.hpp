/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LIBSMART_STM32NETXMQTTCLIENT_TOPIC_HPP
#define LIBSMART_STM32NETXMQTTCLIENT_TOPIC_HPP

#include "nxd_mqtt_client.h"
#include "Print.hpp"

namespace Stm32NetXMqttClient {
    class Topic : public Stm32Common::Print {
    public:
        Topic() = default;

        explicit Topic(const char *name) { setName(name); }

        Topic(const char *name, const char *base_name) {
            setName(name);
            setBaseName(base_name);
        }


        /**
         * @brief Sets the topic string.
         *
         * This method sets the topic string by clearing the existing topic and then copying the given topic string into
         * the topic_name buffer using snprintf.
         *
         * @param topic A const char pointer to the topic string to be set.
         */
        void setTopic(const char *topic) {
            clearTopic();
            snprintf(topic_name, sizeof(topic_name), "%s", topic);
        }


        /**
         * @brief Returns the topic string.
         *
         * This method retrieves the topic string stored in the topic_name buffer and returns it as a const char pointer.
         *
         * @return A const char pointer to the topic string.
         */
        const char *getTopic() {
            return topic_name;
        }


        /**
         * @brief Clears the topic string.
         *
         * This method clears the topic string by setting all bytes in the topic_name buffer to 0.
         *
         * @note After calling this method, the topic name will be an empty string.
         *       The size of the topic_name buffer remains unchanged.
         */
        void clearTopic() {
            std::memset(topic_name, 0, sizeof(topic_name));
        }


        /**
         * @brief Sets the name of the topic.
         *
         * This method sets the name of the topic by copying the specified name to the topic_name buffer.
         * The specified name is truncated if it exceeds the size of the topic_name buffer.
         *
         * @param name The name to set for the topic.
         *
         * @note The name should be a null-terminated string.
         *       If the specified name is longer than the size of the topic_name buffer,
         *       it will be truncated to fit in the buffer.
         */
        void setName(const char *name) {
            clearName();
            snprintf(const_cast<char *>(getName()), sizeof(topic_name) - topic_name_pos, "%s", name);
        }


        /**
         * @brief Gets the name of the topic.
         *
         * This method retrieves the name of the topic by returning a pointer to the topic name.
         * The pointer returned points to the starting position of the topic name in the topic_name buffer.
         *
         * @note The returned pointer should not be modified or freed by the caller. It is only valid as long
         * as the underlying topic_name buffer remains unchanged.
         *
         * @return A pointer to the topic name.
         */
        const char *getName() {
            return topic_name + topic_name_pos;
        }


        /**
         * @brief Clears the remaining space in the topic name buffer.
         *
         * This method clears the remaining space in the topic name buffer by setting the characters to 0.
         * It returns a pointer to the topic object.
         *
         * @return A pointer to the topic object.
         */
        Topic *clearName() {
            std::memset(const_cast<char *>(getName()), 0, sizeof(topic_name) - topic_name_pos);
            return this;
        }


        /**
         * @brief Sets the base name for the topic.
         *
         * This method sets the base name of the topic. It copies the base name into the topic_name buffer,
         * updates the topic_name_pos to the new base name position, and clears the remaining space in the buffer.
         *
         * @param baseName The base name to set for the topic.
         */
        void setBaseName(const char *baseName) {
            if (strlen(baseName) > 0) setBaseName("");
            const auto topic_name_length = strlen(topic_name + topic_name_pos);
            const auto new_topic_name_pos = strlen(baseName);
            std::memmove(topic_name + new_topic_name_pos, topic_name + topic_name_pos, topic_name_length);
            std::memmove(topic_name, baseName, new_topic_name_pos);
            topic_name_pos = new_topic_name_pos;

            std::memset(topic_name + topic_name_pos + topic_name_length, 0,
                        sizeof(topic_name) - (topic_name_pos + topic_name_length));
        }


        /**
         * @brief Sets the current topic name as the base name.
         *
         * This method sets the position of the topic name to the length of the topic name string.
         * It is intended to be used for setting the base name of the topic.
         *
         * For example:
         * If the topic name is "AquaDecay/TankBox/000000000000/", calling this method will set the topic_name_pos
         * to the length of the topic name string, which is 24.
         */
        void setCurrentTopicAsBaseName() {
            topic_name_pos = strlen(topic_name);
        }


        /**
         * @brief Gets the write buffer for writing data.
         *
         * This method retrieves the write buffer for writing data. It returns a pointer to the location in memory where
         * the buffer starts. The buffer is obtained by adding the length of the topic_name string to the address of
         * topic_name. The availableForWrite() method is called to calculate the number of bytes that can be written
         * into the buffer.
         *
         * @param[out] buffer The pointer to the start of the write buffer.
         * @return The number of bytes available for writing in the buffer.
         */
        size_t getWriteBuffer(uint8_t *&buffer) override {
            buffer = reinterpret_cast<uint8_t *>(topic_name + strlen(topic_name));
            return availableForWrite();
        }


        /**
         * @brief Sets the number of bytes that have been written to the buffer.
         *
         * This method sets the number of bytes that have been written to the buffer. It takes the given size as input and
         * returns the minimum value between the given size and the available space for writing in the buffer.
         *
         * @param size The number of bytes that have been written to the buffer.
         * @return The minimum value between the given size and the available space for writing in the buffer.
         */
        size_t setWrittenBytes(size_t size) override {
            // nothing to do
            return std::min(size, static_cast<size_t>(availableForWrite()));
        }


        /**
         * @brief Writes a single byte of data to the buffer.
         *
         * This method writes a single byte of data to the output buffer. If there is no space available in the buffer,
         * it returns 0. Otherwise, it adds the data byte to the end of the topic_name array and returns 1.
         *
         * @param data The byte of data to be written to the output buffer.
         * @return 0 if there is no space available in the output buffer, 1 otherwise.
         */
        size_t write(uint8_t data) override {
            if (availableForWrite() == 0) return 0;
            topic_name[strlen(topic_name)] = data;
            return 1;
        }


        /**
         * @brief Calculates the remaining space in the buffer.
         *
         * This method calculates the number of bytes that are available to write data into the output buffer.
         *
         * @return The number of bytes available in the output buffer.
         */
        int availableForWrite() override {
            return sizeof(topic_name) - strlen(topic_name);
        }


        /**
         * @brief Flushes the output buffer.
         *
         * This method is called to flush the output buffer, if any. As the given code does nothing,
         * it means that no action is taken to flush the output buffer.
         */
        void flush() override {
            // nothing to do
        }


        /**
         * @brief Disables the newline for this class.
         *
         * @return The number of characters printed. This method always returns 0.
         */
        size_t println() override {
            // Newline makes no sense in this case
            return 0;
        }

        using Print::println;

    private:
        /** Topic string buffer */
        char topic_name[LIBSMART_STM32NETXMQTTCLIENT_MAX_TOPIC_LENGTH] = {};

        /** Position, where baseName ends */
        size_t topic_name_pos = 0;
    };
}
#endif
