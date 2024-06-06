/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * This file holds the headers for main.cpp.
 * @see main.cpp
 */

#ifndef EASY_SMART_STM32_skeleton_MAIN_HPP
#define EASY_SMART_STM32_skeleton_MAIN_HPP

#include "main.h"
#include "tx_api.h"

#ifdef __cplusplus
extern "C" {
#endif

    void setup();
    void loopOnce();
    void loop();
    _Noreturn void errorHandler();
    _Noreturn void Stack_Error_Handler(TX_THREAD *thread_ptr);

#ifdef __cplusplus
}
#endif

#endif //EASY_SMART_STM32_skeleton_MAIN_HPP
