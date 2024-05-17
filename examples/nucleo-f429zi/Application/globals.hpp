/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * This file holds exports for the global variables, defined in globals.cpp.
 * @see globals.cpp
 */

#ifndef EASY_SMART_STM32_skeleton_GLOBALS_HPP
#define EASY_SMART_STM32_skeleton_GLOBALS_HPP

#include "globals.h"
#include "Stm32ItmLogger.hpp"
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t dummyCpp;
extern Stm32ItmLogger::Stm32ItmLogger &Logger;

#ifdef __cplusplus
}
#endif

#endif //EASY_SMART_STM32_skeleton_GLOBALS_HPP
