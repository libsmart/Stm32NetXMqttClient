/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "setupMainThread.hpp"
#include "defines.h"
#include "Helper.hpp"
#include "main.hpp"
#include "Stm32ItmLoggerCPPWrapper.hpp"


CHAR threadName_mainLoopThread[] = "loop()";
CCMRAM TX_THREAD threadStruct_mainLoopThread;
_Noreturn static VOID mainLoopThread(ULONG initial_input);


UINT setupMainThread(TX_BYTE_POOL *byte_pool) {
    UINT ret = TX_SUCCESS;
    UCHAR *threadStack_mainLoopThread = {};

    // Allocate stack for the main thread
    ret = tx_byte_allocate(byte_pool, reinterpret_cast<void **>(&threadStack_mainLoopThread),
                           MAIN_THREAD_STACK_SIZE,
                           TX_NO_WAIT);
    if (ret != TX_SUCCESS) {
        Logger_printf("%lu: tx_byte_allocate() = 0x%02x", millis(), ret);
        assert_param(ret != TX_SUCCESS);
    }

    return tx_thread_create(&threadStruct_mainLoopThread, threadName_mainLoopThread, mainLoopThread, 0x1234,
                            threadStack_mainLoopThread, MAIN_THREAD_STACK_SIZE,
                            15, 15, 1, TX_AUTO_START);
}


_Noreturn static VOID mainLoopThread(ULONG initial_input) {
    while (true) {
        loop();
        // Sleep for 1 tick
        tx_thread_sleep(1);
    }
}
