/*
 * SPDX-FileCopyrightText: 2024 Roland Rusch, easy-smart solution GmbH <roland.rusch@easy-smart.ch>
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/**
 * This file holds the main setup() and loop() functions for C++ code.
 * If a RTOS is used, loop() is called in the main task and setup() is called before RTOS initialization.
 * @see App_ThreadX_Init() in Core/Src/app_threadx.c
 */

#include "main.hpp"

#include <Stm32NetXMqttClient.hpp>

#include "Address.hpp"
#include "globals.hpp"
#include "Helper.hpp"
#include "../../../../mqtt-docker/ca_crt.h"

/**
 * @brief Setup function.
 * This function is called once at the beginning of the program before ThreadX is initialized.
 * @see main() in Core/Src/main.c
 */
void setup() {
    Stm32ItmLogger::logger.setSeverity(Stm32ItmLogger::LoggerInterface::Severity::INFORMATIONAL)
            ->println("::setup()");

    dummyCpp = 0;
    dummyCandCpp = 0;

    tx_thread_stack_error_notify(Stack_Error_Handler);
}


/**
 * @brief This function is the main loop that executes continuously.
 * The function is called inside the mainLoopThread().
 * @see mainLoopThread() in AZURE_RTOS/App/app_azure_rtos.c
 */
void loop() {
    //        HAL_GPIO_WritePin(LED1_GRN_GPIO_Port, LED1_GRN_Pin, dummyCpp & 1 ? GPIO_PIN_RESET : GPIO_PIN_SET);
    //        HAL_GPIO_WritePin(LED2_ORG_GPIO_Port, LED2_ORG_Pin, dummyCpp & 2 ? GPIO_PIN_RESET : GPIO_PIN_SET);
    //        HAL_GPIO_WritePin(LED3_RED_GPIO_Port, LED3_RED_Pin, dummyCpp & 4 ? GPIO_PIN_RESET : GPIO_PIN_SET);
    //        HAL_GPIO_WritePin(LED4_BLU_GPIO_Port, LED4_BLU_Pin, dummyCpp & 8 ? GPIO_PIN_RESET : GPIO_PIN_SET);

    Stm32NetX::Address address;
    address.nxd_ip_version = 4;
    address.nxd_ip_address.v4 = IP_ADDRESS(10, 82, 2, 198);;

    if (Stm32NetXMqttClient::mqttClient->isReadyForConnect()) {
        Stm32NetXMqttClient::mqttClient->loginSet("testuser", "eZ.1234");
        // Stm32NetXMqttClient::mqttClient->connect(&address, NXD_MQTT_PORT, 30, NX_TRUE,
        //               Stm32ThreadX::WaitOption{TX_TIMER_TICKS_PER_SECOND * 10});

        // Stm32NetXMqttClient::mqttClient->setGetTrustedCertificateFunction([](Stm32NetX::Secure::X509 &x509TrustedCert) {
        // const auto ret = x509TrustedCert.certificateInitialize(rootca_certs, sizeof(rootca_certs));
        // return ret;
        // });

        Stm32NetXMqttClient::mqttClient->setRootCa(rootca_certs, sizeof(rootca_certs));

        Stm32NetXMqttClient::mqttClient->secureConnect(&address, NXD_MQTT_TLS_PORT, 30, NX_TRUE,
                                                       Stm32ThreadX::WaitOption{TX_TIMER_TICKS_PER_SECOND * 10});
    }


    dummyCpp++;
    dummyCandCpp++;
    HAL_GPIO_TogglePin(LD3_GPIO_Port, LD3_Pin);
    delay(300);
}


/**
 * @brief This function handles fatal errors.
 * @see Error_Handler() in Core/Src/main.c
 */
void errorHandler() {
    while (true) {
        //        for (uint32_t i = (SystemCoreClock / 10); i > 0; i--) { UNUSED(i); }
    }
}

void Stack_Error_Handler(TX_THREAD *thread_ptr) {
    Logger.print("==> Stack_Error_Handler() in ");
    Logger.println(thread_ptr->tx_thread_name);
    __disable_irq();
    while (1) {
    }
}
