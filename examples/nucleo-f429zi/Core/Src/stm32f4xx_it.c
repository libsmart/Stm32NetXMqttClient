/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    stm32f4xx_it.c
  * @brief   Interrupt Service Routines.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2024 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "stm32f4xx_it.h"
/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "Stm32ItmLoggerCPPWrapper.hpp"
#include "FaultHandler.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN TD */

/* USER CODE END TD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */
void ReportHardFault(uint32_t *hard_fault_values, uint32_t exc);
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* External variables --------------------------------------------------------*/
extern ETH_HandleTypeDef heth;
extern TIM_HandleTypeDef htim14;

/* USER CODE BEGIN EV */

/* USER CODE END EV */

/******************************************************************************/
/*           Cortex-M4 Processor Interruption and Exception Handlers          */
/******************************************************************************/
/**
  * @brief This function handles Non maskable interrupt.
  */
void NMI_Handler(void)
{
  /* USER CODE BEGIN NonMaskableInt_IRQn 0 */

  /* USER CODE END NonMaskableInt_IRQn 0 */
  /* USER CODE BEGIN NonMaskableInt_IRQn 1 */
   while (1)
  {
  }
  /* USER CODE END NonMaskableInt_IRQn 1 */
}

/**
  * @brief This function handles Hard fault interrupt.
  */
void HardFault_Handler(void)
{
  /* USER CODE BEGIN HardFault_IRQn 0 */

    __asm volatile
    (
        "TST    LR, #0b0100;      "
        "ITE    EQ;               "
        "MRSEQ  R0, MSP;          "
        "MRSNE  R0, PSP;          "
        "MOV    R1, LR;           "
        "B      ReportHardFault;  "
    );
/*
  // https://interrupt.memfault.com/blog/cortex-m-hardfault-debug
  // DUI0553

  __unused __IM uint32_t BFAR        = SCB->BFAR;
  __unused __IM uint32_t MMFAR       = SCB->MMFAR;

  __unused __IM uint8_t DIVBYZERO    = (SCB->CFSR & SCB_CFSR_DIVBYZERO_Msk) >> SCB_CFSR_DIVBYZERO_Pos;
  __unused __IM uint8_t UNALIGNED    = (SCB->CFSR & SCB_CFSR_UNALIGNED_Msk) >> SCB_CFSR_UNALIGNED_Pos;
  __unused __IM uint8_t NOCP         = (SCB->CFSR & SCB_CFSR_NOCP_Msk) >> SCB_CFSR_NOCP_Pos;
  __unused __IM uint8_t INVPC        = (SCB->CFSR & SCB_CFSR_INVPC_Msk) >> SCB_CFSR_INVPC_Pos;
  __unused __IM uint8_t INVSTATE     = (SCB->CFSR & SCB_CFSR_INVSTATE_Msk) >> SCB_CFSR_INVSTATE_Pos;
  __unused __IM uint8_t UNDEFINSTR   = (SCB->CFSR & SCB_CFSR_UNDEFINSTR_Msk) >> SCB_CFSR_UNDEFINSTR_Pos;

  __unused __IM uint8_t BFARVALID    = (SCB->CFSR & SCB_CFSR_BFARVALID_Msk) >> SCB_CFSR_BFARVALID_Pos;
  __unused __IM uint8_t LSPERR       = (SCB->CFSR & SCB_CFSR_LSPERR_Msk) >> SCB_CFSR_LSPERR_Pos;
  __unused __IM uint8_t STKERR       = (SCB->CFSR & SCB_CFSR_STKERR_Msk) >> SCB_CFSR_STKERR_Pos;
  __unused __IM uint8_t UNSTKERR     = (SCB->CFSR & SCB_CFSR_UNSTKERR_Msk) >> SCB_CFSR_UNSTKERR_Pos;
  __unused __IM uint8_t IMPRECISERR  = (SCB->CFSR & SCB_CFSR_IMPRECISERR_Msk) >> SCB_CFSR_IMPRECISERR_Pos;
  __unused __IM uint8_t PRECISERR    = (SCB->CFSR & SCB_CFSR_PRECISERR_Msk) >> SCB_CFSR_PRECISERR_Pos;
  __unused __IM uint8_t IBUSERR      = (SCB->CFSR & SCB_CFSR_IBUSERR_Msk) >> SCB_CFSR_IBUSERR_Pos;

  __unused __IM uint8_t MMARVALID    = (SCB->CFSR & SCB_CFSR_MMARVALID_Msk) ? 1 : 0;
  __unused __IM uint8_t MLSPERR      = (SCB->CFSR & SCB_CFSR_MLSPERR_Msk) ? 1 : 0;
  __unused __IM uint8_t MSTKERR      = (SCB->CFSR & SCB_CFSR_MSTKERR_Msk) ? 1 : 0;
  __unused __IM uint8_t MUNSTKERR    = (SCB->CFSR & SCB_CFSR_MUNSTKERR_Msk) ? 1 : 0;
  __unused __IM uint8_t DACCVIOL     = (SCB->CFSR & SCB_CFSR_DACCVIOL_Msk) ? 1 : 0;
  __unused __IM uint8_t IACCVIOL     = (SCB->CFSR & SCB_CFSR_IACCVIOL_Msk) ? 1 : 0;

  __unused __IM uint8_t DEBUGEVT     = (SCB->HFSR & SCB_HFSR_DEBUGEVT_Msk) ? 1 : 0;
  __unused __IM uint8_t FORCED       = (SCB->HFSR & SCB_HFSR_FORCED_Msk) ? 1 : 0;
  __unused __IM uint8_t VECTTBL      = (SCB->HFSR & SCB_HFSR_VECTTBL_Msk) ? 1 : 0;




  Logger_println("==> HardFault_Handler()");
*/
  /* USER CODE END HardFault_IRQn 0 */
  while (1)
  {
    /* USER CODE BEGIN W1_HardFault_IRQn 0 */
    /* USER CODE END W1_HardFault_IRQn 0 */
  }
}

/**
  * @brief This function handles Memory management fault.
  */
void MemManage_Handler(void)
{
  /* USER CODE BEGIN MemoryManagement_IRQn 0 */

  /* USER CODE END MemoryManagement_IRQn 0 */
  while (1)
  {
    /* USER CODE BEGIN W1_MemoryManagement_IRQn 0 */
    /* USER CODE END W1_MemoryManagement_IRQn 0 */
  }
}

/**
  * @brief This function handles Pre-fetch fault, memory access fault.
  */
void BusFault_Handler(void)
{
  /* USER CODE BEGIN BusFault_IRQn 0 */

  /* USER CODE END BusFault_IRQn 0 */
  while (1)
  {
    /* USER CODE BEGIN W1_BusFault_IRQn 0 */
    /* USER CODE END W1_BusFault_IRQn 0 */
  }
}

/**
  * @brief This function handles Undefined instruction or illegal state.
  */
void UsageFault_Handler(void)
{
  /* USER CODE BEGIN UsageFault_IRQn 0 */

  /* USER CODE END UsageFault_IRQn 0 */
  while (1)
  {
    /* USER CODE BEGIN W1_UsageFault_IRQn 0 */
    /* USER CODE END W1_UsageFault_IRQn 0 */
  }
}

/**
  * @brief This function handles Debug monitor.
  */
void DebugMon_Handler(void)
{
  /* USER CODE BEGIN DebugMonitor_IRQn 0 */

  /* USER CODE END DebugMonitor_IRQn 0 */
  /* USER CODE BEGIN DebugMonitor_IRQn 1 */

  /* USER CODE END DebugMonitor_IRQn 1 */
}

/******************************************************************************/
/* STM32F4xx Peripheral Interrupt Handlers                                    */
/* Add here the Interrupt Handlers for the used peripherals.                  */
/* For the available peripheral interrupt handler names,                      */
/* please refer to the startup file (startup_stm32f4xx.s).                    */
/******************************************************************************/

/**
  * @brief This function handles TIM8 trigger and commutation interrupts and TIM14 global interrupt.
  */
void TIM8_TRG_COM_TIM14_IRQHandler(void)
{
  /* USER CODE BEGIN TIM8_TRG_COM_TIM14_IRQn 0 */

  /* USER CODE END TIM8_TRG_COM_TIM14_IRQn 0 */
  HAL_TIM_IRQHandler(&htim14);
  /* USER CODE BEGIN TIM8_TRG_COM_TIM14_IRQn 1 */

  /* USER CODE END TIM8_TRG_COM_TIM14_IRQn 1 */
}

/**
  * @brief This function handles Ethernet global interrupt.
  */
void ETH_IRQHandler(void)
{
  /* USER CODE BEGIN ETH_IRQn 0 */

  /* USER CODE END ETH_IRQn 0 */
  HAL_ETH_IRQHandler(&heth);
  /* USER CODE BEGIN ETH_IRQn 1 */

  /* USER CODE END ETH_IRQn 1 */
}

/* USER CODE BEGIN 1 */

#define printf Logger_printf

void ReportHardFault(uint32_t *stack_frame, uint32_t exc)
{
  uint32_t r0   = stack_frame[0];
  uint32_t r1   = stack_frame[1];
  uint32_t r2   = stack_frame[2];
  uint32_t r3   = stack_frame[3];
  uint32_t r12  = stack_frame[4];
  uint32_t lr   = stack_frame[5];
  uint32_t pc   = stack_frame[6];
  uint32_t psr  = stack_frame[7];
  uint32_t hfsr = SCB->HFSR;
  uint32_t cfsr = SCB->CFSR;
  uint32_t mmar = SCB->MMFAR;
  uint32_t bfar = SCB->BFAR;
  uint32_t afsr = SCB->AFSR;

  printf("\n!!!Hard Fault detected!!!\n");

  printf("\nStack frame:\n");
  printf("R0 :        0x%08lX\n", r0);
  printf("R1 :        0x%08lX\n", r1);
  printf("R2 :        0x%08lX\n", r2);
  printf("R3 :        0x%08lX\n", r3);
  printf("R12:        0x%08lX\n", r12);
  printf("LR :        0x%08lX\n", lr);
  printf("PC :        0x%08lX\n", pc);
  printf("PSR:        0x%08lX\n", psr);

  printf("\nFault status:\n");
  printf("HFSR:       0x%08lX\n", hfsr);
  printf("CFSR:       0x%08lX\n", cfsr);
  printf("MMAR:       0x%08lX\n", mmar);
  printf("BFAR:       0x%08lX\n", bfar);
  printf("AFSR:       0x%08lX\n", afsr);

  printf("\nOther:\n");
  printf("EXC_RETURN: 0x%08lX\n", exc);

  printf("\nDetails of the fault status:\n");
  printf("Hard fault status:\n");
  if (CHECK_BIT(hfsr, FORCED))
  {
    printf(" - Forced Hard fault.\n");
  }
  if (CHECK_BIT(hfsr, VECTTBL))
  {
    printf(" - Bus fault on vector table read.\n");
  }
  printf("MemManage fault status:\n");
  if (CHECK_BIT(cfsr, MMARVALID))
  {
    printf(" - MMAR holds a valid address.\n");
  }
  else
  {
    printf(" - MMAR holds an invalid address.\n");
  }
  if (CHECK_BIT(cfsr, MLSPERR))
  {
    printf(" - Fault occurred during floating-point lazy state preservation.\n");
  }
  if (CHECK_BIT(cfsr, MSTKERR))
  {
    printf(" - Stacking has caused an access violation.\n");
  }
  if (CHECK_BIT(cfsr, MUNSTKERR))
  {
    printf(" - Unstacking has caused an access violation.\n");
  }
  if (CHECK_BIT(cfsr, DACCVIOL))
  {
    printf(" - Load or store at a location that does not permit the operation.\n");
  }
  if (CHECK_BIT(cfsr, IACCVIOL))
  {
    printf(" - Instruction fetch from a location that does not permit execution.\n");
  }
  printf("Bus fault status:\n");
  if (CHECK_BIT(cfsr, BFARVALID))
  {
    printf(" - BFAR holds a valid address.\n");
  }
  else
  {
    printf(" - BFAR holds an invalid address.\n");
  }
  if (CHECK_BIT(cfsr, LSPERR))
  {
    printf(" - Fault occurred during floating-point lazy state preservation.\n");
  }
  if (CHECK_BIT(cfsr, STKERR))
  {
    printf(" - Stacking has caused a Bus fault.\n");
  }
  if (CHECK_BIT(cfsr, UNSTKERR))
  {
    printf(" - Unstacking has caused a Bus fault.\n");
  }
  if (CHECK_BIT(cfsr, IMPRECISERR))
  {
    printf(" - Data bus error has occurred, but the return address in the stack is not related to the fault.\n");
  }
  if (CHECK_BIT(cfsr, PRECISERR))
  {
    printf(" - Data bus error has occurred, and the return address points to the instruction that caused the fault.\n");
  }
  if (CHECK_BIT(cfsr, IBUSERR))
  {
    printf(" - Instruction bus error.\n");
  }
  printf("Usage fault status:\n");
  if (CHECK_BIT(cfsr, DIVBYZERO))
  {
    printf(" - The processor has executed an SDIV or UDIV instruction with a divisor of 0.\n");
  }
  if (CHECK_BIT(cfsr, UNALIGNED))
  {
    printf(" - The processor has made an unaligned memory access.\n");
  }
  if (CHECK_BIT(cfsr, NOCP))
  {
    printf(" - Attempted to access a coprocessor.\n");
  }
  if (CHECK_BIT(cfsr, INVPC))
  {
    printf(" - Illegal attempt to load of EXC_RETURN to the PC.\n");
  }
  if (CHECK_BIT(cfsr, INVSTATE))
  {
    printf(" - Attempted to execute an instruction that makes illegal use of the EPSR.\n");
  }
  if (CHECK_BIT(cfsr, INVSTATE))
  {
    printf(" - The processor has attempted to execute an undefined instruction.\n");
  }

  /* Breakpoint. */
  __asm volatile("BKPT #0");

  /* Infinite loop to stop the execution. */
  while(1);
}
/* USER CODE END 1 */
