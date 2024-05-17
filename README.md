# Stm32NetXMqttClient

A MQTT client for Stm32NetX



## Requirements

* ThreadX (Core) (Memory pool size: 5*1024)
* NetX (NX Core, Ethernet Interface, Ethernet Phy Interface) (Memory pool size: 35*1024)
* HAL ethernet configuration (MAC address?)
* Stm32ItmLogger
* Stm32Common
* Stm32ThreadX
* Stm32NetX



## Installation

In file `NetXDuo/App/app_netxduo.c` add the following:

```c
/* USER CODE BEGIN Includes */
#include <main.h>
#include "Stm32NetXCPPWrapper.hpp"
#include "Stm32NetXMqttClientCPPWrapper.hpp"
/* USER CODE END Includes */


// ... //


/* USER CODE BEGIN MX_NetXDuo_Init */

// Jump to the C++ NetX thread setup function
ret = Stm32NetX_setup(byte_pool);
assert_param(ret == TX_SUCCESS);

// Jump to the C++ NetXMqttClient thread setup function
ret = Stm32NetXMqttClient_setup(byte_pool);
assert_param(ret == TX_SUCCESS);


// ... //

/* USER CODE END MX_NetXDuo_Init */
```

