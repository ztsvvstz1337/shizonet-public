# Shizonet

**Shizonet** is a lightweight and efficient networking library designed for fast communication between devices on trusted local networks. Developed by **Erik M.**, it's a modern and extensible alternative to Art-Net, built with home automation, stage lighting, and embedded systems in mind.

> ⚠️ **Security Notice**  
> Shizonet is intended for use in **trusted private networks**. It is **not secure** for use over public or untrusted networks.

---

## 🚀 Features

- ✅ **Reliable & Fast Data Transmission**  
  Suitable for real-time control and critical data.

- 📡 **Unreliable Transmission Mode**  
  Ideal for streaming high-speed, lossy data (e.g., video/audio).

- 🔁 **Send & Get Support**  
  Simple querying and response functionality between devices.

- ⏱️ **Smart Frame Scheduling**  
  Automatically optimizes frame update timing based on incoming traffic.

- 📊 **Built-in Device Diagnostics**  
  - Ping  
  - Bandwidth usage  
  - Time offset  
  - Error rate

- 🧠 **Define Buffers, Functions, and Attributes**  
  Share or remotely execute custom data and logic between devices.

- 🕒 **Planned Feature: Network Time Sync**  
  Time synchronization support is on the roadmap.

---

## 💻 Platform Support

Shizonet is **cross-platform** and highly portable. It works on:

- 🪟 Windows  
- 🐧 Linux  
- 📶 ESP32 (✅ works out of the box)  
- 🧱 Arduino (✅ with minor adjustments)

> ✅ **No extra setup is needed for ESP32** — it works right away.  
> 🔧 For other Arduino boards, you may need to implement a custom `GenericUDPSocket` class for your platform’s networking layer.

---

## 📦 Getting Started

### For C++ Projects

To integrate Shizonet:

1. Add the following source files to your project:
   - `shizonet.h`  
   - `shizonet.cpp`  
   - `shizonet_platform.h`  
   - `shizonet_platform_os.h`  
   - `xxhash.h`

2. Compile as part of your project as usual.

---

### For Arduino

To use Shizonet in Arduino:

1. Copy the `shizonet` folder from the `arduino_libs/` directory.
2. Paste it into your Arduino libraries folder: 'Documents/Arduino/libraries'
3. In your sketch, include it:
```cpp
#include <shizonet.h>
```
4. Make sure to define these two variables somewhere inside your sketch, after including shizonet.h for type based firmware updates.
```cpp
char* ota_class = "esp_demo";
char* ota_subclass = "";
```
5. Or remove this define from shizonet.h
```cpp
#define ESP32_OTA
```

### More Info

💡 ESP32-based Arduino boards are fully supported without modification.
For other boards, define a GenericUDPSocket class suited to your hardware’s networking stack.

🔧 Shizoscript (Demo Only)
This repository contains a small implementation of shizoscript:

⚠️ Note:
shizoscript is not open source — the provided bindings code is for demonstration purposes only.
More info here:
https://github.com/ztsvvstz1337/shizoscript_runtime_windows

🧠 Use Cases
🎛️ Lighting & Stage Control
A powerful and modern Art-Net replacement.

🏡 Home Automation
Connect, monitor, and control smart devices seamlessly.

⚙️ Embedded Systems & IoT
Share data and functions between microcontrollers or SoCs like the ESP32.

⚙️ Performance Highlights
Highly optimized for speed and efficiency

Smart algorithms reduce processing load

Low latency, minimal CPU impact

Designed to run fast even on full OSes

👨‍💻 Author
Erik M.
Open to contributions and collaboration!