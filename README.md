# FLRSAhost

**FLRSAhost** is the open-source Java-based host controller for the **FLRSA** (Fast and Lightweight RSA) cryptographic project. This repository provides the necessary tools and middleware to orchestrate secure communication with the [FLRSAonSmartCard](https://github.com/mbachkat/FLRSAonSmartCard) applet.

---

## 📖 Extended Description

The **FLRSA** project is a research and implementation effort to optimize **RSA (Rivest-Shamir-Adleman)** operations on resource-constrained devices like Java Cards. 

The architecture follows a classic Client-Server model via the **APDU (Application Protocol Data Units)** protocol:

1. **Orchestration**: The host application (this repo) manages the session lifecycle, detects the smart card reader, and selects the applet (AID: `4A434D6174684C6962`).
2. **Offloading**: Complex mathematical operations (Modular Exponentiation, CRT) are triggered by the host but executed within the card's Secure Element. This ensures that sensitive private keys never leave the hardware.
3. **Benchmarking**: FLRSAhost includes specific tasks to measure and analyze the performance of the FLRSA algorithm directly on the chip.



---

## 🛠 Prerequisites & Installation

To use this host application, you must first deploy the applet onto your physical smart card.

### Step 1: GlobalPlatform Setup
1. Install the [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) (GP) tool.
2. Build your applet in the `FLRSAonSmartCard` project.
3. Copy the generated `.cap` file:
    * **From:** `FLRSAonSmartCard/applet/build/javacard/TestPoc.cap`
    * **To:** `GlobalPlatform/GlobalPlatformPro/tool/target/`

### Step 2: Card Deployment
Open a terminal in your GlobalPlatform directory and run these commands:

> [!WARNING]
> Ensure your card reader is connected. Adjust the `-key` parameter if your card uses non-default transport keys.

#### Delete existing instance/package (if present)
java -jar gp.jar -key default -delete 4A434D6174684C6962 -f

#### Install the new applet
java -jar gp.jar -key default -install TestPoc.cap


### 🚀 Usage (FLRSAhost)

Once the applet is installed, navigate to the `FLRSAhost` directory and use the following Gradle commands:

#### 1. Initialization
Sets up the RSA parameters and prepares the card environment:
gradle RunInit

#### 2. Calculation
Executes the optimized RSA calculation logic:
gradle RunCalcl
