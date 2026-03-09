# FLRSAhost

**FLRSAhost** is the open-source host-side implementation for the **FLRSA** (Fast/Flexible Lightweight RSA) project. This repository contains the middleware and client-side logic designed to interact with the [FLRSAonSmartCard](https://github.com/mbachkat/FLRSAonSmartCard) applet.

---

## 📌 Project Overview

The **FLRSA** ecosystem is a specialized cryptographic implementation designed for constrained environments, focusing on RSA optimizations.
* **FLRSAonSmartCard**: The JavaCard applet that handles secure private key storage and on-card cryptographic operations.
* **FLRSAhost (This repo)**: The Java-based orchestrator that manages APDU communication, data formatting, and high-level execution tasks.

---

## 🛠 Prerequisites & Installation

To use this host application, you must first deploy the corresponding applet onto your physical smart card.

### Step 1: GlobalPlatform Setup
You will need [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) (GP) to manage the applet lifecycle.

1.  Build your applet in the `FLRSAonSmartCard` project.
2.  Locate your compiled `.cap` file:  
    `FLRSAonSmartCard/applet/build/javacard/TestPoc.cap`
3.  Copy this file into your GlobalPlatform tool directory:  
    `GlobalPlatform/GlobalPlatformPro/tool/target/`

### Step 2: Card Deployment
Open a terminal in your GlobalPlatform directory and run the following commands to clean and install the applet:

> **Note:** Ensure your card reader is connected and the card is inserted. Adjust the `-key` parameter if your card uses non-default transport keys.

### Delete existing instance/package if already present
java -jar gp.jar -key default -delete 4A434D6174684C6962 -f

### Install the new CAP file
java -jar gp.jar -key default -install TestPoc.cap

### 🚀 Usage (FLRSAhost)
Once the applet is successfully installed on the card, navigate to this FLRSAhost directory on your machine to execute the following Gradle tasks.

## 1. Initialization
Run this command to initialize the card environment and setup necessary parameters:
gradle RunInit

## 2. Calculation
Run this command to trigger the RSA cryptographic calculation logic:
gradle RunCalc
