# 🔐 Keycloak Secret Question & OTP Authenticator

This project implements a custom **Secret Question Authenticator** for **Keycloak**.  
It is designed with a **Bootstrap authentication logic** that prevents user lockouts by allowing new users to log in successfully and immediately prompting them to configure both a **Secret Question** and **OTP**.

---

## 🚀 Features

- **Dual-Factor Authentication**
  - Supports both **Secret Question** and standard **TOTP**
- **"Try Another Way" Support**
  - Allows users to switch between **OTP** and **Secret Question** seamlessly during login
- **Auto-Provisioning (Bootstrap Logic)**
  - Automatically detects unconfigured users
  - Triggers **Required Actions** instead of failing the authentication flow
  - Prevents accidental user lockouts

---

## 🛠️ Installation

### 1. Build the Project

Ensure Maven is installed, then run:

mvn clean package

---

### 2. Deploy to Keycloak (Docker)

Start Keycloak in development mode:

docker run -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.5.2 start-dev

Copy the authenticator JAR to the providers directory:

docker cp target/keycloak-secret-question-authenticator-1.0-SNAPSHOT.jar <CONTAINER_ID>:/opt/keycloak/providers/

Rebuild Keycloak to register the provider:

docker exec -it <CONTAINER_ID> /opt/keycloak/bin/kc.sh build

Restart the container if required:

docker restart <CONTAINER_ID>

---

## ⚙️ Authentication Flow Setup

To enable the **Bootstrap behavior** (users are not locked out if unconfigured), configure the **Browser Flow** as follows:

### Top-Level Sub-Flow (Required)

- **Conditional 2FA**

### Gatekeeper Condition (Required)

- **Condition – User Configured**

This ensures that:
- New users skip 2FA
- They are redirected to **Required Actions** instead of being blocked

### Choice Branches (Alternative)

- **Secret Question Branch**
  - Secret Question Authenticator (**Required**)

- **OTP Branch**
  - OTP Form (**Required**)

This configuration enables **"Try Another Way"** during authentication.

---

## 🔁 Required Actions

Navigate to **Authentication → Required Actions** and enable:

- **Configure OTP**
  - Enabled
- **Secret Question**
  - Enabled
  - Registered

---

## ✅ Result

- New users are never locked out
- Authentication remains secure and flexible
- Users can authenticate using **OTP** or **Secret Question**
- Required Actions are enforced automatically on first login
