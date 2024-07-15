# Cryptography_using_OpenSSL
  Introduction to Cryptography Algorithm using OpenSSL
# Setup Instructions

## Step-by-Step Guide

1. **Install OpenSSL**
   - Download the OpenSSL installer from the official website.
   - Run the installer and follow the on-screen instructions to complete the installation.

2. **Install Visual Studio**
   - Download the Visual Studio installer from the official Microsoft website.
   - Run the installer and select the required components for C++ development.
   - Follow the on-screen instructions to complete the installation.

3. **Install Strawberry Perl**
   - Download the Strawberry Perl installer (version 5.38.2.2, 64-bit) from the official website.
   - Run the installer and follow the on-screen instructions to complete the installation.

4. **Install NASM**
   - Download the NASM installer (version 2.16.03) from the official website.
   - Run the installer and follow the on-screen instructions to complete the installation.

5. **Install Wireshark**
   - Download the Wireshark installer from the official website.
   - Run the installer and follow the on-screen instructions to complete the installation.

6. **Download and Build Custom Protocol**
   - Download the custom protocol zip file provided.
   - Unzip the file to a desired location.
   - Open the solution file (`.sln`) in Visual Studio.
   - Build the solution by selecting `Build` > `Build Solution` from the menu.

7. **Run the Command Prompt Commands**
   - Open two command prompt windows.
   - In the first window, navigate to the debug folder and run the following command for the server:
     ```
     udp_party -port 60000 -key alice.key -pwd alice -cert alice.crt -root rootCA.crt -peer Bob.com
     ```
   - In the second window, navigate to the debug folder and run the following command for the client:
     ```
     udp_party -ip 127.0.0.1 -port 60000 -key bob.key -pwd bobkey -cert bob.crt -root rootCA.crt -peer Alice.com
     ```

8. **Monitor Encryption with Wireshark**
   - Open Wireshark.
   - Start a new capture session.
   - Apply the following filter to see the encrypted traffic:
     ```
     udp.srcport == 60000 or udp.dstport == 60000
     ```

By following these steps, you will have installed all necessary software, built the custom protocol, and monitored the encrypted traffic using Wireshark.
