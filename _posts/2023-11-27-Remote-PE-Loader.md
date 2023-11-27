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

## What do we need? 

To perform this technique we will need 
1. Get the file
2. Check the headers and get the right ones 
3. Load sections 
4. Start from the initial entry point

### File retrieval 

Для получение файла мы будем использовать winsock2 из WinApi 
