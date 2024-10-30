---
title:  "AudioGuard :  controlling microphone access on per-process basis"
date:   2024-10-30
tags: [posts]
excerpt: "controlling microphone access on per-process basis"
---

## Intro
Long-term surveillance hinges critically on microphone capture and recording capabilities, serving as a cornerstone of persistent monitoring operations, whether state-sponsored or not. Threat actors can silently harvest sensitive intelligence from team meetings, voice chats, and  internal discussions as long as the endpoint has a microphone device connected to it, providing access to organizational insights. In this blogpost, our goal is to dive into the audio capturing internals on Windows, and to implement a protection that will allow us to restrict microphone access on a per-process basis.
