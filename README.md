# LBlock vs PRESENT: Lightweight Block Cipher Benchmark

This repository provides implementations and performance comparisons of two lightweight block ciphers: **LBlock** and **PRESENT**. It focuses on analyzing encryption/decryption speeds, memory usage, and suitability for resource-constrained environments such as embedded systems and IoT devices.

## 🔍 Overview

Lightweight cryptography is critical for securing devices with limited computational power and memory. This project compares two well-known lightweight block ciphers:

- **LBlock** (64-bit block, 80-bit key)
- **PRESENT** (64-bit block, 80-bit key)

We analyze the following metrics:

- Memory footprint (stack, heap usage)
- Encryption and decryption throughput
- Code size and performance trade-offs

## 🚀 Features

- Python implementations of both LBlock and PRESENT
- Platform-independent benchmarking framework
- Timing benchmarks using high-precision timers
- Configurable crytography type (LBlock and PRESENT)

## 🛠️ How to Build

### Requirements

- psutil
- crytography

### Build & Run

```bash
python main.py
