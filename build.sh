#!/bin/bash
cython --embed -o main.c main.py
gcc -Os -I /usr/include/python3.8 main.c -lpython3.8 -o main
rm main.c
