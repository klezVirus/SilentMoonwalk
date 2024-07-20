#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

LARGE_INTEGER timer() {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return now;
}


void elapsed_time(LARGE_INTEGER before) {
    LARGE_INTEGER frequency;
    LARGE_INTEGER now;
    double interval;

    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&now);
    interval = (double)(now.QuadPart - before.QuadPart) / frequency.QuadPart;


    printf("%f\n", interval);
}