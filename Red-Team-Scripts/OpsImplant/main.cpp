#include<windows.h>
#include "task.h"

// hide imported function
#pragma comment(linker, "/entry:WinMain")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR lpCmdLine, int nCmdShow){

	start();

}