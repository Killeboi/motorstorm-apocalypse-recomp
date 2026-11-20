@echo off
rem Build the MotorStorm port (port/ + recompiled/) with clang-cl and Ninja.
rem Usage: tools\build_port.bat [configure|build]   (no arg = both)
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
set "PATH=C:\Program Files\LLVM\bin;C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
set "BLD=C:\msa-port\build\port"
set "STEP=%~1"
if "%STEP%"=="build" goto build

cmake -S C:\msa-port\port -B "%BLD%" -G Ninja -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl ^
  -DPython3_EXECUTABLE=C:/Users/Admin/AppData/Local/Programs/Python/Python314/python.exe ^
  -DPS3RECOMP_DIR=C:/msa-port/repo -DRECOMP_DIR=C:/msa-port/recompiled ^
  -DPORT_ENABLE_SPU=ON -DPORT_AVX2=OFF "-DPORT_SPU_INPUTS=" -DSPU_DIR=C:/msa-port/port/spu || exit /b 1
if "%STEP%"=="configure" exit /b 0
:build
cmake --build "%BLD%" -j 12
