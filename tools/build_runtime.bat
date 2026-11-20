@echo off
rem Build the ps3recomp runtime (+ unit tests) with clang-cl and Ninja, out of tree.
rem Usage: tools\build_runtime.bat [configure|build|test]   (no arg = all three)
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
set "PATH=C:\Program Files\LLVM\bin;C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
set "SRC=C:\msa-port\repo"
set "BLD=C:\msa-port\build\runtime"
set "STEP=%~1"

if "%STEP%"=="" goto configure
if "%STEP%"=="configure" goto configure
if "%STEP%"=="build" goto build
if "%STEP%"=="test" goto test
echo unknown step %STEP% & exit /b 2

:configure
cmake -S "%SRC%" -B "%BLD%" -G Ninja -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl ^
  -DPS3RECOMP_BUILD_TESTS=ON || exit /b 1
if not "%STEP%"=="" exit /b 0
:build
cmake --build "%BLD%" || exit /b 1
if not "%STEP%"=="" exit /b 0
:test
ctest --test-dir "%BLD%" --output-on-failure -j 8
