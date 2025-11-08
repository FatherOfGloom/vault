@echo off

set TARGET_NAME=vault-cli.exe
set SRC_FILENAMES=main.c arena.c utils.c vault.c
set ROOT_FOLDER=D:\Users\aauhabin1\dev\c\vault\
@REM set CFLAGS=-Wall -Wextra -pedantic -ggdb -std=c11 -lraylib -lgdi32 -lwinmm -O1
set CFLAGS=-Wall -Wextra -pedantic -ggdb -fanalyzer -std=c11 -O1 -lws2_32

setlocal enabledelayedexpansion

set SRC_PATHS=

@REM for %%i in (%SRC_FILENAMES%) do (set SRC_PATHS=!SRC_PATHS! ..\src\%%i)
for %%i in (%SRC_FILENAMES%) do (set SRC_PATHS=!SRC_PATHS! %ROOT_FOLDER%src\%%i)

echo %SRC_PATHS%

pushd %ROOT_FOLDER%

if not exist bin mkdir bin

pushd bin

@echo on
gcc  %SRC_PATHS% -o %TARGET_NAME% %CFLAGS%
@echo off

if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo build success.

popd
endlocal