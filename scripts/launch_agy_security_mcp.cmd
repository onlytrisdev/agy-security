@echo off
setlocal DisableDelayedExpansion

set "AGY_SECURITY_MCP_SCRIPT=%~dp0..\mcp\server.mjs"
if "%~1"=="--helper" (
  set "AGY_SECURITY_MCP_SCRIPT=%~dp0..\mcp\helpers.mjs"
  goto launch
)

if "%~d0"=="" (cd /d "%SystemRoot%") else (cd /d "%~d0\")
if errorlevel 1 (
  echo AGY Security could not start: no safe Windows working directory. 1>&2
  exit /b 1
)

:launch
if defined AGY_MCP_NODE_PATH if exist "%AGY_MCP_NODE_PATH%" (
  set "AGY_SECURITY_MCP_NODE=%AGY_MCP_NODE_PATH%"
  goto run
)

set "AGY_SECURITY_MCP_SEARCH_PATH=%PATH:"=%"
for %%I in (node.exe) do set "AGY_SECURITY_MCP_NODE=%%~$AGY_SECURITY_MCP_SEARCH_PATH:I"
if defined AGY_SECURITY_MCP_NODE goto run

echo AGY Security could not find a Node runtime. Set AGY_MCP_NODE_PATH or add node.exe to PATH. 1>&2
exit /b 127

:run
"%AGY_SECURITY_MCP_NODE%" "%AGY_SECURITY_MCP_SCRIPT%" %*
if "%~1"=="--helper" exit /b %errorlevel%
exit
