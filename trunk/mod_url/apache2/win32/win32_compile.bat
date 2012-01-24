@echo off
rem ################################################
rem  $Id: win32_compile.bat,v 1.2 2012-01-24 17:34:28 oops Exp $
rem
rem  1. Requirements to compile on Win32 environment
rem  
rem     A. Apache libraries
rem     (%APACHE_DIR%\include, %APACHE_DIR%\lib)
rem     
rem     B. Visual Studio 6 or later
rem     (In a software store ;)
rem  
rem     C. libiconv for Windows
rem     (http://gnuwin32.sourceforge.net/packages/libiconv.htm)
rem 
rem
rem  2. Configuration example
rem  
rem  <IfModule mod_url.c>
rem    CheckURL           On
rem    ServerEncoding     UTF-8
rem    ClientEncoding     EUC-KR
rem  </IfModule>
rem  
rem ################################################


set INCLUDE_APACHE="C:\Program Files\Apache Software Foundation\Apache2.2\include"
set INCLUDE_VS="C:\Program Files\Microsoft Visual Studio\VC98\Include"
set INCLUDE_ICONV="C:\libiconv\include"

set LIBPATH_APACHE="C:\Program Files\Apache Software Foundation\Apache2.2\lib"
set LIBPATH_VS="C:\Program Files\Microsoft Visual Studio\VC98\Lib"
set LIBPATH_ICONV="C:\libiconv\lib"

IF "%OS%" == "Windows_NT" goto WINNT
set CWIN32_FLAG=/D WIN32 /D _WINDOWS
goto WINNT_NEXT

:WINNT
set CWIN32_FLAG=/D WINNT /D WIN32 /D _WINDOWS
:WINNT_NEXT


mkdir out_win32
cd out_win32

echo Compiling mod_url.c ...
cl.exe /nologo /MD /W3 /O2 /D NDEBUG %CWIN32_FLAG% -I%INCLUDE_APACHE% -I%INCLUDE_VS% -I%INCLUDE_ICONV% /c /Fomod_url.lo ..\mod_url.c
IF %ERRORLEVEL% == 0 GOTO NEXT_RC
GOTO ERROR


:NEXT_RC
echo Compiling resource ...
rc.exe /fo win32_resource.res ..\win32_resource.rc
IF %ERRORLEVEL% == 0 GOTO NEXT_LINK
GOTO ERROR


:NEXT_LINK
echo Linking ...
link.exe kernel32.lib win32_resource.RES aprutil-1.lib libapr-1.lib libapriconv-1.lib libaprutil-1.lib libhttpd.lib mod_dav.lib xml.lib libiconv.lib /nologo /subsystem:windows /dll /machine:I386 /libpath:%LIBPATH_APACHE% /libpath:%LIBPATH_VS% /libpath:%LIBPATH_ICONV% /out:mod_url.so mod_url.lo
IF %ERRORLEVEL% == 0 GOTO END
goto ERROR


:ERROR
echo Error occured while compiling mod_url!

:END
cd ..
echo.
