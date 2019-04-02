cd E:\WorkSpaces\DesktopTools\AppStartService\bin\Debug
E:

%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\installutil.exe AppStartService.exe

Net Start AppStartService

sc config AppStartService start= auto

pause