# Impersonate-RemoteSession
 
## Build
```
gcc .\src\impersonate_remote_session.c -o impersonate_remote_session_x64.exe -s -m64 -lwtsapi32
```

## Usage
```
impersonate_remote_session_x64.exe <executable_path> <command_line>
```

## Example
```
impersonate_remote_session_x64.exe cmd.exe "/k echo hi"
```