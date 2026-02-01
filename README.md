# Windows process security tools

these 2 tools are modified from a software called DropMyRights, but safer and make less errors.

## 1 FakeAdminStarter

run program with limited user account rights, and prevent program from requesting administrator rights.

### 1.1 how does it work?

this tool run as administrator rights(token is marked elevated by system), and create a limited token(same as standard user), then run program with this token but the mark is still elevated, so program can't invoke UAC to get administrator rights, all operations is using standard user token.

### 1.2 What's the use of it

normally, some programs can not run without administrator rights, even their functions do not need them.run with administrator rights is not safe.

this tool can make these programs run without administrator rights.

## 2 ConstrainedStarter

make software cannot access certain resources, such as cryptographic keys and credentials, regardless of the user rights of the user.[detail](https://learn.microsoft.com/en-us/windows/win32/api/winsafer/nf-winsafer-safercreatelevel)(see SAFER_LEVELID_CONSTRAINED)

## usage (FakeAdminStarter)

```cmd
FakeAdminStarter.exe program
```

if no parameter is passed, by default, it will start a command prompt windows with fake administrator rights

## usage (ConstrainedStarter)

```cmd
ConstrainedStarter.exe program
```

if no parameter is passed, by default, it will start a command prompt windows with fake administrator rights

## usage (combined use)

if combined use, must use FakeAdminStarter first and then use ConstrainedStarter, otherwise when UAC passed, the right will be reset and ConstrainedStarter will not work

```cmd
FakeAdminStarter.exe ConstrainedStarter.exe program
```
