## Jenkins Groovy Console – Add SSH Key to authorized_keys

```groovy
new File("/var/home/.ssh").mkdirs()
"chmod 700 /var/home/.ssh".execute().waitFor()

new File("/var/home/.ssh/authorized_keys") << "ssh-rsa AAAAB3... example@host\n"
"chmod 600 /var/home/.ssh/authorized_keys".execute().waitFor()
