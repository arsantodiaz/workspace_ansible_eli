
```
ansible pro_ubuntu_new -i inventory -m shell -a "sar -u 1 5" --become -K
ansible pro_ubuntu_new -i inventory -m shell -a "sar -r" --become -K


lscpu | grep -E 'Model name|Socket|Thread|CPU\(s\):'
free -h

sar -u -r -h 1 5

ansible pro_ubuntu_new -i inventory -m apt -a "name=atop state=present" --become -K
ansible pro_ubuntu_new -i inventory -m apt -a "name=btop state=present" --become -K

```


