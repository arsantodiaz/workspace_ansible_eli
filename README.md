# Workspace ANSIBLE


##### ✅ Setup User di Remote Host
Jika user belum ada home directory nya

```bash 
# 1. Buat foldernya
sudo mkdir -p /home/endiaz

# 2. Copy skeleton file (biar ada .bashrc warna-warni dll) - Opsional tapi bagus
sudo cp -r /etc/skel/. /home/endiaz/

# 3. Ubah pemilik folder dari root ke endiaz
sudo chown -R endiaz:endiaz /home/endiaz

# 4. Ubah permission biar aman (hanya endiaz yang bisa buka)
sudo chmod 700 /home/endiaz
```

Tambahkan inventory pada ansible
* Opsi pertama dimasukkan username dan password nya sekalian
```bash
[pro_ubuntu_new]
# Format: Nama_Host  IP  User  Password
ELI-AP104  ansible_host=192.168.10.75  ansible_user=user_spesial  ansible_password=PasswordRumit123!
```

* Opsi kedua, hanya dimasukkan host ip nya saja
```bash
[pro_ubuntu_new]
ELI-AP104  ansible_host=192.168.10.75
```

* Jika hanya host yang dimasukkan buat ini agar kredential password bisa terdeteksi oleh ansible.
```bash
nano host_vars/ELI-AP104.yml
```

```bash
---
ansible_user: user_spesial
ansible_password: PasswordRumit123!
ansible_port: 22   # Opsional, kalau port SSH standar
```

* Lebih aman pakai vault 
```bash
ansible-vault encrypt_string 'EquityJisly&8520*1' --name 'ansible_password'
```

* Hasil yang dikeluarkan
```bash
ansible_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          64313735653237366264326666393934653061343466656531653239313431666332656431373165
          3062386633333137613231666231666430346364643965350a623863343166386234323731643635
          36363339353937373465653363633338646238323462383137346661626534313831356363646530
          3365363665643832650a633137353063376230623238383934643834613830363639303433303233
          38393132653630303637623031663531666337366636353236383535363830653261
```

* Masukkan pada ansible host_vars nya
```bash
ansible_user: endiaz
ansible_port: 22
ansible_python_interpreter: /usr/bin/python3.12
ansible_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          64313735653237366264326666393934653061343466656531653239313431666332656431373165
          3062386633333137613231666231666430346364643965350a623863343166386234323731643635
          36363339353937373465653363633338646238323462383137346661626534313831356363646530
          3365363665643832650a633137353063376230623238383934643834613830363639303433303233
          38393132653630303637623031663531666337366636353236383535363830653261
```


##### ✅ Check Apakah sudah bisa ping ke remote host
```bash
ansible ELI-AP104 -i inventory -m ping
```
##### ✅ Setup Docker di Remote Host
```bash
ansible-playbook -i inventory 03-Setup_Docker/dockerSetup.yml --limit pro_ubuntu_new -K
```

##### ✅ Check Docker di Remote Host
```bash
docker --version

docker compose version

sudo systemctl status docker

df -h /var/lib/docker

docker info | grep "Docker Root Dir"

docker run --rm hello-world
```

##### ✅ Jalankan shell di remote host
```bash
ansible pro_ubuntu_new -i inventory -m shell -a "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -6" --become -K
```

docker exec jenkins-blueocean cat /var/jenkins_home/secrets/initialAdminPassword




