##### Setup Home Directory

Langkah Perbaikan (Jalankan di terminal server 172.16.204.4)
Buat Foldernya:

```Bash
sudo mkdir -p /home/endiaz
```
(Masukkan password endiaz jika diminta)


Ubah Kepemilikan (Biar jadi milik endiaz, bukan root):

```Bash
sudo chown endiaz:endiaz /home/endiaz
```

Copy File Dasar (Biar terminal ada warnanya & settingan bash):

```Bash
sudo cp -r /etc/skel/. /home/endiaz
```

Fix Permission Akhir:

```Bash
sudo chown -R endiaz:endiaz /home/endiaz
```

Tes Ulang
Setelah 4 perintah di atas dijalankan, coba LOGOUT (exit) lalu LOGIN LAGI.
Harusnya pesan error Could not chdir... sudah hilang.

Setelah itu, baru tes Ansible Ping dari laptop kamu:

```Bash
ansible sit_centos -i inventory -m ping -u endiaz
Pasti langsung GREEN / SUCCESS. 🟢
```


##### Buat Password Vault
```bash
ansible-vault encrypt_string 'xxxxxx' --name 'ansible_password'
```

Hasilnya akan seperti ini
```
ansible_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          35626662633662353035366339343864623761613364376337366330653235336337623661643338
          3037303437623866306166343335376237363233623330330a656338323232636634303965653665
          32643564646538336630323361653834333761323234616530323665663461326330363635373362
          6134623238353438630a326363356165646166333239343239666565623464663638633432633134
          32316233336236373435653731653436653632663364353138343162336466316334
```


##### Setup Tools

```bash
ansible sit_ubuntu -i inventory -m ping -u endiaz
ansible-playbook -i inventory 00-Install_Tools.yml 
```