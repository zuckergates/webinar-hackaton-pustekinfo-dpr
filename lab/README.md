# Invoice Lab

Panduan PDF: [Lima simulasi serangan](../panduan-praktik/panduan-simulasi-serangan.pdf) dan [Hardening dari vulnerable ke hardened](../panduan-praktik/panduan-hardening.pdf). Panduan hardening mengikuti kode sebelum/sesudah pada tiga checkpoint, lokasi konfigurasi, dan langkah verifikasinya.

Lab pendamping webinar **Database Security in Practice: From Vulnerable Web App to Hardened Data Layer**, Dendi Zuckergates, 26 September 2026.

Stack teruji: PostgreSQL 17.11, Python 3.12, Flask 3.1.3, psycopg 3.3.6. Image dasar dikunci dengan digest, dependency Python dengan `requirements.lock.txt`.

## Menjalankan di Windows

Prasyarat: Docker Desktop aktif dalam mode Linux containers, Docker Compose v2, PowerShell. Build pertama membutuhkan internet untuk mengunduh image dan dependency. Siapkan beberapa GB ruang kosong. Port localhost 8081–8083 dan subnet Docker 172.30.26.0/24 harus tersedia.

Buka PowerShell pada folder `lab`, lalu jalankan:

```powershell
.\lab.ps1 Start
.\lab.ps1 Test
.\lab.ps1 Attacks
```

Jika kebijakan komputer menghalangi skrip PowerShell, jalankan perintah Compose berikut secara manual sesuai kebijakan perangkat:

```powershell
docker compose --profile tools build setup db
docker compose --profile tools run --rm --no-deps setup
docker compose up -d --wait db vulnerable query-fixed hardened
docker compose --profile tools run --rm tester
docker compose --profile tools run --rm untrusted
docker compose exec -T db bash /lab-scripts/backup_restore.sh
docker compose --profile tools run --rm tester python tests/restore_app.py
```

Perintah Compose yang sama berlaku di Linux/macOS. Jalankan pengujian tester berurutan karena service itu mempunyai satu alamat IP tetap. Bila aplikasi baru saja menyala, tunggu halaman login dapat dibuka sebelum memulai test.

| Checkpoint | URL | Perbedaan |
|---|---|---|
| vulnerable | http://localhost:8081 | Pencarian concatenation, tanpa pemeriksaan pemilik pada detail, role superuser, DB tanpa TLS, error rinci |
| query-fixed | http://localhost:8082 | Pencarian memakai binding. Akses detail lintas pelanggan masih terbuka |
| hardened | http://localhost:8083 | Binding, pemeriksaan pemilik, role SELECT terbatas, TLS verify-full, error umum dan log tersanitasi |

Pakai hostname konsisten saat demo, misalnya selalu `localhost`. Cookie sesi tiap checkpoint mempunyai nama berbeda. Gunakan jendela incognito/profil browser lain jika ingin menunjukkan A dan B bersamaan pada checkpoint yang sama.

## Akun dan data sintetis

| Username | Password lab | Pelanggan | Invoice |
|---|---|---|---|
| alice | Lab-A-2026! | A | INV-001, INV-003 |
| bob | Lab-B-2026! | B | INV-002 |

| Invoice | Pelanggan | Deskripsi | Nilai | Status |
|---|---|---|---:|---|
| INV-001 | A | Web hosting | Rp1.250.000 | Paid |
| INV-002 | B | Database support | Rp980.000 | Pending |
| INV-003 | A | O'Reilly training | Rp750.000 | Paid |

Identitas pelanggan berasal dari cookie sesi Flask yang ditandatangani. Server memverifikasi cookie tersebut. Browser tidak dapat memilih customer ID sembarang untuk memperoleh akses. Password demo diverifikasi dengan hash pada server. Ini autentikasi demonstrasi dengan akun yang telah diketahui peserta.

## Demo ringkas

1. Login sebagai alice pada 8081. Pencarian kosong menampilkan INV-001 dan INV-003.
2. Masukkan input berikut pada kolom pencarian:

   ```text
   ' OR '1'='1' -- 
   ```

   Hasil vulnerable menjadi tiga invoice, termasuk INV-002 milik B.
3. Pada kolom detail, ambil INV-002. Versi vulnerable memberi HTTP 200. Ini kelemahan otorisasi objek yang terpisah dari SQL injection.
4. Coba 8082. Input injection menghasilkan daftar kosong, tetapi detail INV-002 masih berhasil.
5. Coba 8083. Input injection menghasilkan daftar kosong, detail INV-002 memberi HTTP 404, dan INV-001 tetap berhasil.
6. Cari `O'Reilly`. Versi vulnerable error, versi query-fixed dan hardened menampilkan INV-003.
7. Tombol **Uji respons error** menjalankan error pembagian nol yang sengaja disediakan untuk membandingkan respons publik dan log.

Kelima simulasi dijelaskan langkah demi langkah dalam [simulasi-serangan.md](simulasi-serangan.md): S1 SQL injection, S2 IDOR, S3 penyalahgunaan hak akun database, S4 kredensial valid dari sumber terlarang, S5 penggunaan ulang password lama. Dua simulasi melalui web dan tiga melalui terminal. Jalankan Test dan Attacks berurutan.

## Privilege dan koneksi

- `app_runtime` memiliki CONNECT ke database, USAGE schema billing, dan SELECT pada billing.invoices. Aplikasi ini hanya membaca invoice. Role tidak memiliki SUPERUSER, BYPASSRLS, keanggotaan role lain, atau kepemilikan tabel.
- `lab_owner` adalah pemilik objek dan NOLOGIN. `lab_admin` adalah superuser yang sengaja dipakai baseline untuk menunjukkan risiko hak berlebih. Administrasi container lokal memakai postgres.
- Pemeriksaan kepemilikan pelanggan berada pada aplikasi. SELECT tingkat tabel sendiri tidak memisahkan tenant jika kredensial runtime dicuri. Row Level Security merupakan topik lanjutan, belum diterapkan dalam lab ini.
- Database tidak mempublikasikan port ke host. Semua koneksi DB berada pada jaringan Docker internal. pg_hba.conf mengizinkan sumber dan role tertentu. Klien .30 mencapai PostgreSQL tetapi PostgreSQL menolak melalui HBA. Ini berbeda dari penolakan firewall/TCP.
- Aplikasi hardened dan tester mengharuskan `sslmode=verify-full`, CA lokal yang benar, serta hostname `db` yang sesuai SAN sertifikat. Koneksi plaintext, hostname salah, dan CA lain diuji secara terpisah.
- Pengujian rotasi benar-benar mengganti password runtime ke nilai lama, membuktikan koneksi baru memakai password lama berhasil, kemudian menggantinya ke nilai saat ini dan membuktikan koneksi baru memakai password lama gagal. Jangan menjalankan test itu bersamaan dengan demo manual. Koneksi baru aplikasi membaca file secret.
- TLS dalam materi ini melindungi koneksi aplikasi ke database. Browser menggunakan HTTP loopback untuk lab, sehingga cookie Secure tidak diaktifkan. Deployment nyata memerlukan HTTPS dan kontrol operasional lain.

## Bukti pengujian

| File | Isi |
|---|---|
| evidence/attacks.json | Ringkasan kelima skenario dengan run ID, timestamp, dan hasil aktual |
| evidence/attacks-core.json | S1, S2, S3, S5 pada suite lengkap |
| evidence/attack-S*.json | Hasil demonstrasi individual bila dijalankan |
| evidence/retest.json | 51 pemeriksaan aplikasi, privilege, TLS, log, dan rotasi |
| evidence/network.json | Penolakan sumber .30 menggunakan kredensial valid |
| evidence/restore.json | Database pemulihan terpisah, jumlah baris, checksum, dan durasi aktual |
| evidence/restore-app.json | 4 pemeriksaan fungsi aplikasi terhadap database hasil restore |
| evidence/*.jsonl | Log terstruktur per checkpoint, tanpa password atau input pencarian mentah |
| evidence/screenshots/ | Tangkapan browser aktual, bila telah dibuat pada paket ini |

Status PASS pada baseline berarti kelemahan yang direncanakan berhasil direproduksi, bukan berarti baseline aman. Tanggal dan hasil aktual setiap laporan tercatat di dalam file JSON; laporan individual dan suite utama dapat memiliki waktu eksekusi berbeda. Jalankan ulang untuk lingkungan Anda. Laporan attacks.json hanya diperbarui setelah seluruh rangkaian Attacks berhasil mencapai tahap agregasi; periksa timestamp dan run ID agar tidak memakai laporan lama.

Backup memakai pg_dump custom tanpa global role/password. Restore mempertahankan privilege objek pada cluster lab yang sama, lalu menguji aplikasi melalui Flask test client dengan koneksi nyata ke database hasil restore. Pemeriksaan ini bukan uji pemulihan seluruh infrastruktur atau failover. Setiap run menyimpan database restore baru dan dump baru, tanpa menghapus data run sebelumnya. Dump lab berisi data sintetis dan belum dienkripsi. Produksi membutuhkan kebijakan penyimpanan, enkripsi/kunci, retensi, serta uji RPO/RTO sesuai kebutuhan.

## Siklus kerja dan troubleshooting

```powershell
.\lab.ps1 Status
.\lab.ps1 Stop
```

Stop mempertahankan volume database dan runtime. Start berikutnya memakai kredensial yang sama. Jangan menghapus hanya runtime atau hanya volume database: password dan data awal menjadi tidak sinkron. Skrip tidak melakukan reset destruktif otomatis.

- Docker API tidak tersedia: aktifkan Docker Desktop dan tunggu engine Linux siap.
- Port sudah digunakan: ubah hanya port host pada compose.yaml dan sesuaikan URL demo. Test container memakai nama service sehingga tidak bergantung port host.
- Subnet bertabrakan: ubah subnet/IP pada compose.yaml, pg_hba.conf, dan pengujian secara konsisten.
- Error HBA yang tidak diharapkan: periksa IP sumber dan urutan aturan. Runtime hardened hanya menerima jalur yang tercantum.
- Error sertifikat: periksa CA, hostname `db`, waktu sistem, serta masa berlaku. Sertifikat lab berlaku satu tahun sejak setup.
- Build setelah perubahan kode: `docker compose build setup`, lalu `docker compose up -d --force-recreate vulnerable query-fixed hardened`.

## Batas penggunaan paket

Seluruh kelemahan sengaja ada pada lab terisolasi. Binding port tetap `127.0.0.1`. Jangan memakai data/kredensial nyata atau mempublikasikan service vulnerable. `runtime/` berisi secret dan kunci lokal, tidak termasuk paket distribusi. File secret mount merupakan mekanisme demonstrasi, bukan pengganti vault. Server Flask di sini merupakan server development dengan debug mati. Query web memakai default transaksi read-only sebagai pengaman demonstrasi, bukan batas keamanan terhadap akun superuser.

Gambar slide merupakan ilustrasi AI yang mengikuti skenario. Bukti teknis otoritatif ada pada kode, laporan JSON, dan screenshot browser aktual.

## Rujukan

- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
- https://www.postgresql.org/docs/17/libpq-ssl.html
- https://www.postgresql.org/docs/17/auth-pg-hba-conf.html
- https://www.postgresql.org/docs/17/sql-grant.html
- https://www.postgresql.org/docs/17/backup-dump.html
