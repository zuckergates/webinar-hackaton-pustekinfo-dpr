# Lima simulasi keamanan database

Versi PDF khusus yang siap dibuka atau dicetak: [Panduan Praktik 5 Simulasi Serangan](../panduan-praktik/panduan-simulasi-serangan.pdf). Memuat persiapan, langkah tiap skenario, hasil yang diharapkan, retest, dan penanganan kendala.

Seluruh langkah hanya menargetkan Invoice Lab lokal dengan data sintetis. Jalankan PowerShell dari folder `lab`. Siapkan lab dengan `.\lab.ps1 Start`.

## Skenario latihan

| ID | Slide | Jalur dan asumsi | Hasil yang diharapkan |
|---|---:|---|---|
| S1 | 21 | Web; login Alice | Payload menampilkan 3 invoice di 8081, 0 di 8082/8083; pencarian normal tetap 2 |
| S2 | 22 | Web; login Alice meminta INV-002 milik Bob | 200 di 8081/8082; 404 di 8083; invoice sendiri tetap 200 |
| S3 | 23, 32 | Terminal; akun DB lab telah disediakan | lab_admin membaca internal dan UPDATE sementara; app_runtime ditolak 42501; SELECT invoice tetap berhasil |
| S4 | 33 | Terminal; password runtime valid, sumber .30 | PostgreSQL menolak melalui pg_hba.conf; sumber .40 tetap dapat SELECT |
| S5 | 34 | Terminal; password lama telah diketahui | Sebelum rotasi diterima; setelah rotasi koneksi baru ditolak; password saat ini dan aplikasi bekerja |

S3–S5 bukan demonstrasi pencurian kredensial. S3 membandingkan hak akun yang sudah tersedia, bukan memperoleh hak baru. TLS, respons error/log, dan restore merupakan pengujian pendukung di luar lima skenario.

## S1  -  SQL injection

1. Buka http://localhost:8081 dan login `alice / Lab-A-2026!`.
2. Pencarian kosong: INV-001 dan INV-003, keduanya milik A.
3. Tempel payload ASCII berikut; pertahankan spasi setelah dua tanda minus:

```text
' OR '1'='1' -- 
```

4. Tiga invoice muncul, termasuk INV-002 milik B.
5. Ulangi pada 8082 dan 8083: daftar kosong untuk payload.
6. Cari `O'Reilly`: kedua versi yang memakai binding menampilkan INV-003.

**Yang dipelajari:** Input pencarian semula ikut membentuk perintah SQL. Binding menjadikannya nilai. Fungsi pencarian sah tetap bekerja.

## S2  -  IDOR

1. Login Alice pada ketiga checkpoint.
2. Isi kolom detail dengan INV-002.
3. 8081 dan 8082 memberi HTTP 200 dengan customer B. 8083 memberi 404.
4. Minta INV-001 pada 8083: HTTP 200 dengan customer A.

**Yang dipelajari:** Query sudah memakai parameter, tetapi keputusan siapa boleh melihat invoice masih harus diperiksa. Perbaikan SQL injection saja belum menutup akses milik orang lain.

## S3  -  Penyalahgunaan hak akun database

```powershell
docker compose --profile tools run --rm tester python tests/attacks.py --scenario S3
```

Runner mengakses DB dari tester .40 dengan akun yang disediakan lab. Akun lab_admin membaca satu baris internal.audit_sentinel dan mengubah status INV-002 menjadi Demo-only dalam transaksi. Runner membaca perubahan itu lalu ROLLBACK, membuka koneksi baru, dan memeriksa status semula kembali.

Dengan app_runtime, pembacaan internal dan UPDATE ditolak dengan SQLSTATE 42501. SELECT billing.invoices tetap berhasil dengan 3 baris. Data tidak ditinggalkan dalam kondisi berubah. Web lab menggunakan transaksi read-only; demonstrasi UPDATE ini dilakukan langsung melalui koneksi DB.

**Yang dipelajari:** Jika akun berhak terlalu luas disalahgunakan, jangkauan dampaknya besar. Fitur aplikasi hanya membaca invoice; akun runtime cukup memiliki SELECT.

Bukti individual: `evidence/attack-S3.json`.

## S4  -  Kredensial valid dari sumber terlarang

```powershell
docker compose --profile tools run --rm untrusted
```

Klien .30 memakai password runtime valid dan TLS verify-full, tetapi PostgreSQL menolaknya melalui pg_hba.conf. Kesalahan harus menyebut penolakan HBA dan alamat .30, bukan timeout atau password salah. Kontrol positif SELECT dari tester .40 tercatat pada S3 dalam suite lengkap.

**Yang dipelajari:** Password benar belum cukup. Sumber koneksi ini tidak diizinkan oleh PostgreSQL. Aturan HBA tidak dilonggarkan selama demo. Ini perbandingan dua sumber dengan konfigurasi yang sama, bukan perubahan firewall.

Bukti: `evidence/network.json`.

## S5  -  Penggunaan ulang password lama

```powershell
docker compose --profile tools run --rm tester python tests/attacks.py --scenario S5
```

Runner menetapkan password lama untuk baseline, memastikan koneksi baru berhasil, lalu menggantinya ke password saat ini. Koneksi baru dengan password lama harus gagal karena autentikasi. Password saat ini harus berhasil, kemudian aplikasi hardened diuji kembali. Blok finally memulihkan password saat ini jika pengujian gagal secara normal.

**Yang dipelajari:** Kita asumsikan password lama sudah diketahui. Rotasi menghalangi penggunaan ulangnya untuk koneksi baru. Sesi database yang sudah terbuka tidak otomatis terputus.

Jalankan berurutan dengan latihan lain. Jangan menjalankan Test, Attacks, atau S5 bersamaan, dan biarkan perintah selesai. Jangan menampilkan isi secret di layar.

Bukti individual: `evidence/attack-S5.json`.

## Retest seluruh lima skenario

```powershell
.\lab.ps1 Attacks
```

Perintah menjalankan S1, S2, S3, S5 dari tester, S4 dari untrusted, lalu menyatukan laporan. Target hasil: `FIVE SCENARIOS: 5/5` dan exit code 0. Run ID memastikan laporan inti dan sumber terlarang berasal dari eksekusi yang sama.

Buka `evidence/attacks.json` setelah pengujian selesai. Periksa timestamp, run_id, passed, total, dan actual tiap skenario. PASS pada baseline berarti kelemahan yang direncanakan berhasil direproduksi. Laporan tidak menyatakan semua keamanan sistem telah terbukti.

Perintah manual setara bila skrip PowerShell dibatasi:

```powershell
$demoRunId=[guid]::NewGuid().ToString()
docker compose --profile tools run --rm tester python tests/attacks.py --run-id $demoRunId
docker compose --profile tools run --rm -e "ATTACK_RUN_ID=$demoRunId" untrusted
docker compose --profile tools run --rm tester python tests/attacks.py --report --run-id $demoRunId
```

Hentikan rangkaian jika satu perintah gagal; jangan menggunakan laporan lama sebagai hasil run baru. Perintah individual tidak memperbarui attacks.json. Sesudah demo individual, jalankan Attacks untuk mendapatkan laporan lengkap yang konsisten.

## Pengujian pendukung

```powershell
.\lab.ps1 Test
```

Suite ini memeriksa 51 kondisi aplikasi, privilege, TLS, log dan rotasi, sumber koneksi, backup/restore, serta 4 kondisi aplikasi hasil restore. Jalankan Test dan Attacks berurutan. Data normal Alice dan Bob harus tetap dapat dibaca sesuai kepemilikan.
