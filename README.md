# Database Security in Practice

### From Vulnerable Web App to Hardened Data Layer

Materi dan latihan mandiri peserta webinar **Pustekinfo DPR bersama Onno Center International**.

**Dendi Zuckergates** · 26 September 2026

Pelajari SQL injection, otorisasi objek, hak akun database, pembatasan koneksi, dan rotasi password melalui aplikasi latihan dengan data sintetis.

**[Unduh materi PDF](materi-presentasi/database-security-in-practice.pdf?raw=true)** · [Mulai belajar](mulai-di-sini.md) · [Panduan lab](lab/README.md)

## Materi peserta

| Materi | Akses |
|---|---|
| Materi webinar, 47 slide | [Unduh PDF](materi-presentasi/database-security-in-practice.pdf?raw=true) |
| Praktik lima simulasi keamanan | [Panduan PDF](panduan-praktik/panduan-simulasi-serangan.pdf) |
| Hardening aplikasi dan database | [Panduan PDF](panduan-praktik/panduan-hardening.pdf) |
| Ringkasan perintah, satu halaman | [PDF ringkas](panduan-praktik/catatan-sintaks.pdf) |
| Langkah latihan dalam Markdown | [Simulasi keamanan](lab/simulasi-serangan.md) |
| Referensi untuk belajar lebih lanjut | [Daftar referensi](panduan-praktik/rujukan-teori.md) |

PDF materi berukuran sekitar **84 MiB**. Gunakan tautan unduhan jika pratinjau tidak muncul.

## Mulai latihan

**Siapkan:** Docker Desktop dengan Linux containers, Docker Compose v2, dan PowerShell. Build pertama membutuhkan internet.

1. Unduh repository melalui **Code → Download ZIP**, lalu ekstrak seluruh isinya, atau gunakan Git clone.
2. Klik dua kali **`jalankan-lab.cmd`** di folder utama.
3. Tunggu pesan **Lab siap**, lalu buka aplikasi latihan.
4. Ikuti [panduan lima simulasi](lab/simulasi-serangan.md) dan bandingkan hasil setiap versi.

Alternatif dari PowerShell di folder utama:

```powershell
.\lab\lab.ps1 Start
```

> Gunakan lab hanya di komputer lokal dengan data sintetis. Versi vulnerable sengaja memuat celah keamanan. Pertahankan binding ke `127.0.0.1` dan jalankan satu salinan lab pada satu waktu.

### Aplikasi dan akun latihan

| Versi | Buka di komputer Anda | Fokus |
|---|---|---|
| Vulnerable | [localhost:8081](http://localhost:8081) | Mengamati celah awal |
| Query-fixed | [localhost:8082](http://localhost:8082) | Memperbaiki query dengan parameter |
| Hardened | [localhost:8083](http://localhost:8083) | Menggabungkan kontrol akses dan keamanan database |

| Akun | Password latihan | Invoice milik akun |
|---|---|---|
| `alice` | `Lab-A-2026!` | INV-001, INV-003 |
| `bob` | `Lab-B-2026!` | INV-002 |

Akun tersebut sengaja tersedia untuk latihan. Secret database dan sesi dibuat secara lokal saat setup. Jika mengalami kendala, baca [setup dan troubleshooting](lab/README.md).

## Yang akan dipelajari

1. **SQL injection:** membandingkan query rentan dengan query berparameter.
2. **Otorisasi objek:** memastikan pengguna hanya mengakses invoice miliknya.
3. **Hak akun database:** membatasi akun aplikasi sesuai operasi yang dibutuhkan.
4. **Sumber koneksi:** menolak koneksi dari sumber yang tidak diizinkan.
5. **Rotasi password:** menguji penolakan password lama pada koneksi baru.

## Pengujian dan selesai latihan

Jalankan setiap perintah sampai selesai sebelum melanjutkan:

```powershell
.\lab\lab.ps1 Test
.\lab\lab.ps1 Attacks
.\lab\lab.ps1 Status
.\lab\lab.ps1 Stop
```

`Stop` menghentikan lab dan mempertahankan data. Jangan menjalankan pengujian atau rotasi password bersamaan.

<details>
<summary>Membaca hasil pengujian</summary>

Target hasil adalah **51 pemeriksaan utama**, **4 pemeriksaan aplikasi hasil restore**, dan **5 skenario latihan**. PASS pada versi rentan berarti celah yang disiapkan berhasil direproduksi.

Hasil baru ditulis ke `lab/evidence`. [Contoh hasil](lab/contoh-hasil/README.md) berasal dari persiapan paket awal; periksa timestamp dan run ID untuk membedakannya dari hasil latihan Anda.

Rincian batas lab, TLS, izin database, dan pemulihan data tersedia di [panduan lab](lab/README.md).

</details>

## Isi repository

```text
.
├── README.md
├── mulai-di-sini.md
├── jalankan-lab.cmd
├── materi-presentasi/   Materi webinar dalam PDF
├── panduan-praktik/     Panduan latihan dan referensi
└── lab/                Aplikasi, konfigurasi Docker, dan pengujian
```

## Hak penggunaan

Belum ada lisensi open-source yang ditetapkan untuk paket ini. Hubungi pemilik materi untuk izin di luar yang telah diberikan. Nama, logo, dan materi pihak ketiga mengikuti hak pemilik masing-masing.
