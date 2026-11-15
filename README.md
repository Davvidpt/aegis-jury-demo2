# AEGIS — demo publik untuk juri

Entry point Streamlit Community Cloud: `streamlit_app.py`.
Python 3.12 direkomendasikan. Requirements: `-e .[mvp]`.
Repository ini hanya berisi source aplikasi, rules dan dua contoh koleksi
sintetis. Tidak ada database operasional, collection nyata, API key atau
binary Hayabusa. Demo awal memakai ZIP positif sintetis (4 rule matches).

Setiap tab/browser session memiliki database sementara terpisah. Tombol
"Mulai sesi baru" menghapus database sesi saat ini. File sesi lain dapat tetap
ada sampai proses Streamlit restart. Jangan unggah evidence pribadi/rahasia.
Untuk juri, gunakan hanya data lab yang sudah ditinjau untuk publikasi.

Cloud ini menampilkan assessment M1–M4. Integrasi Hayabusa M6/M7 ke UI
belum tersedia pada branch demo ini. Tidak ada klaim deteksi EVTX dari UI.

Deploy: buat repository GitHub terpisah, upload isi folder ini, lalu pada
share.streamlit.io pilih repo tersebut, branch utama, `streamlit_app.py`,
Python 3.12, dan set app Public. Jangan menambahkan secrets atau data pribadi.
Uji dari browser incognito: 4 temuan awal → impor `demo/baseline.zip` →
pilih collection baseline → assessment 0 matches → unduh PDF sintetis.
