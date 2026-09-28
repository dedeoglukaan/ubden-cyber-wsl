# RUNBOOK — Engagement Günü (AnyDesk üzerinden iç ağ / AD)

Bu dosya **uzun anlatım**. Sahada tek sayfa isterseniz `CHEATSHEET.md` kullanın — komutlar birebir
aynı, burada her komutun *neden* orada olduğu ve *ters giderse ne yapılacağı* da var.

Çalışma modeli: sen "el"sin (AnyDesk'te müşteri makinesinde), yanındaki asistan "beyin" (kendi
laptobunda). **Her komutun çıktısını yapıştır** → yorumlansın, sıradaki söylensin. Tahmin etme.

---

## 0. Bağlanmadan ÖNCE (kendi laptobunda, o sabah)

- [ ] İmzalı yetkilendirme + **tarih ve saat** yazılı olarak teyitli mi? Değilse **başlama**.
- [ ] Müşteriden gelmiş olmalı: hedef IP/subnet listesi, domain adı, DC adresi,
      **read-only test hesabı** (kullanıcı adı; parola ayrı kanaldan), hariç tutulan sistemler.
- [ ] Müşteriye hatırlat: UBDEN kurulumu makinedeki **tüm WSL dağıtımlarına mirrored networking
      uygular ve makineyi bir kez yeniden başlatabilir**. Onay alınsın, yedek/snapshot hazır olsun.
- [ ] Acil durdurma için kimi arayacağını bil (müşteri BT yetkilisi, telefonu elinde).
- [ ] **`setup-offensive.sh`'i önceden koştur** (§5). Araç kurulumu internet ister; saha gecesi
      20:00'de indirme beklemek istemezsin.
- [ ] Ekranı ikiye böl: sol = AnyDesk, sağ = asistan.

---

## 1. AnyDesk + ortam kontrolü

- [ ] Bağlan, **tam ekran yapma** — yarım ekran kal ki kendi tarafını da görebilesin.
- [ ] Makine Win11 22H2+ mı, yönetici yetkin var mı, ~30 GB boş disk + internet var mı?
      (UBDEN bunları şart koşuyor.)

---

## 2. İlk 5 dakika: makineden bilgi topla (müşteriden hiçbir şey isteme)

Müşterinin BT ekibi çoğu zaman domain adını, DC'yi, kilitlenme eşiğini bilmez. Hepsi makinede
zaten var. Windows `cmd`'de, **hepsi salt okunur**, hiçbiri parola denemez, hiçbiri yönetici
istemez — oturum açmış kullanıcının hakkıyla çalışır:

```cmd
echo %USERDNSDOMAIN%
echo %USERDOMAIN%
whoami /upn
whoami /groups
nltest /dsgetdc:%USERDNSDOMAIN%
nltest /dclist:%USERDNSDOMAIN%
ipconfig /all
net accounts /domain
```

| çıktı | ne verir |
|---|---|
| `echo %USERDNSDOMAIN%` | **DOMAIN** — AD alan adı |
| `nltest /dsgetdc:` | **DC FQDN + IP** — o an kullanılan denetleyici |
| `nltest /dclist:` | **tüm** DC'ler. Müşteri envanterinde iki DC'ye aynı IP yazılmış olabilir (sık rastlanan yazım hatası); gerçeği burada çıkar |
| `ipconfig /all` | hangi VLAN'dayız + DNS sunucuları (genelde DC'lerin kendisi) |
| `whoami /groups` | elimizdeki oturumun yetkisi. Yönetici çıkarsa zincir düşük yetkiden başlamıyor demektir — **raporda belirtilir**, yoksa bulgular olduğundan ağır görünür |
| `net accounts /domain` | parola politikası + **kilitlenme eşiği** |

⚠️ **Kilitlenme eşiğini §8'e girmeden oku.** Eşik 3 veya altıysa `guard.py`'nin bütçesini **1**'e
indir. Gerçek bir kullanıcı hesabını kilitlemek üretim kesintisidir; ortak kullanılan bir hesabı
kilitlemek doğrudan iş durdurur.

**Makine domain'e katılı değilse** alan adı yine alınır:

```cmd
nslookup -type=SRV _ldap._tcp.dc._msdcs.<alan-adi>
```

Kali tarafından, kimlik doğrulamasız (anonim RootDSE — alan adını ve naming context'i verir):

```bash
ldapsearch -x -H ldap://<DC_IP> -s base -b "" namingContexts defaultNamingContext
```

**Makineden çıkmayan tek şey paroladır.** Onu müşterinin BT yetkilisi yazar. **Yönetici olmasına
gerek yok, olmaması tercih edilir** — zincirin sorusu "sıradan bir kullanıcıdan nereye kadar
gidiliyor". Parola yoksa tarama, port/sürüm ve paylaşım kontrolleri yine çalışır; **kerberoast /
AS-REP / ADCS / BloodHound düşer** ve `pipeline.py` zaten kimliksiz plan kurmayı reddeder
(`no credential — refusing to build a plan`).

---

## 3. UBDEN taraması (önce bu biter, sonra biz başlarız)

PowerShell (yönetici):

```powershell
irm 'https://raw.githubusercontent.com/ubden/ubden-cyber-wsl/v5.0.0-wsl.25/bootstrap.ps1' | iex
```

⚠️ **Sürümü çalıştırmadan önce güncel etiketi kontrol et.** UBDEN hızlı sürüm çıkarıyor
(2026-09-27'de tek günde 11 `wsl` sürümü, 2026-09-28'de 4 tane daha). Güncel liste:

```bash
git ls-remote --tags https://github.com/ubden/ubden-cyber-wsl | tail
```

- [ ] Sihirbazda kapsamı gir: müşteri adı, hedefler, hariçler, DC, test hesabı.
- [ ] Profil menüsü **ok tuşlarıyla** gezilir (`k`/`j` de çalışır), Enter seçer. İç ağ işi için
      **network** profili + AD modülü.
- [ ] Tarama bitsin. Rapor klasörü: `~/Desktop/UBDEN-Cyber-Reports/<CLIENT>_<tarih>_<id>/`
- [ ] **Bu klasörün tam yolunu not al** → aşağıda `$RUN`.

**Aynı host'u hem IP hem FQDN olarak girme.** UBDEN ikisini ayrı hedef sayar ve tüm tarama
zincirini iki kez koşar; ölçülen bir vakada tekrar, toplam sürenin yaklaşık yarısını yemişti.
Biri yeter.

---

## 4. Değişkenler (Kali WSL'de, BİR kez; aynı terminalde kal)

```bash
wsl -d kali-linux
```

```bash
export RUN='/root/Desktop/UBDEN-Cyber-Reports/<CLIENT>_<tarih>_<id>'
export DOM='<DOMAIN>'            # ör. corp.local
export DC='<DC_FQDN>'            # ör. dc01.corp.local
export IP='<DC_IP>'              # ör. 10.0.0.10
export U='<TEST_KULLANICI>'
export P='<PAROLA>'
export EXT="$HOME/offensive-ext"
export PY="$EXT/.venv/bin/python3"
export UBDEN_REVIEWER='<FIRMA/ANALIST ADI>'   # rapora "Doğrulayan analist" olarak basılır
printf '%s\n' '<CIDR>' "$IP" "$DC" > "$HOME/scope.txt"
export SCOPE="$HOME/scope.txt"
cat "$SCOPE"
```

Kontrol: `echo "$RUN" && ls "$RUN" | head` → klasör doğru mu?

⚠️ **Scope'a DOMAIN adı yazmak host'ları yetkilendirmez.** `corp.local` satırı
`dc01.corp.local`'i kapsama **almaz** — sözleşmedeki her hostname'i ayrı satıra birebir yaz
(CIDR'ler zaten içindekileri kapsar). Eksiğini §7'deki `N in / M dropped` satırından anlarsın.
Bilerek böyle: domain adını joker saymak, sözleşme dışı bir host'a sessizce yayılmak olurdu.

⚠️ `UBDEN_REVIEWER` boş bırakılırsa imza `Analist` olur. Müşteri raporunda *"Doğrulayan analist"*
diye görünen alan budur — kendi veya firmanın adını yaz. Aynısı `--reviewer` bayrağıyla da verilir.

---

## 5. Kurulum (makinede bir kez — tercihen önceden)

```bash
git clone --branch offensive-ext-v5 https://github.com/ubden/ubden-cyber-wsl "$HOME/ubden-src"
cp -r "$HOME/ubden-src/offensive-ext" "$HOME/offensive-ext"
sudo bash "$EXT/setup-offensive.sh" && source ~/.bashrc
```

Bakılacak satırlar: `[OK] nxc -> netexec`, `[OK] hashcat backend -> ...`,
`[OK] Offensive toolchain hazir`.

- `hashcat backend YOK` çıkarsa kırma adımında **john** kullan (§10); hashcat hiçbir şey kıramaz.
- Rapor yeniden üretimi UBDEN'in `/opt/ubden-cyber/` kurulumunu (report_v2 + reportlab'lı venv)
  otomatik bulur, o yüzden `offensive-ext` nerede dursa çalışır.

---

## 6. GO / NO-GO (canlıdan önce; hiçbir kimlik denemesi yapmaz)

```bash
"$PY" "$EXT/doctor.py" --scope "$SCOPE" --run-dir "$RUN" \
  --dc "$DC" --domain "$DOM" --ip "$IP" --user "$U" --password "$P"
```

Araçlar kurulu mu, scope geçerli mi, kimlik var mı, DC'ye ağ yolu var mı, rapor motoru
(reportlab) çalışır mı, **ve saat kayması** var mı — hepsini kontrol eder. Kimlik doğrulaması
yapmaz, kapsam dışı hedefe prob atmaz.

**`==> GO` görmeden ilerleme.**

⚠️ **Saat kayması Kerberos'u öldürür.** `clock skew` FAIL/WARN → `sudo ntpdate "$IP"` (veya
`sudo timedatectl set-ntp true`). 5 dakikadan fazla fark = kerberoast, AS-REP, certipy hepsi patlar.

---

## 7. Planı gör (hiçbir şey çalıştırmaz)

```bash
"$PY" "$EXT/pipeline.py" --run-dir "$RUN" --scope "$SCOPE" \
  --dc "$DC" --domain "$DOM" --ip "$IP" --user "$U" --password "$P" --dry-run
```

**`# scope: N in / M dropped` satırını oku:**

- `0 in` → hiçbir host'a dokunulmayacak. `$SCOPE` ile UBDEN'in bulduğu hedefler uyuşmuyor, düzelt.
- `dropped > 0` → düşen hedef sözleşmede varsa scope dosyasına ekle; yoksa doğru davranış.

Planı yapıştır, mantıklıysa devam.

---

## 8. Lockout bütçesi (kimseyi kilitlemeyelim)

```bash
"$PY" "$EXT/guard.py" --policy --dc "$DC" --domain "$DOM" --ip "$IP" --user "$U" --password "$P"
```

`SAFE BUDGET` satırını göster. §2'de okuduğun `net accounts /domain` eşiğiyle tutuyor mu,
karşılaştır. Tutmuyorsa küçük olanı esas al.

---

## 9. CANLI (read-only zincir; yazma/dump KAPALI)

```bash
"$PY" "$EXT/pipeline.py" --run-dir "$RUN" --scope "$SCOPE" \
  --dc "$DC" --domain "$DOM" --ip "$IP" --user "$U" --password "$P"
```

Sırasıyla: ADCS → BloodHound (DCOnly) → AS-REP → kerberoast → SMB auth matrix → paylaşım
triyajı → coercion taraması. Sonra:

```bash
sed -n '1,40p' "$RUN/offensive-ext/SUMMARY.md"
```

⚠️ **`!! N step(s) did NOT complete cleanly` uyarısı varsa, `0 bulgu` "hedef temiz" DEMEK
DEĞİLDİR.** Adı geçen adımları tekrar çalıştır veya aşağıdaki elle karşılığını dene. Bu uyarı tam
olarak "araç patladı ama rapor sessiz kaldı" durumunu yakalamak için var.

Bir şey ters giderse: `touch "$RUN/STOP"` → çalışan zincir bir sonraki adımdan **önce** durur,
o ana kadarki kanıt kalır. Devam için `rm -f "$RUN/STOP"`.

---

## 10. Hash'leri OFFLINE kır (ağa dokunmaz, kilitleme riski yok)

```bash
"$PY" "$EXT/crack.py" "$RUN"          # .hash dosyaları + DOĞRU hashcat/john komutlarını basar
```

Bastığı komutu çalıştır (mod etype'a göre değişir: RC4→13100, AES→19600/19700), sonra geri besle:

```bash
"$PY" "$EXT/crack.py" "$RUN" --results show.txt                               # hashcat kullandıysan
"$PY" "$EXT/crack.py" "$RUN" --results "$RUN/offensive-ext/hashes/john.pot"   # john kullandıysan
"$PY" "$EXT/pipeline.py" --run-dir "$RUN" --skip-attack --no-report           # bulguya işle
```

> ⚠️ **hashcat GPU'suz makinede hiçbir şey kırmaz.** `No OpenCL, HIP or CUDA compatible platform
> found` yazıp **0 ile çıkar** — adım çalışmış gibi görünür. `doctor.py` bunu `crack backend`
> kontrolüyle yakalar. İki çözüm:
> - `apt install pocl-opencl-icd ocl-icd-libopencl1` (ikisi birden; tek başına ICD yetmiyor),
>   sonra `hashcat -I` bir CPU cihazı göstermeli;
> - ya da `crack.py`'ın bastığı **john** komutunu kullan — CPU'da çalışır, kurulu gelir.
>
> john kullanırsan sonucu `--show` ile değil **potfile** ile geri besle: `john --show` krb5tgs
> için hesabı `?` diye basıyor. `crack.py`'ın verdiği komutta `--pot=...john.pot` zaten var.

"Roastable" → "şifresi kırıldı = gerçek kimlik" bulgusuna döner.

---

## 11. Yazma / dump (yalnız gerekliyse, açık onayla)

```bash
"$PY" "$EXT/pipeline.py" --run-dir "$RUN" --scope "$SCOPE" \
  --dc "$DC" --domain "$DOM" --ip "$IP" --user "$U" --password "$P" \
  --enable-writes --allow-dcsync
```

Elle `YETKILIYIM` yazman istenir. DCSync = **sadece kanıt** (`-just-dc-ntlm`), veri sızdırma yok.

⚠️ **`--assume-yes` KULLANMA.** `--enable-writes --allow-dcsync --assume-yes` birlikte = insan
onayı olmadan tüm domain hash'lerini dökme. O bayrak yalnızca gerçekten insansız otomasyon için.

---

## 12. Rapor

- [ ] `$RUN/offensive-ext/` altında: `SUMMARY.md`, `KILL_CHAIN.md`, `COVERAGE_MATRIX.md`,
      `REMEDIATION.md`, `ATTACK_LAYER.json`. Bulgular UBDEN'in `review.json`'ına işlendi ve
      `report_v2.py` yeniden koştu (`report_regenerated: true`).
- [ ] **CVSS / severity'yi elle gözden geçir.** Araç öneri üretir; rapor müşteriye gitmeden önce
      `review.json` elden geçirilir.
- [ ] **UBDEN'in topladığı ama raporuna basmadığı iki veriyi elle bulguya çevir.** İkisi de
      `review.json`'a elle girilir:
      1. **Parola ve kilitlenme politikası** — `AD_ASSESSMENT.json` → `password_policy` +
         `machine_account_quota`. `report_v2.py`'nin `ad_story()` fonksiyonu bu bloğu basmaz;
         bastığı bölümün sonunda zaten *"parola ilkesi ancak ayrıca kaydedilen kontrollerle
         değerlendirilmiş sayılır"* yazar. Bakılacaklar: `lockout_threshold` (0 = kilitlenme yok),
         `machine_account_quota` (0 olmalı), `min_length`.
      2. **SMB imzalama** — `targets/*/raw/*.xml` içinde nmap'in `smb-security-mode` /
         `smb2-security-mode` çıktısı, `message_signing` anahtarı. Rapor TCP/445 için
         *"imzalama denetlenmedi"* yazar, halbuki nmap denetlemiştir.
- [ ] Bunları **ekleme**: CVE listesi (`UBDEN_CVE.json`) ve dizin envanteri (kullanıcı / grup /
      bilgisayar sayıları) rapora zaten giriyor. İkinci kez yazmak çift bulgu olur.
Bu ikisini çıkaran komutlar (girintisiz yapıştır — heredoc sonlandırıcısı satır başında olmalı):

```bash
python3 -c "import json;d=json.load(open('$RUN/AD_ASSESSMENT.json'));print(d.get('password_policy'),d.get('machine_account_quota'))"
```

```bash
python3 - "$RUN" <<'PYEND'
import glob,sys,xml.etree.ElementTree as ET
bad=set()
for f in glob.glob(sys.argv[1]+'/targets/*/raw/*.xml'):
    try: root=ET.parse(f).getroot()
    except Exception: continue
    for h in root.iter('host'):
        ip=next((a.get('addr') for a in h.iter('address') if a.get('addrtype')=='ipv4'),'')
        for sc in h.iter('script'):
            if sc.get('id') in ('smb-security-mode','smb2-security-mode'):
                for el in sc.iter('elem'):
                    if el.get('key')=='message_signing' and (el.text or '').strip()=='disabled':
                        bad.add(ip)
print('SMB imzalama KAPALI:', ', '.join(sorted(bad)) or 'yok')
PYEND
```

- [ ] Çıktıyı AnyDesk dosya transferiyle kendi laptobuna çek, cilalı raporu orada bitir,
      müşterinin verdiği güvenli konuma teslim et.

---

## 13. Temizlik (iş biter bitmez)

- [ ] **Zayıf `ubden` kullanıcısı** (şifre `password`) → `sudo passwd ubden`, güçlü şifre ver.
- [ ] **DCSync hash'lerini kendi laptobuna ÇEKME.** `dcsync_dump.txt` krbtgt dahil tüm hash'leri
      içerir; rapora sadece asgari kanıt girer, ham dosya transfer edilmez.
- [ ] Loot'u sil:
      ```bash
      shred -u "$RUN/offensive-ext/dcsync_dump.txt" "$RUN/offensive-ext/hashes/"*.hash show.txt 2>/dev/null
      ```
      (`hashes/*.hash` = roastable Kerberos hash'leri, `show.txt` = kırılmış açık şifreler —
      ikisi de toksik.)
- [ ] Müşteri isterse `destroy` ile WSL'i kaldır. ⚠️ **TÜM WSL dağıtımlarını siler** — önce raporu
      dışarı al.

---

## Elle yedek komutlar (pipeline takılırsa)

```bash
# Lockout politikasi (HER auth'tan once):
"$PY" "$EXT/guard.py" --policy --dc "$DC" --domain "$DOM" --ip "$IP" --user "$U" --password "$P"

# ADCS (en sessiz DA yolu):
certipy find -u "$U@$DOM" -p "$P" -dc-ip "$IP" -vulnerable -stdout

# BloodHound (sessiz). CE kuruluysa bloodhound-ce-python, degilse bloodhound-python:
bloodhound-ce-python -d "$DOM" -u "$U" -p "$P" -c DCOnly -ns "$IP" --zip

# Kerberoast / AS-REP (gecerli hesap, lockout riski yok):
impacket-GetUserSPNs "$DOM/$U:$P" -request -dc-ip "$IP"
impacket-GetNPUsers "$DOM/$U:$P" -request -format hashcat -dc-ip "$IP"

# Yerel-admin haritasi (tek bilinen kimlik):
nxc smb <HOSTS> -u "$U" -p "$P" -t 1

# Coercion (sadece tarama, ateslemez):
coercer scan -u "$U" -p "$P" -d "$DOM" -t "$IP"
```

`attack.py` bloodhound'u çağırırken önce `bloodhound-ce-python`, yoksa `bloodhound-python` dener
(eski sürüm CE'nin yiyemediği v4 JSON üretiyor). Elle çalıştırırken hangisi kuruluysa onu kullan.

---

## Takıldığında

| belirti | bak |
|---|---|
| `doctor` NO-GO | `[FAIL]` satırlarını tek tek düzelt, tekrar koş |
| `0 in / N dropped` | scope dosyası ile UBDEN hedefleri uyuşmuyor (§4 uyarısı) |
| Tüm Kerberos adımları patlıyor | saat kayması — `sudo ntpdate "$IP"` (§6) |
| `no credential — refusing to build a plan` | parola/hash verilmemiş, bilerek reddediliyor |
| `report_v2.py exited 1` | reportlab yok. Bulgular `review.json`'da duruyor, kaybolmadı; venv'e `pip install reportlab` |
| hashcat 0 ile çıkıyor ama hiçbir şey kırmıyor | GPU/OpenCL yok — john'a geç (§10) |
| Bulgu 0 ama adımlar hata vermiş | `!! N step(s) did NOT complete cleanly` uyarısını oku (§9) |
| `dc_ip` boş / zincir DNS'e düşüyor | UBDEN'in `ad` bloğu adres taşımaz. `--ip` bayrağını elle ver |
| Hesap kilitlendi / müşteri şikayet etti | **DUR** → `touch "$RUN/STOP"`, müşteri BT yetkilisini bilgilendir |

---

## Altın kurallar

1. Kapsam dışına **tek paket** gitmesin — sadece `$SCOPE` dosyasındaki hedefler.
2. Her parola denemesi guard'dan geçsin. Hesap kilitleme işi bitirir.
3. Yazma / dump / coercion ateşleme = açık gerekçe + onay + elle `YETKILIYIM`.
4. Takıldığın an dur, çıktıyı yapıştır. Tahmin etme.
5. Raporda ne **yapmadığını** da yaz. Atlanan kontrol, kapsam dışı kalan host, çalışmayan araç —
   hepsi rapora girer. Sessiz boşluk, yanlış "temiz" demektir.
