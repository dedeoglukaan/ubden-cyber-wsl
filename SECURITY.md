# Güvenlik Politikası

## Açık bildirimi

UBDEN'de bir güvenlik açığı bulduysanız **herkese açık issue açmayın.**
Doğrudan **admin@ubden.com** adresine yazın.

Bildirimde şunlar olsun:

- Etkilenen sürüm (`git describe --tags` veya rapor klasöründeki `tool_version`)
- Ne olduğu ve neden bir güvenlik sorunu olduğu
- Adım adım tekrar üretimi
- Sizce etkisi

Bildiriminizi **3 iş günü** içinde aldığımızı teyit ederiz. Düzeltme süresi ciddiyete göre
değişir; süreç boyunca durumu size iletiriz. Düzeltme yayınlanana kadar ayrıntıyı
paylaşmamanızı rica ederiz.

İsterseniz düzeltmenin sürüm notunda adınıza yer veririz.

## Desteklenen sürümler

Yalnızca **en son `v5.0.0-wsl.*` etiketi** desteklenir. Düzeltmeler yeni bir etiketle çıkar;
eski etiketlere geri taşınmaz.

## Kapsam

UBDEN bir **sızma testi aracıdır**; işi güvenlik açığı aramaktır. Bu nedenle şunlar bu
politikanın kapsamı **dışındadır**:

- Aracın hedef sistemlerde açık bulması, port taraması yapması veya kimlik denemesi yapması —
  bunlar amaçlanan davranıştır
- Aracın yetkisiz bir sistemde çalıştırılması. Yetkilendirme kullanıcının sorumluluğundadır
- `offensive-ext/` altındaki saldırı modüllerinin saldırı gerçekleştirmesi

Kapsam **içinde** olanlar, aracın kendisinin veya onu çalıştıran makinenin güvenliğini
etkileyen her şey — örneğin:

- Kimlik bilgilerinin, hash'lerin veya kanıt dosyalarının diske güvensiz yazılması
- Rapor veya kanıt dosyaları üzerinden komut/kod çalıştırma
- Yetki yükseltme, kurulum betiklerindeki güvensiz dosya izinleri
- Kullanıcının verdiği kapsam dışına çıkan bir kod yolu

## Yetkili kullanım

UBDEN yalnızca **yazılı yetki verilmiş** sistemlerde çalıştırılır. Yetkisiz kullanım
kullanıcının kendi sorumluluğundadır ve birçok ülkede suçtur.
