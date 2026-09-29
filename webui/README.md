# UBDEN® Pentest WebUI

Bu klasörü `engagement.json`, `REPORT.html`, `targets` ve diğer rapor dosyalarıyla **aynı rapor kökünün içine** kopyalayın. Ardından Windows'ta `webui/start.cmd` dosyasını açın. Panel, `webui` klasörünün üst dizinindeki raporu otomatik bulur ve yalnız `127.0.0.1` üzerinde çalışır. Klasör rapor içermiyorsa “Lütfen Pentest Raporu seçin” ekranı açılır.

## Gereksinimler

- Python 3 (`python` veya `py -3` komutu)
- PDF yayınlamak için Microsoft Edge veya Google Chrome
- Ağ bağlantısı ya da ek Python paketi gerekmez

`index.html` dosyasını doğrudan `file://` üzerinden açmayın: tarayıcı üst dizindeki rapor verilerini bu biçimde otomatik okuyamaz. Başlatıcıyı açınca görünen konsolu panel açık olduğu sürece kapatmayın.

## İnceleme ve yayınlama

Gözlem ve görev düzenlemeleri, rapor kökündeki `.webui/review.json` dosyasında tutulur. Bu dosya taslaktır; mevcut PDF ve HTML çıktıları **Yayınla** düğmesine basılıncaya kadar değişmez. “Doğrulandı” için analist adı, not ve rapor içinde mevcut en az bir kanıt yolu gerekir. “Giderildi” için ayrıca yeniden test kanıtı gerekir.

Yayınlama `REPORT.html`, üç PDF, `ANALIST_GOREV_RAPORU.json/.md`, `REMEDIATION_ROADMAP.md`, `WEBUI_PUBLISHED_REVIEW.json` ve `SHA256SUMS.txt` dosyalarını birlikte yeniler. Önceki dosyalar `.webui/backups/` altında saklanır. PDF'ler eski sayfa düzenini birebir kopyalamaz; aynı bilgileri yeni Ubden düzeninde sunar. PDF içindeki kanıt yolları metin olarak rapor köküne göre yazılır. Tıklanabilir yerel bağlantılar rapor başka bilgisayara taşınırsa eski konuma işaret edebilir; dosya gezginindeki göreli yollar taşınabilir kalır.

Ham tarama dosyaları, `AI_FINDINGS.json`, `AI_OPERATOR.json`, CVE aday kaydı ve korelasyon kaynakları yayınlama sırasında değiştirilmez. Yeni inceleme kayıtları analist tarafından girilmiş metindir; kullanıcı kimliği kriptografik olarak doğrulanmaz. Panel internet servisine veri göndermez. Marka bağlantıları yalnız kullanıcı tıkladığında açılır.

## Veri anlamı

- `REPORT.html` içindeki `section.finding` kayıtları otomatik gözlemlerin ayrıntı kaynağıdır. Gözlem ID'leri (`OBS-...`) ile eşlenir.
- `DEVICE_INVENTORY.json` cihaz ve port görünürlüğünü, `ASSESSMENT_COVERAGE.json` yürütme kapsamını, `steps.json` adım günlüğünü sağlar.
- `UBDEN_CVE.json` kayıtları adaydır; görülen sürüm, CVE uygulanabilirliğini kanıtlamaz.
- `UBDEN_CORRELATION.json` grafiği kural kaynaklı maruziyet ilişkilerini gösterir; fiziksel topoloji veya başarılı saldırı değildir.
- OSINT verisi kullanılamıyorsa görünen kaynak skoru panelde ölçülmüş güvenlik sonucu olarak sunulmaz.

Test için `python -m unittest discover -s webui -p 'test_*.py'` çalıştırılabilir.
