# Burp Scanner

Burp Scanner, Burp Suite HTTP History XML dışa aktarımlarını tamamen yerel ortamda analiz eden güvenlik odaklı bir komut satırı aracıdır. Trafiği önce deterministik kurallarla inceler, tekrar eden endpointleri gruplar, hassas verileri maskeler ve yalnızca seçilmiş temsilci kayıtları yerel bir dil modeline gönderir.

Varsayılan profil WSL2 içinde OpenVINO kullanır ve Intel Arc GPU üzerinde çalışır. Bulut API anahtarı gerekmez; HTTP istekleri, yanıtları, cookie değerleri ve tokenlar üçüncü taraf bir modele gönderilmez.

Bu araç yalnızca test etme yetkiniz bulunan sistemlerde kullanılmalıdır.

## Temel özellikler

- Burp Suite HTTP History XML kayıtlarını akış halinde okur.
- Base64 kodlanmış request ve response alanlarını çözer.
- Büyük XML dosyalarını bütünüyle belleğe almadan işler.
- DTD ve entity içeren güvensiz XML belgelerini reddeder.
- Mesaj ve toplam kayıt sınırlarıyla kaynak tüketimini kontrol eder.
- Authorization, cookie, token, API anahtarı, parola, JWT ve e-posta değerlerini model analizinden önce maskeler.
- Yalnızca açıkça izin verilen hostları analiz edebilir.
- Dinamik ID, UUID ve uzun hex değerleri içeren benzer endpointleri gruplar.
- Cookie bayrakları, CORS, teknoloji ifşası, eksik güvenlik başlıkları, stack trace ve olası sır ifşası için deterministik kontroller çalıştırır.
- Seçilmiş HTTP kayıtlarını yerel OpenVINO, Ollama veya OpenAI uyumlu bir sunucuyla analiz eder.
- Markdown ve makine tarafından işlenebilir JSON raporları üretir.
- Model, sağlayıcı, cihaz, analiz süresi, güven seviyesi, CWE ve request ID bilgilerini rapora ekler.
- Model bulgularını kesin zafiyet yerine manuel doğrulama gerektiren aday bulgu olarak işaretler.

## Çalışma akışı

```text
Burp XML
  -> Güvenli ve akış tabanlı ayrıştırma
  -> Base64 çözme ve HTTP mesajlarını ayırma
  -> Host kapsamı kontrolü
  -> Deterministik güvenlik kuralları
  -> Hassas veri maskeleme
  -> Benzer endpointleri gruplama
  -> Yerel model analizi
  -> Bulgu birleştirme
  -> Markdown ve JSON raporları
```

## Otonomluk sınırı

Araç, XML dosyasının verilmesinden raporların oluşturulmasına kadar müdahalesiz çalışır. Aşağıdaki işlemleri yapmaz:

- Burp Suite oturumundan trafiği canlı olarak çekmez.
- Hedefe yeni HTTP istekleri göndermez.
- Exploit veya aktif saldırı gerçekleştirmez.
- IDOR ve iş mantığı gibi çok adımlı bulguları kesin olarak doğrulamaz.
- Model çıktısını insan doğrulaması olmadan kesin zafiyet kabul etmez.

Bu sınırlar, aracı pasif ve denetlenebilir bir trafik analiz katmanı olarak tutar.

## Gereksinimler

Varsayılan Intel GPU profili için:

- Windows 11 ve WSL2
- Ubuntu WSL dağıtımı
- Python 3.12
- `uv` paket ve ortam yöneticisi
- WSL içinde OpenVINO tarafından görülebilen Intel GPU
- En az 16 GB sistem belleği
- OpenVINO biçiminde Qwen2.5 7B Instruct INT4 modeli

CPU, Ollama, llama.cpp, LM Studio veya vLLM kullanımı için Intel GPU zorunlu değildir.

## Kurulum

Depoyu WSL içinde klonlayın:

```bash
mkdir -p /home/ardam/projects
cd /home/ardam/projects
git clone https://github.com/mecik-arda/burp-scanner.git
cd burp-scanner
```

`uv` kurulu değilse kurun:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Python ortamını oluşturun ve OpenVINO profilini kurun:

```bash
~/.local/bin/uv python install 3.12
~/.local/bin/uv venv --python 3.12 .venv
~/.local/bin/uv pip install --python .venv/bin/python -e '.[openvino]'
source .venv/bin/activate
```

Modeli indirin:

```bash
mkdir -p models/Qwen-2.5-7B-Instruct-INT4
~/.local/bin/uvx --from huggingface-hub hf download OpenVINO/Qwen2.5-7B-Instruct-int4-ov --local-dir models/Qwen-2.5-7B-Instruct-INT4
```

Model dosyaları büyük olduğu için Git deposuna eklenmez.

## Intel GPU doğrulaması

OpenVINO cihazlarını ve Intel GPU yeteneklerini görüntüleyin:

```bash
.venv/bin/python scripts/gpu-info.py
```

Beklenen çıktıda `CPU`, `GPU`, Intel cihaz adı, FP16, INT8 ve `GPU_HW_MATMUL` yetenekleri bulunmalıdır.

Varsayılan komutta sağlayıcı `openvino`, cihaz `GPU` ve model yolu `models/Qwen-2.5-7B-Instruct-INT4` olarak seçilir. OpenVINO GPU kullanılamıyorsa işlem sessizce CPU'ya düşmez; açık bir hata üretir.

## Burp Suite dışa aktarımı

1. Burp Suite içinde `Proxy` ve ardından `HTTP history` bölümünü açın.
2. Analiz edilecek ve test yetkiniz kapsamında bulunan kayıtları seçin.
3. Sağ tıklayıp `Save items` seçeneğini kullanın.
4. Request ve response alanlarını Base64 kodlama seçeneğini etkinleştirin.
5. Dosyayı XML biçiminde kaydedin.

Base64 kullanılması, ikili yanıtların ve özel karakterlerin XML yapısını bozmasını önler.

## Hızlı kullanım

Sanal ortamı etkinleştirin:

```bash
cd /home/ardam/projects/burp-scanner
source .venv/bin/activate
```

Windows İndirilenler klasöründeki bir Burp XML dosyasını analiz edin:

```bash
burp-reader \
  --file /mnt/c/Users/ardam/Downloads/history.xml \
  --allowed-host example.com \
  --output reports/example-report.md
```

Üretilen dosyalar:

```text
reports/example-report.md
reports/example-report.json
```

JSON dosya yolu ayrıca belirtilmezse Markdown çıktısının dosya adı kullanılarak otomatik oluşturulur.

## Birden fazla host

Her yetkili hostu ayrı parametre olarak verin:

```bash
burp-reader \
  --file history.xml \
  --allowed-host example.com \
  --allowed-host api.example.com \
  --allowed-host auth.example.com \
  --output reports/full-scope.md
```

`--allowed-host` verilmezse XML içindeki bütün hostlar işlenir. Gerçek testlerde açık kapsam kullanılması önerilir.

## Yalnızca deterministik tarama

Modeli yüklemeden hızlı kontrol çalıştırın:

```bash
burp-reader \
  --file history.xml \
  --allowed-host example.com \
  --rules-only \
  --output reports/rules-only.md
```

Bu profil cookie, CORS, güvenlik başlıkları, stack trace ve bilgi ifşası kontrollerini çalıştırır.

## OpenVINO GPU profilini açıkça seçme

```bash
burp-reader \
  --file history.xml \
  --provider openvino \
  --device GPU \
  --model models/Qwen-2.5-7B-Instruct-INT4 \
  --allowed-host example.com
```

## Ollama kullanımı

Ollama servisini yerel makinede başlatın ve bir model indirin:

```bash
ollama serve
ollama pull qwen3.5:9b
```

Ardından sağlayıcıyı seçin:

```bash
burp-reader \
  --file history.xml \
  --provider ollama \
  --endpoint http://127.0.0.1:11434 \
  --model qwen3.5:9b \
  --allowed-host example.com
```

HTTP tabanlı sağlayıcılarda varsayılan olarak yalnızca loopback adreslerine izin verilir.

## OpenAI uyumlu yerel sunucular

llama.cpp, LM Studio veya vLLM gibi OpenAI uyumlu bir yerel sunucu kullanılabilir:

```bash
burp-reader \
  --file history.xml \
  --provider openai \
  --endpoint http://127.0.0.1:1234 \
  --model local-model \
  --allowed-host example.com
```

Uzak bir model endpointi ancak `--allow-remote-model` açıkça verildiğinde kabul edilir. Bu seçenek kullanıldığında maskelenmiş olsa bile HTTP trafiğinin başka bir sisteme aktarılacağı dikkate alınmalıdır.

## Büyük trafik dosyaları

```bash
burp-reader \
  --file history.xml \
  --allowed-host example.com \
  --max-items 100000 \
  --max-groups 500 \
  --max-message-bytes 1000000 \
  --timeout 300 \
  --output reports/large-scan.md
```

Önemli sınırlar:

- `--max-items`: XML içinden kabul edilecek en fazla kayıt sayısıdır.
- `--max-groups`: Yerel modele gönderilecek en fazla benzersiz endpoint grubudur.
- `--max-message-bytes`: Tek request veya response için tutulacak en fazla bayt miktarıdır.
- `--timeout`: HTTP tabanlı yerel model çağrılarının saniye cinsinden zaman aşımıdır.

## Ortam değişkenleri

Desteklenen değişkenler:

- `BURP_READER_PROVIDER`
- `BURP_READER_MODEL`
- `BURP_READER_OPENVINO_DEVICE`
- `BURP_READER_OPENVINO_CACHE`
- `BURP_READER_LLM_ENDPOINT`

Örnek değerler `.env.example` dosyasında bulunur. Araç `.env` dosyasını otomatik yüklemez. Değerleri mevcut kabuğa aktarmak için:

```bash
set -a
source .env
set +a
```

## Rapor yapısı

Markdown ve JSON raporlarında şu bilgiler bulunur:

- Toplam ve kapsam içindeki HTTP kayıt sayıları
- Yerel model tarafından analiz edilen grup sayısı
- Sağlayıcı, model, cihaz ve toplam süre
- Bulgunun kaynağı
- Önem ve güven seviyesi
- Etkilenen Burp request ID değerleri
- Maskelenmiş kanıt
- Düzeltme önerisi
- Uygunsa CWE numarası
- Analiz sırasında oluşan model hataları

Model tarafından üretilen bulgular adaydır. Özellikle IDOR, yetkilendirme, yarış durumu ve iş mantığı bulguları manuel olarak yeniden üretilmelidir.

## Güvenlik modeli

- XML içinde DTD ve entity bildirimleri kabul edilmez.
- Trafik verisi varsayılan OpenVINO profilinde aynı süreç içinde kalır.
- Authorization ve cookie header değerleri modele aktarılmaz.
- Set-Cookie değeri maskelenirken güvenlik bayrakları korunur.
- Yaygın sır anahtarları, Bearer değerleri, JWT ve e-posta adresleri maskelenir.
- Model girdisindeki HTTP içeriği güvenilmeyen veri olarak sınırlandırılır.
- Prompt injection içeren HTTP gövdelerinin model talimatlarını değiştirmesine izin verilmez.
- Raporlar tespit edilen sır değerlerini doğrudan kopyalamaz.
- Model sunucusu uzaksa kullanıcıdan açık izin bayrağı istenir.

## Testler

Birim ve entegrasyon testlerini çalıştırın:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Sentetik Burp kaydıyla uçtan uca GPU analizi çalıştırın:

```bash
burp-reader \
  --file samples/synthetic-history.xml \
  --allowed-host demo.local \
  --output reports/synthetic-report.md
```

Sentetik örnekte sahte parola, token, cookie ve e-posta değerleri bulunur. Test, bu değerlerin model girdisi ve raporlarda maskelenmesini doğrulamak için kullanılabilir.

## Proje yapısı

```text
src/burp_reader/cli.py             Komut satırı arayüzü
src/burp_reader/xml_reader.py      Güvenli ve akış tabanlı Burp XML okuyucu
src/burp_reader/http_message.py    Base64 ve HTTP mesaj ayrıştırma
src/burp_reader/redaction.py       Hassas veri maskeleme
src/burp_reader/rules.py           Deterministik güvenlik kontrolleri
src/burp_reader/grouping.py        Endpoint normalizasyonu ve gruplama
src/burp_reader/local_llm.py       OpenVINO, Ollama ve OpenAI uyumlu sağlayıcılar
src/burp_reader/pipeline.py        Analiz iş akışı
src/burp_reader/reporting.py       Markdown ve JSON raporlama
scripts/gpu-info.py                OpenVINO GPU tanılama
samples/synthetic-history.xml      Güvenli uçtan uca test verisi
tests/                             Birim ve entegrasyon testleri
```

## Sorun giderme

GPU listede görünmüyorsa:

```bash
wsl --update
.venv/bin/python scripts/gpu-info.py
```

Model yolu bulunamıyorsa model indirme komutunu tekrar çalıştırın veya `--model` ile doğru dizini verin.

OpenVINO derleme cache'ini sıfırlamak gerekirse `.openvino_cache` dizinini kaldırıp analizi yeniden çalıştırın. İlk model yüklemesi sonraki çalıştırmalardan daha uzun sürebilir.

Ollama bağlantısı başarısızsa servisin yalnızca yerel adreste çalıştığını doğrulayın:

```bash
curl http://127.0.0.1:11434/api/tags
```

## Gizlilik ve yetkilendirme

Burp kayıtları oturum cookie'leri, erişim tokenları, kişisel veriler ve özel uygulama yanıtları içerebilir. Gerçek trafik XML dosyaları, raporlar, model dosyaları ve yerel cache dizinleri `.gitignore` kapsamındadır. Bu dosyalar GitHub deposuna eklenmemelidir.

Aracı yalnızca yazılı veya açık test yetkinizin bulunduğu hedeflerde kullanın.

## Lisans

Bu proje [MIT Lisansı](LICENSE) altında yayımlanır. Lisans, yazılımın kullanımına, değiştirilmesine, dağıtılmasına ve ticari olarak değerlendirilmesine izin verir; yazılım herhangi bir garanti olmadan sunulur.
