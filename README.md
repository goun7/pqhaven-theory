# PQHaven-Theory — Post-Quantum Teori Araştırma Varyantı

Post-quantum (PQC) geçiş teorisini araştıran, kuantum tehditlerini keşfedip kriptografik borçları (crypto debt) ölçen teorik araştırma motoru.

## Problem: Bu Teori Ne Araştırır?

Shor algoritması bir CRQC (Cryptographically Relevant Quantum Computer) ile RSA, ECDSA, ECDH ve Diffie-Hellman'ı kırar; Grover ise AES/SHA güvenliğini yarıya indirir. Mosca teoremi (X: veri raf ömrü, Y: geçiş süresi, Z: CRQC geliş zamanı) bu projenin teorik çekirdeğidir: **X + Y > Z** olduğunda veriler "harvest now, decrypt later" riski altındadır.

PQHaven-Theory aşağıdaki teorik soruları araştırır:

- **Keşif (Discovery):** Canlı TLS 1.3 / SSH / QUIC / IKEv2 uç noktaları ve yerel depo, keystore, sertifika ve kaynak kodunda klasik algoritmaların tespiti.
- **CBOM (Cryptographic Bill of Materials):** CycloneDX 1.6 standardında kriptografik envanter çıkarımı.
- **Risk skorlama:** Mosca PQRI (Post-Quantum Risk Index) hesaplama ve CRITICAL / HIGH / TRANSITIONAL / READY derecelendirmesi.
- **Monte Carlo simülasyonu:** Q-Day zamanlaması üzerinde stokastik senaryo üretimi (`pqscan simulate`).
- **Kripto-çeviklik (crypto-agility):** Klasik algoritmalar için NIST önerilen PQC yedekleri (ML-KEM, ML-DSA, hibrit TLS kod noktaları).
- **Onaylama (Attestation):** Değiştirilebilir kimlik bilgisi (Verifiable Credential) formatında kanıt üretimi.

## Hızlı Başlangıç

Gereksinimler: Python ≥ 3.11.

```bash
pip install -e .
pqscan --help              # CLI genel yardım
pqscan scan --demo         # Çevrimdışı referans mimarisi ile demo tarama
pqscan scan -n ornek.gov.tr:443 --output-cbom cbom.json
pqscan simulate            # Monte Carlo Q-Day simülasyonu
pqscan attest              # Kanıt (attestation) üretimi
pqscan serve --port 8080   # Yönetici kokpiti (HTML rapor)
```

Alternatif olarak Docker: `docker compose up` (bkz. `docker-compose.yml`).

Ana modüller (`src/pqhaven/`): `engine.py` (Mosca + Monte Carlo), `scanner.py` (yerel keşif), `network.py` (canlı uç nokta problama), `models.py` (Pydantic modelleri), `remediator.py` (düzeltme önerileri), `daemon.py` (sürekli izleme), `cockpit.py` (HTML rapor), `cli.py` (`pqscan`).

## Test Durumu

**57 test passed** (pytest, `tests/` altında 5 dosya: core, scanner, network+cockpit, cli, autonomous).

```bash
python3 -m pytest -p no:cacheprovider --tb=no -q
```

Sonuç: `57 passed` — temel modeller, Mosca denklemleri, motor, tarayıcı, ağ probları ve CLI komutları kapsanıyor.

## İlişki

Bu proje, **`pqhaven/25-pqhaven-x402`** (75 puan) projesinin **teorik kardeşidir** (theoretical sibling). x402 varyantı üretim/ödeme (x402 protokolü) entegrasyonuna odaklanırken; `pqhaven-theory` varyantı post-quantum teorisini, Mosca risk modelini ve Monte Carlo simülasyonunu araştırma odağı olarak alır. Her iki proje aynı `pqhaven` çekirdeğini paylaşır.

## Akademik & teknik temel

- **Mosca's quantum risk model** — "when will a quantum computer be
  able to break RSA/ECC, and how long must my data stay secret?"
  PQHaven bu modelin parametrelerini (harvest-now-decrypt-later
  penceresi) kullanarak önceliklendirme yapar.
- **NIST PQC standardization** — ML-KEM (Kyber) ve ML-DSA (Dilithium)
  NIST FIPS 203/204 standartları; PQHaven bu algoritmaların
  keşfini ve CBOM çıktısını üretir.
- **CBOM (Cryptographic Bill of Materials)** — CycloneDX tabanlı
  kriptografik envanter: bir sistemin nerede hangi algoritmayı
  kullandığını belgeleyen makine-okunur çıktı.
- **Monte Carlo simülasyonu** — geçiş zamanlaması belirsizliğini
  modellemek için: quantum kapasite tahminini olasılıksal bir
  dağılım olarak alır, "kriptografik borç" skoru üretir.
- **x402 ile bağlantı** — [25-pqhaven-x402](../../02_sahis/25-pqhaven-x402)
  üretim varyantı, x402 ödemelerinde **quantum-safe imzaları** kullanır
  (agent kimlikleri uzun süreli geçerli olmalı — harvest-now-decrypt-later
  ödeme geçmişini de tehdit eder).

## Akademik Kaynaklar (2024-2026)

Bu çalışma aşağıdaki araştırmaya dayanır (tüm bağlantılar canlı olarak
doğrulanmıştır — `https://arxiv.org/abs/...` → HTTP 200):

- [1] **Quantum-Safe Hybrid Key Exchanges with KEM-Based Authentication** —
  Battarbee, Striecks, Perret, Ramacher, Verhaeghe, arXiv (cs.CR) 2024.
  [arXiv:2411.04030](https://arxiv.org/abs/2411.04030)
  *Hibrit PQ TLS:* KEM tabanlı kimlik doğrulamalı hibrit anahtar değişimi —
  PQHaven'in hibrit TLS kod noktası önerilerinin temeli.
- [2] **Classifying Implementations of Cryptographic Primitives and Protocols
  that Use Post-Quantum Algorithms** — Mallick, Nita-Rotaru, Kundu, Kompella,
  arXiv (cs.CR) 2025.
  [arXiv:2503.17830](https://arxiv.org/abs/2503.17830)
  *Keşif:* kriptografik ilkel/protokol uygulamalarının sınıflandırılması —
  `scanner.py` ile elde edilen envanterin yorumlanmasını destekler.
- [3] **Post-Quantum Cryptography and Quantum-Safe Security: A Comprehensive
  Survey** — Chhetri, Somvanshi, Hebli, Brotee, Das, arXiv (cs.CR) 2025.
  [arXiv:2510.10436](https://arxiv.org/abs/2510.10436)
  *Arka plan:* NIST PQC standardizasyonu (ML-KEM/ML-DSA) ve RSA/ECC üzerindeki
  kuantum tehdidi (Shor/Grover) için genel çerçeve.
- [4] **Quantifying quantum risk: a measure of crypto agility** —
  Wilson-Shah, arXiv (cs.CR) 2026.
  [arXiv:2606.17116](https://arxiv.org/abs/2606.17116)
  *Risk skorlama:* kuantum riskinin ölçülmesi ve kripto-çeviklik metriği —
  Mosca PQRI ve CRITICAL/HIGH/TRANSITIONAL/READY derecelendirmesi ile paralel.
- [5] **Post-Quantum Discovery as a Governance Capability: Evidence-Based
  Cryptographic Visibility and Exposure Prioritisation in a Critical Service
  Provider** — Zelenovic, Taghizadeh, Pena-Gonzalez, Gomez Garcia, Preneel,
  arXiv (cs.CR) 2026.
  [arXiv:2605.16549](https://arxiv.org/abs/2605.16549)
  *CBOM:* kanıt temelli kriptografik görünürlük ve maruziyet önceliklendirmesi
  — CycloneDX 1.6 CBOM çıktısının yönetişim gerekçesi.
- [6] **Measurement Study of Post-Quantum Readiness of Internet: 2026** —
  Dubey, Varshney, arXiv (cs.CR) 2026.
  [arXiv:2606.16473](https://arxiv.org/abs/2606.16473)
  *Ağ probu:* internet çapında PQ hazırlık ölçüm yöntemleri —
  `network.py` ile canlı TLS 1.3/SSH/QUIC/IKEv2 problamasını yönlendirir.
- [7] **Signature Placement in Post-Quantum TLS Certificate Hierarchies: An
  Experimental Study of ML-DSA and SLH-DSA in TLS 1.3 Authentication** —
  Delgado Jiménez, arXiv (cs.CR) 2026.
  [arXiv:2604.06100](https://arxiv.org/abs/2604.06100)
  *NIST PQC:* ML-DSA ve SLH-DSA imzalarının TLS 1.3 sertifika hiyerarşisinde
  konumlandırılması — `remediator.py` düzeltme önerileri için deneysel veri.
- [8] **Transcript-Bound Combiners for Downgrade-Resilient Hybrid Post-Quantum
  Key Establishment: Definition, Proof, and Embedded-Device Cost** —
  Gupta, Rana, arXiv (cs.CR) 2026.
  [arXiv:2609.21273](https://arxiv.org/abs/2609.21273)
  *Hibrit PQ TLS:* downgrade saldırılarına dayanıklı hibrit birleştiriciler —
  geçiş döneminde klasik+PQ hibrit kullanımının güvenlik gerekçesi.

## Durum ve Lisans

- **Sürüm:** 2.0.0 — teorik araştırma varyantı.
- **Lisans:** Apache-2.0 (bkz. `pyproject.toml`).
- **Detaylı dokümantasyon:** `PQHAVEN.md` (111 KB) ve `MERGEN.md`.
