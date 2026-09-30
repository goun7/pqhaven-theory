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

## Durum ve Lisans

- **Sürüm:** 2.0.0 — teorik araştırma varyantı.
- **Lisans:** Apache-2.0 (bkz. `pyproject.toml`).
- **Detaylı dokümantasyon:** `PQHAVEN.md` (111 KB) ve `MERGEN.md`.
