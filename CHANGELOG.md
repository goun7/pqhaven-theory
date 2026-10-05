# Changelog

## [Unreleased]

### [Fix-2026-10-05] — TamgaProtocol kanıt-anchor mesh köprüsü
- `src/pqhaven/mesh_anchor.py`: `AssessmentReport`'u (CBOM Merkle kökü + PQRI)
  TamgaProtocol hash-zincirlenmiş `ledger.jsonl` kanıt modelinde **bayt-uyumlu**
  kayda dönüştürür (`build_anchor_record`, `verify_chain`, `anchor_report`).
- Zincir kuralı `h = sha256(prev + jcs(rec))`, `seq` 1'den başlar, RFC 8785 (JCS)
  canonicalization — `tamga_runner._verify_chain` / `tamga_verify_mini` ile uyumlu;
  JCS `tamga_canon` ile bayt-parite (testlerle makine-çekilir).
- "Harvest now, decrypt later" tehditine karşı: *neyin ne zaman savunmasız
  olduğu* kanıtının kendisi değiştirilemez hale gelir (geriye-dönük yeniden-yazım
  "zaten PQ-hazırdık" tespit-edilebilir).
- 3 yeni test (`tests/test_mesh_anchor.py`): zincir kurma+doğrulama+append,
  tamga_canon bayt-paritesi, tamper tespiti + kirik-zincire fail-closed koruma.
  Toplam: 57 → **60 test passed**.

## [0.1.0] — 2026-09-30
- İlk genel sürüm: PQHaven-Theory — Post-Quantum Teori Araştırma Varyantı
- Post-quantum (PQC) geçiş teorisini araştıran, kuantum tehditlerini keşfedip kriptografik borçları (crypto debt) ölçen teorik araştırma motoru.

## Sürümleme

- [SemVer](https://semver.org/lang/tr/) uyumludur.
