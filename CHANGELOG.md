## 0.2.0

- The TSL1 lineage tokens, copied from tstokenlib: `TSL1_LT_FT` and
  `TSL1_LT_NFT` (`LtBuilder`, `LtScriptGen`, `LtReceive`, `LtIdentity`,
  `LtSuccession`, `LtPayload`) and the fuelled family `TSL1_LT_FNFT` with its
  Voucher and Note kinds (`FnftBuilder`, `FnftScriptGen`, `FnftReceive`,
  `FnftSuccession`). With them the script generator helpers, the Rabin
  signatures, and the identity anchor (MAP + AIP) the issuer check verifies.
  Their interpreter suites (`test/lt_ft_test.dart`, `lt_nft_test.dart`,
  `lt_fnft_test.dart`) and the regtest suites (`LT_LOCALNET=1`) come with
  them; the specifications are in `doc/lt/`.
- The rest of the family's tests, helpers and documents: the Listed NFT
  (`TSL1_LT_LNFT`), the Voucher and Note kinds and the sale versions
  (`TSL1_LT_FNFT_S`, `VNFT_S`, `NOTE_S`) with their suites; the swap
  (`LtSwap`, `FnftSwap`) and the instrument math (`NoteMath`, `VoucherMath`);
  the payload suite; the NFT, Listed NFT, Voucher and Note integration
  documents. 199 interpreter tests, 10 regtest tests skipped without
  `LT_LOCALNET=1`.
- The lineage tokens as libspiffy plugins, from `lt-spiffy-plugin`:
  `LtNftPlugin`, `LtLnftPlugin`, `LtFnftPlugin`, `LtVnftPlugin`,
  `LtNotePlugin` and the sale versions (`LtFnftSalePlugin`,
  `LtVnftSalePlugin`, `LtNoteSalePlugin`); the payee's checks
  (`LtNftReceive`, `LtFnftReceive`, `LtVnftReceive`, `LtNoteReceive`);
  `WalletKey`. Their documents are in `doc/spiffy/`, their tests in
  `test/spiffy/` (45, the wallet ones in a real libspiffy wallet with ARC
  stubbed). The tests run one suite at a time (`dart_test.yaml`).

## 0.1.0

- PushDrop scripts (`PushDrop`, lock and unlock builders), byte for byte as
  `@bsv/sdk` writes them.
- `PushDropPlugin`: a libspiffy `TransactionBuilderPlugin` that makes and
  spends PushDrop tokens in wallet-funded transactions.
- `OverlayClient`: BRC-24 lookup and BRC-22 submit, with SLAP/SHIP host
  discovery.
