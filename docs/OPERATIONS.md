# Operations

Use `nftfw status`, `nftfw health`, and `nftfw audit` for routine observation.
`nftfw plan` compiles desired plus active claims without mutation. `nftfw
explain` uses the same policy model as the compiler.

Safe changes:

```bash
sudo nftfw config validate
sudo nftfw plan
sudo nftfw apply --safe
sudo nftfw status
sudo nftfw commit <generation>
```

Claims are independent records:

```bash
sudo nftfw block add 203.0.113.20/32 manual scanner
sudo nftfw blocks list
sudo nftfw block remove <claim-id>
```

Removing one claim does not remove another source's claim for the address.
