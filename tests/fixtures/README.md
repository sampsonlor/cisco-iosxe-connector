# Synthetic fixture policy

Future CLI/NETCONF fixtures belong here and must contain only synthetic data.
Use `router.example.test`, example CA names and RFC documentation addresses.
Record the format/model version being simulated and the expected parse result.

Do not commit real certificates, host keys, transcripts, private keys or lab
output. Generate cryptographic test material in memory. Initial HTTP/DTO
fixtures live directly in the contract test so their limited purpose is clear.
