# strongswan-pqc-lab

A research lab for testing **fully post-quantum IPsec** using the experimental `ml-dsa` branch of strongSwan on Ubuntu 26.04 LTS.

This repo documents what I actually did to get ML-KEM (key exchange) and ML-DSA (authentication) working together in an IKEv2 tunnel — including the bugs I hit along the way.

---

## What's running

```
[vm1] 10.0.2.5  ←—— IKEv2/ESP ——→  [vm2] 10.0.2.6

IKE Key Exchange : ML-KEM-768   (FIPS 203)
IKE Auth         : ML-DSA-65    (FIPS 204)
Encryption       : AES-GCM-256  (FIPS 197)
```

No RSA. No ECDSA. No classical asymmetric crypto anywhere in the handshake.

---

## Why this matters

The "store now, decrypt later" attack is the reason ML-KEM should be deployed **today** — an adversary can record your encrypted traffic now and decrypt it once a quantum computer is available. That threat is real for anything with long-term confidentiality requirements.

ML-DSA authentication is less urgent (breaking it requires a quantum computer *at the time of the connection*), but getting the full stack working in a lab environment is the first step toward understanding the deployment challenges.

---

## Requirements

- Ubuntu 26.04 LTS (tested) or 24.04
- `libbotan-3-dev` ≥ 3.6 — for ML-KEM support
- strongSwan `ml-dsa` branch — [github.com/strongswan/strongswan/tree/ml-dsa](https://github.com/strongswan/strongswan/tree/ml-dsa)

> **Note:** This uses an experimental branch implementing `draft-ietf-ipsecme-ikev2-pqc-auth`, which is not yet finalized. Don't use this in production.

---

## Build

```bash
sudo apt install -y \
    build-essential pkg-config autoconf automake libtool \
    gettext git ca-certificates gperf flex bison \
    libgmp-dev libssl-dev libcurl4-openssl-dev \
    libsystemd-dev systemd-dev libbotan-3-dev \
    libsqlite3-dev iptables iproute2

git clone https://github.com/strongswan/strongswan.git
cd strongswan
git checkout ml-dsa

./autogen.sh

./configure \
    --prefix=/usr \
    --sysconfdir=/etc \
    --localstatedir=/var \
    --runstatedir=/run \
    --with-systemdsystemunitdir=/lib/systemd/system \
    --disable-charon \
    --enable-systemd \
    --enable-charon-systemd \
    --enable-swanctl \
    --enable-vici \
    --enable-botan \
    --enable-ml \
    --disable-openssl \
    --enable-pem --enable-pkcs1 --enable-pkcs8 --enable-pkcs12 \
    --enable-x509 --enable-pubkey --enable-constraints --enable-revocation \
    --enable-pki --enable-curl \
    --enable-eap-identity --enable-eap-md5 --enable-eap-mschapv2 \
    --enable-kernel-netlink --enable-socket-default --enable-counters

make -j$(nproc)
sudo make install
```

### Why `--disable-openssl`?

The OpenSSL plugin has probably a bug with ML-DSA private keys — `belongs_to()` fails because `EVP_PKEY_get_octet_string_param` doesn't expose the public key component for ML-DSA types in OpenSSL 3.5.x. This causes `CA private key does not match CA certificate` when trying to issue certificates, even when the key and cert are correct.

The fix is to build without the OpenSSL plugin and use the `ml` plugin instead — a pure-C reference implementation of ML-DSA written by Andreas Steffen. The `botan` plugin handles ML-KEM.

---

## Generate certificates

> **Important:** Run all of this as a single block. If you interrupt and re-run only `pki --gen`, the CA key and cert get out of sync and you'll hit `CA private key does not match CA certificate`. This cost me more debugging time than I'd like to admit.

```bash
mkdir -p ~/pqc-ca && cd ~/pqc-ca

pki --gen --type mldsa65 --outform pem > strongswanKey.pem && \
pki --self --ca --lifetime 3652 \
    --in strongswanKey.pem \
    --dn "C=GR, O=PQC-Lab, CN=PQC Lab Root CA" \
    --outform pem > strongswanCert.pem && \
\
pki --gen --type mldsa65 --outform pem > vm1Key.pem && \
pki --req --type priv --in vm1Key.pem \
    --dn "C=GR, O=PQC-Lab, CN=vm1" --san vm1 \
    --outform pem > vm1Req.pem && \
pki --issue \
    --cacert strongswanCert.pem --cakey strongswanKey.pem \
    --type pkcs10 --in vm1Req.pem \
    --serial 01 --lifetime 730 --flag serverAuth \
    --outform pem > vm1Cert.pem && \
\
pki --gen --type mldsa65 --outform pem > vm2Key.pem && \
pki --req --type priv --in vm2Key.pem \
    --dn "C=GR, O=PQC-Lab, CN=vm2" --san vm2 \
    --outform pem > vm2Req.pem && \
pki --issue \
    --cacert strongswanCert.pem --cakey strongswanKey.pem \
    --type pkcs10 --in vm2Req.pem \
    --serial 02 --lifetime 730 --flag serverAuth \
    --outform pem > vm2Cert.pem && \
\
echo "Done." && \
pki --print --in vm1Cert.pem | grep -E "pubkey|subject" && \
pki --print --in vm2Cert.pem | grep -E "pubkey|subject"
```

Expected output:
```
  subject:  "C=GR, O=PQC-Lab, CN=vm1"
  pubkey:    ML_DSA_65 15616 bits
  subject:  "C=GR, O=PQC-Lab, CN=vm2"
  pubkey:    ML_DSA_65 15616 bits
```

---

## Configuration

See [`configs/swanctl_vm1.conf`](configs/swanctl_vm1.conf) and [`configs/swanctl_vm2.conf`](configs/swanctl_vm2.conf).

Copy to `/etc/swanctl/swanctl.conf` on each VM, then:

```bash
sudo systemctl enable --now strongswan
sudo swanctl --load-creds
sudo swanctl --load-conns
sudo swanctl --initiate --child host-host   # from vm1
```

---

## Verification

```bash
sudo swanctl --list-sas
```

```
vm1-vm2: #1, ESTABLISHED, IKEv2
  AES_GCM_16-256/PRF_HMAC_SHA2_384/ML_KEM_768
  host-host: #2, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
```

ML-DSA doesn't show up in `--list-sas` — it's used during the handshake, not stored in the SA. Check the logs:

```bash
sudo journalctl -u strongswan | grep authentication
```

```
authentication of 'vm1' with ML_DSA_65 successful
authentication of 'vm2' with ML_DSA_65 successful
```

Run the verification script for a full report:

```bash
sudo python3 pqc_verify.py
# generates pqc_report_<hostname>.html
```

---

## One thing I didn't expect

The `IKE_AUTH` exchange fragmented into **8 UDP packets**. With classical ECDSA-256 you get a ~72 byte signature and the whole auth fits in one packet. ML-DSA-65 signatures are 3,309 bytes — so IKEv2 fragmentation kicks in automatically. You can see this clearly in Wireshark or in the logs:

```
parsed IKE_AUTH request 1 [ EF(1/8) ]
parsed IKE_AUTH request 1 [ EF(2/8) ]
...
parsed IKE_AUTH request 1 [ EF(8/8) ]
```

This is expected and handled correctly by strongSwan, but it's worth keeping in mind for latency-sensitive deployments.

---

## Known issues

| Issue | Status |
|---|---|
| OpenSSL plugin `belongs_to()` bug with ML-DSA keys | Workaround: `--disable-openssl` |
| `draft-ietf-ipsecme-ikev2-pqc-auth` not finalized | Interop only between same commit |
| `pki --print` has no `--outform` flag | Don't redirect its output to a .pem file |

---

## References

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA
- [RFC 9370](https://www.rfc-editor.org/rfc/rfc9370) — Multiple Key Exchanges in IKEv2
- [RFC 9242](https://www.rfc-editor.org/rfc/rfc9242) — IKE_INTERMEDIATE Exchange
- [draft-ietf-ipsecme-ikev2-pqc-auth](https://datatracker.ietf.org/doc/draft-ietf-ipsecme-ikev2-pqc-auth/) — IKEv2 PQC Authentication
- strongSwan `ml-dsa` branch — commit `cb03d65`
