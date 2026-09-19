# PoE-Passkey
![PoE-Passkey Image](https://github.com/Xorlent/PoE-Passkey/blob/main/images/PoE-Passkey.jpg)  
PoE-Passkey is designed for an M5Stack **Unit-PoE-P4**, a power-over-Ethernet device 
that acts as a **hardware-key gate**. It turns tapping a security key (a YubiKey, Thetis Nano, or 
compatible FIDO2/WebAuthn key) into a short-lived list of authorized IP addresses your firewall 
can use to dynamically allow connections to protected services/resources.

---

## What it does

- **Sign in** - a user taps their key; the device authorizes the IP address they came from.
- **Enroll / revoke** - an administrator (from an approved IP address) registers/revokes keys, 
and manages the authorized-address list.
- **Consume** - a downstream appliance fetches the current list of authorized IP addresses.

Everything runs over **HTTPS on port 443**. Certificates must be P-256 / ES256 for optimal performance 
and memory utilization.

---

## What you need

- The device [M5Stack **Unit-PoE-P4**](https://shop.m5stack.com/products/unit-poe-with-esp32-p4).
- Arduino IDE (or `arduino-cli`) with the `esp32` board package.
- A **TLS certificate and private key** for the device (see below).
- At least one FIDO2 security key to register.
- A computer whose IP address is in the admin list (see `kAdminIPs` in Config.h).

---

## Setup

### 1. Change the settings (`Config.h`)

Everything you customize is at the top of `Config.h`. The important ones:

| Setting | What it is | Default |
|---|---|---|
| `ip` / `gateway` / `subnet` | The device's network address | `192.168.1.25` |
| `dns1` / `dns2` | DNS servers | `9.9.9.9` / `149.112.112.112` |
| `ntpSvr` | Time server (used for "last used" dates) | `192.168.1.5` - change it |
| `kRpId` | Domain name keys are bound to | `passkey.vuln.plc.local` - change it |
| `kOrigin` | Same, with `https://` | `https://passkey.vuln.plc.local` - change it |
| `kAdminIPs` | Computers allowed to enroll / revoke | `192.168.1.5` |
| `kConsumerAllowlist` | Systems allowed to read the address list | `192.168.1.5` |
| `kConsumerSecret` | Secret the consuming system must send | `CHANGE_ME` - change it |
| `kAuthorizedIPTtlMs` | How long an address stays authorized | 10 hours |
| `kSessionTtlMs` | How long a sign-in prompt stays valid | 1 minute |

**Set a real `kConsumerSecret`.** Choose something long and random and treat it like a password.

### 2. Set up the Arduino IDE and flash the device

Set up your programming environment once (skip steps 1 to 3 for later units):

1. Download and install the latest [Arduino IDE](https://www.arduino.cc/en/software) for your system.
2. Open the **Boards Manager**, search for `esp32`, select **"esp32 by Espressif Systems"** (not
   "Arduino ESP32 Boards"), and install version **3.3.11**.
3. No extra libraries are needed - everything the firmware uses ships with the esp32 core.

Then, for each device:

4. In the Arduino IDE, open the `PoE-Passkey` sketch folder.
5. Select **Tools > Board > esp32** and choose **"ESP32P4 Dev Module"**. 
   - Configure board settings according to the [Unit-PoE-P4 Board Configuration](https://github.com/Xorlent/PoE-Passkey/blob/main/images/ESP32P4-Config.jpg)
6. Connect the Unit-PoE-P4 to your computer with its USB cable, then select its **Tools > Port**.
   If unsure which port, unplug the device, note the list, then plug it back in and pick the new entry.

> [!WARNING]
> Do not plug the device into a PoE-powered Ethernet port until after you have finished
> flashing - applying PoE while USB is connected risks damaging your USB port.

7. Edit `Config.h` with the settings you collected in step 1.
8. Select **Sketch > Upload** to flash the device. Wait for the progress to reach 100% and the IDE
   to report `Hard resetting via RTS pin...`.
9. Open **Tools > Serial Monitor** and confirm the device boots without configuration errors. If you
   did not open it right away, reconnect the device to see the startup output.
10. When finished, disconnect the USB cable and connect the device to its PoE network port.

> Note: the sketch folder contains a `partitions.csv` that defines the flash layout this firmware
> needs. It overrides the Arduino IDE's Partition Scheme setting, so leave that setting unchanged.

### 3. Create and import the TLS certificate

The device serves **HTTPS**, so it needs a trusted certificate and a private key. You must generate, 
sign, then import them over the Arduino USB serial console on first boot and when renewing certificates.

The certificate must be ECDSA and list the device's domain name in its **Subject Alternative Name (SAN)**.  
Example, for
`passkey.vuln.plc.local`:

```bash
# One command: ECDSA P-256 key + self-signed certificate with the SAN
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=passkey.vuln.plc.local" \
  -addext "subjectAltName=DNS:passkey.vuln.plc.local"
```

### Production: get the device certificate signed by a CA

A self-signed certificate works for testing, but WebAuthn will not run until the certificate
is trusted. In production it must be signed by a CA your clients already trust (your own PKI,
or a public CA). Make the key and the signing request together, with the SAN already inside:

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout key.pem -out passkey.csr \
  -subj "/CN=passkey.vuln.plc.local" \
  -addext "subjectAltName=DNS:passkey.vuln.plc.local"
```

Check the request carries the domain name (look for `X509v3 Subject Alternative Name`):

```bash
openssl req -in passkey.csr -noout -text
```

Send `passkey.csr` to your CA; they return the signed certificate to import with the key. If
**you** are the CA, sign it and keep the SAN. OpenSSL 3.x copies it with `-copy_extensions`:

```bash
openssl x509 -req -in passkey.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out cert.pem -days 365 -copy_extensions copy
```

`-addext` and `-copy_extensions` need OpenSSL 1.1.1 or newer. On an older build, put the SAN in
a config file and pass it with `-config` when creating the request and `-extfile`/`-extensions`
when signing:

```
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = passkey.vuln.plc.local
[ext]
subjectAltName = DNS:passkey.vuln.plc.local
```

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout key.pem -out passkey.csr -config csr.cnf

openssl x509 -req -in passkey.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out cert.pem -days 365 -extfile csr.cnf -extensions ext
```

**To import:**

1. Open the Arduino IDE Serial Monitor (115200 baud).
2. Boot the device using USB only; ensure no delivered Power-over-Ethernet.
3. Type `import` and press Enter.
4. Paste the certificate PEM (leaf/device cert first, then CA intermediates) and stop. The prompt ends on its
   own once the paste is quiet for half a second.
5. Paste the private key PEM when asked, then press Enter.
6. The device will report success and reboot automatically.

With no certificate/key, the device stops at boot and keeps the console open so you can run
`import`. Check the served chain later with:

```bash
openssl s_client -connect <your-domain>:443 -servername <your-domain> -showcerts
```

### 4. Trust the certificate in the browser

WebAuthn requires a fully-valid origin, so you can't ignore a certificate warning, as sign-in 
will be refused. Install the certificate into the trusted root CA store of every computer that 
will be used to test the device. For production, use an enterprise PKI or have a public
certificate authority sign the certificate request (see the CSR steps above). For a public CA,
inexpensive RapidSSL certificates can be purchased from
[Cheap SSL Security](https://www.cheapsslsecurity.com) for as little as $9/yr.

### 5. First boot, then register keys

1. Boot the device and watch the serial console until it prints `PoE-Passkey ready: https://...`.
2. From a computer in `kAdminIPs`, open `https://<your-domain>/admin`.
3. Use the page to **register** each hardware key (type the identity - usually an e-mail
   address - and tap the key when prompted).

---

## Using PoE-Passkey

### Signing in (authorizing an address)

A user opens `https://<your-domain>/` in a browser and taps their security key. On success,
the IP address they came from is added to the authorized list for the configured TTL. Your 
firewall then periodically retrieves the latest authorized IP list to grant user access.

### The admin console

Open `https://<your-domain>/admin` from an allowed admin IP. From there you can:

- **Register** a new key.
- **Revoke** a key.
- **Disable / re-enable** a key (disabled keys can't sign in until re-enabled).
- **See authorized addresses** and who is behind each one.
- **Revoke an address** immediately.

Only the IPs in `kAdminIPs` can reach these pages. Anyone else is refused, and by default
their address is blocked on the spot (recoverable from the console - see `unblock`).

### The downstream appliance (consumer endpoint)

The system that uses the list fetches it from:

```
https://<your-domain>/authorized-ips?key=<kConsumerSecret>
```

The answer is plain text, one authorized IPv4 address per line:

```
192.168.1.50
192.168.1.51
```

Both conditions must hold: the request must come from an IP in `kConsumerAllowlist`, **and**
the `key` must match `kConsumerSecret`. Poll it on as short an interval as possible so 
authorized addresses are picked up (and expiries are noticed) promptly.

---

## Serial console commands

The device has a simple text console over USB (115200 baud):

| Command | What it does |
|---|---|
| `import` | Import the TLS certificate and private key |
| `status` | Show TLS material and the device clock |
| `stats` | Memory, socket, and gate telemetry (for diagnosing problems) |
| `creds` | List stored keys (identity, last used, disabled?) |
| `blocks` | List blocked IP addresses |
| `unblock <ip>` | Allow one blocked IP again |
| `clear-blocks` | Allow all blocked IPs again |
| `clear-cert` / `clear-key` | Remove the imported TLS material |
| `reboot` | Restart the device |
| `help` | List commands |

---

## Troubleshooting

**The page shows a certificate error.**
The certificate isn't trusted by your device - see "Trust the certificate in the browser". You must 
access the authentication site using its fully qualified domain name (matching the certificate), not 
an IP address.

**Key registration or sign-in fails in the browser.**
Usually due to an untrusted certificate or a name mismatch. WebAuthn checks the browser's origin, and
a certificate/domain mismatch makes the browser refuse the call.

**`import` saved "N PEM block(s)" but the browser still rejects the chain.**
Count how many blocks you expected (a leaf plus one intermediate = 2). Then check what the
device actually serves with `openssl s_client -showcerts`.

**The device stops at boot on the serial console.**
It's waiting for the TLS certificate and key. Run `import` and paste both.

**A legitimate machine was blocked and can't reach the device.**
From the serial console: `unblock <ip>` (or `clear-blocks`). Consider whether `kAdminIPs` or
`kConsumerAllowlist` needs updating.

---

## Notes

- Anyone who taps a **valid registered key** can authorize the address they're on. Keep keys
  physically secure.
- Enrollment is gated only by the admin's **source IP** (`kAdminIPs` in Config.h) - anyone on that trusted
  network can register a key. Keep that network trusted.
- Authorized addresses expire on their own - the TTL (`kAuthorizedIPTtlMs` in Config.h) is your main safety margin.
