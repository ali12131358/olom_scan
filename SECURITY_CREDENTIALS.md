# Credential security setup

## 1. Install dependencies
```bash
python -m pip install -r backend/requirements.txt
```

## 2. Configure secrets outside Git
Copy `.env.example` to a local `.env` and set:
- `NETSCAN_CREDENTIALS_KEY`: a newly generated Fernet key.
- `NETSCAN_ADMIN_USER` and `NETSCAN_ADMIN_PASSWORD`: a unique administrator account and strong password.

Generate a Fernet key:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Do not commit the generated key. In production, inject these values through the service manager/container secret store rather than relying on a committed file.

## 3. Important compatibility note
The credential crypto helper in `backend/credential_crypto.py` provides Fernet encryption/decryption for profile secret fields. Integrate it with the VPN profile load/save paths before relying on encrypted-at-rest storage. Existing plaintext profiles are not automatically migrated by adding this helper alone; back them up privately and migrate them only after configuring the key.

The admin login now fails closed when the admin username/password environment variables are unset. Set both before starting the service.

## 4. Rotate previously exposed credentials
If VPN, router, or administrator passwords have ever been committed to a public repository, change those credentials at the respective services. Encryption in a new commit does not remove secrets from older Git history.
