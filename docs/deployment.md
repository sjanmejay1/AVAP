# Deploying AVAP on an Oracle Cloud Always Free VM

This guide puts the whole of AVAP on one free Oracle Cloud VM with HTTPS. No Docker knowledge is needed: you copy and paste each command.

```
Internet ──https──▶ Caddy (ports 80/443, free Let's Encrypt certificate)
                      ├── /api/*, /health ──▶ backend (FastAPI + Nmap)
                      └── everything else ──▶ frontend (Next.js)
                    backend ──▶ db (PostgreSQL)   backend ──▶ demo-web, demo-cache
```

Everything runs as Docker containers on the VM. Docker builds them from this repository, and one command starts them all.

Total time: about an hour, most of it waiting.

---

## 1. Create the VM

In the Oracle Cloud console:

1. **Menu → Compute → Instances → Create instance.**
2. **Name:** `avap`.
3. **Image and shape → Edit:**
   - **Image:** Canonical **Ubuntu 24.04** (the "aarch64" build is picked automatically for Ampere).
   - **Shape:** Ampere → **VM.Standard.A1.Flex**, **2 OCPUs, 12 GB memory**. It shows "Always Free-eligible".
4. **Networking:** keep "Create new virtual cloud network" and "Create new public subnet". Make sure **Assign a public IPv4 address** is on.
5. **Add SSH keys:** choose **Generate a key pair for me**, then **Save private key**. Keep this file safe: it is the only way into the VM.
6. **Create.** Wait until the state is **Running**, then copy the **Public IP address** from the instance page.

> "Out of capacity" means Oracle has no free Ampere VMs right then. Try another availability domain in step 3, or try again later.

## 2. Open ports 80 and 443 in Oracle's firewall

1. On the instance page, click the **subnet** link, then the **Default Security List**.
2. **Add Ingress Rules**, twice:
   - Source CIDR `0.0.0.0/0`, IP protocol TCP, destination port **80**.
   - Source CIDR `0.0.0.0/0`, IP protocol TCP, destination port **443**.

(Port 22 for SSH is already open.)

## 3. Get a free hostname (DuckDNS)

1. Go to <https://www.duckdns.org> and sign in (GitHub or Google).
2. Add a subdomain, for example `avap-yourname`. Your hostname is then `avap-yourname.duckdns.org`.
3. In **current ip**, paste the VM's public IP and click **update ip**.

## 4. Connect to the VM from Windows

Move the downloaded key to `C:\Users\<you>\.ssh\avap-oracle.key`, then in **PowerShell**:

```powershell
icacls "$env:USERPROFILE\.ssh\avap-oracle.key" /inheritance:r
```

```powershell
icacls "$env:USERPROFILE\.ssh\avap-oracle.key" /grant:r "$($env:USERNAME):(R)"
```

```powershell
ssh -i "$env:USERPROFILE\.ssh\avap-oracle.key" ubuntu@YOUR_VM_IP
```

Answer `yes` the first time. Every command from here on runs **on the VM**, in that SSH window.

## 5. Prepare the server (one time)

**Open ports 80/443 in Ubuntu's own firewall** (Oracle's Ubuntu images block them):

```bash
sudo iptables -I INPUT 1 -p tcp -m state --state NEW --dport 80 -j ACCEPT
sudo iptables -I INPUT 1 -p tcp -m state --state NEW --dport 443 -j ACCEPT
sudo netfilter-persistent save
```

**Install Docker** (Docker's official packages for Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git openssl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
```

Type `exit`, then connect again with the same `ssh` command, so the last line takes effect. Check it:

```bash
docker run --rm hello-world
```

It should print "Hello from Docker!".

## 6. Get the code and create the settings file

The deployment files (`docker-compose.prod.yml`, `deploy/`) must be committed and pushed to the branch you deploy (here `main`).

```bash
git clone --branch main https://github.com/sjanmejay1/AVAP.git avap
cd avap
sh deploy/make-env.sh avap-yourname.duckdns.org
```

`make-env.sh` writes `.env` with fresh random secrets: the database password, the JWT key, the encryption key and the proxy secret. It also sets the list of targets visitors may scan:

```
SCAN_TARGET_ALLOWLIST=demo-web,demo-cache,scanme.nmap.org
```

Keep that list. Without it, anyone who signs up could point Nmap at other people's machines, or at the VM's own containers and Oracle's internal network. To add a host you own, edit the line with `nano .env` (save with Ctrl+O, Enter, then Ctrl+X).

Never share or commit `.env`. If you lose `APP_ENCRYPTION_KEY`, the OpenRouter keys users saved can't be recovered (they re-enter them).

## 7. Start AVAP

```bash
docker compose up -d --build
```

The first run downloads and builds everything: about 5–15 minutes. Later starts take seconds. When it returns, check that every container is running:

```bash
docker compose ps
```

`db`, `backend`, `frontend`, `caddy`, `demo-web` and `demo-cache` should be `running`, and `backend`/`frontend` should also show `healthy`. Caddy fetches the HTTPS certificate within a minute.

## 8. Check it works

Open `https://avap-yourname.duckdns.org`:

1. The page loads with a padlock (a valid certificate).
2. **Register** an account, then reload the page: you stay signed in.
3. **Add target** `demo-web`, then **New scan → Quick**. It completes in about a minute. Ports shows `80/tcp open` (nginx), and Hosts shows OS guesses: raw-socket scans work on the VM.
4. Add `example.com`: it is refused with "This target isn't on this deployment's approved list."
5. On the scan page, **Download PDF** and **Raw output** both download.
6. The audit log records your real IP, not a Docker address:

```bash
docker compose exec db psql -U avap_user -d avap -c "select event_type, source_ip from audit_events order by occurred_at desc limit 3;"
```

For AI analysis, each user adds their own free OpenRouter key on the **Profile** page.

## 9. Everyday commands (run inside `~/avap`)

| Task | Command |
|---|---|
| See what's running | `docker compose ps` |
| Follow the backend log (Ctrl+C to stop) | `docker compose logs -f backend` |
| Restart everything | `docker compose restart` |
| Stop everything (data is kept) | `docker compose down` |
| Start again | `docker compose up -d` |
| Update to the latest code | `git pull && docker compose up -d --build` |
| Back up the database | `docker compose exec -T db pg_dump -U avap_user avap > avap-$(date +%F).sql` |

Copy backups to your PC from PowerShell:

```powershell
scp -i "$env:USERPROFILE\.ssh\avap-oracle.key" ubuntu@YOUR_VM_IP:~/avap/avap-*.sql .
```

The containers restart by themselves after a VM reboot.

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| Site doesn't load at all | Check step 2 (security list) and step 5 (iptables), and that DuckDNS shows the VM's current IP. |
| Browser shows a certificate error | Caddy couldn't get a certificate, usually because port 80 or 443 is blocked or DuckDNS is wrong. Check `docker compose logs caddy`, fix it, then run `docker compose restart caddy`. |
| `permission denied ... docker.sock` | You skipped the re-login after `usermod`. Run `exit` and reconnect. |
| `Set AVAP_DOMAIN in .env` (or another variable) | You're not in `~/avap`, or `.env` is missing. Run `cd ~/avap` and `ls -a`. |
| Signed out on every reload | The site must be opened at exactly `https://AVAP_DOMAIN`, the hostname in `.env`. |
| A scan fails immediately | `docker compose logs backend` shows why. Targets must be on `SCAN_TARGET_ALLOWLIST`. |
| VM's public IP changed | Update it in DuckDNS; nothing else changes. |

## 11. Good to know

- **Idle VMs.** Oracle's Always Free docs say it may reclaim Always Free instances that stay idle: under 20% CPU (95th percentile) over 7 days. Keep database backups. Check Oracle's current Always Free page for the rules that apply to your account type.
- **scanme.nmap.org** is Nmap's public test host. It allows occasional scans, not repeated heavy ones. The demo containers are the best targets for visitors.
- **Free OpenRouter models** allow about 20 requests a minute and 50 a day per user key.
- **Changing secrets.** Edit `.env`, then run `docker compose up -d`. Changing `JWT_SECRET_KEY` signs everyone out. Changing `TRUSTED_PROXY_SECRET` is harmless. Don't change `POSTGRES_PASSWORD` after the first start: the database keeps the original password.
- **Remove everything** (deletes all data): `docker compose down -v`, then terminate the instance in the Oracle console.
