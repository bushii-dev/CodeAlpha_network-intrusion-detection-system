# Running Suricata in IPS (inline blocking) mode

By default this project runs Suricata as a passive **IDS** — it alerts but doesn't block traffic. To actively drop malicious packets instead, run it as an **IPS** using NFQUEUE.

## 1. Route traffic through NFQUEUE

```bash
sudo iptables -I FORWARD -j NFQUEUE
```

## 2. Start Suricata bound to the queue

```bash
sudo suricata -c /etc/suricata/suricata.yaml -q 0
```

## 3. Change rule action from `alert` to `drop`

Only do this for rules you've validated against real traffic — an untuned `drop` rule can block legitimate users.

```diff
- alert tcp any any -> $HOME_NET 22 (msg:"Possible SSH Brute Force"; ...)
+ drop  tcp any any -> $HOME_NET 22 (msg:"Blocking SSH Brute Force"; ...)
```

## Notes

- Start in IDS mode, watch alerts for a few days, confirm low false-positive rate, *then* promote specific rules to `drop`.
- Keep a rollback plan: `sudo iptables -D FORWARD -j NFQUEUE` immediately returns to passive monitoring.
- fail2ban (see `scripts/fail2ban-suricata.conf`) is a gentler alternative — it bans repeat offenders after the fact rather than blocking every matching packet inline.
