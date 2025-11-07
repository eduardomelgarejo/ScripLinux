#!/usr/bin/env bash
# patch_systemd_overrides.sh
# Aplica los override.conf de hardening para los servicios trabajados
# Seguro por defecto: NO reinicia ssh.service, ifup@ens33.service ni getty@tty1.service
#
# Uso:
#   sudo ./patch_systemd_overrides.sh
#
set -euo pipefail

# ------------------ Configurables ------------------
# Si quieres que el script reinicie ssh (Riesgo de perder la sesión SSH),
# pon SKIP_SSH=0 (recomendado solo si ejecutas desde consola local o tienes otra sesión).
SKIP_SSH=1
SKIP_IFUP=1
SKIP_GETTY=1

BACKUP_DIR="/backup"
BACKUP_FILE="${BACKUP_DIR}/systemd_backup_$(date +%F_%T).tar.gz"
LOGFILE="/var/log/hardening_overrides_$(date +%F).log"

SERVICES_TO_PROCESS=( \
  cron.service \
  dbus.service \
  lynis.service \
  rc-local.service \
  systemd-fsckd.service \
  systemd-initctl.service \
  ssh.service \
  vgauth.service \
  user@.service \
)

echo "Inicio: $(date)" | tee -a "$LOGFILE"

# ------------- Pre-checks -------------
if (( EUID != 0 )); then
  echo "ERROR: Debes ejecutar este script como root (sudo)." | tee -a "$LOGFILE"
  exit 1
fi

mkdir -p "$BACKUP_DIR"
echo "Creando backup de /etc/systemd en $BACKUP_FILE" | tee -a "$LOGFILE"
tar czf "$BACKUP_FILE" /etc/systemd || { echo "Warning: fallo al crear backup"; }

# Función helper para crear override
write_override () {
  local dir="$1"
  local file="$2"
  local content="$3"

  mkdir -p "$dir"
  # backup existing file if present
  if [ -f "${dir}/${file}" ]; then
    cp -a "${dir}/${file}" "${dir}/${file}.bak_$(date +%F_%T)"
  fi

  tee "${dir}/${file}" >/dev/null <<'EOF'
${content}
EOF
  chmod 0644 "${dir}/${file}"
  echo "Wrote ${dir}/${file}" | tee -a "$LOGFILE"
}

# ------------------ Overrides ------------------
echo "Aplicando overrides..." | tee -a "$LOGFILE"

# 1) cron.service
write_override "/etc/systemd/system/cron.service.d" "override.conf" "[Service]
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
LockPersonality=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelTunables=yes
RestrictRealtime=yes
ReadWritePaths=/var/spool/cron /etc/cron.d /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
UMask=0077"

# 2) dbus.service
write_override "/etc/systemd/system/dbus.service.d" "override.conf" "[Service]
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RestrictRealtime=yes
UMask=0077
RestrictAddressFamilies=AF_UNIX
ProtectProc=invisible
ProcSubset=pid"

# 3) emergency & rescue (mask)
echo "Masking emergency.service and rescue.service" | tee -a "$LOGFILE"
systemctl mask emergency.service || true
systemctl mask rescue.service || true

# 4) getty@tty1.service -> create override but do not restart by default
write_override "/etc/systemd/system/getty@tty1.service.d" "override.conf" "[Service]
# Disabled override placeholder; careful with restarts on remote sessions
# If you want to unmask/unmask, do it manually.
"

# 5) ifup@ens33.service -> create override but skip restart by default
write_override "/etc/systemd/system/ifup@ens33.service.d" "override.conf" "[Service]
# Network interface override placeholder - do NOT restart if you are SSH'd over this interface
"

# 6) lynis.service (protected + timer enable)
mkdir -p /root/lynis-reports
touch /var/log/lynis.log /var/log/lynis-report.dat || true
chown root:root /var/log/lynis.log /var/log/lynis-report.dat || true
write_override "/etc/systemd/system/lynis.service.d" "override.conf" "[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
LockPersonality=yes
RuntimeDirectory=lynis
RuntimeDirectoryMode=0755
ReadWritePaths=/run/lynis /var/log/lynis.log /var/log/lynis-report.dat /root/lynis-reports /var/tmp
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
UMask=0077"

# Unmask and enable timer (safe)
systemctl unmask lynis.service lynis.timer || true
systemctl daemon-reload
systemctl enable --now lynis.timer || true

# 7) rc-local.service
write_override "/etc/systemd/system/rc-local.service.d" "override.conf" "[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
ReadWritePaths=/var/log /tmp /run
UMask=0077
RestrictRealtime=yes
ProtectKernelLogs=yes
ProtectProc=invisible
ProcSubset=pid
CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_SYS_MODULE CAP_SYS_TIME CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_NET_RAW CAP_BPF CAP_MAC_ADMIN CAP_WAKE_ALARM CAP_BLOCK_SUSPEND CAP_IPC_LOCK CAP_LINUX_IMMUTABLE
SystemCallFilter=@system-service
SystemCallFilter=~@mount @module @raw-io @reboot @obsolete @debug @swap @cpu-emulation @resources"

# 8) systemd-fsckd.service
write_override "/etc/systemd/system/systemd-fsckd.service.d" "override.conf" "[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
RestrictRealtime=yes
SystemCallArchitectures=native
PrivateUsers=yes
UMask=0077
CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_SYS_MODULE CAP_SYS_TIME CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_MAC_ADMIN CAP_WAKE_ALARM CAP_BLOCK_SUSPEND CAP_IPC_LOCK CAP_LINUX_IMMUTABLE
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=@system-service
SystemCallFilter=~@mount @module @reboot @obsolete @raw-io @debug @swap @cpu-emulation @resources
ProtectProc=invisible
ProcSubset=pid
ReadWritePaths=/run /tmp /var/log /var/tmp"

# 9) systemd-initctl.service
write_override "/etc/systemd/system/systemd-initctl.service.d" "override.conf" "[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
PrivateDevices=yes
PrivateUsers=yes
RestrictRealtime=yes
SystemCallArchitectures=native
UMask=0077
CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_SYS_MODULE CAP_SYS_TIME CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_MAC_ADMIN CAP_WAKE_ALARM CAP_BLOCK_SUSPEND CAP_IPC_LOCK CAP_LINUX_IMMUTABLE
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=@system-service
SystemCallFilter=~@mount @module @reboot @obsolete @raw-io @debug @swap @cpu-emulation @resources
ProtectProc=invisible
ProcSubset=pid
ReadWritePaths=/run /tmp /var/log /var/tmp"

# 10) ssh.service (write override but skip restart by default)
write_override "/etc/systemd/system/ssh.service.d" "override.conf" "[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ProtectClock=yes
ProtectHostname=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectKernelLogs=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
SystemCallArchitectures=native
UMask=0077
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ProtectProc=invisible
ProcSubset=pid"

# 11) vgauth.service (VMware guest auth)
# Ensure directories exist (needed for vgauth to start)
mkdir -p /var/lib/open-vm-tools /var/lib/vmware /run/vmware /run/vgauth
chown -R root:root /var/lib/open-vm-tools /var/lib/vmware /run/vmware /run/vgauth || true
write_override "/etc/systemd/system/vgauth.service.d" "override.conf" "[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
SystemCallArchitectures=native
UMask=0077
ProtectProc=invisible
ProcSubset=pid
CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_SYS_MODULE CAP_SYS_TIME CAP_SYS_BOOT CAP_SYS_CHROOT CAP_SYS_TTY_CONFIG CAP_SYSLOG CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_MAC_ADMIN CAP_WAKE_ALARM CAP_BLOCK_SUSPEND CAP_IPC_LOCK CAP_LINUX_IMMUTABLE
RestrictAddressFamilies=AF_UNIX AF_VSOCK AF_NETLINK
IPAddressDeny=any
RuntimeDirectory=vgauth
RuntimeDirectoryMode=0755
ReadWritePaths=/run/vmware /run/vgauth /var/lib/open-vm-tools /var/lib/vmware /var/log /var/tmp"

# 12) user@.service (template for user sessions)
write_override "/etc/systemd/system/user@.service.d" "override.conf" "[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
RestrictSUIDSGID=yes
RestrictRealtime=yes
SystemCallArchitectures=native
UMask=0077
ReadWritePaths=/run/user/%i /tmp /var/tmp /home"

# ------------- Daemon reload and restart (careful with ssh/ifup/getty) -------------
echo "Daemon reload..." | tee -a "$LOGFILE"
systemctl daemon-reload

# Restart services (skip SSH/IFUP/GETTY per safety flags)
RESTART_LIST=( \
  cron.service \
  dbus.service \
  lynis.service \
  rc-local.service \
  systemd-fsckd.service \
  systemd-initctl.service \
  vgauth.service \
)

for svc in "${RESTART_LIST[@]}"; do
  echo "Restarting $svc ..." | tee -a "$LOGFILE"
  systemctl restart "$svc" 2>/dev/null || echo "Warning: could not fully restart $svc (check logs)" | tee -a "$LOGFILE"
done

# Conditional restarts for sensitive services
if [ "$SKIP_SSH" -eq 0 ]; then
  echo "Restarting ssh.service (user requested)..." | tee -a "$LOGFILE"
  systemctl restart ssh.service || echo "Warning: ssh restart failed"
else
  echo "SKIP ssh.service restart (safe mode). To apply immediately run: sudo systemctl daemon-reload && sudo systemctl restart ssh" | tee -a "$LOGFILE"
fi

if [ "$SKIP_IFUP" -eq 0 ]; then
  echo "Restarting ifup@ens33.service (user requested)..." | tee -a "$LOGFILE"
  systemctl restart ifup@ens33.service || echo "Warning: ifup restart failed"
else
  echo "SKIP ifup@ens33.service restart (safe mode). If you manage network locally, you can restart it manually." | tee -a "$LOGFILE"
fi

if [ "$SKIP_GETTY" -eq 0 ]; then
  echo "Restarting getty@tty1.service (user requested)..." | tee -a "$LOGFILE"
  systemctl restart getty@tty1.service || echo "Warning: getty restart failed"
else
  echo "SKIP getty@tty1.service restart (safe mode)." | tee -a "$LOGFILE"
fi

# Ensure lynis.timer enabled
systemctl enable --now lynis.timer 2>/dev/null || true

# Final summary: list security exposures
echo "" | tee -a "$LOGFILE"
echo "Resumen systemd-analyze security (primeras 40 líneas):" | tee -a "$LOGFILE"
systemd-analyze security | sed -n '1,40p' | tee -a "$LOGFILE"

echo "Fin: $(date)" | tee -a "$LOGFILE"
echo "Backup guardado en: $BACKUP_FILE"
echo ""
echo "IMPORTANTE: si omitiste reiniciar ssh/ifup/getty, reinicialos manualmente desde consola local o habilita el reinicio modifcando las variables SKIP_* en el script y ejecutandolo desde la consola local."
