#!/usr/bin/env bash

echo "============ Prepapring to install CyberSentinel ============"
# --- Function to force-remove existing Docker containers and images ---
cleanup_docker() {
    # Stop and remove existing Graylog containers
    if [ -f /opt/cybersentinel/graylog/docker-compose.yml ]; then
        cd /opt/cybersentinel/graylog
        docker-compose down -v --remove-orphans >/dev/null 2>&1 || true
        rm -rf /opt/cybersentinel/graylog
    fi
}

# --- Function to remove existing Wazuh/CyberSentinel files ---
cleanup_files() {
    # Remove existing Wazuh/CyberSentinel configuration and rules
    rm -f /var/ossec/etc/ossec.conf
    rm -f /var/ossec/etc/rules/local_rules.xml
    rm -f /var/ossec/etc/rules/misp_threat_intel.xml
    rm -f /var/ossec/etc/rules/chavecloak_rules.xml
    rm -f /var/ossec/etc/rules/alienOTX.xml
    rm -f /var/ossec/etc/decoders/local_decoder.xml

    # Remove integration scripts
    rm -rf /var/ossec/integrations
}

# --- Function to remove existing services ---
cleanup_services() {
    # Remove CyberSentinel services if they exist
    if [ -f /etc/systemd/system/cybersentinel-manager.service ]; then
        systemctl stop cybersentinel-manager.service &>/dev/null || true
        systemctl disable cybersentinel-manager.service &>/dev/null || true
        rm /etc/systemd/system/cybersentinel-manager.service
    fi
    if [ -f /etc/systemd/system/cybersentinel-indexer.service ]; then
        systemctl stop cybersentinel-indexer.service &>/dev/null || true
        systemctl disable cybersentinel-indexer.service &>/dev/null || true
        rm /etc/systemd/system/cybersentinel-indexer.service
    fi
    if [ -f /etc/systemd/system/wazuh-dashboard.service ]; then
        systemctl stop wazuh-dashboard.service &>/dev/null || true
        systemctl disable wazuh-dashboard.service &>/dev/null || true
        rm /etc/systemd/system/wazuh-dashboard.service
    fi

    # Reload systemd
    systemctl daemon-reload &>/dev/null
}

# --- Function to remove existing Wazuh install files ---
cleanup_wazuh_files() {
    rm -f /var/ossec/logs/alerts/alerts.json
    rm -f /var/ossec/logs/malware_summary.log
    rm -rf /var/ossec/integrations/*
}

# --- Function to completely remove Wazuh Dashboard ---
remove_wazuh_dashboard() {
    # Stop and disable Wazuh Dashboard service
    systemctl stop wazuh-dashboard.service &>/dev/null || true
    systemctl disable wazuh-dashboard.service &>/dev/null || true

    # Remove Wazuh Dashboard package
    if command -v wazuh-dashboard &>/dev/null; then
        apt-get purge -y wazuh-dashboard &>/dev/null
    fi

    # Remove Wazuh Dashboard directories and files
    rm -rf /var/ossec/dashboard
    rm -rf /etc/wazuh-dashboard
    rm -rf /usr/share/wazuh-dashboard

    # Remove service unit file if present
    if [ -f /etc/systemd/system/wazuh-dashboard.service ]; then
        rm /etc/systemd/system/wazuh-dashboard.service
    elif [ -f /usr/lib/systemd/system/wazuh-dashboard.service ]; then
        rm /usr/lib/systemd/system/wazuh-dashboard.service
    elif [ -f /lib/systemd/system/wazuh-dashboard.service ]; then
        rm /lib/systemd/system/wazuh-dashboard.service
    fi

    # Reload systemd
    systemctl daemon-reload &>/dev/null
}

# --- Main Installation Logic ---
# Cleanup existing components before reinstalling
cleanup_docker
cleanup_files
cleanup_services
cleanup_wazuh_files
remove_wazuh_dashboard  # Call the new function to remove Wazuh Dashboard

# Download the Wazuh all-in-one installer silently
echo  "============ CyberSentinel Download Started ============"
curl -sSL "https://packages.wazuh.com/4.11/wazuh-install.sh" -o wazuh-install.sh

# Rename the installer
mv wazuh-install.sh cybersentinel-install.sh

# Run the installer in all-in-one mode (quiet, ignore checks)
bash cybersentinel-install.sh -a -i -o > install.log 2>&1
install_status=$?

echo "============ Phase 1 Complete ==========="

if [ $install_status -eq 0 ]; then
    # --- Post-installation configuration ---

    # Prompt for the root password and generate SHA256 hash
    echo -n "Enter Password: "
    echo " "
    read -s PASSWORD_INPUT
    GRAYLOG_ROOT_PASSWORD_SHA2=$(echo -n "$PASSWORD_INPUT" | sha256sum | cut -d" " -f1)

    # Generate GRAYLOG_PASSWORD_SECRET
    GRAYLOG_PASSWORD_SECRET=$(< /dev/urandom tr -dc A-Z-a-z-0-9 | head -c 96; echo)

    # Create .env file for Graylog
    mkdir -p /opt/cybersentinel/graylog
    echo -e "GRAYLOG_PASSWORD_SECRET=\"$GRAYLOG_PASSWORD_SECRET\"\nGRAYLOG_ROOT_PASSWORD_SHA2=\"$GRAYLOG_ROOT_PASSWORD_SHA2\"" > /opt/cybersentinel/graylog/.env
    chown root:root /opt/cybersentinel/graylog/.env
    chmod 600 /opt/cybersentinel/graylog/.env

    # Stop and disable Wazuh Manager service
    systemctl stop wazuh-manager.service &>/dev/null
    systemctl disable wazuh-manager.service &>/dev/null
    # Rename service unit file if present
    if [ -f /etc/systemd/system/wazuh-manager.service ]; then
        mv /etc/systemd/system/wazuh-manager.service /etc/systemd/system/cybersentinel-manager.service
    elif [ -f /usr/lib/systemd/system/wazuh-manager.service ]; then
        mv /usr/lib/systemd/system/wazuh-manager.service /usr/lib/systemd/system/cybersentinel-manager.service
    elif [ -f /lib/systemd/system/wazuh-manager.service ]; then
        mv /lib/systemd/system/wazuh-manager.service /lib/systemd/system/cybersentinel-manager.service
    fi

    # Stop and disable Wazuh Indexer service
    systemctl stop wazuh-indexer.service &>/dev/null
    systemctl disable wazuh-indexer.service &>/dev/null
    # Rename service unit file if present
    if [ -f /etc/systemd/system/wazuh-indexer.service ]; then
        mv /etc/systemd/system/wazuh-indexer.service /etc/systemd/system/cybersentinel-indexer.service
    elif [ -f /usr/lib/systemd/system/wazuh-indexer.service ]; then
        mv /usr/lib/systemd/system/wazuh-indexer.service /usr/lib/systemd/system/cybersentinel-indexer.service
    elif [ -f /lib/systemd/system/wazuh-indexer.service ]; then
        mv /lib/systemd/system/wazuh-indexer.service /lib/systemd/system/cybersentinel-indexer.service
    fi

    # Reload systemd to apply service renames
    systemctl daemon-reload &>/dev/null
    systemctl enable cybersentinel-manager.service &>/dev/null
    systemctl start cybersentinel-manager.service  &>/dev/null
    echo "============ CyberSentinel Manager Started ============"
    systemctl enable cybersentinel-indexer.service &>/dev/null
    systemctl start cybersentinel-indexer.service  &>/dev/null
    echo "============ CyberSentinel indexer Started ============"

    # Replace main ossec.conf with CyberSentinel version
    curl -sSL "https://github.com/cybersentinel-06/CyberSentinel-SIEM/raw/main/SERVER/ossec.conf" \
         -o /var/ossec/etc/ossec.conf

    # Replace custom rules
    curl -sSL "https://github.com/cybersentinel-06/CyberSentinel-SIEM/raw/main/SERVER/RULES/local_rules.xml" \
         -o /var/ossec/etc/rules/local_rules.xml
    curl -sSL "https://github.com/cybersentinel-06/CyberSentinel-SIEM/raw/main/SERVER/RULES/misp_threat_intel.xml" \
         -o /var/ossec/etc/rules/misp_threat_intel.xml
    curl -sSL "https://github.com/cybersentinel-06/CyberSentinel-SIEM/raw/main/SERVER/RULES/chavecloak_rules.xml" \
         -o /var/ossec/etc/rules/chavecloak_rules.xml
    curl -sSL "https://github.com/cybersentinel-06/CyberSentinel-SIEM/raw/main/SERVER/RULES/alienOTX.xml" \
         -o /var/ossec/etc/rules/alienOTX.xml
    # Decoder replacement
    curl -sSL "https://github.com/cybersentinel-06/CyberSentinel-SIEM/raw/main/SERVER/DECODERS/local_decoder.xml" \
         -o /var/ossec/etc/decoders/local_decoder.xml

    # Fetch integration scripts and set permission
    mkdir -p /var/ossec/integrations
    INTEGRATIONS=(
        "custom-abuseipdb.py"
        "custom-alienvault"
        "custom-alienvault.py"
        "get_malicious.py"
        "malware_llm_monitor.py"
        "shuffle"
        "shuffle.py"
    )
    for script in "${INTEGRATIONS[@]}"; do
        curl -sSL "https://github.com/cybersentinel-06/CyberSentinel-SIEM/raw/main/SERVER/INTEGRATIONS/$script" \
             -o /var/ossec/integrations/"$script"
        chmod 750 /var/ossec/integrations/"$script"
        chown root:wazuh /var/ossec/integrations/"$script"
    done

    # === Install Docker if not already installed; force reinstall if it exists ===
    if command -v docker >/dev/null 2>&1; then
        apt-get purge -y docker.io &>/dev/null
        rm -rf /var/lib/docker
    fi
    apt-get update -qq
    apt-get install -qq -y docker.io
    systemctl start docker &>/dev/null
    systemctl enable docker &>/dev/null

    # === Install Docker Compose if needed; force reinstall ===
    if command -v docker-compose >/dev/null 2>&1; then
        apt-get purge -y docker-compose &>/dev/null
    fi
    apt-get install -qq -y docker-compose

    echo "============ Deploy CyberSentinel Stack ============"
    #mkdir -p /opt/cybersentinel/graylog
    curl -sSL "https://github.com/cybersentinel-06/CyberSentinel-SIEM/raw/main/GRAYLOG/docker-compose.yml" \
         -o /opt/cybersentinel/graylog/docker-compose.yml
    chown -R root:root /opt/cybersentinel/graylog
    chmod 700 /opt/cybersentinel/graylog

    cd /opt/cybersentinel/graylog
    systemctl stop docker &>/dev/null
    sudo rm -rf /var/lib/docker/tmp/*
    sudo systemctl start docker &>/dev/null
    docker-compose pull &>/dev/null
    docker-compose up -d &>/dev/null || true

    # === Install Fluent Bit; force reinstall ===
    if command -v fluent-bit >/dev/null 2>&1; then
        apt-get purge -y fluent-bit &>/dev/null
        rm -rf /etc/fluent-bit
    fi
    apt-get update -qq
    curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh
    systemctl daemon-reload
    systemctl start fluent-bit &>/dev/null
    systemctl enable fluent-bit &>/dev/null

    # === Replace Fluent Bit Configuration ===
    mkdir -p /etc/fluent-bit
    curl -sSL "https://github.com/cybersentinel-06/CyberSentinel-SIEM/raw/main/FLUENT_BIT/fluent-bit.conf" \
         -o /etc/fluent-bit/fluent-bit.conf
    chown root:root /etc/fluent-bit/fluent-bit.conf
    chmod 644 /etc/fluent-bit/fluent-bit.conf
    systemctl restart fluent-bit &>/dev/null

    # Indicate success
    echo "============ CyberSentinel Installed successfully ============"

    # Clean up temporary files
    rm -f cybersentinel-install.sh
    rm -f install.log

    exit 0
else
    # Installation failed: extract and print the first relevant error line
    err_line=$(grep -i wazuh install.log | grep -i error | head -n1)
    err_line=${err_line//Wazuh/CyberSentinel}
    err_line=${err_line//wazuh/CyberSentinel}

    echo "$err_line"

    # Clean up before exiting with error
    rm -f cybersentinel-install.sh
    rm -f install.log
    exit 1
fi
