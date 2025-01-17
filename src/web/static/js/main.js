function startScan() {
  const interface = document.getElementById("interface").value;

  fetch("/api/scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ interface: interface }),
  })
    .then((response) => response.json())
    .then((data) => {
      console.log("Scan started:", data);
      updateDevicesList();
    })
    .catch((error) => console.error("Error:", error));
}

function updateDevicesList() {
  fetch("/api/devices")
    .then((response) => response.json())
    .then((devices) => {
      const devicesList = document.getElementById("devices-list");
      devicesList.innerHTML = devices
        .map(
          (device) => `
            <div class="device-item">
                <h3>${device.name}</h3>
                <p>IP: ${device.ip}</p>
                <p>MAC: ${device.mac}</p>
                <p>Type: ${device.type}</p>
                <p>Vendor: ${device.vendor}</p>
                <p>Last Seen: ${device.last_seen}</p>
                <p>Status: <span class="status-${device.status.toLowerCase()}">${
            device.status
          }</span></p>
                ${
                  device.ports.length
                    ? `<p>Open Ports: ${device.ports.join(", ")}</p>`
                    : ""
                }
                <button onclick="showExploits('${device.type}', '${
            device.ip
          }')">Show Exploits</button>
            </div>
        `
        )
        .join("");
    });
}

function showExploits(deviceType, deviceIp) {
  fetch(`/api/exploits/${deviceType}`)
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    })
    .then((exploits) => {
      const exploitsList = document.getElementById("exploits-list");
      if (Object.keys(exploits).length === 0) {
        exploitsList.innerHTML = `<p class="no-exploits">No exploits available for ${deviceType}</p>`;
        return;
      }

      exploitsList.innerHTML = `
            <h3>Exploits for ${deviceType}</h3>
            <div class="exploits-grid">
                ${Object.entries(exploits)
                  .map(
                    ([id, info]) => `
                    <div class="exploit-card risk-${info.risk.toLowerCase()}">
                        <h4>${info.name}</h4>
                        <p>${info.description}</p>
                        <p class="risk-label">Risk: ${info.risk}</p>
                        <button onclick="runExploit('${id}', '${deviceIp}', '${deviceType}')" 
                                class="exploit-button">
                            Run Exploit
                        </button>
                    </div>
                `
                  )
                  .join("")}
            </div>
        `;
    })
    .catch((error) => {
      console.error("Error:", error);
      document.getElementById("exploits-list").innerHTML = `
            <p class="error-message">Error loading exploits: ${error.message}</p>
        `;
    });
}

function runExploit(exploitId, deviceIp, deviceType) {
  // Show loading state
  const button = event.target;
  const originalText = button.innerText;
  button.disabled = true;
  button.innerText = "Running...";

  fetch("/api/exploit/run", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      exploit_id: exploitId,
      device_ip: deviceIp,
      device_type: deviceType,
    }),
  })
    .then((response) => {
      if (!response.ok) {
        return response.json().then((err) => {
          throw new Error(err.message || "Unknown error occurred");
        });
      }
      return response.json();
    })
    .then((data) => {
      if (data.status === "success") {
        showNotification(
          "success",
          `Exploit executed successfully: ${data.message}`
        );
      } else {
        showNotification("error", `Exploit failed: ${data.message}`);
      }
    })
    .catch((error) => {
      console.error("Error:", error);
      showNotification("error", `Error running exploit: ${error.message}`);
    })
    .finally(() => {
      // Restore button state
      button.disabled = false;
      button.innerText = originalText;
    });
}

function showNotification(type, message) {
  const notification = document.createElement("div");
  notification.className = `notification ${type}`;
  notification.innerHTML = `
        <span class="notification-message">${message}</span>
        <button onclick="this.parentElement.remove()">×</button>
    `;
  document.body.appendChild(notification);
  setTimeout(() => notification.remove(), 5000);
}

// Update devices list every 30 seconds
setInterval(updateDevicesList, 30000);
