document.addEventListener("DOMContentLoaded", () => {
  const urlInput = document.getElementById("url");
  const scanBtn = document.getElementById("scanBtn");
  const clearBtn = document.getElementById("clearBtn");
  const result = document.getElementById("result");
  const statusText = document.getElementById("statusText");
  const messageText = document.getElementById("messageText");
  const issuesList = document.getElementById("issuesList");
  const scoreVal = document.getElementById("scoreVal");

  function showResult(data) {
    result.classList.remove("hidden");
    statusText.textContent = (data.status || "").toUpperCase();
    messageText.textContent = data.message || "";
    scoreVal.textContent = data.score ?? "N/A";
    issuesList.innerHTML = "";
    if (Array.isArray(data.issues) && data.issues.length) {
      data.issues.forEach(i => {
        const d = document.createElement("div");
        d.className = "issue";
        d.textContent = "• " + i;
        issuesList.appendChild(d);
      });
    } else {
      issuesList.innerHTML = "<div class='issue'>No specific issues detected.</div>";
    }

    statusText.classList.remove("status-safe", "status-suspicious", "status-danger");
    if (data.status === "safe") statusText.classList.add("status-safe");
    else if (data.status === "suspicious") statusText.classList.add("status-suspicious");
    else if (data.status === "danger") statusText.classList.add("status-danger");
  }

  scanBtn.addEventListener("click", async () => {
    const url = urlInput.value.trim();
    if (!url) return alert("Please paste a URL first.");
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";
    try {
      const resp = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await resp.json();
      if (!resp.ok) {
        alert(data.error || "Error scanning URL");
      } else {
        showResult(data);
      }
    } catch (err) {
      alert("Network error or server not running.");
      console.error(err);
    } finally {
      scanBtn.disabled = false;
      scanBtn.textContent = "Scan Link";
    }
  });

  clearBtn.addEventListener("click", () => {
    urlInput.value = "";
    result.classList.add("hidden");
  });

  // quick paste handler for convenience
  urlInput.addEventListener("paste", () => {
    setTimeout(() => urlInput.value = urlInput.value.trim(), 50);
  });
});
