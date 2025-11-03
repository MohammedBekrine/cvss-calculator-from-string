const $ = (sel) => document.querySelector(sel);

const form = $("#calc-form");
const vectorInput = $("#vector");
const resultBox = $("#result");
const errorBox = $("#error");
const submitBtn = $("#submit-btn");
const ex31 = $("#ex-v31");
const ex40 = $("#ex-v40");

const V31_SAMPLE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const V40_SAMPLE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";

function showResult(data) {
  resultBox.classList.remove("hidden");
  errorBox.classList.add("hidden");
  resultBox.innerHTML = `
    <strong>Risultato</strong><br />
    <div style="margin-top:.5rem">
      <div><strong>Vector:</strong> <code>${escapeHtml(data.vector)}</code></div>
      <div><strong>Versione:</strong> ${escapeHtml(String(data.version))}</div>
      <div style="font-size:1.25rem;margin-top:.25rem">
        <strong>Punteggio Base:</strong> ${Number(data.score).toFixed(1)}
      </div>
    </div>
  `;
}

function showError(err) {
  errorBox.classList.remove("hidden");
  resultBox.classList.add("hidden");
  const msg = (err && err.message) ? err.message : "Errore sconosciuto";
  let hint = "";
  if (err && err.error === "runtime_error" && /cvss/i.test(msg)) {
    hint = "<br/><small>Sembra mancare la dipendenza per CVSS 4.0. Installa il pacchetto <code>cvss</code>.</small>";
  }
  errorBox.innerHTML = `<strong>Errore:</strong> ${escapeHtml(msg)}${hint}`;
}

function setLoading(loading) {
  submitBtn.disabled = loading;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const vector = vectorInput.value.trim();
  if (!vector) {
    showError({ message: "Inserisci una vector string CVSS" });
    return;
  }
  setLoading(true);
  try {
    const res = await fetch("/calculate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vector }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showError(data);
    } else {
      showResult(data);
    }
  } catch (err) {
    showError({ message: String(err) });
  } finally {
    setLoading(false);
  }
});

ex31.addEventListener("click", () => {
  vectorInput.value = V31_SAMPLE;
});

ex40.addEventListener("click", () => {
  vectorInput.value = V40_SAMPLE;
});

// Prefill a sample for convenience
if (!vectorInput.value) {
  vectorInput.value = V31_SAMPLE;
}

