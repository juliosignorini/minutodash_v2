
// Integrador extra de Inteligência de Ameaças - MinutoDash

// 1. ThreatFox (abuse.ch)
async function getThreatFoxIndicators() {
    const postData = { query: "get_iocs", limit: 10 };
    const resp = await fetch("https://threatfox.abuse.ch/api/v1/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(postData)
    });
    const data = await resp.json();
    return data && data.data ? data.data : [];
}

// 2. URLhaus - URLs maliciosas (abuse.ch)
async function getUrlhausRecent() {
    const resp = await fetch("https://urlhaus-api.abuse.ch/v1/urls/recent/");
    const data = await resp.json();
    return data && data.urls ? data.urls.slice(0, 10) : [];
}

// 3. MalwareBazaar - Hashes de malware recentes (abuse.ch)
async function getMalwareBazaar() {
    const postData = { query: "get_recent", selector: "time" };
    const resp = await fetch("https://mb-api.abuse.ch/api/v1/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(postData)
    });
    const data = await resp.json();
    return data && data.data ? data.data.slice(0, 10) : [];
}

// 4. CISA KEV - Vulnerabilidades exploradas ativamente
async function getCISAKnownExploited() {
    const url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    const resp = await fetch(url);
    const data = await resp.json();
    return data.vulnerabilities ? data.vulnerabilities.slice(0, 10) : [];
}

// Renderizar dados nos respectivos cards
async function renderThreatIntelCards() {
    // ThreatFox
    const fox = await getThreatFoxIndicators();
    let tfHtml = "";
    if (fox.length > 0) {
        tfHtml = fox.map(o => 
          `<li><span>[${o.threat_type}]</span> <strong>${o.ioc}</strong> <small>${o.ioc_type}</small> - ${o.tags.join(", ")}</li>`
        ).join("");
    } else { tfHtml = "<li>Nenhum IOC obtido.</li>"; }
    document.getElementById("threatfox-card-list").innerHTML = tfHtml;

    // URLhaus
    const urls = await getUrlhausRecent();
    let uhHtml = "";
    if (urls.length > 0) {
        uhHtml = urls.map(u =>
          `<li><a href="${u.url}" target="_blank">${u.url}</a> <small>${u.threat}</small></li>`
        ).join("");
    } else { uhHtml = "<li>Nenhuma URL maliciosa recente.</li>"; }
    document.getElementById("urlhaus-card-list").innerHTML = uhHtml;

    // MalwareBazaar
    const mal = await getMalwareBazaar();
    let mzHtml = "";
    if (mal.length > 0) {
        mzHtml = mal.map(m =>
          `<li><code>${m.sha256_hash}</code> <small>${m.file_type}</small> - <b>${m.tags && m.tags.join(", ")}</b></li>`
        ).join("");
    } else { mzHtml = "<li>Nenhum hash recente.</li>"; }
    document.getElementById("malwarebazaar-card-list").innerHTML = mzHtml;

    // CISA KEV
    const kev = await getCISAKnownExploited();
    let kevHtml = "";
    if (kev.length > 0) {
        kevHtml = kev.map(k =>
          `<li><strong>${k.cveID}</strong> <small>${k.vendorProject || ""} - ${k.product || ""}</small>: <em>${k.vulnerabilityName || ""}</em></li>`
        ).join("");
    } else { kevHtml = "<li>Sem vulnerabilidades recentes.</li>"; }
    document.getElementById("cisa-kev-card-list").innerHTML = kevHtml;
}

// Autoexecução após carregamento
window.addEventListener("DOMContentLoaded", renderThreatIntelCards);
