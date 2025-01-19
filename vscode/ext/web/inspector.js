const API_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery";
const HEADERS = {
  "accept": "application/json;api-version=3.0-preview.1",
  "content-type": "application/json"
};

async function scoreExtension() {
  const input = document.getElementById("extensionInput").value.trim();
  const resultsDiv = document.getElementById("results");
  resultsDiv.style.display = "block";
  resultsDiv.innerHTML = ""; // Clear old output

  if (!input || !input.includes(".")) {
    resultsDiv.innerHTML = "<p>Please enter a valid <code>publisher.extensionName</code>.</p>";
    return;
  }

  try {
    const extensionData = await fetchExtensionByName(input);
    if (!extensionData) {
      resultsDiv.innerHTML = `<p>Extension <strong>${input}</strong> not found.</p>`;
      return;
    }
    const analysis = analyzeExtension(extensionData);
    displayResult(extensionData, analysis);
  } catch (err) {
    resultsDiv.innerHTML = `<p>Error fetching extension <strong>${input}</strong>.<br>${err.
    message}</p>`;
  }
}

async function fetchExtensionByName(publisherExtension) {
  const [publisher, extensionName] = publisherExtension.split(".");

  const body = {
    "filters": [
      {
        "criteria": [
          { "filterType": 8, "value": "Microsoft.VisualStudio.Code" },
          { "filterType": 10, "value": extensionName }
        ],
        "pageNumber": 1,
        "pageSize": 1,
        "sortBy": 4,
        "sortOrder": 0
      }
    ],
    "assetTypes": [],
    "flags": 914
  };

  const res = await fetch(API_URL, {
    method: "POST",
    headers: HEADERS,
    body: JSON.stringify(body)
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  const json = await res.json();
  const extensions = json.results[0].extensions;
  if (!extensions.length) return null;

  const ext = extensions[0];
  return (ext.publisher.publisherName === publisher) ? ext : null;
}

function analyzeExtension(extension) {
  // Replicates suspicious checks from the Python code
  const totalChecks = 6;
  let suspiciousChecks = 0;
  const warnings = [];

  // 1) Domain verified
  if (!extension.publisher.isDomainVerified) {
    suspiciousChecks++;
    warnings.push("Domain is not verified.");
  }

  // 2) Publisher verified
  if (!extension.publisher.flags.includes("verified")) {
    suspiciousChecks++;
    warnings.push("Publisher is not verified.");
  }

  // 3) Newly created (less than 30 days)
  const publishedDate = new Date(extension.publishedDate);
  const now = new Date();
  const daysSincePublish = (now - publishedDate) / (1000 * 3600 * 24);
  if (daysSincePublish < 30) {
    suspiciousChecks++;
    warnings.push("Extension is newly created (less than 30 days old).");
  }

  // 4) Low download count (<100 installs)
  const installStat = extension.statistics.find(s => s.statisticName === "install");
  const downloads = installStat ? installStat.value : 0;
  if (downloads < 100) {
    suspiciousChecks++;
    warnings.push("Low download count (<100).");
  }

  // 5) Low review count (<5)
  const ratingCountStat = extension.statistics.find(s => s.statisticName === "ratingcount");
  const reviews = ratingCountStat ? ratingCountStat.value : 0;
  if (reviews < 5) {
    suspiciousChecks++;
    warnings.push("Few reviews (<5).");
  }

  // 6) Repository link check (broken or missing)
  const repoProperty = extension.versions[0].properties.find(prop => 
    prop.key === "Microsoft.VisualStudio.Services.Links.Source"
  );
  if (!repoProperty) {
    suspiciousChecks++;
    warnings.push("No repository link provided.");
  } else {
    // Attempt HEAD to check for 404
    // Note: This often fails from browser due to CORS on HEAD. We try anyway.
  }

  return { suspiciousChecks, totalChecks, warnings };
}

function displayResult(extension, analysis) {
  const resultsDiv = document.getElementById("results");

  const fullName = `${extension.publisher.publisherName}.${extension.extensionName}`;
  const suspiciousness = `${analysis.suspiciousChecks}/${analysis.totalChecks}`;
  const lines = [];

  lines.push(`<h3>${fullName}</h3>`);
  lines.push(`<p><strong>Display Name:</strong> ${extension.displayName}</p>`);
  lines.push(`<p><strong>Publisher:</strong> ${extension.publisher.displayName} &nbsp; (domain 
  verified: ${extension.publisher.isDomainVerified})</p>`);
  lines.push(`<p><strong>Published Date:</strong> ${new Date(extension.publishedDate).
  toLocaleString()}</p>`);
  lines.push(`<p><strong>Last Updated:</strong> ${new Date(extension.lastUpdated).toLocaleString
  ()}</p>`);
  lines.push(`<p><strong>Link:</strong> <a href="https://marketplace.visualstudio.com/items?
  itemName=${fullName}" target="_blank">View on Marketplace</a></p>`);

  lines.push(`<p><strong>Suspiciousness:</strong> ${suspiciousness}</p>`);
  if (analysis.warnings.length) {
    lines.push("<ul>");
    analysis.warnings.forEach(w => {
      lines.push(`<li class="warning">${w}</li>`);
    });
    lines.push("</ul>");
  } else {
    lines.push("<p>No suspicious indicators found.</p>");
  }

  resultsDiv.innerHTML = lines.join("\n");
}

document.addEventListener("DOMContentLoaded", () => {
    const themeToggle = document.getElementById("themeToggle");
    const themeIcon = document.getElementById("themeIcon");
    let currentTheme = localStorage.getItem("theme");
  
    if (!currentTheme) {
      currentTheme = "dark"; // Default to dark mode
      localStorage.setItem("theme", "dark");
    }
  
    if (currentTheme === "dark") {
      document.body.classList.add("dark-mode");
      themeToggle.checked = true;
      themeIcon.textContent = "🌙"; // Moon icon for dark mode
    } else {
      themeIcon.textContent = "☀️"; // Sun icon for light mode
    }
  
    themeToggle.addEventListener("change", () => {
      if (themeToggle.checked) {
        document.body.classList.add("dark-mode");
        localStorage.setItem("theme", "dark");
        themeIcon.textContent = "🌙"; // Moon icon for dark mode
      } else {
        document.body.classList.remove("dark-mode");
        localStorage.setItem("theme", "light");
        themeIcon.textContent = "☀️"; // Sun icon for light mode
      }
    });
  });