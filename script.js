// ── CHECK 1: Protocol ──
function checkProtocol(url) {
  const isHTTP = url.startsWith("http://") && !url.startsWith("https://");
  return {
    triggered: isHTTP,
    severity: "high", icon: "🔓",
    title: "Insecure Protocol (HTTP)",
    detail: "This URL uses HTTP instead of HTTPS. Legitimate sites almost always use HTTPS.",
    points: 3
  };
}

// ── CHECK 2: IP Address ──
function checkIPAddress(url) {
  const ipPattern = /https?:\/\/(\d{1,3}\.){3}\d{1,3}/;
  return {
    triggered: ipPattern.test(url),
    severity: "high", icon: "🔢",
    title: "IP Address Used Instead of Domain",
    detail: "The URL uses a raw IP address. Legitimate services always use domain names.",
    points: 4
  };
}

// ── CHECK 3: URL Length ──
function checkURLLength(url) {
  const length = url.length;
  if (length > 100) return {
    triggered: true, severity: "high", icon: "📏",
    title: `Very Long URL (${length} characters)`,
    detail: "Unusually long URLs are often padded with junk to hide the real destination.",
    points: 3
  };
  if (length > 75) return {
    triggered: true, severity: "medium", icon: "📏",
    title: `Long URL (${length} characters)`,
    detail: "This URL is longer than average, which can sometimes indicate suspicious activity.",
    points: 1
  };
  return { triggered: false };
}

// ── CHECK 4: Suspicious Keywords ──
function checkSuspiciousKeywords(url) {
  const keywords = [
    "login","signin","verify","verification","secure","security",
    "update","confirm","account","banking","password","credential",
    "wallet","recover","suspend","unusual"
  ];
  const lowerURL = url.toLowerCase();
  const found = keywords.filter(w => lowerURL.includes(w));
  if (found.length >= 3) return {
    triggered: true, severity: "high", icon: "🔑",
    title: `Many Suspicious Keywords (${found.join(", ")})`,
    detail: "Multiple phishing-related keywords found in the URL.",
    points: 4
  };
  if (found.length >= 1) return {
    triggered: true, severity: "medium", icon: "🔑",
    title: `Suspicious Keyword: "${found[0]}"`,
    detail: `The word "${found.join('", "')}" appears in the URL, common in phishing attacks.`,
    points: 2
  };
  return { triggered: false };
}

// ── CHECK 5: Too Many Subdomains ──
function checkSubdomains(url) {
  try {
    const hostname = new URL(url).hostname;
    const dots = (hostname.match(/\./g) || []).length;
    if (dots >= 4) return {
      triggered: true, severity: "high", icon: "🌐",
      title: "Excessive Subdomains Detected",
      detail: `"${hostname}" has too many subdomains — a trick to make fake sites look real.`,
      points: 3
    };
    if (dots === 3) return {
      triggered: true, severity: "medium", icon: "🌐",
      title: "Multiple Subdomains",
      detail: `"${hostname}" has multiple subdomains, which can be suspicious.`,
      points: 1
    };
  } catch(e) {}
  return { triggered: false };
}

// ── CHECK 6: Typosquatting ──
function checkTyposquatting(url) {
const patterns = [
  [/paypa[l1]|paypai/i, "PayPal"],
  [/g00gle|googl3/i, "Google"],
  [/[a4]m[a4]z[o0]n|arnazon/i, "Amazon"],
  [/[f4]aceb[o0][o0]k/i, "Facebook"],
  [/4pple|appl3/i, "Apple"],
  [/micr[o0]s[o0]ft|micros0ft/i, "Microsoft"],
  [/netfl[i1]x|netf1ix/i, "Netflix"],
  [/[i1]nstagram|instaqram/i, "Instagram"],
  [/twitt[e3]r|tw1tter/i, "Twitter"],
  [/linkedln|l[i1]nked[i1]n/i, "LinkedIn"],
  [/y[o0]utube|y0utube/i, "YouTube"],
  [/wh[a4]ts[a4]pp/i, "WhatsApp"]
]; 
  const lowerURL = url.toLowerCase();
  for (const [pattern, brand] of patterns) {
    if (pattern.test(lowerURL)) return {
      triggered: true, severity: "high", icon: "✏️",
      title: `Possible ${brand} Impersonation`,
      detail: `This URL appears to impersonate "${brand}" with a misspelled domain name.`,
      points: 5
    };
  }
  return { triggered: false };
}

// ── CHECK 7: @ Symbol ──
function checkAtSymbol(url) {
  const beforePath = url.split("/").slice(0, 3).join("/");
  return {
    triggered: beforePath.includes("@"),
    severity: "high", icon: "🔣",
    title: "@ Symbol in URL",
    detail: 'The "@" symbol hides the real destination — everything after @ is where you actually go.',
    points: 5
  };
}

// ── CHECK 8: Double Slash ──
function checkDoubleSlash(url) {
  const withoutProtocol = url.replace(/^https?:\/\//, "");
  return {
    triggered: withoutProtocol.includes("//"),
    severity: "medium", icon: "↪️",
    title: "Double Slash (//) in URL Path",
    detail: "A double slash after the domain can be used to redirect users unexpectedly.",
    points: 2
  };
}

// ── CHECK 9: Dangerous File Extension ──
function checkFileExtension(url) {
  const dangerous = [".exe",".bat",".cmd",".vbs",".scr",".zip",".rar",".7z",".dmg",".iso"];
  const lowerURL = url.toLowerCase().split("?")[0];
  const found = dangerous.find(ext => lowerURL.endsWith(ext));
  return {
    triggered: !!found,
    severity: "high", icon: "📁",
    title: `Dangerous File Extension: ${found}`,
    detail: `The URL links to a "${found}" file. This could be malware or an unwanted download.`,
    points: 4
  };
}

// ── CHECK 10: URL Shortener ──
function checkURLShortener(url) {
  const shorteners = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","short.link","rb.gy","cutt.ly","is.gd","buff.ly","tiny.cc"];
  try {
    const hostname = new URL(url).hostname.replace("www.", "");
    const matched = shorteners.find(s => hostname === s);
    return {
      triggered: !!matched,
      severity: "low", icon: "🔗",
      title: `URL Shortener Detected (${matched})`,
      detail: "URL shorteners hide the real destination. Be cautious about where this leads.",
      points: 1
    };
  } catch(e) {}
  return { triggered: false };
}

// ── SCORING ENGINE ──
function analyseURL(url) {
  const checks = [
    checkProtocol, checkIPAddress, checkURLLength,
    checkSuspiciousKeywords, checkSubdomains, checkTyposquatting,
    checkAtSymbol, checkDoubleSlash, checkFileExtension, checkURLShortener
  ];
  let score = 0, flags = [];
  for (const check of checks) {
    const result = check(url);
    if (result.triggered) {
      score += result.points;
      flags.push(result);
    }
  }
  return { score, flags };
}

// ── VERDICT ──
function getVerdict(score) {
  if (score === 0)  return { label: "✅ Likely Safe",          cssClass: "verdict-safe",   color: "#3fb950" };
  if (score <= 3)   return { label: "⚠️ Slightly Suspicious",  cssClass: "verdict-warn",   color: "#d29922" };
  if (score <= 6)   return { label: "🚨 Suspicious",           cssClass: "verdict-warn",   color: "#d29922" };
  return              { label: "☠️ Likely Phishing!",          cssClass: "verdict-danger", color: "#f85149" };
}

// ── DISPLAY RESULTS ──
function displayResults(score, flags) {
  const resultBox = document.getElementById("resultBox");
  const verdictEl = document.getElementById("verdict");
  const scoreBar  = document.getElementById("scoreBar");
  const scoreText = document.getElementById("scoreText");
  const flagsList = document.getElementById("flagsList");
  const clearBtn  = document.getElementById("clearBtn");

  const verdict = getVerdict(score);
  verdictEl.textContent = verdict.label;
  verdictEl.className   = `verdict ${verdict.cssClass}`;
const percent = Math.min((score / 20) * 100, 100);
  scoreBar.style.width      = percent + "%";
  scoreBar.style.background = verdict.color;
  scoreText.textContent     = `${score} pts`;

  flagsList.innerHTML = "";
  if (flags.length === 0) {
    flagsList.innerHTML = `
      <div class="flag-item low">
        <span class="flag-icon">✅</span>
        <div class="flag-text">
          <strong>No red flags detected</strong>
          <span>This URL passed all our automated checks.</span>
        </div>
      </div>`;
  } else {
    for (const flag of flags) {
      flagsList.innerHTML += `
        <div class="flag-item ${flag.severity}">
          <span class="flag-icon">${flag.icon}</span>
          <div class="flag-text">
            <strong>${flag.title}</strong>
            <span>${flag.detail}</span>
          </div>
        </div>`;
    }
  }

  resultBox.classList.remove("hidden");
  clearBtn.classList.remove("hidden");
}

// ── MAIN ENTRY POINT ──
function checkURL() {
  const input  = document.getElementById("urlInput");
  const rawURL = input.value.trim();

  if (!rawURL) {
    input.style.border = "1px solid var(--danger)";
    setTimeout(() => { input.style.border = "1px solid var(--border)"; }, 1500);
    return;
  }

  let url = rawURL;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "http://" + url;
  }

  const { score, flags } = analyseURL(url);
  displayResults(score, flags);
}

// ── CLEAR ──
function clearAll() {
  document.getElementById("urlInput").value = "";
  document.getElementById("resultBox").classList.add("hidden");
  document.getElementById("clearBtn").classList.add("hidden");
  document.getElementById("scoreBar").style.width = "0%";
  document.getElementById("flagsList").innerHTML = "";
  document.getElementById("urlInput").focus();
}

// ── ENTER KEY SUPPORT ──
document.getElementById("urlInput").addEventListener("keydown", function(e) {
  if (e.key === "Enter") checkURL();
});
