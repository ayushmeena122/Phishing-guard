const analyzeBtn = document.getElementById("analyzeBtn");
const urlInput = document.getElementById("urlInput");

const resultSection = document.getElementById("resultSection");
const errorMessage = document.getElementById("errorMessage");

const riskLevel = document.getElementById("riskLevel");
const riskScore = document.getElementById("riskScore");
const progressBar = document.getElementById("progressBar");
const resultMessage = document.getElementById("resultMessage");

const checksContainer = document.getElementById("checksContainer");


/*
    Known URL shortening services.
*/

const shorteners = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at"
];


/*
    Words commonly found in phishing URLs.
*/

const suspiciousWords = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "bank",
    "wallet",
    "payment",
    "confirm",
    "credential",
    "unlock"
];


function analyzeURL(input) {

    let url;

    /*
        Allow users to enter:
        example.com
        or
        https://example.com
    */

    try {

        if (!input.includes("://")) {
            input = "https://" + input;
        }

        url = new URL(input);

    } catch (error) {

        throw new Error("Please enter a valid URL.");

    }


    let score = 0;
    const checks = [];


    /*
        CHECK 1
        HTTPS
    */

    if (url.protocol === "https:") {

        checks.push({
            title: "HTTPS Encryption",
            description: "The website uses HTTPS.",
            status: "PASS",
            className: "safe"
        });

    } else {

        score += 20;

        checks.push({
            title: "HTTPS Encryption",
            description: "The website does not use HTTPS.",
            status: "WARNING",
            className: "warning"
        });

    }


    /*
        CHECK 2
        IP ADDRESS
    */

    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(url.hostname)) {

        score += 25;

        checks.push({
            title: "IP Address Detection",
            description: "The URL uses an IP address instead of a domain.",
            status: "WARNING",
            className: "warning"
        });

    } else {

        checks.push({
            title: "IP Address Detection",
            description: "The URL uses a normal domain name.",
            status: "PASS",
            className: "safe"
        });

    }


    /*
        CHECK 3
        @ SYMBOL
    */

    if (url.href.includes("@")) {

        score += 25;

        checks.push({
            title: "Suspicious @ Symbol",
            description: "The URL contains an @ symbol.",
            status: "WARNING",
            className: "warning"
        });

    } else {

        checks.push({
            title: "Suspicious @ Symbol",
            description: "No @ symbol detected.",
            status: "PASS",
            className: "safe"
        });

    }


    /*
        CHECK 4
        URL LENGTH
    */

    if (url.href.length > 100) {

        score += 15;

        checks.push({
            title: "URL Length",
            description: "The URL is unusually long.",
            status: "WARNING",
            className: "warning"
        });

    } else {

        checks.push({
            title: "URL Length",
            description: "The URL length appears normal.",
            status: "PASS",
            className: "safe"
        });

    }


    /*
        CHECK 5
        SUBDOMAINS
    */

    const domainParts = url.hostname.split(".");

    if (domainParts.length > 4) {

        score += 15;

        checks.push({
            title: "Subdomain Analysis",
            description: "The URL contains many subdomain levels.",
            status: "WARNING",
            className: "warning"
        });

    } else {

        checks.push({
            title: "Subdomain Analysis",
            description: "No excessive subdomains detected.",
            status: "PASS",
            className: "safe"
        });

    }


    /*
        CHECK 6
        SUSPICIOUS KEYWORDS
    */

    const lowerURL = url.href.toLowerCase();

    const foundWords = suspiciousWords.filter(word =>
        lowerURL.includes(word)
    );

    if (foundWords.length >= 3) {

        score += 20;

        checks.push({
            title: "Suspicious Keywords",
            description:
                "Multiple security-related keywords detected: " +
                foundWords.join(", "),
            status: "WARNING",
            className: "warning"
        });

    } else if (foundWords.length > 0) {

        score += 10;

        checks.push({
            title: "Suspicious Keywords",
            description:
                "Potentially sensitive keyword detected: " +
                foundWords.join(", "),
            status: "NOTICE",
            className: "warning"
        });

    } else {

        checks.push({
            title: "Suspicious Keywords",
            description: "No common phishing keywords detected.",
            status: "PASS",
            className: "safe"
        });

    }


    /*
        CHECK 7
        URL SHORTENER
    */

    if (shorteners.includes(url.hostname.toLowerCase())) {

        score += 20;

        checks.push({
            title: "URL Shortener",
            description:
                "The URL uses a known URL shortening service.",
            status: "WARNING",
            className: "warning"
        });

    } else {

        checks.push({
            title: "URL Shortener",
            description: "No known URL shortener detected.",
            status: "PASS",
            className: "safe"
        });

    }


    /*
        CHECK 8
        DOMAIN HYPHENS
    */

    const hyphenCount =
        (url.hostname.match(/-/g) || []).length;

    if (hyphenCount >= 3) {

        score += 10;

        checks.push({
            title: "Domain Structure",
            description:
                "The domain contains several hyphens.",
            status: "NOTICE",
            className: "warning"
        });

    } else {

        checks.push({
            title: "Domain Structure",
            description: "Domain structure appears normal.",
            status: "PASS",
            className: "safe"
        });

    }


    /*
        Maximum score = 100
    */

    score = Math.min(score, 100);


    return {
        score,
        checks
    };
}


function displayResults(data) {

    const score = data.score;

    riskScore.textContent = score;

    progressBar.style.width = score + "%";


    /*
        Risk classification
    */

    if (score < 30) {

        riskLevel.textContent = "Low Risk";

        progressBar.style.background = "#22c55e";

        resultMessage.textContent =
            "Few suspicious indicators were detected. This does not guarantee that the website is safe.";

    } else if (score < 60) {

        riskLevel.textContent = "Medium Risk";

        progressBar.style.background = "#facc15";

        resultMessage.textContent =
            "Some suspicious characteristics were detected. Proceed carefully.";

    } else {

        riskLevel.textContent = "High Risk";

        progressBar.style.background = "#ef4444";

        resultMessage.textContent =
            "Several phishing indicators were detected. Avoid entering sensitive information.";

    }


    /*
        Display individual checks
    */

    checksContainer.innerHTML = "";

    data.checks.forEach(check => {

        const element = document.createElement("div");

        element.className = "check";

        element.innerHTML = `
            <div class="check-info">
                <h4>${check.title}</h4>
                <p>${check.description}</p>
            </div>

            <div class="status ${check.className}">
                ${check.status}
            </div>
        `;

        checksContainer.appendChild(element);

    });


    resultSection.classList.remove("hidden");
}


function analyze() {

    const value = urlInput.value.trim();

    errorMessage.textContent = "";

    if (!value) {

        resultSection.classList.add("hidden");

        errorMessage.textContent =
            "Please enter a URL.";

        return;
    }


    try {

        const result = analyzeURL(value);

        displayResults(result);

    } catch (error) {

        resultSection.classList.add("hidden");

        errorMessage.textContent =
            error.message;

    }
}


/*
    Analyze button
*/

analyzeBtn.addEventListener("click", analyze);


/*
    Press Enter to analyze
*/

urlInput.addEventListener("keydown", function(event) {

    if (event.key === "Enter") {
        analyze();
    }

});


/*
    Example buttons
*/

const exampleButtons =
    document.querySelectorAll(".example-btn");

exampleButtons.forEach(button => {

    button.addEventListener("click", function() {

        urlInput.value =
            button.dataset.url;

        analyze();

    });

});