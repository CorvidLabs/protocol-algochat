/**
 * Generate status.html from test results
 *
 * Usage: bun scripts/generate-status.ts [--results-dir <path>]
 *
 * Reads test results from JSON files and generates a status dashboard page.
 */

interface Implementation {
    id: string;
    name: string;
    language: string;
    repo: string;
    status: "production" | "active-dev" | "early-stage";
    description: string;
    testCommand: string | null;
}

interface TestResult {
    implementationId: string;
    passed: number;
    failed: number;
    skipped: number;
    total: number;
    duration: number;
    error: string | null;
    timestamp: string;
}

interface ImplementationsConfig {
    implementations: Implementation[];
}

const resultsDir = process.argv.includes("--results-dir")
    ? process.argv[process.argv.indexOf("--results-dir") + 1]
    : "./test-results";

async function loadImplementations(): Promise<Implementation[]> {
    const configPath = "./implementations.json";
    const file = Bun.file(configPath);
    const config: ImplementationsConfig = await file.json();
    return config.implementations;
}

async function loadTestResults(implementationId: string): Promise<TestResult | null> {
    const resultPath = `${resultsDir}/${implementationId}.json`;
    const file = Bun.file(resultPath);

    if (!(await file.exists())) {
        return null;
    }

    try {
        return await file.json();
    } catch {
        return null;
    }
}

function getStatusBadgeClass(status: Implementation["status"]): string {
    switch (status) {
        case "production":
            return "is-success";
        case "active-dev":
            return "is-warning";
        case "early-stage":
            return "is-error";
    }
}

function getStatusLabel(status: Implementation["status"]): string {
    switch (status) {
        case "production":
            return "Production";
        case "active-dev":
            return "Active Dev";
        case "early-stage":
            return "Early Stage";
    }
}

function getTestStatusClass(result: TestResult | null): string {
    if (result === null) {
        return "";
    }
    if (result.error !== null) {
        return "is-error";
    }
    if (result.failed > 0) {
        return "is-warning";
    }
    return "is-success";
}

function getProgressClass(result: TestResult | null): string {
    if (result === null) {
        return "is-pattern";
    }
    if (result.error !== null) {
        return "is-error";
    }
    if (result.failed > 0) {
        return "is-warning";
    }
    return "is-success";
}

function formatDuration(ms: number): string {
    if (ms < 1000) {
        return `${ms}ms`;
    }
    return `${(ms / 1000).toFixed(1)}s`;
}

function generateImplementationCard(impl: Implementation, result: TestResult | null): string {
    const statusClass = getStatusBadgeClass(impl.status);
    const statusLabel = getStatusLabel(impl.status);
    const testStatusClass = getTestStatusClass(result);
    const progressClass = getProgressClass(result);

    let testInfo: string;
    let progressBar: string;
    let progressPercent = 0;

    if (impl.testCommand === null) {
        testInfo = `<span class="nes-text">No Tests</span>`;
        progressBar = `<progress class="nes-progress is-pattern" value="0" max="100"></progress>`;
    } else if (result === null) {
        testInfo = `<span class="nes-text">Pending</span>`;
        progressBar = `<progress class="nes-progress is-pattern" value="0" max="100"></progress>`;
    } else if (result.error !== null) {
        testInfo = `<span class="nes-text is-error">Error: ${escapeHtml(result.error)}</span>`;
        progressBar = `<progress class="nes-progress is-error" value="100" max="100"></progress>`;
    } else {
        progressPercent = result.total > 0 ? Math.round((result.passed / result.total) * 100) : 0;
        const testText = result.failed > 0
            ? `<span class="nes-text is-warning">${result.passed}/${result.total} passed</span>`
            : `<span class="nes-text is-success">${result.passed}/${result.total} passed</span>`;
        const durationText = `<span class="duration">${formatDuration(result.duration)}</span>`;
        testInfo = `${testText} ${durationText}`;
        progressBar = `<progress class="nes-progress ${progressClass}" value="${progressPercent}" max="100"></progress>`;
    }

    const timestamp = result?.timestamp
        ? `<div class="card-timestamp">Updated: ${new Date(result.timestamp).toLocaleString()}</div>`
        : "";

    return `
        <div class="impl-card">
            <div class="card-header">
                <div class="card-title">
                    <strong>${escapeHtml(impl.name)}</strong>
                    <span class="nes-badge"><span class="${statusClass}">${statusLabel}</span></span>
                </div>
                <div class="card-language">${escapeHtml(impl.language)}</div>
            </div>
            <div class="card-description">${escapeHtml(impl.description)}</div>
            <div class="card-tests">
                ${testInfo}
                ${progressBar}
            </div>
            <div class="card-links">
                <a href="https://github.com/${impl.repo}" class="nes-btn is-primary is-small">GitHub</a>
            </div>
            ${timestamp}
        </div>
    `;
}

function escapeHtml(text: string): string {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function generateSvgBadge(impl: Implementation, result: TestResult | null): string {
    let label: string;
    let color: string;
    let value: string;

    if (impl.testCommand === null) {
        label = impl.id;
        value = "no tests";
        color = "#6c757d";
    } else if (result === null) {
        label = impl.id;
        value = "pending";
        color = "#6c757d";
    } else if (result.error !== null) {
        label = impl.id;
        value = "error";
        color = "#e76e55";
    } else if (result.failed > 0) {
        label = impl.id;
        value = `${result.passed}/${result.total}`;
        color = "#f7d51d";
    } else {
        label = impl.id;
        value = `${result.passed}/${result.total}`;
        color = "#92cc41";
    }

    const labelWidth = label.length * 6.5 + 10;
    const valueWidth = value.length * 6.5 + 10;
    const totalWidth = labelWidth + valueWidth;

    return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </mask>
  <g mask="url(#a)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="${labelWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="${labelWidth / 2}" y="14">${label}</text>
    <text x="${labelWidth + valueWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${value}</text>
    <text x="${labelWidth + valueWidth / 2}" y="14">${value}</text>
  </g>
</svg>`;
}

function generateHtml(implementations: Implementation[], results: Map<string, TestResult | null>): string {
    const cards = implementations
        .map((impl) => generateImplementationCard(impl, results.get(impl.id) ?? null))
        .join("\n");

    const totalTests = Array.from(results.values())
        .filter((r): r is TestResult => r !== null && r.error === null)
        .reduce((sum, r) => sum + r.total, 0);
    const totalPassed = Array.from(results.values())
        .filter((r): r is TestResult => r !== null && r.error === null)
        .reduce((sum, r) => sum + r.passed, 0);
    const totalFailed = Array.from(results.values())
        .filter((r): r is TestResult => r !== null && r.error === null)
        .reduce((sum, r) => sum + r.failed, 0);

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AlgoChat Implementation Status</title>
    <link href="https://unpkg.com/nes.css@2.3.0/css/nes.min.css" rel="stylesheet" />
    <link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet">
    <style>
        * {
            font-family: 'Press Start 2P', cursive;
        }
        body {
            background-color: #212529;
            color: #f8f9fa;
            padding: 20px;
            font-size: 12px;
            line-height: 1.8;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        .nes-container {
            background-color: #2d3238;
        }
        .nes-container.is-dark {
            background-color: #212529;
        }
        .nes-container.with-title > .title {
            background-color: #212529;
            color: #92cc41;
        }
        h1, h2, h3 {
            color: #92cc41;
        }
        a {
            color: #209cee;
        }
        a:hover {
            color: #92cc41;
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .header i {
            font-size: 64px;
            color: #f7d51d;
        }
        .summary-stats {
            display: flex;
            justify-content: center;
            gap: 32px;
            margin: 24px 0;
            flex-wrap: wrap;
        }
        .stat-box {
            text-align: center;
            padding: 16px 24px;
            background-color: #1a1d21;
            border: 2px solid #3d4348;
        }
        .stat-value {
            font-size: 24px;
            display: block;
            margin-bottom: 8px;
        }
        .stat-value.is-success {
            color: #92cc41;
        }
        .stat-value.is-warning {
            color: #f7d51d;
        }
        .stat-value.is-error {
            color: #e76e55;
        }
        .stat-label {
            font-size: 8px;
            color: #adb5bd;
        }
        .impl-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 24px;
            margin: 20px 0;
        }
        @media (max-width: 700px) {
            .impl-grid {
                grid-template-columns: 1fr;
            }
        }
        .impl-card {
            padding: 16px;
            background-color: #1a1d21;
            border: 2px solid #3d4348;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 8px;
        }
        .card-title {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .card-title strong {
            color: #92cc41;
            font-size: 11px;
        }
        .card-language {
            color: #6c757d;
            font-size: 8px;
        }
        .card-description {
            color: #adb5bd;
            font-size: 9px;
            margin-bottom: 16px;
        }
        .card-tests {
            margin-bottom: 16px;
        }
        .card-tests .nes-text {
            display: block;
            margin-bottom: 8px;
            font-size: 9px;
        }
        .card-tests .duration {
            color: #6c757d;
            font-size: 8px;
            margin-left: 8px;
        }
        .card-tests .nes-progress {
            height: 16px;
        }
        .card-links {
            display: flex;
            gap: 8px;
        }
        .card-links .nes-btn {
            font-size: 8px;
            padding: 4px 8px;
        }
        .card-timestamp {
            margin-top: 12px;
            font-size: 7px;
            color: #6c757d;
        }
        .nes-badge span {
            font-size: 7px;
            padding: 2px 6px;
        }
        .links-section {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            justify-content: center;
            margin-top: 30px;
        }
        footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #6c757d;
            font-size: 10px;
        }
        .corvid-logo {
            color: #ff6b35;
        }
        .section {
            margin-top: 24px;
        }
        .back-link {
            margin-bottom: 20px;
        }
        .back-link a {
            font-size: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link">
            <a href="index.html">&lt; Back to Protocol</a>
        </div>

        <div class="header">
            <i class="nes-icon is-large trophy"></i>
            <h1>Implementation Status</h1>
            <p>Test results across all AlgoChat implementations</p>
        </div>

        <section class="nes-container with-title is-dark">
            <p class="title">Summary</p>
            <div class="summary-stats">
                <div class="stat-box">
                    <span class="stat-value">${implementations.length}</span>
                    <span class="stat-label">Implementations</span>
                </div>
                <div class="stat-box">
                    <span class="stat-value is-success">${totalPassed}</span>
                    <span class="stat-label">Tests Passed</span>
                </div>
                <div class="stat-box">
                    <span class="stat-value ${totalFailed > 0 ? "is-error" : ""}">${totalFailed}</span>
                    <span class="stat-label">Tests Failed</span>
                </div>
                <div class="stat-box">
                    <span class="stat-value">${totalTests}</span>
                    <span class="stat-label">Total Tests</span>
                </div>
            </div>
        </section>

        <section class="nes-container with-title is-dark section">
            <p class="title">Implementations</p>
            <div class="impl-grid">
                ${cards}
            </div>
        </section>

        <div class="links-section">
            <a href="index.html" class="nes-btn is-primary">
                Protocol Docs
            </a>
            <a href="https://github.com/CorvidLabs/protocol-algochat" class="nes-btn is-success">
                GitHub
            </a>
        </div>

        <footer>
            <p>Made with <i class="nes-icon is-small heart"></i> by <span class="corvid-logo">Corvid Labs</span></p>
            <p><a href="https://github.com/CorvidLabs">github.com/CorvidLabs</a></p>
            <p style="margin-top: 12px;">Last generated: ${new Date().toISOString()}</p>
        </footer>
    </div>
</body>
</html>`;
}

async function main(): Promise<void> {
    console.log("Loading implementations...");
    const implementations = await loadImplementations();
    console.log(`Found ${implementations.length} implementations`);

    console.log("Loading test results...");
    const results = new Map<string, TestResult | null>();
    for (const impl of implementations) {
        const result = await loadTestResults(impl.id);
        results.set(impl.id, result);
        if (result !== null) {
            console.log(`  ${impl.id}: ${result.passed}/${result.total} passed`);
        } else {
            console.log(`  ${impl.id}: no results`);
        }
    }

    console.log("Generating status.html...");
    const html = generateHtml(implementations, results);
    await Bun.write("status.html", html);
    console.log("Generated status.html");

    console.log("Generating badges...");
    const badgesDir = "./badges";
    await Bun.write(`${badgesDir}/.gitkeep`, "");
    for (const impl of implementations) {
        const badge = generateSvgBadge(impl, results.get(impl.id) ?? null);
        await Bun.write(`${badgesDir}/${impl.id}.svg`, badge);
        console.log(`  Generated ${impl.id}.svg`);
    }

    console.log("Done!");
}

main().catch((error) => {
    console.error("Error:", error);
    process.exit(1);
});
