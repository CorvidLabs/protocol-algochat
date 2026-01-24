/**
 * Generate status.html from test results
 *
 * Usage: bun scripts/generate-status.ts [--results-dir <path>]
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
    const file = Bun.file("./implementations.json");
    const config: ImplementationsConfig = await file.json();
    return config.implementations;
}

async function loadTestResults(implementationId: string): Promise<TestResult | null> {
    const file = Bun.file(`${resultsDir}/${implementationId}.json`);
    if (!(await file.exists())) {
        return null;
    }
    try {
        return await file.json();
    } catch {
        return null;
    }
}

function escapeHtml(text: string): string {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function getStatusClass(status: Implementation["status"]): string {
    switch (status) {
        case "production":
            return "is-success";
        case "active-dev":
            return "is-warning";
        case "early-stage":
            return "is-primary";
    }
}

function getStatusLabel(status: Implementation["status"]): string {
    switch (status) {
        case "production":
            return "Production";
        case "active-dev":
            return "Active";
        case "early-stage":
            return "Early";
    }
}

function generateTableRow(impl: Implementation, result: TestResult | null): string {
    const statusClass = getStatusClass(impl.status);
    const statusLabel = getStatusLabel(impl.status);

    let testsCell: string;
    if (impl.testCommand === null) {
        testsCell = `<span class="test-status test-none">-</span>`;
    } else if (result === null) {
        testsCell = `<span class="test-status test-pending">...</span>`;
    } else if (result.error !== null) {
        testsCell = `<span class="test-status test-error">ERR</span>`;
    } else if (result.failed > 0) {
        testsCell = `<span class="test-status test-warning">${result.passed}/${result.total}</span>`;
    } else {
        testsCell = `<span class="test-status test-success">${result.passed}/${result.total}</span>`;
    }

    return `
                <tr>
                    <td>
                        <a href="https://github.com/${impl.repo}">${escapeHtml(impl.name)}</a>
                    </td>
                    <td>${escapeHtml(impl.language)}</td>
                    <td>${escapeHtml(impl.description)}</td>
                    <td><span class="nes-text ${statusClass}">${statusLabel}</span></td>
                    <td class="tests-col">${testsCell}</td>
                </tr>`;
}

function generateSvgBadge(impl: Implementation, result: TestResult | null): string {
    let value: string;
    let color: string;

    if (impl.testCommand === null) {
        value = "no tests";
        color = "#6c757d";
    } else if (result === null) {
        value = "pending";
        color = "#6c757d";
    } else if (result.error !== null) {
        value = "error";
        color = "#e76e55";
    } else if (result.failed > 0) {
        value = `${result.passed}/${result.total}`;
        color = "#f7d51d";
    } else {
        value = `${result.passed}/${result.total}`;
        color = "#92cc41";
    }

    const label = impl.id;
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
    const rows = implementations
        .map((impl) => generateTableRow(impl, results.get(impl.id) ?? null))
        .join("\n");

    const testedImpls = Array.from(results.values()).filter(
        (r): r is TestResult => r !== null && r.error === null
    );
    const totalPassed = testedImpls.reduce((sum, r) => sum + r.passed, 0);
    const totalFailed = testedImpls.reduce((sum, r) => sum + r.failed, 0);
    const totalTests = testedImpls.reduce((sum, r) => sum + r.total, 0);

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AlgoChat Status</title>
    <link href="https://unpkg.com/nes.css@2.3.0/css/nes.min.css" rel="stylesheet" />
    <link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'Press Start 2P', cursive; }
        body {
            background-color: #212529;
            color: #f8f9fa;
            padding: 20px;
            font-size: 11px;
            line-height: 1.6;
        }
        .container { max-width: 960px; margin: 0 auto; }
        .nes-container { background-color: #2d3238; }
        .nes-container.is-dark { background-color: #212529; }
        .nes-container.with-title > .title {
            background-color: #212529;
            color: #92cc41;
        }
        h1 { color: #92cc41; font-size: 18px; }
        a { color: #209cee; }
        a:hover { color: #92cc41; }

        .header {
            text-align: center;
            margin-bottom: 32px;
        }
        .header i { font-size: 48px; color: #f7d51d; }
        .header p { color: #adb5bd; font-size: 10px; margin-top: 8px; }

        .summary {
            display: flex;
            justify-content: center;
            gap: 48px;
            margin: 24px 0;
        }
        .stat { text-align: center; }
        .stat-value {
            font-size: 28px;
            display: block;
            margin-bottom: 4px;
        }
        .stat-value.green { color: #92cc41; }
        .stat-value.red { color: #e76e55; }
        .stat-label { font-size: 8px; color: #6c757d; }

        .impl-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 10px;
        }
        .impl-table th {
            text-align: left;
            padding: 12px 8px;
            border-bottom: 2px solid #92cc41;
            color: #92cc41;
            font-size: 9px;
        }
        .impl-table td {
            padding: 12px 8px;
            border-bottom: 1px solid #3d4348;
            vertical-align: middle;
        }
        .impl-table tr:hover td { background-color: #2d3238; }
        .impl-table a { text-decoration: none; }
        .impl-table a:hover { text-decoration: underline; }

        .tests-col { text-align: center; }
        .test-status {
            display: inline-block;
            padding: 4px 8px;
            font-size: 9px;
            min-width: 48px;
            text-align: center;
        }
        .test-success { color: #92cc41; }
        .test-warning { color: #f7d51d; }
        .test-error { color: #e76e55; }
        .test-none { color: #6c757d; }
        .test-pending { color: #6c757d; }

        .links {
            display: flex;
            justify-content: center;
            gap: 16px;
            margin-top: 32px;
        }
        .links .nes-btn { font-size: 10px; }

        footer {
            text-align: center;
            margin-top: 40px;
            padding: 16px;
            color: #6c757d;
            font-size: 8px;
        }
        .corvid { color: #ff6b35; }

        .section { margin-top: 24px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <i class="nes-icon trophy"></i>
            <h1>Implementation Status</h1>
            <p>Test results for AlgoChat protocol implementations</p>
        </div>

        <section class="nes-container with-title is-dark">
            <p class="title">Summary</p>
            <div class="summary">
                <div class="stat">
                    <span class="stat-value green">${totalPassed}</span>
                    <span class="stat-label">Passed</span>
                </div>
                <div class="stat">
                    <span class="stat-value ${totalFailed > 0 ? "red" : ""}">${totalFailed}</span>
                    <span class="stat-label">Failed</span>
                </div>
                <div class="stat">
                    <span class="stat-value">${totalTests}</span>
                    <span class="stat-label">Total</span>
                </div>
            </div>
        </section>

        <section class="nes-container with-title is-dark section">
            <p class="title">Implementations</p>
            <table class="impl-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Language</th>
                        <th>Platforms</th>
                        <th>Status</th>
                        <th class="tests-col">Tests</th>
                    </tr>
                </thead>
                <tbody>
${rows}
                </tbody>
            </table>
        </section>

        <div class="links">
            <a href="index.html" class="nes-btn is-primary">Protocol</a>
            <a href="https://github.com/CorvidLabs/protocol-algochat" class="nes-btn">GitHub</a>
        </div>

        <footer>
            <p>Made with <i class="nes-icon is-small heart"></i> by <span class="corvid">Corvid Labs</span></p>
            <p style="margin-top: 8px;">Updated: ${new Date().toISOString().split("T")[0]}</p>
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
        console.log(
            result !== null
                ? `  ${impl.id}: ${result.passed}/${result.total} passed`
                : `  ${impl.id}: no results`
        );
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
