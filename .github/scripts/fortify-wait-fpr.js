const fs = require("node:fs");
const timers = require("node:timers/promises");
const { exec } = require("node:child_process");
const { promisify } = require("node:util");

const scanId = process.argv[2];
const FORTIFY_USER = process.env.FORTIFY_USER;
const FORTIFY_TOKEN = process.env.FORTIFY_API_TOKEN;
const FORTIFY_TENANT = process.env.FORTIFY_TENANT;

const execAsync = promisify(exec);

async function grepCount(pattern, filePath) {
  try {
    const { stdout } = await execAsync(`grep -c "${pattern}" ${filePath}`);
    const count = parseInt(stdout.trim(), 10);
    return count;
  } catch (error) {
    return 0;
  }
}

async function unzip(filePath) {
  try {
    const { stdout } = await execAsync(`unzip ${filePath}`);
    return stdout;
  } catch (error) {
    console.error(`Error executing command: ${error}`);
    return "";
  }
}

async function main() {
  const tokenData = await fetch("https://api.ams.fortify.com/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: `grant_type=password&scope=api-tenant&username=${FORTIFY_TENANT}\\${FORTIFY_USER}&password=${FORTIFY_TOKEN}&security_code=`,
  }).then((r) => r.json());

  if (!tokenData || !tokenData.access_token) {
    throw new Error("Can't authenticate, check credentials.");
  }

  const token = tokenData.access_token;

  while (true) {
    const summaryResponse = await fetch(
      `https://api.ams.fortify.com/api/v3/scans/${scanId}/summary`,
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    if (summaryResponse.status === 200) {
      const summaryData = await summaryResponse.json();

      if (summaryData.analysisStatusType === "Completed") {
        break;
      }
      console.log(`Scan status: ${summaryData.analysisStatusType}...`);
    } else {
      console.log(`Scan API status: ${summaryResponse.status}...`);
    }
    await timers.setTimeout(5000);
  }

  let buffer;

  while (true) {
    const fileResponse = await fetch(
      `https://api.ams.fortify.com/api/v3/scans/${scanId}/fpr`,
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    if (fileResponse.status === 200) {
      buffer = await fileResponse.arrayBuffer();
      break;
    }

    if ([202, 429].includes(fileResponse.status)) {
      console.log(`Waiting FPR file...`);
      await timers.setTimeout(5000);
    } else {
      throw new Error(
        `Unexpected status code from fpr endpoint: ${fileResponse.status}.`
      );
    }
  }

  fs.writeFileSync("./scandata.fpr", Buffer.from(buffer));

  await unzip("./scandata.fpr");

  const numberOfInfoSevIssues = await grepCount(
    "<InstanceSeverity>1.0</InstanceSeverity>",
    "audit.fvdl"
  );
  const numberOfLowSevIssues = await grepCount(
    "<InstanceSeverity>2.0</InstanceSeverity>",
    "audit.fvdl"
  );
  const numberOfMediumSevIssues = await grepCount(
    "<InstanceSeverity>3.0</InstanceSeverity>",
    "audit.fvdl"
  );
  const numberOfHighSevIssues = await grepCount(
    "<InstanceSeverity>4.0</InstanceSeverity>",
    "audit.fvdl"
  );
  const numberOfCriticalSevIssues = await grepCount(
    "<InstanceSeverity>5.0</InstanceSeverity>",
    "audit.fvdl"
  );
  const hasBlockingIssues =
    numberOfCriticalSevIssues > 0 || numberOfHighSevIssues > 0;
  console.log(
    `Scan complete, number of info severity issues: ${numberOfInfoSevIssues}, number of low severity issues: ${numberOfLowSevIssues}, number of medium severity issues: ${numberOfMediumSevIssues}, number of high severity issues: ${numberOfHighSevIssues}, number of critical severity issues: ${numberOfCriticalSevIssues}`
  );
  if (hasBlockingIssues) {
    process.exit(1);
  }
}

main().catch(console.error);
