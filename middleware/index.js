const express = require("express");
const { spawn } = require("child_process");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const { PythonShell } = require("python-shell");

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

let idsProcess = null;
let rules = [];
let blockedIps = new Set();

const pythonScriptPath = path.join(__dirname, "../engine/ids.py");
const logsPath = path.join(__dirname, "../logs/alerts.json");

if (!fs.existsSync(logsPath)) {
    fs.writeFileSync(logsPath, JSON.stringify([]));
}

// Load blocked IPs from API on startup
app.get("/blocked-ips", (req, res) => {
    res.status(200).json({ blockedIps: Array.from(blockedIps) });
});

/**
 * Start the IDS process
 */
app.post("/start", (req, res) => {
    if (idsProcess) {
        return res
            .status(400)
            .json({ error: "IDS is already running", pid: idsProcess.pid });
    }

    try {
        idsProcess = new PythonShell(pythonScriptPath, {
            mode: "text",
            pythonOptions: ["-u"], // Unbuffered output
            args: ["start"], // Signal to start sniffing
        });

        idsProcess.on("message", (message) => {
            console.log(`[Python] ${message}`);
        });

        idsProcess.on("error", (err) => {
            console.error(`[Python Error] ${err}`);
        });

        idsProcess.on("close", (code) => {
            console.log(`IDS process exited with code ${code}`);
            idsProcess = null;
        });

        res.status(200).json({
            message: "IDS started successfully",
            pid: idsProcess.childProcess.pid,
        });
    } catch (err) {
        console.error("Error starting IDS:", err);
        res.status(500).json({ error: "Failed to start IDS" });
    }
});

/**
 * Stop the IDS process
 */
app.post("/stop", (req, res) => {
    if (!idsProcess || !idsProcess.childProcess) {
        idsProcess = null;
        return res.status(400).json({ error: "IDS is not running" });
    }

    try {
        // Check if the process is still running
        if (idsProcess.childProcess && !idsProcess.childProcess.killed) {
            // Send SIGTERM to the Python process to stop it gracefully
            idsProcess.childProcess.kill("SIGTERM");
        }

        // Ensure the process is terminated
        idsProcess.end((err) => {
            if (err) {
                console.error("Error ending Python process:", err);
            }
            idsProcess = null;
            res.status(200).json({ message: "IDS stopped successfully" });
        });
    } catch (err) {
        console.error("Error stopping IDS:", err);
        idsProcess = null;
        res.status(500).json({ error: "Failed to stop IDS" });
    }
});

/**
 * Read alert logs
 */
app.get("/logs", (req, res) => {
    try {
        const logsPath = path.join(__dirname, "../logs/alerts.json");
        if (fs.existsSync(logsPath)) {
            const logs = JSON.parse(fs.readFileSync(logsPath, "utf8"));
            res.json({ logs: logs || [] });
        } else {
            res.json({ logs: [] });
        }
    } catch (err) {
        console.error("Error reading logs:", err);
        res.status(500).json({ error: "Failed to fetch logs" });
    }
});
/**
 * Get IDS status
 */
app.get("/status", (req, res) => {
    if (idsProcess) {
        res.status(200).json({ status: "Running", pid: idsProcess.pid });
    } else {
        res.status(200).json({ status: "Stopped" });
    }
});

/**
 * Health check
 */
app.get("/", (req, res) => {
    res.send("IDS Middleware API is running.");
});
app.get("/rules", (req, res) => {
    res.status(200).json({ rules });
});

app.post("/rules", (req, res) => {
    const { type, threshold, description } = req.body;
    if (!type || !threshold) {
        return res
            .status(400)
            .json({ error: "Type and threshold are required" });
    }
    const newRule = {
        id: rules.length + 1,
        type,
        threshold,
        description: description || "",
        createdAt: new Date().toISOString(),
    };
    rules.push(newRule);
    res.status(201).json({ message: "Rule added successfully", rule: newRule });
});

app.delete("/rules/:id", (req, res) => {
    const ruleId = parseInt(req.params.id);
    const ruleIndex = rules.findIndex((rule) => rule.id === ruleId);
    if (ruleIndex === -1) {
        return res.status(404).json({ error: "Rule not found" });
    }
    rules.splice(ruleIndex, 1);
    res.status(200).json({ message: "Rule deleted successfully" });
});

app.get("/alerts", (req, res) => {
    fs.readFile(logsPath, "utf-8", (err, data) => {
        if (err) {
            console.error("Error reading logs for alerts:", err);
            return res.status(500).json({ error: "Failed to read logs" });
        }
        try {
            const logs = JSON.parse(data);
            const fiveMinutesAgo = new Date(
                Date.now() - 5 * 60 * 1000
            ).toISOString();
            const activeAlerts = logs.filter(
                (log) => log.timestamp && log.timestamp >= fiveMinutesAgo
            );
            res.status(200).json({ alerts: activeAlerts });
        } catch (parseErr) {
            console.error("Invalid JSON in logs:", parseErr);
            res.status(500).json({ error: "Corrupted log format" });
        }
    });
});

/**
 * POST /block-ip - Block a specific IP manually
 */

app.post("/block-ip", (req, res) => {
    const { ip } = req.body;
    if (!ip || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
        return res.status(400).json({ error: "Invalid IP address" });
    }
    blockedIps.add(ip);
    fs.writeFileSync(
        path.join(__dirname, "../engine/blocked_ips.json"),
        JSON.stringify(Array.from(blockedIps))
    );
    res.status(200).json({ message: `IP ${ip} blocked successfully` });
    console.log(`Blocked IP: ${ip}`);
});
app.get("/blocked-ips", (req, res) => {
    res.status(200).json({ blockedIps: Array.from(blockedIps) });
});

/**
 * POST /unblock-ip - Unblock a specific IP manually
 */
const blockedIpsPath = path.join(__dirname, "../logs/blocked_ips.json");

app.post("/unblock-ip", (req, res) => {
    const { ip } = req.body;
    if (!ip || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
        return res.status(400).json({ error: "Invalid IP address" });
    }
    if (!blockedIps.has(ip)) {
        return res.status(404).json({ error: "IP not blocked" });
    }
    blockedIps.delete(ip);
    fs.writeFileSync(blockedIpsPath, JSON.stringify(Array.from(blockedIps)));
    res.status(200).json({ message: `IP ${ip} unblocked successfully` });
    console.log(`Unblocked IP: ${ip}`);
});

app.get("/logs/export", (req, res) => {
    fs.readFile(logsPath, "utf-8", (err, data) => {
        if (err) {
            console.error("Error reading logs for export:", err);
            return res.status(500).json({ error: "Failed to read logs" });
        }
        try {
            const logs = JSON.parse(data);
            res.setHeader("Content-Type", "application/json");
            res.setHeader(
                "Content-Disposition",
                "attachment; filename=logs.json"
            );
            res.status(200).send(logs);
        } catch (parseErr) {
            console.error("Invalid JSON in logs:", parseErr);
            res.status(500).json({ error: "Corrupted log format" });
        }
    });
});

app.post("/reset", (req, res) => {
    try {
        fs.writeFileSync(logsPath, JSON.stringify([]));
        res.status(200).json({ message: "Logs cleared successfully" });
    } catch (err) {
        console.error("Error resetting logs:", err);
        res.status(500).json({ error: "Failed to reset logs" });
    }
});

app.post("/shutdown", (req, res) => {
    if (idsProcess) {
        idsProcess.kill("SIGINT");
        idsProcess = null;
    }
    try {
        fs.writeFileSync(logsPath, JSON.stringify([]));
        rules = [];
        blockedIps.clear();
        res.status(200).json({
            message: "IDS shutdown and state reset successfully",
        });
    } catch (err) {
        console.error("Error during shutdown:", err);
        res.status(500).json({ error: "Failed to shutdown IDS" });
    }
});

app.listen(port, () => {
    console.log(`Middleware server running on http://localhost:${port}`);
});
