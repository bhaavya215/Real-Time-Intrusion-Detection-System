const express = require("express");
const { spawn } = require("child_process");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

// Global state for IDS process
let idsProcess = null;

// Paths
const pythonScriptPath = path.join(__dirname, "../engine/ids.py");
const logsPath = path.join(__dirname, "../logs/alerts.json");

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
        idsProcess = spawn("python", ["-u", pythonScriptPath]);

        idsProcess.stdout.on("data", (data) => {
            console.log(`[Python STDOUT] ${data}`);
        });

        idsProcess.stderr.on("data", (data) => {
            console.error(`[Python STDERR] ${data}`);
        });

        idsProcess.on("close", (code) => {
            console.log(`IDS process exited with code ${code}`);
            idsProcess = null;
        });

        res.status(200).json({
            message: "IDS started successfully",
            pid: idsProcess.pid,
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
    if (!idsProcess) {
        return res.status(400).json({ error: "IDS is not running" });
    }

    try {
        idsProcess.kill("SIGINT");
        idsProcess = null;
        res.status(200).json({ message: "IDS stopped successfully" });
    } catch (err) {
        console.error("Error stopping IDS:", err);
        res.status(500).json({ error: "Failed to stop IDS" });
    }
});

/**
 * Read alert logs
 */
app.get("/logs", (req, res) => {
    fs.readFile(logsPath, "utf-8", (err, data) => {
        if (err) {
            console.error("Error reading logs:", err);
            return res.status(500).json({ error: "Failed to read logs" });
        }

        try {
            const logs = JSON.parse(data);
            res.status(200).json({ logs });
        } catch (parseErr) {
            console.error("Invalid JSON in logs:", parseErr);
            res.status(500).json({ error: "Corrupted log format" });
        }
    });
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

// Start server
app.listen(port, () => {
    console.log(`Middleware server running on http://localhost:${port}`);
});
