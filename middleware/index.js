const express = require("express");
const { spawn } = require("child_process");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(express.json());

// State to track IDS process
let idsProcess = null;

app.post("/start", (req, res) => {
    if (idsProcess) {
        return res.status(400).json({ error: "IDS is already running" });
    }
    const pythonScript = path.join(__dirname, "../engine/ids.py");
    idsProcess = spawn("python", ["-u", pythonScript]);

    idsProcess.stdout.on("data", (data) => {
        console.log(`Python stdout: ${data}`);
    });

    idsProcess.stderr.on("data", (data) => {
        console.error(`Python stderr: ${data}`);
    });

    idsProcess.on("close", (code) => {
        console.log(`IDS process exited with code ${code}`);
        idsProcess = null;
    });

    res.json({ message: "IDS started", pid: idsProcess.pid });
});

app.post("/stop", (req, res) => {
    if (!idsProcess) {
        return res.status(400).json({ error: "IDS is not running" });
    }
    idsProcess.kill("SIGINT"); // Send Ctrl+C to stop sniffing
    res.json({ message: "IDS stopped" });
});

// Start server
app.listen(port, () => {
    console.log(`Middleware server running on port ${port}`);
});
