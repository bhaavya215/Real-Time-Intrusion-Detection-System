import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

function App() {
    const [status, setStatus] = useState("Stopped");
    const [message, setMessage] = useState("");
    const [logs, setLogs] = useState([]);
    const [blockedIps, setBlockedIps] = useState([]);
    const [rules, setRules] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [blockIp, setBlockIp] = useState("");
    const [unblockIp, setUnblockIp] = useState("");
    const [ruleType, setRuleType] = useState("");
    const [ruleThreshold, setRuleThreshold] = useState("");
    const [ruleDescription, setRuleDescription] = useState("");
    const apiUrl = "http://localhost:3000";

    // Start IDS
    const startIDS = async () => {
        if (isLoading || status === "Running") return;
        setIsLoading(true);
        setMessage("");
        try {
            const response = await axios.post(`${apiUrl}/start`);
            setStatus("Running");
            setMessage(response.data.message);
        } catch (error) {
            setStatus("Stopped");
            setMessage(error.response?.data?.error || "Failed to start IDS");
        } finally {
            setIsLoading(false);
        }
    };

    // Stop IDS
    const stopIDS = async () => {
        if (isLoading || status === "Stopped") return;
        setIsLoading(true);
        setMessage("");
        try {
            const response = await axios.post(`${apiUrl}/stop`);
            setStatus("Stopped");
            setMessage(response.data.message);
        } catch (error) {
            setMessage(error.response?.data?.error || "Failed to stop IDS");
        } finally {
            setIsLoading(false);
        }
    };

    // Shutdown IDS
    const shutdownIDS = async () => {
        if (isLoading) return;
        setIsLoading(true);
        setMessage("");
        try {
            const response = await axios.post(`${apiUrl}/shutdown`);
            setStatus("Stopped");
            setMessage(response.data.message);
            setBlockedIps([]);
            setRules([]);
            setLogs([]);
        } catch (error) {
            setMessage(error.response?.data?.error || "Failed to shutdown IDS");
        } finally {
            setIsLoading(false);
        }
    };

    // Fetch Status
    const fetchStatus = async () => {
        try {
            const res = await axios.get(`${apiUrl}/status`);
            setStatus(res.data.status || "Stopped");
        } catch (error) {
            setStatus("Stopped");
        }
    };

    // Fetch Logs
    const fetchLogs = async () => {
        try {
            const response = await axios.get(`${apiUrl}/logs`);
            console.log("API Response:", response.data); // Debug log
            const parsedLogs = Array.isArray(response.data.logs)
                ? response.data.logs
                : [];
            setLogs(parsedLogs);
            console.log("Updated Logs State:", parsedLogs); // Debug state
        } catch (error) {
            console.error("Fetch Logs Error:", error); // Debug error
            setMessage("Failed to fetch logs");
            setLogs([]);
        }
    };

    // Fetch Blocked IPs
    const fetchBlockedIps = async () => {
        try {
            const response = await axios.get(`${apiUrl}/blocked-ips`);
            setBlockedIps(response.data.blockedIps || []);
        } catch (error) {
            setMessage("Failed to fetch blocked IPs");
            setBlockedIps([]);
        }
    };

    // Fetch Rules
    const fetchRules = async () => {
        try {
            const response = await axios.get(`${apiUrl}/rules`);
            setRules(response.data.rules || []);
        } catch (error) {
            setMessage("Failed to fetch rules");
            setRules([]);
        }
    };

    // Block IP
    const blockIP = async () => {
        if (!blockIp || isLoading) return;
        setIsLoading(true);
        setMessage("");
        try {
            const response = await axios.post(`${apiUrl}/block-ip`, {
                ip: blockIp,
            });
            setMessage(response.data.message);
            fetchBlockedIps();
            setBlockIp("");
        } catch (error) {
            setMessage(error.response?.data?.error || "Failed to block IP");
        } finally {
            setIsLoading(false);
        }
    };

    // Unblock IP
    const unblockIP = async () => {
        if (!unblockIp || isLoading) return;
        setIsLoading(true);
        setMessage("");
        try {
            const response = await axios.post(`${apiUrl}/unblock-ip`, {
                ip: unblockIp,
            });
            setMessage(response.data.message);
            fetchBlockedIps();
            setUnblockIp("");
        } catch (error) {
            setMessage(error.response?.data?.error || "Failed to unblock IP");
        } finally {
            setIsLoading(false);
        }
    };

    // Add Rule
    const addRule = async () => {
        if (!ruleType || !ruleThreshold || isLoading) return;
        setIsLoading(true);
        setMessage("");
        try {
            const response = await axios.post(`${apiUrl}/rules`, {
                type: ruleType,
                threshold: parseInt(ruleThreshold),
                description: ruleDescription || "",
            });
            setMessage(response.data.message);
            fetchRules();
            setRuleType("");
            setRuleThreshold("");
            setRuleDescription("");
        } catch (error) {
            setMessage(error.response?.data?.error || "Failed to add rule");
        } finally {
            setIsLoading(false);
        }
    };

    // Delete Rule
    const deleteRule = async (ruleId) => {
        if (isLoading) return;
        setIsLoading(true);
        setMessage("");
        try {
            const response = await axios.delete(`${apiUrl}/rules/${ruleId}`);
            setMessage(response.data.message);
            fetchRules();
        } catch (error) {
            setMessage(error.response?.data?.error || "Failed to delete rule");
        } finally {
            setIsLoading(false);
        }
    };

    // Reset Logs
    const resetLogs = async () => {
        if (isLoading) return;
        setIsLoading(true);
        setMessage("");
        try {
            const response = await axios.post(`${apiUrl}/reset`);
            setMessage(response.data.message);
            setLogs([]);
        } catch (error) {
            setMessage(error.response?.data?.error || "Failed to reset logs");
        } finally {
            setIsLoading(false);
        }
    };

    // Export Logs
    const exportLogs = async () => {
        try {
            const response = await axios.get(`${apiUrl}/logs/export`, {
                responseType: "blob",
            });
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement("a");
            link.href = url;
            link.setAttribute("download", "logs.json");
            document.body.appendChild(link);
            link.click();
            link.remove();
            setMessage("Logs exported successfully");
        } catch (error) {
            setMessage("Failed to export logs");
        }
    };

    // Fetch data periodically
    useEffect(() => {
        fetchStatus();
        fetchLogs();
        fetchBlockedIps();
        fetchRules();
        const interval = setInterval(() => {
            fetchLogs();
            fetchStatus();
            fetchBlockedIps();
            fetchRules();
        }, 5000);

        return () => clearInterval(interval);
    }, []);

    return (
        <div className="IDSControlPanelContainer">
            <h1 className="IDSControlPanelTitle">IDS Control Panel</h1>
            <div className="IDSControlPanelStatus">
                Status:{" "}
                <span
                    className={
                        status === "Running" ? "statusRunning" : "statusStopped"
                    }
                >
                    {status}
                </span>
            </div>
            {message && <div className="IDSControlPanelMessage">{message}</div>}

            <div className="IDSControlPanelButtonGroup">
                <button
                    onClick={startIDS}
                    className="IDSControlButton IDSControlStartButton"
                    disabled={isLoading || status === "Running"}
                >
                    Start IDS
                </button>
                <button
                    onClick={stopIDS}
                    className="IDSControlStopButton"
                    disabled={isLoading || status === "Stopped"}
                >
                    Stop IDS
                </button>
                <button
                    onClick={shutdownIDS}
                    className="IDSControlStopButton"
                    disabled={isLoading}
                >
                    Shutdown IDS
                </button>
            </div>

            {/* Block IP Section */}
            <div className="IDSControlSection">
                <h2>Block an IP</h2>
                <div className="IDSControlInputGroup">
                    <input
                        type="text"
                        placeholder="IP Address"
                        value={blockIp}
                        onChange={(e) => setBlockIp(e.target.value)}
                        className="IDSControlInput"
                    />
                    <button
                        onClick={blockIP}
                        className="IDSControlButton"
                        disabled={isLoading}
                    >
                        Block
                    </button>
                </div>
            </div>

            {/* Unblock IP Section */}
            <div className="IDSControlSection">
                <h2>Unblock an IP</h2>
                <div className="IDSControlInputGroup">
                    <input
                        type="text"
                        placeholder="IP Address"
                        value={unblockIp}
                        onChange={(e) => setUnblockIp(e.target.value)}
                        className="IDSControlInput"
                    />
                    <button
                        onClick={unblockIP}
                        className="IDSControlButton"
                        disabled={isLoading}
                    >
                        Unblock
                    </button>
                </div>
            </div>

            {/* Add Rule Section */}
            <div className="IDSControlSection">
                <h2>Add Rule</h2>
                <div className="IDSControlInputGroup">
                    <input
                        type="text"
                        placeholder="Rule Type"
                        value={ruleType}
                        onChange={(e) => setRuleType(e.target.value)}
                        className="IDSControlInput"
                    />
                    <input
                        type="number"
                        placeholder="Threshold"
                        value={ruleThreshold}
                        onChange={(e) => setRuleThreshold(e.target.value)}
                        className="IDSControlInput"
                    />
                    <input
                        type="text"
                        placeholder="Description (optional)"
                        value={ruleDescription}
                        onChange={(e) => setRuleDescription(e.target.value)}
                        className="IDSControlInput"
                    />
                    <button
                        onClick={addRule}
                        className="IDSControlButton"
                        disabled={isLoading}
                    >
                        Add Rule
                    </button>
                </div>
            </div>

            {/* Rules List */}
            <div className="IDSControlSection">
                <h2>Existing Rules</h2>
                {rules.length > 0 ? (
                    rules.map((rule) => (
                        <div key={rule.id} className="IDSControlInputGroup">
                            <span>
                                {rule.type} - {rule.threshold} -{" "}
                                {rule.description}
                            </span>
                            <button
                                onClick={() => deleteRule(rule.id)}
                                className="IDSControlDeleteButton"
                                disabled={isLoading}
                            >
                                Delete
                            </button>
                        </div>
                    ))
                ) : (
                    <div>No rules available.</div>
                )}
            </div>

            {/* Blocked IPs List */}
            <div className="IDSControlSection">
                <h2>Blocked IPs</h2>
                {blockedIps.length > 0 ? (
                    blockedIps.map((ip, index) => <div key={index}>{ip}</div>)
                ) : (
                    <div>No blocked IPs.</div>
                )}
            </div>

            {/* Logs */}
            <div className="IDSLogBox">
                <h2 className="IDSLogBoxTitle">Logs</h2>
                <div className="IDSLogScrollArea">
                    {logs.length > 0 ? (
                        logs.map((log, index) => (
                            <div key={index} className="IDSLogEntry">
                                <p>
                                    <strong>Timestamp:</strong> {log.timestamp}
                                </p>
                                <p>
                                    <strong>Type:</strong> {log.type}
                                </p>
                                <p>
                                    <strong>IP Address:</strong> {log.ip}
                                </p>
                                <p>
                                    <strong>Count:</strong> {log.count}
                                </p>
                            </div>
                        ))
                    ) : (
                        <div className="IDSLogNoData">No logs available.</div>
                    )}
                </div>

                <div className="IDSControlPanelButtonGroup">
                    <button
                        onClick={resetLogs}
                        className="IDSControlButton"
                        disabled={isLoading}
                    >
                        Reset Logs
                    </button>
                    <button
                        onClick={exportLogs}
                        className="IDSControlButton"
                        disabled={isLoading}
                    >
                        Export Logs
                    </button>
                </div>
            </div>
        </div>
    );
}

export default App;
