// App.jsx
import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

function App() {
    const [status, setStatus] = useState("Stopped");
    const [message, setMessage] = useState("");
    const [logs, setLogs] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const apiUrl = "http://localhost:3000";

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

    const fetchStatus = async () => {
        try {
            const res = await axios.get(`${apiUrl}/status`);
            setStatus(res.data.status || "Stopped");
        } catch (error) {
            setStatus("Stopped");
        }
    };

    const fetchLogs = async () => {
        try {
            const response = await axios.get(`${apiUrl}/logs`);
            const parsedLogs = Array.isArray(response.data.logs)
                ? response.data.logs
                : [];
            setLogs(parsedLogs);
        } catch (error) {
            setMessage("Failed to fetch logs");
            setLogs([]);
        }
    };

    useEffect(() => {
        fetchStatus();
        fetchLogs();
        const interval = setInterval(() => {
            fetchLogs();
            fetchStatus();
        }, 5000); // Realtime update every 5 seconds

        return () => clearInterval(interval);
    }, []);

    return (
        <div className="IDSControlPanelContainer">
            <h1 className="IDSControlPanelTitle">IDS Control Panel</h1>
            <p className="IDSControlPanelStatus">
                Status:{" "}
                <span
                    className={
                        status === "Running" ? "statusRunning" : "statusStopped"
                    }
                >
                    {status}
                </span>
            </p>
            <p className="IDSControlPanelMessage">{message}</p>
            <div className="IDSControlPanelButtonGroup">
                <button
                    onClick={startIDS}
                    disabled={isLoading || status === "Running"}
                    className="IDSControlButton"
                >
                    Start IDS
                </button>
                <button
                    onClick={stopIDS}
                    disabled={isLoading || status === "Stopped"}
                    className="IDSControlStopButton"
                >
                    Stop IDS
                </button>
            </div>
            <div className="IDSLogBox">
                <h2 className="IDSLogBoxTitle">Alerts & Logs</h2>
                {logs.length > 0 ? (
                    [...logs].reverse().map((log, index) => (
                        <div key={index} className="IDSLogEntry">
                            <p>
                                <strong>Type:</strong> {log.type || "N/A"}
                            </p>
                            <p>
                                <strong>IP:</strong> {log.ip || "N/A"}
                            </p>
                            <p>
                                <strong>Count:</strong> {log.syn_count || "N/A"}
                            </p>
                            <p>
                                <strong>Time:</strong>{" "}
                                {log.timestamp
                                    ? new Date(log.timestamp).toLocaleString()
                                    : "N/A"}
                            </p>
                        </div>
                    ))
                ) : (
                    <p className="IDSLogNoData">No logs available</p>
                )}
            </div>
        </div>
    );
}

export default App;
