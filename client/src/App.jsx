import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

function App() {
    const [status, setStatus] = useState("Stopped");
    const [message, setMessage] = useState("");
    const apiUrl = "http://localhost:3000";

    const startIDS = async () => {
        try {
            const response = await axios.post(`${apiUrl}/start`);
            setStatus("Running");
            setMessage(response.data.message);
        } catch (error) {
            setMessage(error.response?.data?.error || "Failed to start IDS");
        }
    };

    const stopIDS = async () => {
        try {
            const response = await axios.post(`${apiUrl}/stop`);
            setStatus("Stopped");
            setMessage(response.data.message);
        } catch (error) {
            setMessage(error.response?.data?.error || "Failed to stop IDS");
        }
    };

    useEffect(() => {
        // Initial status check (optional, can be expanded later)
    }, []);

    return (
        <div className="App">
            <h1>IDS Control Panel</h1>
            <p>Status: {status}</p>
            <p>{message}</p>
            <button onClick={startIDS} disabled={status === "Running"}>
                Start IDS
            </button>
            <button onClick={stopIDS} disabled={status === "Stopped"}>
                Stop IDS
            </button>
        </div>
    );
}

export default App;
