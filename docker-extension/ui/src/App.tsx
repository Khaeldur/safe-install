import React, { useState, useEffect, useCallback } from "react";
import {
  Box,
  Typography,
  Tabs,
  Tab,
  TextField,
  Button,
  CircularProgress,
  Alert,
  Paper,
  Chip,
} from "@mui/material";
import ShieldIcon from "@mui/icons-material/Shield";
import { ImageList } from "./components/ImageList";
import { ScanResults } from "./components/ScanResults";

// Docker Desktop Extension SDK — falls back to direct HTTP for standalone testing
let ddClient: any = null;
try {
  const { createDockerDesktopClient } = require("@docker/extension-api-client");
  ddClient = createDockerDesktopClient();
} catch {
  // Running outside Docker Desktop — use fetch directly
}

const API_BASE = ddClient ? "" : "http://localhost:9080";

async function apiFetch(path: string, options?: RequestInit) {
  if (ddClient) {
    const method = options?.method || "GET";
    if (method === "POST") {
      const res = await ddClient.extension.vm?.service?.post(path, options?.body);
      return typeof res === "string" ? JSON.parse(res) : res;
    }
    const res = await ddClient.extension.vm?.service?.get(path);
    return typeof res === "string" ? JSON.parse(res) : res;
  }
  const resp = await fetch(`${API_BASE}${path}`, options);
  return resp.json();
}

interface TabPanelProps {
  children: React.ReactNode;
  value: number;
  index: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  if (value !== index) return null;
  return <Box sx={{ pt: 2 }}>{children}</Box>;
}

export function App() {
  const [tab, setTab] = useState(0);
  const [status, setStatus] = useState<any>(null);

  // Dockerfile scan state
  const [dockerfileContent, setDockerfileContent] = useState("");
  const [dockerfileScanResult, setDockerfileScanResult] = useState<any>(null);
  const [dockerfileScanning, setDockerfileScanning] = useState(false);

  // Image scan state
  const [imageScanResult, setImageScanResult] = useState<any>(null);

  // History state
  const [history, setHistory] = useState<any[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const loadStatus = useCallback(async () => {
    try {
      const data = await apiFetch("/api/status");
      setStatus(data);
    } catch {}
  }, []);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const data = await apiFetch("/api/findings?channel=docker-extension&limit=50");
      setHistory(data.findings || []);
    } catch {
      setHistory([]);
    }
    setHistoryLoading(false);
  }, []);

  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  useEffect(() => {
    if (tab === 2) loadHistory();
  }, [tab, loadHistory]);

  const handleScanImage = async (image: string) => {
    setImageScanResult(null);
    try {
      const data = await apiFetch(`/api/scan-image?image=${encodeURIComponent(image)}`);
      setImageScanResult(data);
    } catch (err: any) {
      setImageScanResult({ error: err.message || "Scan failed" });
    }
  };

  const handleScanDockerfile = async () => {
    if (!dockerfileContent.trim()) return;
    setDockerfileScanning(true);
    setDockerfileScanResult(null);
    try {
      const data = await apiFetch("/api/scan-dockerfile", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: dockerfileContent }),
      });
      setDockerfileScanResult(data);
    } catch (err: any) {
      setDockerfileScanResult({ error: err.message || "Scan failed" });
    }
    setDockerfileScanning(false);
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1200, mx: "auto" }}>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
        <ShieldIcon sx={{ fontSize: 40, color: "success.main" }} />
        <Box>
          <Typography variant="h4" fontWeight="bold">
            Safe Install
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Supply chain security scanner for Docker images and Dockerfiles
          </Typography>
        </Box>
        {status && (
          <Box sx={{ ml: "auto", display: "flex", gap: 1 }}>
            <Chip
              label={`${status.recent_scans_1h || 0} scans (1h)`}
              size="small"
              variant="outlined"
            />
            {status.critical_1h > 0 && (
              <Chip label={`${status.critical_1h} critical`} size="small" color="error" />
            )}
            {status.high_1h > 0 && (
              <Chip label={`${status.high_1h} high`} size="small" color="warning" />
            )}
          </Box>
        )}
      </Box>

      {/* Tabs */}
      <Paper sx={{ borderBottom: 1, borderColor: "divider" }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)}>
          <Tab label="Images" />
          <Tab label="Dockerfile Scan" />
          <Tab label="History" />
        </Tabs>
      </Paper>

      {/* Images Tab */}
      <TabPanel value={tab} index={0}>
        <ImageList onScan={handleScanImage} ddClient={ddClient} />
        {imageScanResult && (
          <Box sx={{ mt: 3 }}>
            <ScanResults result={imageScanResult} />
          </Box>
        )}
      </TabPanel>

      {/* Dockerfile Tab */}
      <TabPanel value={tab} index={1}>
        <Typography variant="h6" gutterBottom>
          Scan Dockerfile Content
        </Typography>
        <TextField
          multiline
          rows={12}
          fullWidth
          placeholder={"FROM python:3.12-slim\nRUN pip install flask\nCOPY . /app\nCMD [\"python\", \"app.py\"]"}
          value={dockerfileContent}
          onChange={(e) => setDockerfileContent(e.target.value)}
          sx={{ fontFamily: "monospace", mb: 2 }}
        />
        <Button
          variant="contained"
          onClick={handleScanDockerfile}
          disabled={dockerfileScanning || !dockerfileContent.trim()}
          startIcon={dockerfileScanning ? <CircularProgress size={18} /> : <ShieldIcon />}
        >
          {dockerfileScanning ? "Scanning..." : "Scan Dockerfile"}
        </Button>
        {dockerfileScanResult && (
          <Box sx={{ mt: 3 }}>
            <ScanResults result={dockerfileScanResult} />
          </Box>
        )}
      </TabPanel>

      {/* History Tab */}
      <TabPanel value={tab} index={2}>
        <Typography variant="h6" gutterBottom>
          Recent Scans
        </Typography>
        {historyLoading ? (
          <CircularProgress />
        ) : history.length === 0 ? (
          <Alert severity="info">No scan history yet.</Alert>
        ) : (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
            {history.map((entry, i) => (
              <Paper key={entry.id || i} sx={{ p: 2, display: "flex", alignItems: "center", gap: 2 }}>
                <SeverityChip severity={entry.severity} />
                <Typography variant="body1" fontWeight="medium" sx={{ minWidth: 200 }}>
                  {entry.package}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {entry.ecosystem}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ ml: "auto" }}>
                  {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : ""}
                </Typography>
                <Chip
                  label={`${entry.findings_count || 0} findings`}
                  size="small"
                  variant="outlined"
                />
              </Paper>
            ))}
          </Box>
        )}
      </TabPanel>
    </Box>
  );
}

function SeverityChip({ severity }: { severity: string }) {
  const colorMap: Record<string, "error" | "warning" | "info" | "success" | "default"> = {
    CRITICAL: "error",
    HIGH: "warning",
    MEDIUM: "info",
    LOW: "default",
    CLEAN: "success",
  };
  return <Chip label={severity || "CLEAN"} color={colorMap[severity] || "default"} size="small" />;
}
