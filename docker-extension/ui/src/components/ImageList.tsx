import React, { useState, useEffect, useCallback } from "react";
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Button,
  CircularProgress,
  Chip,
  TextField,
  Alert,
} from "@mui/material";
import ShieldIcon from "@mui/icons-material/Shield";
import SearchIcon from "@mui/icons-material/Search";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";

interface DockerImage {
  id: string;
  repository: string;
  tag: string;
  size: string;
  created: string;
}

interface ImageListProps {
  onScan: (image: string) => void;
  ddClient: any;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

export function ImageList({ onScan, ddClient }: ImageListProps) {
  const [images, setImages] = useState<DockerImage[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState<string | null>(null);

  const loadImages = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      if (ddClient?.docker) {
        const result = await ddClient.docker.listImages();
        const parsed: DockerImage[] = result.map((img: any) => {
          const repoTag = img.RepoTags?.[0] || "<none>:<none>";
          const [repository, tag] = repoTag.split(":");
          return {
            id: img.Id?.replace("sha256:", "").substring(0, 12) || "",
            repository: repository || "<none>",
            tag: tag || "<none>",
            size: formatBytes(img.Size || 0),
            created: img.Created
              ? new Date(img.Created * 1000).toLocaleDateString()
              : "",
          };
        });
        setImages(parsed);
      } else {
        // Standalone mode: try docker CLI via fetch or show placeholder
        setImages([
          { id: "abc123def456", repository: "nginx", tag: "latest", size: "187 MB", created: "2024-01-15" },
          { id: "789ghi012jkl", repository: "python", tag: "3.12-slim", size: "125 MB", created: "2024-01-10" },
          { id: "mno345pqr678", repository: "node", tag: "20-alpine", size: "178 MB", created: "2024-01-08" },
          { id: "stu901vwx234", repository: "redis", tag: "7-alpine", size: "30 MB", created: "2024-01-05" },
        ]);
      }
    } catch (err: any) {
      setError(err.message || "Failed to list images");
    }
    setLoading(false);
  }, [ddClient]);

  useEffect(() => {
    loadImages();
  }, [loadImages]);

  const handleScan = async (image: string) => {
    setScanning(image);
    await onScan(image);
    setScanning(null);
  };

  const handleBulkScan = async () => {
    for (const img of filteredImages) {
      const fullName = `${img.repository}:${img.tag}`;
      setScanning(fullName);
      await onScan(fullName);
    }
    setScanning(null);
  };

  const filteredImages = images.filter(
    (img) =>
      !filter ||
      img.repository.toLowerCase().includes(filter.toLowerCase()) ||
      img.tag.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
        <TextField
          size="small"
          placeholder="Filter images..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          InputProps={{ startAdornment: <SearchIcon sx={{ mr: 1, color: "text.secondary" }} /> }}
          sx={{ flexGrow: 1, maxWidth: 400 }}
        />
        <Button variant="outlined" onClick={loadImages} disabled={loading}>
          {loading ? <CircularProgress size={18} /> : "Refresh"}
        </Button>
        <Button
          variant="contained"
          color="warning"
          onClick={handleBulkScan}
          disabled={!!scanning || filteredImages.length === 0}
          startIcon={<PlayArrowIcon />}
        >
          Scan All ({filteredImages.length})
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Image</TableCell>
              <TableCell>Tag</TableCell>
              <TableCell>Size</TableCell>
              <TableCell>Created</TableCell>
              <TableCell align="center">Status</TableCell>
              <TableCell align="right">Action</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                  <CircularProgress />
                </TableCell>
              </TableRow>
            ) : filteredImages.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                  <Typography color="text.secondary">
                    {filter ? "No images match filter" : "No Docker images found"}
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              filteredImages.map((img) => {
                const fullName = `${img.repository}:${img.tag}`;
                const isScanning = scanning === fullName;
                return (
                  <TableRow key={img.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium" fontFamily="monospace">
                        {img.repository}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={img.tag} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>{img.size}</TableCell>
                    <TableCell>{img.created}</TableCell>
                    <TableCell align="center">
                      <ShieldIcon
                        sx={{ fontSize: 20, color: "action.disabled" }}
                        titleAccess="Not scanned yet"
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={() => handleScan(fullName)}
                        disabled={!!scanning}
                        startIcon={
                          isScanning ? (
                            <CircularProgress size={14} />
                          ) : (
                            <ShieldIcon fontSize="small" />
                          )
                        }
                      >
                        {isScanning ? "Scanning..." : "Scan"}
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}
